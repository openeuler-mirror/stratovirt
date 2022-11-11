// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// StratoVirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use address_space::Region;
use log::debug;

use super::config::{
    BRIDGE_CONTROL, BRIDGE_CTL_SEC_BUS_RESET, SECONDARY_BUS_NUM, SUBORDINATE_BUS_NUM,
};
use super::hotplug::HotplugOps;
use super::PciDevOps;
use anyhow::{bail, Context, Result};

type DeviceBusInfo = (Arc<Mutex<PciBus>>, Arc<Mutex<dyn PciDevOps>>);

/// PCI bus structure.
pub struct PciBus {
    /// Bus name
    pub name: String,
    /// Devices attached to the bus.
    pub devices: HashMap<u8, Arc<Mutex<dyn PciDevOps>>>,
    /// Child buses of the bus.
    pub child_buses: Vec<Arc<Mutex<PciBus>>>,
    /// Pci bridge which the bus orignates from.
    pub parent_bridge: Option<Weak<Mutex<dyn PciDevOps>>>,
    /// IO region which the parent bridge manages.
    #[cfg(target_arch = "x86_64")]
    pub io_region: Region,
    /// Memory region which the parent bridge manages.
    pub mem_region: Region,
    /// Hot Plug controller for obtaining hot plug ops.
    pub hotplug_controller: Option<Weak<Mutex<dyn HotplugOps>>>,
}

impl PciBus {
    /// Create new bus entity.
    ///
    /// # Arguments
    ///
    /// * `name` - String name of pci bus.
    /// * `io_region` - IO region which the parent bridge manages(only for x86_64).
    /// * `mem_region` - Memory region which the parent bridge manages.
    pub fn new(
        name: String,
        #[cfg(target_arch = "x86_64")] io_region: Region,
        mem_region: Region,
    ) -> Self {
        Self {
            name,
            devices: HashMap::new(),
            child_buses: Vec::new(),
            parent_bridge: None,
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
            hotplug_controller: None,
        }
    }

    /// Get secondary bus number / subordinary bus number of the bus
    /// from configuration space of parent.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset of bus number register.
    pub fn number(&self, offset: usize) -> u8 {
        let mut data = vec![0_u8; 1];
        self.get_bridge_control_reg(offset, &mut data);

        data[0]
    }

    /// Get device by the bdf.
    ///
    /// # Arguments
    ///
    /// * `bus_num` - The bus number.
    /// * `devfn` - Slot number << 8 | device number.
    pub fn get_device(&self, bus_num: u8, devfn: u8) -> Option<Arc<Mutex<dyn PciDevOps>>> {
        if let Some(dev) = self.devices.get(&devfn) {
            return Some((*dev).clone());
        }
        debug!("Can't find device {}:{}", bus_num, devfn);
        None
    }

    fn in_range(&self, bus_num: u8) -> bool {
        if self.is_during_reset() {
            return false;
        }

        let secondary_bus_num: u8 = self.number(SECONDARY_BUS_NUM as usize);
        let subordinate_bus_num: u8 = self.number(SUBORDINATE_BUS_NUM as usize);
        if bus_num > secondary_bus_num && bus_num <= subordinate_bus_num {
            return true;
        }
        false
    }

    /// Find bus by the bus number.
    ///
    /// # Arguments
    ///
    /// * `bus` - Bus to find from.
    /// * `bus_number` - The bus number.
    pub fn find_bus_by_num(bus: &Arc<Mutex<Self>>, bus_num: u8) -> Option<Arc<Mutex<Self>>> {
        let locked_bus = bus.lock().unwrap();
        if locked_bus.number(SECONDARY_BUS_NUM as usize) == bus_num {
            return Some((*bus).clone());
        }
        if locked_bus.in_range(bus_num) {
            for sub_bus in &locked_bus.child_buses {
                if let Some(b) = PciBus::find_bus_by_num(sub_bus, bus_num) {
                    return Some(b);
                }
            }
        }
        None
    }

    /// Find bus by name.
    ///
    /// # Arguments
    ///
    /// * `bus` - Bus to find from.
    /// * `name` - Bus name.
    pub fn find_bus_by_name(bus: &Arc<Mutex<Self>>, bus_name: &str) -> Option<Arc<Mutex<Self>>> {
        let locked_bus = bus.lock().unwrap();
        if locked_bus.name.as_str() == bus_name {
            return Some((*bus).clone());
        }
        for sub_bus in &locked_bus.child_buses {
            if let Some(b) = PciBus::find_bus_by_name(sub_bus, bus_name) {
                return Some(b);
            }
        }
        None
    }

    /// Find the bus to which the device is attached.
    ///
    /// # Arguments
    ///
    /// * `pci_bus` - On which bus to find.
    /// * `name` - Device name.
    pub fn find_attached_bus(pci_bus: &Arc<Mutex<PciBus>>, name: &str) -> Option<DeviceBusInfo> {
        // Device is attached in pci_bus.
        let locked_bus = pci_bus.lock().unwrap();
        for dev in locked_bus.devices.values() {
            if dev.lock().unwrap().name() == name {
                return Some((pci_bus.clone(), dev.clone()));
            }
        }
        // Find in child bus.
        for bus in &locked_bus.child_buses {
            if let Some(found) = PciBus::find_attached_bus(bus, name) {
                return Some(found);
            }
        }
        None
    }

    /// Detach device from the bus.
    ///
    /// # Arguments
    ///
    /// * `bus` - Bus to detach from.
    /// * `dev` - Device attached to the bus.
    pub fn detach_device(bus: &Arc<Mutex<Self>>, dev: &Arc<Mutex<dyn PciDevOps>>) -> Result<()> {
        let mut dev_locked = dev.lock().unwrap();
        dev_locked
            .unrealize()
            .with_context(|| format!("Failed to unrealize device {}", dev_locked.name()))?;

        let devfn = dev_locked
            .devfn()
            .with_context(|| format!("Failed to get devfn: device {}", dev_locked.name()))?;

        let mut locked_bus = bus.lock().unwrap();
        if locked_bus.devices.get(&devfn).is_some() {
            locked_bus.devices.remove(&devfn);
        } else {
            bail!("Device {} not found in the bus", dev_locked.name());
        }

        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        for (_id, pci_dev) in self.devices.iter() {
            pci_dev
                .lock()
                .unwrap()
                .reset(false)
                .with_context(|| "Fail to reset pci dev")?;
        }

        for child_bus in self.child_buses.iter_mut() {
            child_bus
                .lock()
                .unwrap()
                .reset()
                .with_context(|| "Fail to reset child bus")?;
        }

        Ok(())
    }

    fn is_during_reset(&self) -> bool {
        let mut data = vec![0_u8; 2];
        self.get_bridge_control_reg(BRIDGE_CONTROL as usize + 1, &mut data);
        if data[1] & ((BRIDGE_CTL_SEC_BUS_RESET >> 8) as u8) != 0 {
            return true;
        }
        false
    }

    fn get_bridge_control_reg(&self, offset: usize, data: &mut [u8]) {
        if self.parent_bridge.is_none() {
            return;
        }

        self.parent_bridge
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .read_config(offset, data);
    }
}

#[cfg(test)]
mod tests {
    use address_space::{AddressSpace, Region};

    use super::*;
    use crate::bus::PciBus;
    use crate::config::{PciConfig, PCI_CONFIG_SPACE_SIZE};
    use crate::root_port::RootPort;
    use crate::PciHost;
    use anyhow::Result;

    #[derive(Clone)]
    struct PciDevice {
        name: String,
        devfn: u8,
        config: PciConfig,
        parent_bus: Weak<Mutex<PciBus>>,
    }

    impl PciDevOps for PciDevice {
        fn init_write_mask(&mut self) -> Result<()> {
            Ok(())
        }

        fn init_write_clear_mask(&mut self) -> Result<()> {
            Ok(())
        }

        fn read_config(&mut self, offset: usize, data: &mut [u8]) {
            self.config.read(offset, data);
        }

        fn write_config(&mut self, offset: usize, data: &[u8]) {
            #[allow(unused_variables)]
            self.config.write(
                offset,
                data,
                0,
                #[cfg(target_arch = "x86_64")]
                None,
                None,
            );
        }

        fn name(&self) -> String {
            self.name.clone()
        }

        fn realize(mut self) -> Result<()> {
            let devfn = self.devfn;
            self.init_write_mask()?;
            self.init_write_clear_mask()?;

            let dev = Arc::new(Mutex::new(self));
            dev.lock()
                .unwrap()
                .parent_bus
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .devices
                .insert(devfn, dev.clone());
            Ok(())
        }

        fn unrealize(&mut self) -> Result<()> {
            Ok(())
        }

        fn devfn(&self) -> Option<u8> {
            Some(0)
        }
    }

    pub fn create_pci_host() -> Arc<Mutex<PciHost>> {
        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16)).unwrap();
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        Arc::new(Mutex::new(PciHost::new(
            #[cfg(target_arch = "x86_64")]
            &sys_io,
            &sys_mem,
            (0xB000_0000, 0x1000_0000),
            (0xC000_0000, 0x3000_0000),
            #[cfg(target_arch = "aarch64")]
            (0xF000_0000, 0x1000_0000),
            #[cfg(target_arch = "aarch64")]
            (512 << 30, 512 << 30),
        )))
    }

    #[test]
    fn test_find_attached_bus() {
        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.root_bus);

        let root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus.clone(), false);
        root_port.realize().unwrap();

        // Test device is attached to the root bus.
        let pci_dev = PciDevice {
            name: String::from("test1"),
            devfn: 10,
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus: root_bus.clone(),
        };
        pci_dev.realize().unwrap();

        // Test device is attached to the root port.
        let bus = PciBus::find_bus_by_name(&locked_pci_host.root_bus, "pcie.1").unwrap();
        let pci_dev = PciDevice {
            name: String::from("test2"),
            devfn: 12,
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus: Arc::downgrade(&bus),
        };
        pci_dev.realize().unwrap();

        let info = PciBus::find_attached_bus(&locked_pci_host.root_bus, "test0");
        assert!(info.is_none());

        let info = PciBus::find_attached_bus(&locked_pci_host.root_bus, "test1");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name, "pcie.0");
        assert_eq!(dev.lock().unwrap().name(), "test1");

        let info = PciBus::find_attached_bus(&locked_pci_host.root_bus, "test2");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name, "pcie.1");
        assert_eq!(dev.lock().unwrap().name(), "test2");
    }

    #[test]
    fn test_detach_device() {
        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.root_bus);

        let root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus.clone(), false);
        root_port.realize().unwrap();

        let bus = PciBus::find_bus_by_name(&locked_pci_host.root_bus, "pcie.1").unwrap();
        let pci_dev = PciDevice {
            name: String::from("test1"),
            devfn: 0,
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus: Arc::downgrade(&bus),
        };
        let dev = Arc::new(Mutex::new(pci_dev.clone()));
        let dev_ops: Arc<Mutex<dyn PciDevOps>> = dev;
        pci_dev.realize().unwrap();

        let info = PciBus::find_attached_bus(&locked_pci_host.root_bus, "test1");
        assert!(info.is_some());

        let res = PciBus::detach_device(&bus, &dev_ops);
        assert!(res.is_ok());

        let info = PciBus::find_attached_bus(&locked_pci_host.root_bus, "test1");
        assert!(info.is_none());
    }
}
