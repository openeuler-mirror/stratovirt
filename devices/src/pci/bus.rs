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

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{Context, Result};
use log::debug;

use super::{
    config::{BRIDGE_CONTROL, BRIDGE_CTL_SEC_BUS_RESET, SECONDARY_BUS_NUM, SUBORDINATE_BUS_NUM},
    hotplug::HotplugOps,
    PciDevOps, PciIntxState,
};
use crate::pci::{to_pcidevops, RootPort};
use crate::{
    convert_bus_mut, convert_bus_ref, convert_device_mut, convert_device_ref, Bus, BusBase, Device,
    MsiIrqManager, MUT_ROOT_PORT, PCI_BUS_DEVICE, ROOT_PORT,
};
use address_space::Region;
use util::gen_base_func;

type DeviceBusInfo = (Arc<Mutex<dyn Bus>>, Arc<Mutex<dyn Device>>);

/// PCI bus structure.
pub struct PciBus {
    pub base: BusBase,
    /// IO region which the parent bridge manages.
    #[cfg(target_arch = "x86_64")]
    pub io_region: Region,
    /// Memory region which the parent bridge manages.
    pub mem_region: Region,
    /// Hot Plug controller for obtaining hot plug ops.
    pub hotplug_controller: Option<Weak<Mutex<dyn HotplugOps>>>,
    /// Interrupt info related to INTx.
    pub intx_state: Option<Arc<Mutex<PciIntxState>>>,
    pub msi_irq_manager: Option<Arc<dyn MsiIrqManager>>,
}

/// Convert from Arc<Mutex<dyn Bus>> to &mut PciBus.
#[macro_export]
macro_rules! MUT_PCI_BUS {
    ($trait_bus:expr, $lock_bus: ident, $struct_bus: ident) => {
        convert_bus_mut!($trait_bus, $lock_bus, $struct_bus, PciBus);
    };
}

/// Convert from Arc<Mutex<dyn Bus>> to &PciBus.
#[macro_export]
macro_rules! PCI_BUS {
    ($trait_bus:expr, $lock_bus: ident, $struct_bus: ident) => {
        convert_bus_ref!($trait_bus, $lock_bus, $struct_bus, PciBus);
    };
}

impl Bus for PciBus {
    gen_base_func!(bus_base, bus_base_mut, BusBase, base);

    fn reset(&self) -> Result<()> {
        for dev in self.child_devices().values() {
            PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
            pci_dev
                .reset(false)
                .with_context(|| format!("Fail to reset pci dev {}", pci_dev.name()))?;

            if let Some(bus) = pci_dev.child_bus() {
                MUT_PCI_BUS!(bus, locked_bus, pci_bus);
                pci_bus.reset().with_context(|| "Fail to reset child bus")?;
            }
        }

        Ok(())
    }
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
            base: BusBase::new(name),
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
            hotplug_controller: None,
            intx_state: None,
            msi_irq_manager: None,
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
    /// * `devfn` - Slot number << 3 | Function number.
    pub fn get_device(&self, bus_num: u8, devfn: u8) -> Option<Arc<Mutex<dyn Device>>> {
        if let Some(dev) = self.child_dev(devfn as u64) {
            return Some(dev.clone());
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
    pub fn find_bus_by_num(bus: &Arc<Mutex<dyn Bus>>, bus_num: u8) -> Option<Arc<Mutex<dyn Bus>>> {
        PCI_BUS!(bus, locked_bus, pci_bus);
        if pci_bus.number(SECONDARY_BUS_NUM as usize) == bus_num {
            return Some(bus.clone());
        }
        if pci_bus.in_range(bus_num) {
            for dev in pci_bus.child_devices().values() {
                let child_bus = dev.lock().unwrap().child_bus();
                if let Some(sub_bus) = child_bus {
                    if let Some(b) = PciBus::find_bus_by_num(&sub_bus, bus_num) {
                        return Some(b);
                    }
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
    pub fn find_bus_by_name(
        bus: &Arc<Mutex<dyn Bus>>,
        bus_name: &str,
    ) -> Option<Arc<Mutex<dyn Bus>>> {
        let locked_bus = bus.lock().unwrap();
        if locked_bus.name().as_str() == bus_name {
            return Some(bus.clone());
        }
        for dev in locked_bus.child_devices().values() {
            let child_bus = dev.lock().unwrap().child_bus();
            if let Some(sub_bus) = child_bus {
                if let Some(b) = PciBus::find_bus_by_name(&sub_bus, bus_name) {
                    return Some(b);
                }
            }
        }
        None
    }

    /// Find the bus to which the device is attached.
    ///
    /// # Arguments
    ///
    /// * `bus` - On which bus to find.
    /// * `name` - Device name.
    pub fn find_attached_bus(bus: &Arc<Mutex<dyn Bus>>, name: &str) -> Option<DeviceBusInfo> {
        // Device is attached in bus.
        let locked_bus = bus.lock().unwrap();
        for dev in locked_bus.child_devices().values() {
            if dev.lock().unwrap().name() == name {
                return Some((bus.clone(), dev.clone()));
            }

            // Find in child bus.
            let child_bus = dev.lock().unwrap().child_bus();
            if let Some(sub_bus) = child_bus {
                if let Some(found) = PciBus::find_attached_bus(&sub_bus, name) {
                    return Some(found);
                }
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
    pub fn detach_device(bus: &Arc<Mutex<dyn Bus>>, dev: &Arc<Mutex<dyn Device>>) -> Result<()> {
        PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
        pci_dev
            .unrealize()
            .with_context(|| format!("Failed to unrealize device {}", pci_dev.name()))?;

        let devfn = pci_dev.pci_base().devfn as u64;
        let mut locked_bus = bus.lock().unwrap();
        locked_bus
            .detach_child(devfn)
            .with_context(|| format!("Device {} not found in the bus", pci_dev.name()))?;

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
        if let Some(parent_bridge) = self.parent_device() {
            let bridge = parent_bridge.upgrade().unwrap();
            MUT_ROOT_PORT!(bridge, locked_bridge, rootport);
            rootport.read_config(offset, data);
        }
    }

    pub fn generate_dev_id(&self, devfn: u8) -> u16 {
        let bus_num = self.number(SECONDARY_BUS_NUM as usize);
        ((bus_num as u16) << 8) | (devfn as u16)
    }

    pub fn update_dev_id(&self, devfn: u8, dev_id: &Arc<AtomicU16>) {
        dev_id.store(self.generate_dev_id(devfn), Ordering::Release);
    }

    pub fn get_msi_irq_manager(&self) -> Option<Arc<dyn MsiIrqManager>> {
        match self.parent_device().as_ref() {
            Some(parent_bridge) => {
                let bridge = parent_bridge.upgrade().unwrap();
                ROOT_PORT!(bridge, locked_bridge, rootport);
                rootport.get_msi_irq_manager()
            }
            None => self.msi_irq_manager.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::bus::PciBus;
    use crate::pci::host::tests::create_pci_host;
    use crate::pci::root_port::{RootPort, RootPortConfig};
    use crate::pci::tests::TestPciDevice;
    use crate::pci::{clean_pcidevops_type, register_pcidevops_type};

    #[test]
    fn test_find_attached_bus() {
        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.child_bus().unwrap());
        let root_port_config = RootPortConfig {
            addr: (1, 0),
            id: "pcie.1".to_string(),
            ..Default::default()
        };
        let root_port = RootPort::new(root_port_config, root_bus.clone());
        root_port.realize().unwrap();

        // Test device is attached to the root bus.
        let pci_dev = TestPciDevice::new("test1", 10, root_bus);
        pci_dev.realize().unwrap();

        // Test device is attached to the root port.
        let bus =
            PciBus::find_bus_by_name(&locked_pci_host.child_bus().unwrap(), "pcie.1").unwrap();
        let pci_dev = TestPciDevice::new("test2", 12, Arc::downgrade(&bus));
        pci_dev.realize().unwrap();

        let info = PciBus::find_attached_bus(&locked_pci_host.child_bus().unwrap(), "test0");
        assert!(info.is_none());

        let info = PciBus::find_attached_bus(&locked_pci_host.child_bus().unwrap(), "test1");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name(), "pcie.0");
        assert_eq!(dev.lock().unwrap().name(), "test1");

        let info = PciBus::find_attached_bus(&locked_pci_host.child_bus().unwrap(), "test2");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name(), "pcie.1");
        assert_eq!(dev.lock().unwrap().name(), "test2");
    }

    #[test]
    fn test_detach_device() {
        register_pcidevops_type::<TestPciDevice>().unwrap();

        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.child_bus().unwrap());

        let root_port_config = RootPortConfig {
            id: "pcie.1".to_string(),
            addr: (1, 0),
            ..Default::default()
        };
        let root_port = RootPort::new(root_port_config, root_bus.clone());
        root_port.realize().unwrap();

        let bus =
            PciBus::find_bus_by_name(&locked_pci_host.child_bus().unwrap(), "pcie.1").unwrap();
        let pci_dev = TestPciDevice::new("test1", 0, Arc::downgrade(&bus));
        let dev_ops: Arc<Mutex<dyn Device>> = Arc::new(Mutex::new(pci_dev.clone()));
        pci_dev.realize().unwrap();

        let info = PciBus::find_attached_bus(&locked_pci_host.child_bus().unwrap(), "test1");
        assert!(info.is_some());

        let res = PciBus::detach_device(&bus, &dev_ops);
        assert!(res.is_ok());

        let info = PciBus::find_attached_bus(&locked_pci_host.child_bus().unwrap(), "test1");
        assert!(info.is_none());

        clean_pcidevops_type();
    }
}
