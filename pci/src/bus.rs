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

use super::config::{SECONDARY_BUS_NUM, SUBORDINATE_BUS_NUM};
use super::PciDevOps;

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
        }
    }

    /// Get secondary bus number / subordinary bus number of the bus
    /// from configuration space of parent.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset of bus number register.
    pub fn number(&self, offset: usize) -> u8 {
        if self.parent_bridge.is_none() {
            return 0;
        }

        let mut data = vec![0_u8; 1];
        self.parent_bridge
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .read_config(offset, &mut data);
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
                if let Some(b) = PciBus::find_bus_by_num(&sub_bus, bus_num) {
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
            if let Some(b) = PciBus::find_bus_by_name(&sub_bus, bus_name) {
                return Some(b);
            }
        }
        None
    }
}
