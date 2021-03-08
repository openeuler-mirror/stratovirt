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

use std::sync::{Arc, Mutex};

use address_space::{AddressSpace, GuestAddress, RegionOps};
use sysbus::SysBusDevOps;

use crate::{bus::PciBus, PciDevOps};
#[cfg(target_arch = "x86_64")]
use crate::{le_read_u32, le_write_u32};

#[cfg(target_arch = "x86_64")]
const CONFIG_ADDRESS_ENABLE_MASK: u32 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const PIO_BUS_SHIFT: u32 = 16;
#[cfg(target_arch = "x86_64")]
const PIO_DEVFN_SHIFT: u32 = 8;
#[cfg(target_arch = "x86_64")]
const PIO_OFFSET_MASK: u32 = 0xff;

const CONFIG_BUS_MASK: u32 = 0xff;
const CONFIG_DEVFN_MASK: u32 = 0xff;
#[allow(dead_code)]
const ECAM_BUS_SHIFT: u32 = 20;
#[allow(dead_code)]
const ECAM_DEVFN_SHIFT: u32 = 12;
#[allow(dead_code)]
const ECAM_OFFSET_MASK: u64 = 0xfff;

#[allow(dead_code)]
pub struct PciHost {
    pub root_bus: Arc<Mutex<PciBus>>,
    device: Option<Arc<Mutex<dyn PciDevOps>>>,
    #[cfg(target_arch = "x86_64")]
    config_addr: u32,
}

impl PciHost {
    /// Construct PCI/PCIe host.
    ///
    /// # Arguments
    ///
    /// * `sys_io` - IO space which the host bridge maps (only on x86_64).
    /// * `sys_mem`- Memory space which the host bridge maps.
    #[allow(dead_code)]
    pub fn new(
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
    ) -> Self {
        #[cfg(target_arch = "x86_64")]
        let io_region = sys_io.root().clone();
        let mem_region = sys_mem.root().clone();
        let root_bus = PciBus::new(
            "pcie.0".to_string(),
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
        );
        PciHost {
            root_bus: Arc::new(Mutex::new(root_bus)),
            device: None,
            #[cfg(target_arch = "x86_64")]
            config_addr: 0,
        }
    }

    fn find_device(&self, bus_num: u8, devfn: u8) -> Option<Arc<Mutex<dyn PciDevOps>>> {
        let locked_root_bus = self.root_bus.lock().unwrap();
        if bus_num == 0 {
            return locked_root_bus.get_device(0, devfn);
        }
        for bus in &locked_root_bus.child_buses {
            if let Some(b) = PciBus::find_bus_by_num(bus, bus_num) {
                return b.lock().unwrap().get_device(bus_num, devfn);
            }
        }
        None
    }

    /// Build RegionOps for configuration space access by mmconfig.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    pub fn build_mmconfig_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_hb.lock().unwrap().read(data, addr, offset)
        };
        let write = move |data: &[u8], addr: GuestAddress, offset: u64| {
            host_bridge.lock().unwrap().write(data, addr, offset)
        };
        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }

    /// Build RegionOps for access at 0xCF8.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn build_pio_addr_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset != 0 || data.len() != 4 {
                return true;
            }
            le_write_u32(data, 0, cloned_hb.lock().unwrap().config_addr).unwrap();
            true
        };
        let write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset != 0 || data.len() != 4 {
                return true;
            }
            host_bridge.lock().unwrap().config_addr = le_read_u32(data, 0).unwrap();
            true
        };

        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }

    /// Build RegionOps for access at 0xCFC.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn build_pio_data_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            let locked_hb = cloned_hb.lock().unwrap();
            let buf_size = data.len();
            if buf_size > 4 || locked_hb.config_addr & CONFIG_ADDRESS_ENABLE_MASK == 0 {
                for d in data.iter_mut() {
                    *d = 0xff;
                }
                return true;
            }

            let mut offset: u32 =
                (locked_hb.config_addr & !CONFIG_ADDRESS_ENABLE_MASK) + offset as u32;
            let bus_num = ((offset as u32 >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset as u32 >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
            match locked_hb.find_device(bus_num, devfn) {
                Some(dev) => {
                    offset &= PIO_OFFSET_MASK;
                    dev.lock().unwrap().read_config(offset as usize, data);
                }
                None => {
                    for d in data.iter_mut() {
                        *d = 0xff;
                    }
                }
            }
            true
        };
        let write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            let locked_hb = host_bridge.lock().unwrap();
            if data.len() > 4 || locked_hb.config_addr & CONFIG_ADDRESS_ENABLE_MASK == 0 {
                return true;
            }

            let mut offset: u32 =
                (locked_hb.config_addr & !CONFIG_ADDRESS_ENABLE_MASK) + offset as u32;
            let bus_num = ((offset as u32 >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset as u32 >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
            if let Some(dev) = locked_hb.find_device(bus_num, devfn) {
                offset &= PIO_OFFSET_MASK;
                dev.lock().unwrap().write_config(offset as usize, data);
            }
            true
        };

        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }
}

impl SysBusDevOps for PciHost {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let bus_num = ((offset as u32 >> ECAM_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
        let devfn = ((offset as u32 >> ECAM_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
        match self.find_device(bus_num, devfn) {
            Some(dev) => {
                let addr: usize = (offset & ECAM_OFFSET_MASK) as usize;
                dev.lock().unwrap().read_config(addr, data);
            }
            None => {
                for d in data.iter_mut() {
                    *d = 0xff;
                }
            }
        }
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let bus_num = ((offset as u32 >> ECAM_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
        let devfn = ((offset as u32 >> ECAM_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
        match self.find_device(bus_num, devfn) {
            Some(dev) => {
                let addr: usize = (offset & ECAM_OFFSET_MASK) as usize;
                dev.lock().unwrap().write_config(addr, data);
                true
            }
            None => true,
        }
    }
}
