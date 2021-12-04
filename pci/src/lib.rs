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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate migration_derive;

pub mod errors {
    error_chain! {
        errors {
            AddPciCap(id: u8, size: usize) {
                display("Failed to add PCI capability: id 0x{:x}, size: 0x{:x}.", id, size)
            }
            AddPcieExtCap(id: u8, size: usize) {
                display("Failed to add PCIe extended capability: id 0x{:x}, size: 0x{:x}.", id, size)
            }
            UnregMemBar(id: usize) {
                display("Failed to unmap BAR {} in memory space.", id)
            }
            DeviceStatus(status: u32) {
                display("Invalid device status 0x{:x}", status)
            }
            PciRegister(offset: u64) {
                display("Unsupported pci register, 0x{:x}", offset)
            }
        }
    }
}

pub mod config;
pub mod hotplug;
pub mod msix;

mod bus;
mod host;
mod root_port;

pub use bus::PciBus;
use config::{HEADER_TYPE, HEADER_TYPE_MULTIFUNC, MAX_FUNC};
pub use host::PciHost;
pub use msix::init_msix;
pub use root_port::RootPort;

use std::{
    mem::size_of,
    sync::{Mutex, Weak},
};

use byteorder::{ByteOrder, LittleEndian};

use errors::Result;

const BDF_FUNC_SHIFT: u8 = 3;

/// Macros that write data in little endian.
macro_rules! le_write {
    ($name: ident, $func: ident, $type: tt) => {
        pub fn $name(buf: &mut [u8], offset: usize, data: $type) -> Result<()> {
            let data_len: usize = size_of::<$type>();
            let buf_len: usize = buf.len();
            if offset + data_len > buf_len {
                bail!(
                    "Out-of-bounds write access: buf_len = {}, offset = {}, data_len = {}",
                    buf_len,
                    offset,
                    data_len
                );
            }
            LittleEndian::$func(&mut buf[offset..(offset + data_len)], data);
            Ok(())
        }
    };
}

le_write!(le_write_u16, write_u16, u16);
le_write!(le_write_u32, write_u32, u32);
le_write!(le_write_u64, write_u64, u64);

/// Macros that read data in little endian.
macro_rules! le_read {
    ($name: ident, $func: ident, $type: tt) => {
        pub fn $name(buf: &[u8], offset: usize) -> Result<$type> {
            let data_len: usize = size_of::<$type>();
            let buf_len: usize = buf.len();
            if offset + data_len > buf_len {
                bail!(
                    "Out-of-bounds read access: buf_len = {}, offset = {}, data_len = {}",
                    buf_len,
                    offset,
                    data_len
                );
            }
            Ok(LittleEndian::$func(&buf[offset..(offset + data_len)]))
        }
    };
}

le_read!(le_read_u16, read_u16, u16);
le_read!(le_read_u32, read_u32, u32);
le_read!(le_read_u64, read_u64, u64);

pub fn pci_devfn(slot: u8, func: u8) -> u8 {
    ((slot & 0x1f) << 3) | (func & 0x07)
}

pub fn pci_slot(devfn: u8) -> u8 {
    devfn >> 3 & 0x1f
}

pub fn pci_func(devfn: u8) -> u8 {
    devfn & 0x07
}

pub trait PciDevOps: Send {
    /// Init writable bit mask.
    fn init_write_mask(&mut self) -> Result<()>;

    /// Init write-and-clear bit mask.
    fn init_write_clear_mask(&mut self) -> Result<()>;

    /// Realize PCI/PCIe device.
    fn realize(self) -> Result<()>;

    /// Configuration space read.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in configuration space.
    /// * `data` - Data buffer for reading.
    fn read_config(&self, offset: usize, data: &mut [u8]);

    /// Configuration space write.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in configuration space.
    /// * `data` - Data to write.
    fn write_config(&mut self, offset: usize, data: &[u8]);

    /// Set device id to send MSI/MSI-X.
    ///
    /// # Arguments
    ///
    /// * `bus_num` - Bus number.
    /// * `devfn` - Slot number << 8 | Function number.
    ///
    /// # Returns
    ///
    /// Device id to send MSI/MSI-X.
    fn set_dev_id(&self, bus_num: u8, devfn: u8) -> u16 {
        let bus_shift: u16 = 8;
        ((bus_num as u16) << bus_shift) | (devfn as u16)
    }

    /// Get device name.
    fn name(&self) -> String;
}

/// Init multifunction for pci devices.
///
/// # Arguments
///
/// * `multifunction` - Whether to open multifunction.
/// * `config` - Configuration space of pci devices.
/// * `devfn` - Devfn number.
/// * `parent_bus` - Parent bus of pci devices.
pub fn init_multifunction(
    multifunction: bool,
    config: &mut Vec<u8>,
    devfn: u8,
    parent_bus: Weak<Mutex<PciBus>>,
) -> Result<()> {
    let mut header_type =
        le_read_u16(&config, HEADER_TYPE as usize)? & (!HEADER_TYPE_MULTIFUNC as u16);
    if multifunction {
        header_type |= HEADER_TYPE_MULTIFUNC as u16;
    }
    le_write_u16(config, HEADER_TYPE as usize, header_type as u16)?;

    // Allow two ways of multifunction bit:
    // 1. The multifunction bit of all devices must be set;
    // 2. Function 0 must set the bit, the rest function (1~7) is allowed to
    // leave the bit to 0.
    let slot = pci_slot(devfn);
    let bus = parent_bus.upgrade().unwrap();
    let locked_bus = bus.lock().unwrap();
    if pci_func(devfn) != 0 {
        let pci_dev = locked_bus.devices.get(&pci_devfn(slot, 0));
        if pci_dev.is_none() {
            return Ok(());
        }

        let mut data = vec![0_u8; 2];
        pci_dev
            .unwrap()
            .lock()
            .unwrap()
            .read_config(HEADER_TYPE as usize, data.as_mut_slice());
        if LittleEndian::read_u16(&data) & HEADER_TYPE_MULTIFUNC as u16 == 0 {
            // Function 0 should set multifunction bit.
            bail!(
                "PCI: single function device can't be populated in bus {} function {}.{}",
                &locked_bus.name,
                slot,
                devfn & 0x07
            );
        }
        return Ok(());
    }

    if multifunction {
        return Ok(());
    }

    // If function 0 is set to single function, the rest function should be None.
    for func in 1..MAX_FUNC {
        if locked_bus.devices.get(&pci_devfn(slot, func)).is_some() {
            bail!(
                "PCI: {}.0 indicates single function, but {}.{} is already populated",
                slot,
                slot,
                func
            );
        }
    }
    Ok(())
}

/// Check whether two regions overlap with each other.
///
/// # Arguments
///
/// * `start` - Start address of the first region.
/// * `end` - End address of the first region.
/// * `region_start` - Start address of the second region.
/// * `region_end` - End address of the second region.
pub fn ranges_overlap(start: usize, end: usize, range_start: usize, range_end: usize) -> bool {
    if start >= range_end || range_start >= end {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le_write_u16_01() {
        let mut buf: [u8; 2] = [0; 2];
        le_write_u16(&mut buf, 0, 0x1234_u16).unwrap();
        assert_eq!(buf, [0x34, 0x12]);
    }

    #[test]
    fn test_le_write_u16_02() {
        let mut buf: [u8; 2] = [0; 2];
        assert!(le_write_u16(&mut buf, 1, 0x1234).is_err());
    }

    #[test]
    fn test_le_write_u32_01() {
        let mut buf: [u8; 4] = [0; 4];
        le_write_u32(&mut buf, 0, 0x1234_5678_u32).unwrap();
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_le_write_u32_02() {
        let mut buf: [u8; 4] = [0; 4];
        assert!(le_write_u32(&mut buf, 1, 0x1234_5678_u32).is_err());
    }

    #[test]
    fn test_le_write_u64_01() {
        let mut buf: [u8; 8] = [0; 8];
        le_write_u64(&mut buf, 0, 0x1234_5678_9abc_deff).unwrap();
        assert_eq!(buf, [0xff, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_le_write_u64_02() {
        let mut buf: [u8; 8] = [0; 8];
        assert!(le_write_u64(&mut buf, 1, 0x1234_5678_9abc_deff).is_err());
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(100, 200, 150, 250));
        assert!(ranges_overlap(100, 200, 150, 200));
        assert!(!ranges_overlap(100, 200, 200, 250));
        assert!(ranges_overlap(100, 200, 100, 150));
        assert!(!ranges_overlap(100, 200, 50, 100));
        assert!(ranges_overlap(100, 200, 50, 150));
    }

    #[test]
    fn set_dev_id() {
        struct PciDev {
            name: String,
        }

        impl PciDevOps for PciDev {
            fn init_write_mask(&mut self) -> Result<()> {
                Ok(())
            }

            fn init_write_clear_mask(&mut self) -> Result<()> {
                Ok(())
            }

            fn read_config(&self, _offset: usize, _data: &mut [u8]) {}

            fn write_config(&mut self, _offset: usize, _data: &[u8]) {}

            fn name(&self) -> String {
                self.name.clone()
            }

            fn realize(self) -> Result<()> {
                Ok(())
            }
        }

        let dev = PciDev {
            name: "PCI device".to_string(),
        };
        assert_eq!(dev.set_dev_id(1, 2), 258);
    }
}
