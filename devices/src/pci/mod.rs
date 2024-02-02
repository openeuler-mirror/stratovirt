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

pub mod config;
#[cfg(feature = "demo_device")]
pub mod demo_device;
pub mod error;
pub mod host;
pub mod hotplug;
pub mod intx;
pub mod msix;

mod bus;
mod root_port;

pub use bus::PciBus;
pub use config::{PciConfig, INTERRUPT_PIN};
pub use error::PciError;
pub use host::PciHost;
pub use intx::{init_intx, InterruptHandler, PciIntxState};
pub use msix::{init_msix, MsiVector};
pub use root_port::RootPort;

use std::{
    mem::size_of,
    sync::{Arc, Mutex, Weak},
};

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

use crate::{
    pci::config::{HEADER_TYPE, HEADER_TYPE_MULTIFUNC, MAX_FUNC},
    MsiIrqManager,
};
use crate::{Device, DeviceBase};
use util::AsAny;

const BDF_FUNC_SHIFT: u8 = 3;
pub const PCI_SLOT_MAX: u8 = 32;
pub const PCI_PIN_NUM: u8 = 4;
pub const PCI_INTR_BASE: u8 = 32;

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

fn le_write_set_value_u16(buf: &mut [u8], offset: usize, data: u16) -> Result<()> {
    let val = le_read_u16(buf, offset)?;
    le_write_u16(buf, offset, val | data)
}

fn le_write_clear_value_u16(buf: &mut [u8], offset: usize, data: u16) -> Result<()> {
    let val = le_read_u16(buf, offset)?;
    le_write_u16(buf, offset, val & !data)
}

fn pci_devfn(slot: u8, func: u8) -> u8 {
    ((slot & 0x1f) << 3) | (func & 0x07)
}

fn pci_slot(devfn: u8) -> u8 {
    devfn >> 3 & 0x1f
}

fn pci_func(devfn: u8) -> u8 {
    devfn & 0x07
}

pub fn pci_ext_cap_id(header: u32) -> u16 {
    (header & 0xffff) as u16
}

pub fn pci_ext_cap_ver(header: u32) -> u32 {
    (header >> 16) & 0xf
}

pub fn pci_ext_cap_next(header: u32) -> usize {
    ((header >> 20) & 0xffc) as usize
}

#[derive(Clone)]
pub struct PciDevBase {
    pub base: DeviceBase,
    /// Pci config space.
    pub config: PciConfig,
    /// Devfn.
    pub devfn: u8,
    /// Primary Bus.
    pub parent_bus: Weak<Mutex<PciBus>>,
}

pub trait PciDevOps: Device + Send + AsAny {
    /// Get base property of pci device.
    fn pci_base(&self) -> &PciDevBase;

    /// Get mutable base property of pci device.
    fn pci_base_mut(&mut self) -> &mut PciDevBase;

    /// Init writable bit mask.
    fn init_write_mask(&mut self, is_bridge: bool) -> Result<()> {
        self.pci_base_mut().config.init_common_write_mask()?;
        if is_bridge {
            self.pci_base_mut().config.init_bridge_write_mask()?;
        }

        Ok(())
    }

    /// Init write-and-clear bit mask.
    fn init_write_clear_mask(&mut self, is_bridge: bool) -> Result<()> {
        self.pci_base_mut().config.init_common_write_clear_mask()?;
        if is_bridge {
            self.pci_base_mut().config.init_bridge_write_clear_mask()?;
        }

        Ok(())
    }

    /// Realize PCI/PCIe device.
    fn realize(self) -> Result<()>;

    /// Unrealize PCI/PCIe device.
    fn unrealize(&mut self) -> Result<()> {
        bail!("Unrealize of the pci device is not implemented");
    }

    /// Configuration space read.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in configuration space.
    /// * `data` - Data buffer for reading.
    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.pci_base_mut().config.read(offset, data);
    }

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

    /// Reset device
    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        Ok(())
    }

    /// Get the path of the PCI bus where the device resides.
    fn get_parent_dev_path(&self, parent_bus: Arc<Mutex<PciBus>>) -> String {
        let locked_parent_bus = parent_bus.lock().unwrap();
        let parent_dev_path = if locked_parent_bus.name.eq("pcie.0") {
            String::from("/pci@ffffffffffffffff")
        } else {
            // This else branch will not be executed currently,
            // which is mainly to be compatible with new PCI bridge devices.
            // unwrap is safe because pci bus under root port will not return null.
            locked_parent_bus
                .parent_bridge
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .get_dev_path()
                .unwrap()
        };
        parent_dev_path
    }

    /// Fill the device path according to parent device path and device function.
    fn populate_dev_path(&self, parent_dev_path: String, devfn: u8, dev_type: &str) -> String {
        let slot = pci_slot(devfn);
        let function = pci_func(devfn);

        let slot_function = if function != 0 {
            format!("{:x},{:x}", slot, function)
        } else {
            format!("{:x}", slot)
        };

        format!("{}{}{}", parent_dev_path, dev_type, slot_function)
    }

    /// Get firmware device path.
    fn get_dev_path(&self) -> Option<String> {
        None
    }

    fn change_irq_level(&self, _irq_pin: u32, _level: i8) -> Result<()> {
        Ok(())
    }

    fn get_intx_state(&self) -> Option<Arc<Mutex<PciIntxState>>> {
        None
    }

    fn get_msi_irq_manager(&self) -> Option<Arc<dyn MsiIrqManager>> {
        None
    }
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
    config: &mut [u8],
    devfn: u8,
    parent_bus: Weak<Mutex<PciBus>>,
) -> Result<()> {
    let mut header_type =
        le_read_u16(config, HEADER_TYPE as usize)? & (!HEADER_TYPE_MULTIFUNC as u16);
    if multifunction {
        header_type |= HEADER_TYPE_MULTIFUNC as u16;
    }
    le_write_u16(config, HEADER_TYPE as usize, header_type)?;

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

/// 0 <= pin <= 3. 0 = INTA, 1 = INTB, 2 = INTC, 3 = INTD.
/// PCI-to-PCI bridge specification 9.1: Interrupt routing.
pub fn swizzle_map_irq(devfn: u8, pin: u8) -> u32 {
    let pci_slot = devfn >> 3 & 0x1f;
    ((pci_slot + pin) % PCI_PIN_NUM) as u32
}

#[cfg(test)]
mod tests {
    use crate::DeviceBase;
    use address_space::{AddressSpace, Region};

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
    fn set_dev_id() {
        struct PciDev {
            base: PciDevBase,
        }

        impl Device for PciDev {
            fn device_base(&self) -> &DeviceBase {
                &self.base.base
            }

            fn device_base_mut(&mut self) -> &mut DeviceBase {
                &mut self.base.base
            }
        }

        impl PciDevOps for PciDev {
            fn pci_base(&self) -> &PciDevBase {
                &self.base
            }

            fn pci_base_mut(&mut self) -> &mut PciDevBase {
                &mut self.base
            }

            fn write_config(&mut self, _offset: usize, _data: &[u8]) {}

            fn realize(self) -> Result<()> {
                Ok(())
            }
        }

        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "sysmem"),
            "sysmem",
            None,
        )
        .unwrap();
        let parent_bus: Arc<Mutex<PciBus>> = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16, "parent_bus"),
            sys_mem.root().clone(),
        )));

        let dev = PciDev {
            base: PciDevBase {
                base: DeviceBase::new("PCI device".to_string(), false),
                config: PciConfig::new(1, 1),
                devfn: 0,
                parent_bus: Arc::downgrade(&parent_bus),
            },
        };
        assert_eq!(dev.set_dev_id(1, 2), 258);
    }
}
