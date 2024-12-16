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
pub use root_port::{RootPort, RootPortConfig};

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::mem::size_of;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

#[cfg(feature = "scream")]
use crate::misc::ivshmem::Ivshmem;
#[cfg(feature = "pvpanic")]
use crate::misc::pvpanic::PvPanicPci;
use crate::pci::config::{HEADER_TYPE, HEADER_TYPE_MULTIFUNC, MAX_FUNC};
use crate::usb::xhci::xhci_pci::XhciPciDevice;
use crate::{
    convert_bus_ref, convert_device_ref, Bus, Device, DeviceBase, MsiIrqManager, PCI_BUS, ROOT_PORT,
};
#[cfg(feature = "demo_device")]
use demo_device::DemoDev;

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
    /// Bus master enable.
    pub bme: Arc<AtomicBool>,
}

pub trait PciDevOps: Device + Send {
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
    /// * `devfn` - Slot number << 3 | Function number.
    ///
    /// # Returns
    ///
    /// Device id to send MSI/MSI-X.
    fn set_dev_id(&self, bus_num: u8, devfn: u8) -> u16 {
        let bus_shift: u16 = 8;
        (u16::from(bus_num) << bus_shift) | u16::from(devfn)
    }

    /// Get the path of the PCI bus where the device resides.
    fn get_parent_dev_path(&self, parent_bus: Arc<Mutex<dyn Bus>>) -> String {
        PCI_BUS!(parent_bus, locked_bus, pci_bus);

        if pci_bus.name().eq("pcie.0") {
            String::from("/pci@ffffffffffffffff")
        } else {
            // This else branch will not be executed currently,
            // which is mainly to be compatible with new PCI bridge devices.
            // unwrap is safe because pci bus under root port will not return null.
            let parent_bridge = pci_bus.parent_device().unwrap().upgrade().unwrap();
            ROOT_PORT!(parent_bridge, locked_bridge, rootport);
            rootport.get_dev_path().unwrap()
        }
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

pub type ToPciDevOpsFunc = fn(&mut dyn Any) -> &mut dyn PciDevOps;

static mut PCIDEVOPS_HASHMAP: Option<HashMap<TypeId, ToPciDevOpsFunc>> = None;

pub fn convert_to_pcidevops<T: PciDevOps>(item: &mut dyn Any) -> &mut dyn PciDevOps {
    // SAFETY: The typeid of `T` is the typeid recorded in the hashmap. The target structure type of
    // the conversion is its own structure type, so the conversion result will definitely not be `None`.
    let t = item.downcast_mut::<T>().unwrap();
    t as &mut dyn PciDevOps
}

pub fn register_pcidevops_type<T: PciDevOps>() -> Result<()> {
    let type_id = TypeId::of::<T>();
    // SAFETY: PCIDEVOPS_HASHMAP will be built in `type_init` function sequentially in the main thread.
    // And will not be changed after `type_init`.
    unsafe {
        if PCIDEVOPS_HASHMAP.is_none() {
            PCIDEVOPS_HASHMAP = Some(HashMap::new());
        }
        let types = PCIDEVOPS_HASHMAP.as_mut().unwrap();
        if types.get(&type_id).is_some() {
            bail!("Type Id {:?} has been registered.", type_id);
        }
        types.insert(type_id, convert_to_pcidevops::<T>);
    }

    Ok(())
}

pub fn devices_register_pcidevops_type() -> Result<()> {
    #[cfg(feature = "scream")]
    register_pcidevops_type::<Ivshmem>()?;
    #[cfg(feature = "pvpanic")]
    register_pcidevops_type::<PvPanicPci>()?;
    register_pcidevops_type::<RootPort>()?;
    #[cfg(feature = "demo_device")]
    register_pcidevops_type::<DemoDev>()?;
    register_pcidevops_type::<XhciPciDevice>()
}

#[cfg(test)]
pub fn clean_pcidevops_type() {
    unsafe {
        PCIDEVOPS_HASHMAP = None;
    }
}

pub fn to_pcidevops(dev: &mut dyn Device) -> Option<&mut dyn PciDevOps> {
    // SAFETY: PCIDEVOPS_HASHMAP has been built. And this function is called without changing hashmap.
    unsafe {
        let types = PCIDEVOPS_HASHMAP.as_mut().unwrap();
        let func = types.get(&dev.device_type_id())?;
        let pcidev = func(dev.as_any_mut());
        Some(pcidev)
    }
}

/// Convert from Arc<Mutex<dyn Device>> to &mut dyn PciDevOps.
#[macro_export]
macro_rules! PCI_BUS_DEVICE {
    ($trait_device:expr, $lock_device: ident, $trait_pcidevops: ident) => {
        let mut $lock_device = $trait_device.lock().unwrap();
        let $trait_pcidevops = to_pcidevops(&mut *$lock_device).unwrap();
    };
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
    parent_bus: Weak<Mutex<dyn Bus>>,
) -> Result<()> {
    let mut header_type =
        le_read_u16(config, HEADER_TYPE as usize)? & u16::from(!HEADER_TYPE_MULTIFUNC);
    if multifunction {
        header_type |= u16::from(HEADER_TYPE_MULTIFUNC);
    }
    le_write_u16(config, HEADER_TYPE as usize, header_type)?;

    // Allow two ways of multifunction bit:
    // 1. The multifunction bit of all devices must be set;
    // 2. Function 0 must set the bit, the rest function (1~7) is allowed to
    // leave the bit to 0.
    let slot = pci_slot(devfn);
    let bus = parent_bus.upgrade().unwrap();
    PCI_BUS!(bus, locked_bus, pci_bus);
    if pci_func(devfn) != 0 {
        let dev = pci_bus.child_dev(u64::from(pci_devfn(slot, 0)));
        if dev.is_none() {
            return Ok(());
        }

        let mut data = vec![0_u8; 2];
        PCI_BUS_DEVICE!(dev.unwrap(), locked_dev, pci_dev);
        pci_dev.read_config(HEADER_TYPE as usize, data.as_mut_slice());
        if LittleEndian::read_u16(&data) & u16::from(HEADER_TYPE_MULTIFUNC) == 0 {
            // Function 0 should set multifunction bit.
            bail!(
                "PCI: single function device can't be populated in bus {} function {}.{}",
                &pci_bus.name(),
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
        if pci_bus
            .child_dev(u64::from(pci_devfn(slot, func)))
            .is_some()
        {
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
    u32::from((pci_slot + pin) % PCI_PIN_NUM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::config::{PciConfig, PCI_CONFIG_SPACE_SIZE};
    use crate::DeviceBase;
    use address_space::{AddressSpace, Region};
    use util::gen_base_func;

    #[derive(Clone)]
    pub struct TestPciDevice {
        base: PciDevBase,
    }

    impl TestPciDevice {
        pub fn new(name: &str, devfn: u8, parent_bus: Weak<Mutex<dyn Bus>>) -> Self {
            Self {
                base: PciDevBase {
                    base: DeviceBase::new(name.to_string(), false, Some(parent_bus)),
                    config: PciConfig::new(devfn, PCI_CONFIG_SPACE_SIZE, 0),
                    devfn,
                    bme: Arc::new(AtomicBool::new(false)),
                },
            }
        }
    }

    impl Device for TestPciDevice {
        gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

        fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
            let devfn = u64::from(self.base.devfn);
            self.init_write_mask(false)?;
            self.init_write_clear_mask(false)?;

            let dev = Arc::new(Mutex::new(self));
            let parent_bus = dev.lock().unwrap().parent_bus().unwrap().upgrade().unwrap();
            parent_bus
                .lock()
                .unwrap()
                .attach_child(devfn, dev.clone())?;

            Ok(dev)
        }

        fn unrealize(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl PciDevOps for TestPciDevice {
        gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

        fn write_config(&mut self, offset: usize, data: &[u8]) {
            self.base.config.write(
                offset,
                data,
                0,
                #[cfg(target_arch = "x86_64")]
                None,
                None,
            );
        }

        fn init_write_mask(&mut self, _is_bridge: bool) -> Result<()> {
            let mut offset = 0_usize;
            while offset < self.base.config.config.len() {
                LittleEndian::write_u32(
                    &mut self.base.config.write_mask[offset..offset + 4],
                    0xffff_ffff,
                );
                offset += 4;
            }
            Ok(())
        }

        fn init_write_clear_mask(&mut self, _is_bridge: bool) -> Result<()> {
            Ok(())
        }
    }

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
        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "sysmem"),
            "sysmem",
            None,
        )
        .unwrap();
        let parent_bus = Arc::new(Mutex::new(PciBus::new(
            String::from("test bus"),
            #[cfg(target_arch = "x86_64")]
            Region::init_container_region(1 << 16, "parent_bus"),
            sys_mem.root().clone(),
        ))) as Arc<Mutex<dyn Bus>>;

        let dev = TestPciDevice::new("PCI device", 0, Arc::downgrade(&parent_bus));
        assert_eq!(dev.set_dev_id(1, 2), 258);
    }
}
