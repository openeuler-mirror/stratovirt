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

//! Interfaces for simulating various devices.
//!
//! This crate simulates:
//! - interrupt controller (aarch64)
//! - legacy devices, such as serial devices

pub mod acpi;
#[cfg(feature = "usb_camera")]
pub mod camera_backend;
pub mod interrupt_controller;
pub mod legacy;
pub mod misc;
pub mod pci;
pub mod scsi;
pub mod smbios;
pub mod sysbus;
pub mod usb;

#[cfg(target_arch = "aarch64")]
pub use interrupt_controller::{
    GICDevice, GICVersion, GICv2, GICv2Access, GICv3, GICv3Access, GICv3ItsAccess, GICv3ItsState,
    GICv3State, GicRedistRegion, ICGICConfig, ICGICv2Config, ICGICv3Config, InterruptController,
    InterruptError as IntCtrlErrs, GIC_IRQ_INTERNAL, GIC_IRQ_MAX,
};
pub use interrupt_controller::{IrqManager, IrqState, LineIrqManager, MsiIrqManager, TriggerMode};
pub use legacy::error::LegacyError as LegacyErrs;
pub use scsi::bus as ScsiBus;
pub use scsi::disk as ScsiDisk;

use std::any::Any;
use std::any::TypeId;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};
use util::AsAny;

#[derive(Clone, Default)]
pub struct DeviceBase {
    /// Name of this device
    pub id: String,
    /// Whether it supports hot-plug/hot-unplug.
    pub hotpluggable: bool,
    /// parent bus.
    pub parent: Option<Weak<Mutex<dyn Bus>>>,
    /// Child bus.
    pub child: Option<Arc<Mutex<dyn Bus>>>,
}

impl DeviceBase {
    pub fn new(id: String, hotpluggable: bool, parent: Option<Weak<Mutex<dyn Bus>>>) -> Self {
        DeviceBase {
            id,
            hotpluggable,
            parent,
            child: None,
        }
    }
}

pub trait Device: Any + AsAny + Send + Sync {
    fn device_base(&self) -> &DeviceBase;

    fn device_base_mut(&mut self) -> &mut DeviceBase;

    /// `Any` trait requires a `'static` lifecycle. Error "argument requires that `device` is borrowed for `'static`"
    /// will be reported when using `as_any` directly for local variables which don't have `'static` lifecycle.
    /// Encapsulation of `as_any` can solve this problem.
    fn device_as_any(&mut self) -> &mut dyn Any {
        self.as_any_mut()
    }

    fn device_type_id(&self) -> TypeId {
        self.type_id()
    }

    /// Get device name.
    fn name(&self) -> String {
        self.device_base().id.clone()
    }

    /// Query whether it supports hot-plug/hot-unplug.
    fn hotpluggable(&self) -> bool {
        self.device_base().hotpluggable
    }

    /// Get the bus which this device is mounted on.
    fn parent_bus(&self) -> Option<Weak<Mutex<dyn Bus>>> {
        self.device_base().parent.clone()
    }

    fn set_parent_bus(&mut self, bus: Arc<Mutex<dyn Bus>>) {
        self.device_base_mut().parent = Some(Arc::downgrade(&bus));
    }

    /// Get the bus which this device has.
    fn child_bus(&self) -> Option<Arc<Mutex<dyn Bus>>> {
        self.device_base().child.clone()
    }

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        Ok(())
    }

    /// Realize device.
    fn realize(self) -> Result<Arc<Mutex<Self>>>
    where
        Self: Sized,
    {
        // Note: Only PciHost does not have its own realization logic,
        // but it will not be called.
        bail!("Realize of the device {} is not implemented", self.name());
    }

    /// Unrealize device.
    fn unrealize(&mut self) -> Result<()> {
        bail!("Unrealize of the device {} is not implemented", self.name());
    }
}

/// Macro `convert_device_ref!`: Convert from Arc<Mutex<dyn Device>> to &$device_type.
///
/// # Arguments
///
/// * `$trait_device` - Variable defined as Arc<Mutex<dyn Device>>.
/// * `$lock_device` - Variable used to get MutexGuard<'_, dyn Device>.
/// * `$struct_device` - Variable used to get &$device_type.
/// * `$device_type` - Struct corresponding to device type.
#[macro_export]
macro_rules! convert_device_ref {
    ($trait_device:expr, $lock_device: ident, $struct_device: ident, $device_type: ident) => {
        let mut $lock_device = $trait_device.lock().unwrap();
        let $struct_device = $lock_device
            .device_as_any()
            .downcast_ref::<$device_type>()
            .unwrap();
    };
}

/// Macro `convert_device_mut!`: Convert from Arc<Mutex<dyn Device>> to &mut $device_type.
///
/// # Arguments
///
/// * `$trait_device` - Variable defined as Arc<Mutex<dyn Device>>.
/// * `$lock_device` - Variable used to get MutexGuard<'_, dyn Device>.
/// * `$struct_device` - Variable used to get &mut $device_type.
/// * `$device_type` - Struct corresponding to device type.
#[macro_export]
macro_rules! convert_device_mut {
    ($trait_device:expr, $lock_device: ident, $struct_device: ident, $device_type: ident) => {
        let mut $lock_device = $trait_device.lock().unwrap();
        let $struct_device = $lock_device
            .device_as_any()
            .downcast_mut::<$device_type>()
            .unwrap();
    };
}

#[derive(Default)]
pub struct BusBase {
    /// Name of this bus.
    pub name: String,
    /// Parent device.
    pub parent: Option<Weak<Mutex<dyn Device>>>,
    /// Children devices.
    ///
    /// Note:
    /// 1. The construction of FDT table needs to strictly follow the order of sysbus,
    ///    so `BTreemap` needs to be used.
    /// 2. every device has a unique address on the bus. Using `u64` is sufficient for we can
    ///    convert it to u8(devfn) for PCI bus and convert it to (u8, u16)(target, lun) for SCSI bus.
    ///    SysBus doesn't need this unique `u64` address, so we will incrementally fill in a useless number.
    pub children: BTreeMap<u64, Arc<Mutex<dyn Device>>>,
}

impl BusBase {
    fn new(name: String) -> BusBase {
        Self {
            name,
            ..Default::default()
        }
    }
}

pub trait Bus: Any + AsAny + Send + Sync {
    fn bus_base(&self) -> &BusBase;

    fn bus_base_mut(&mut self) -> &mut BusBase;

    /// `Any` trait requires a `'static` lifecycle. Error "argument requires that `bus` is borrowed for `'static`"
    /// will be reported when using `as_any` directly for local variables which don't have `'static` lifecycle.
    /// Encapsulation of `as_any` can solve this problem.
    fn bus_as_any(&mut self) -> &mut dyn Any {
        self.as_any_mut()
    }

    /// Get the name of this bus.
    fn name(&self) -> String {
        self.bus_base().name.clone()
    }

    /// Get the device that owns this bus.
    fn parent_device(&self) -> Option<Weak<Mutex<dyn Device>>> {
        self.bus_base().parent.clone()
    }

    /// Get the devices mounted on this bus.
    fn child_devices(&self) -> BTreeMap<u64, Arc<Mutex<dyn Device>>> {
        self.bus_base().children.clone()
    }

    /// Get the specific device mounted on this bus.
    fn child_dev(&self, key: u64) -> Option<&Arc<Mutex<dyn Device>>> {
        self.bus_base().children.get(&key)
    }

    /// Attach device to this bus.
    fn attach_child(&mut self, key: u64, dev: Arc<Mutex<dyn Device>>) -> Result<()> {
        let children = &mut self.bus_base_mut().children;
        if children.get(&key).is_some() {
            bail!(
                "Location of the device {} is same as one of the bus {}",
                dev.lock().unwrap().name(),
                self.name()
            );
        }
        children.insert(key, dev);

        Ok(())
    }

    /// Detach device from this bus.
    fn detach_child(&mut self, key: u64) -> Result<()> {
        self.bus_base_mut()
            .children
            .remove(&key)
            .with_context(|| format!("No such device using key {} in bus {}.", key, self.name()))?;

        Ok(())
    }

    /// Bus reset means that all devices attached to this bus should reset.
    fn reset(&self) -> Result<()> {
        for dev in self.child_devices().values() {
            let mut locked_dev = dev.lock().unwrap();
            locked_dev
                .reset(true)
                .with_context(|| format!("Failed to reset device {}", locked_dev.name()))?;
        }

        Ok(())
    }
}

/// Macro `convert_bus_ref!`: Convert from Arc<Mutex<dyn Bus>> to &$bus_type.
///
/// # Arguments
///
/// * `$trait_bus` - Variable defined as Arc<Mutex<dyn Bus>>.
/// * `$lock_bus` - Variable used to get MutexGuard<'_, dyn Bus>.
/// * `$struct_bus` - Variable used to get &$bus_type.
/// * `$bus_type` - Struct corresponding to bus type.
#[macro_export]
macro_rules! convert_bus_ref {
    ($trait_bus:expr, $lock_bus: ident, $struct_bus: ident, $bus_type: ident) => {
        let mut $lock_bus = $trait_bus.lock().unwrap();
        let $struct_bus = $lock_bus.bus_as_any().downcast_ref::<$bus_type>().unwrap();
    };
}

/// Macro `convert_bus_mut!`: Convert from Arc<Mutex<dyn Bus>> to &mut $bus_type.
///
/// # Arguments
///
/// * `$trait_bus` - Variable defined as Arc<Mutex<dyn Bus>>.
/// * `$lock_bus` - Variable used to get MutexGuard<'_, dyn Bus>.
/// * `$struct_bus` - Variable used to get &mut $bus_type.
/// * `$bus_type` - Struct corresponding to bus type.
#[macro_export]
macro_rules! convert_bus_mut {
    ($trait_bus:expr, $lock_bus: ident, $struct_bus: ident, $bus_type: ident) => {
        let mut $lock_bus = $trait_bus.lock().unwrap();
        let $struct_bus = $lock_bus.bus_as_any().downcast_mut::<$bus_type>().unwrap();
    };
}

#[cfg(test)]
pub mod test {
    use std::sync::Arc;

    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};

    pub fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36, "root");
        let sys_space = AddressSpace::new(root, "sys_space", None).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                0x1000_0000,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone(), "region_1"),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }
}
