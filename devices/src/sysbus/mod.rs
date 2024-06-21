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

pub mod error;

pub use error::SysBusError;

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use vmm_sys_util::eventfd::EventFd;

#[cfg(target_arch = "x86_64")]
use crate::acpi::cpu_controller::CpuController;
use crate::acpi::ged::Ged;
#[cfg(target_arch = "aarch64")]
use crate::acpi::power::PowerDev;
#[cfg(all(feature = "ramfb", target_arch = "aarch64"))]
use crate::legacy::Ramfb;
#[cfg(target_arch = "x86_64")]
use crate::legacy::{FwCfgIO, RTC};
#[cfg(target_arch = "aarch64")]
use crate::legacy::{FwCfgMem, PL011, PL031};
use crate::legacy::{PFlash, Serial};
use crate::pci::PciHost;
use crate::{Bus, BusBase, Device, DeviceBase, IrqState, LineIrqManager, TriggerMode};
use acpi::{AmlBuilder, AmlScope};
use address_space::{AddressSpace, GuestAddress, Region, RegionIoEventFd, RegionOps};
use util::gen_base_func;

// Now that the serial device use a hardcoded IRQ number (4), and the starting
// free IRQ number can be 5.
#[cfg(target_arch = "x86_64")]
pub const IRQ_BASE: i32 = 5;
#[cfg(target_arch = "x86_64")]
pub const IRQ_MAX: i32 = 15;

// 0-31 is private to each CPU (SGIs and PPIs).
#[cfg(target_arch = "aarch64")]
pub const IRQ_BASE: i32 = 32;
#[cfg(target_arch = "aarch64")]
pub const IRQ_MAX: i32 = 191;

pub struct SysBus {
    pub base: BusBase,
    // Record the largest key used in the BTreemap of the busbase(children field).
    max_key: u64,
    #[cfg(target_arch = "x86_64")]
    pub sys_io: Arc<AddressSpace>,
    pub sys_mem: Arc<AddressSpace>,
    pub free_irqs: (i32, i32),
    pub min_free_irq: i32,
    pub mmio_region: (u64, u64),
    pub min_free_base: u64,
    pub irq_manager: Option<Arc<dyn LineIrqManager>>,
}

impl fmt::Debug for SysBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("SysBus");

        #[cfg(target_arch = "x86_64")]
        let debug = debug.field("sys_io", &self.sys_io);

        debug
            .field("sys_mem", &self.sys_mem)
            .field("free_irqs", &self.free_irqs)
            .field("min_free_irq", &self.min_free_irq)
            .field("mmio_region", &self.mmio_region)
            .field("min_free_base", &self.min_free_base)
            .finish()
    }
}

impl SysBus {
    pub fn new(
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
        free_irqs: (i32, i32),
        mmio_region: (u64, u64),
    ) -> Self {
        Self {
            base: BusBase::new("sysbus".to_string()),
            max_key: 0,
            #[cfg(target_arch = "x86_64")]
            sys_io: sys_io.clone(),
            sys_mem: sys_mem.clone(),
            free_irqs,
            min_free_irq: free_irqs.0,
            mmio_region,
            min_free_base: mmio_region.0,
            irq_manager: None,
        }
    }

    pub fn build_region_ops<T: 'static + SysBusDevOps>(&self, dev: &Arc<Mutex<T>>) -> RegionOps {
        let cloned_dev = dev.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_dev.lock().unwrap().read(data, addr, offset)
        };

        let cloned_dev = dev.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_dev.lock().unwrap().write(data, addr, offset)
        };

        RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        }
    }

    pub fn attach_device<T: 'static + SysBusDevOps>(&mut self, dev: &Arc<Mutex<T>>) -> Result<()> {
        let res = dev.lock().unwrap().get_sys_resource().clone();
        let region_base = res.region_base;
        let region_size = res.region_size;
        let region_name = res.region_name;

        // region_base/region_size are both 0 means this device doesn't have its own memory layout.
        // The normally allocated device region_base is above the `MEM_LAYOUT[LayoutEntryType::Mmio as usize].0`.
        if region_base != 0 && region_size != 0 {
            let region_ops = self.build_region_ops(dev);
            let region = Region::init_io_region(region_size, region_ops, &region_name);
            let locked_dev = dev.lock().unwrap();

            region.set_ioeventfds(&locked_dev.ioeventfds());
            match locked_dev.sysbusdev_base().dev_type {
                #[cfg(target_arch = "x86_64")]
                SysBusDevType::Serial | SysBusDevType::FwCfg | SysBusDevType::Rtc => {
                    self.sys_io
                        .root()
                        .add_subregion(region, region_base)
                        .with_context(|| {
                            SysBusError::AddRegionErr("I/O", region_base, region_size)
                        })?;
                }
                _ => self
                    .sys_mem
                    .root()
                    .add_subregion(region, region_base)
                    .with_context(|| {
                        SysBusError::AddRegionErr("memory", region_base, region_size)
                    })?,
            }
        }

        self.sysbus_attach_child(dev.clone())?;
        Ok(())
    }

    pub fn sysbus_attach_child(&mut self, dev: Arc<Mutex<dyn Device>>) -> Result<()> {
        self.attach_child(self.max_key, dev.clone())?;
        // Note: Incrementally generate a number that has no substantive effect, and is only used for the
        // key of Btreemap in the busbase(children field).
        // The number of system-bus devices is limited, and it is also difficult to reach the `u64` range for
        // hot-plug times. So, `u64` is currently sufficient for using and don't consider overflow issues for now.
        self.max_key += 1;
        Ok(())
    }
}

impl Bus for SysBus {
    gen_base_func!(bus_base, bus_base_mut, BusBase, base);
}

#[derive(Clone)]
pub struct SysRes {
    // Note: region_base/region_size are both 0 means that this device doesn't have its own memory layout.
    // The normally allocated device memory region is above the `MEM_LAYOUT[LayoutEntryType::Mmio as usize].0`.
    pub region_base: u64,
    pub region_size: u64,
    pub region_name: String,
    pub irq: i32,
}

impl Default for SysRes {
    fn default() -> Self {
        Self {
            region_base: 0,
            region_size: 0,
            region_name: "".to_string(),
            irq: -1,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum SysBusDevType {
    Serial,
    Rtc,
    VirtioMmio,
    #[cfg(target_arch = "aarch64")]
    PL011,
    FwCfg,
    Flash,
    #[cfg(all(feature = "ramfb", target_arch = "aarch64"))]
    Ramfb,
    Others,
}

#[derive(Clone)]
pub struct SysBusDevBase {
    pub base: DeviceBase,
    /// System bus device type.
    pub dev_type: SysBusDevType,
    /// System resource.
    pub res: SysRes,
    /// Interrupt event file descriptor.
    pub interrupt_evt: Option<Arc<EventFd>>,
    /// Interrupt state.
    pub irq_state: IrqState,
}

impl Default for SysBusDevBase {
    fn default() -> Self {
        SysBusDevBase {
            base: DeviceBase::default(),
            dev_type: SysBusDevType::Others,
            res: SysRes::default(),
            interrupt_evt: None,
            irq_state: IrqState::default(),
        }
    }
}

impl SysBusDevBase {
    pub fn new(dev_type: SysBusDevType) -> SysBusDevBase {
        Self {
            dev_type,
            ..Default::default()
        }
    }

    pub fn set_sys(&mut self, irq: i32, region_base: u64, region_size: u64, region_name: &str) {
        self.res.irq = irq;
        self.res.region_base = region_base;
        self.res.region_size = region_size;
        self.res.region_name = region_name.to_string();
    }
}

/// Operations for sysbus devices.
pub trait SysBusDevOps: Device + Send + AmlBuilder {
    fn sysbusdev_base(&self) -> &SysBusDevBase;

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase;

    /// Read function of device.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address of this device.
    /// * `offset` - Offset from base address.
    fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool;

    /// Write function of device.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address of this device.
    /// * `offset` - Offset from base address.
    fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool;

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        Vec::new()
    }

    fn interrupt_evt(&self) -> Option<Arc<EventFd>> {
        self.sysbusdev_base().interrupt_evt.clone()
    }

    fn get_irq(&self, sysbus: &mut SysBus) -> Result<i32> {
        let irq = sysbus.min_free_irq;
        if irq > sysbus.free_irqs.1 {
            bail!("IRQ number exhausted.");
        }

        sysbus.min_free_irq = irq + 1;
        Ok(irq)
    }

    fn get_sys_resource(&mut self) -> &mut SysRes {
        &mut self.sysbusdev_base_mut().res
    }

    fn set_sys_resource(
        &mut self,
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        region_name: &str,
    ) -> Result<()> {
        let mut locked_sysbus = sysbus.lock().unwrap();
        let irq = self.get_irq(&mut locked_sysbus)?;
        let interrupt_evt = self.sysbusdev_base().interrupt_evt.clone();
        let irq_manager = locked_sysbus.irq_manager.clone();
        drop(locked_sysbus);

        self.sysbusdev_base_mut().irq_state =
            IrqState::new(irq as u32, interrupt_evt, irq_manager, TriggerMode::Edge);
        let irq_state = &mut self.sysbusdev_base_mut().irq_state;
        irq_state.register_irq()?;

        self.sysbusdev_base_mut()
            .set_sys(irq, region_base, region_size, region_name);
        Ok(())
    }

    fn inject_interrupt(&self) {
        let irq_state = &self.sysbusdev_base().irq_state;
        irq_state.trigger_irq().unwrap_or_else(|e| {
            log::error!(
                "Device {:?} failed to inject interrupt: {:?}",
                self.sysbusdev_base().dev_type,
                e
            )
        });
    }

    fn reset(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Convert from Arc<Mutex<dyn Device>> to &mut dyn SysBusDevOps.
#[macro_export]
macro_rules! SYS_BUS_DEVICE {
    ($trait_device:expr, $lock_device: ident, $trait_sysbusdevops: ident) => {
        let mut $lock_device = $trait_device.lock().unwrap();
        let $trait_sysbusdevops = to_sysbusdevops(&mut *$lock_device).unwrap();
    };
}

impl AmlBuilder for SysBus {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut scope = AmlScope::new("_SB");
        let child_devices = self.base.children.clone();
        for dev in child_devices.values() {
            SYS_BUS_DEVICE!(dev, locked_dev, sysbusdev);
            scope.append(&sysbusdev.aml_bytes());
        }

        scope.aml_bytes()
    }
}

pub type ToSysBusDevOpsFunc = fn(&mut dyn Any) -> &mut dyn SysBusDevOps;

static mut SYSBUSDEVTYPE_HASHMAP: Option<HashMap<TypeId, ToSysBusDevOpsFunc>> = None;

pub fn convert_to_sysbusdevops<T: SysBusDevOps>(item: &mut dyn Any) -> &mut dyn SysBusDevOps {
    // SAFETY: The typeid of `T` is the typeid recorded in the hashmap. The target structure type of
    // the conversion is its own structure type, so the conversion result will definitely not be `None`.
    let t = item.downcast_mut::<T>().unwrap();
    t as &mut dyn SysBusDevOps
}

pub fn register_sysbusdevops_type<T: SysBusDevOps>() -> Result<()> {
    let type_id = TypeId::of::<T>();
    // SAFETY: SYSBUSDEVTYPE_HASHMAP will be built in `type_init` function sequentially in the main thread.
    // And will not be changed after `type_init`.
    unsafe {
        if SYSBUSDEVTYPE_HASHMAP.is_none() {
            SYSBUSDEVTYPE_HASHMAP = Some(HashMap::new());
        }
        let types = SYSBUSDEVTYPE_HASHMAP.as_mut().unwrap();
        if types.get(&type_id).is_some() {
            bail!("Type Id {:?} has been registered.", type_id);
        }
        types.insert(type_id, convert_to_sysbusdevops::<T>);
    }

    Ok(())
}

pub fn devices_register_sysbusdevops_type() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        register_sysbusdevops_type::<FwCfgIO>()?;
        register_sysbusdevops_type::<CpuController>()?;
        register_sysbusdevops_type::<RTC>()?;
    }
    #[cfg(target_arch = "aarch64")]
    {
        register_sysbusdevops_type::<FwCfgMem>()?;
        #[cfg(all(feature = "ramfb"))]
        register_sysbusdevops_type::<Ramfb>()?;
        register_sysbusdevops_type::<PL011>()?;
        register_sysbusdevops_type::<PL031>()?;
        register_sysbusdevops_type::<PowerDev>()?;
    }
    register_sysbusdevops_type::<Ged>()?;
    register_sysbusdevops_type::<PFlash>()?;
    register_sysbusdevops_type::<Serial>()?;
    register_sysbusdevops_type::<PciHost>()
}

pub fn to_sysbusdevops(dev: &mut dyn Device) -> Option<&mut dyn SysBusDevOps> {
    // SAFETY: SYSBUSDEVTYPE_HASHMAP has been built. And this function is called without changing hashmap.
    unsafe {
        let types = SYSBUSDEVTYPE_HASHMAP.as_mut().unwrap();
        let func = types.get(&dev.device_type_id())?;
        let sysbusdev = func(dev.as_any_mut());
        Some(sysbusdev)
    }
}

#[cfg(test)]
pub fn sysbus_init() -> Arc<Mutex<SysBus>> {
    let sys_mem = AddressSpace::new(
        Region::init_container_region(u64::max_value(), "sys_mem"),
        "sys_mem",
        None,
    )
    .unwrap();
    #[cfg(target_arch = "x86_64")]
    let sys_io = AddressSpace::new(
        Region::init_container_region(1 << 16, "sys_io"),
        "sys_io",
        None,
    )
    .unwrap();
    let free_irqs: (i32, i32) = (IRQ_BASE, IRQ_MAX);
    let mmio_region: (u64, u64) = (0x0A00_0000, 0x1000_0000);
    Arc::new(Mutex::new(SysBus::new(
        #[cfg(target_arch = "x86_64")]
        &sys_io,
        &sys_mem,
        free_irqs,
        mmio_region,
    )))
}
