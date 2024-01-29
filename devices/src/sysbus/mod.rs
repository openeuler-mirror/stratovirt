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

use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use vmm_sys_util::eventfd::EventFd;

use crate::{Device, DeviceBase, IrqState, LineIrqManager, TriggerMode};
use acpi::{AmlBuilder, AmlScope};
use address_space::{AddressSpace, GuestAddress, Region, RegionIoEventFd, RegionOps};
use util::AsAny;

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
    #[cfg(target_arch = "x86_64")]
    pub sys_io: Arc<AddressSpace>,
    pub sys_mem: Arc<AddressSpace>,
    pub devices: Vec<Arc<Mutex<dyn SysBusDevOps>>>,
    pub free_irqs: (i32, i32),
    pub min_free_irq: i32,
    pub mmio_region: (u64, u64),
    pub min_free_base: u64,
    pub irq_manager: Option<Arc<dyn LineIrqManager>>,
}

impl fmt::Debug for SysBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(target_arch = "x86_64")]
        let debug = f
            .debug_struct("SysBus")
            .field("sys_io", &self.sys_io)
            .field("sys_mem", &self.sys_mem)
            .field("free_irqs", &self.free_irqs)
            .field("min_free_irq", &self.min_free_irq)
            .field("mmio_region", &self.mmio_region)
            .field("min_free_base", &self.min_free_base)
            .finish();
        #[cfg(target_arch = "aarch64")]
        let debug = f
            .debug_struct("SysBus")
            .field("sys_mem", &self.sys_mem)
            .field("free_irqs", &self.free_irqs)
            .field("min_free_irq", &self.min_free_irq)
            .field("mmio_region", &self.mmio_region)
            .field("min_free_base", &self.min_free_base)
            .finish();
        debug
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
            #[cfg(target_arch = "x86_64")]
            sys_io: sys_io.clone(),
            sys_mem: sys_mem.clone(),
            devices: Vec::new(),
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

    pub fn attach_device<T: 'static + SysBusDevOps>(
        &mut self,
        dev: &Arc<Mutex<T>>,
        region_base: u64,
        region_size: u64,
        region_name: &str,
    ) -> Result<()> {
        let region_ops = self.build_region_ops(dev);
        let region = Region::init_io_region(region_size, region_ops, region_name);
        let locked_dev = dev.lock().unwrap();

        region.set_ioeventfds(&locked_dev.ioeventfds());
        match locked_dev.sysbusdev_base().dev_type {
            SysBusDevType::Serial if cfg!(target_arch = "x86_64") => {
                #[cfg(target_arch = "x86_64")]
                self.sys_io
                    .root()
                    .add_subregion(region, region_base)
                    .with_context(|| {
                        format!(
                            "Failed to register region in I/O space: offset={},size={}",
                            region_base, region_size
                        )
                    })?;
            }
            SysBusDevType::FwCfg if cfg!(target_arch = "x86_64") => {
                #[cfg(target_arch = "x86_64")]
                self.sys_io
                    .root()
                    .add_subregion(region, region_base)
                    .with_context(|| {
                        format!(
                            "Failed to register region in I/O space: offset 0x{:x}, size {}",
                            region_base, region_size
                        )
                    })?;
            }
            SysBusDevType::Rtc if cfg!(target_arch = "x86_64") => {
                #[cfg(target_arch = "x86_64")]
                self.sys_io
                    .root()
                    .add_subregion(region, region_base)
                    .with_context(|| {
                        format!(
                            "Failed to register region in I/O space: offset 0x{:x}, size {}",
                            region_base, region_size
                        )
                    })?;
            }
            _ => self
                .sys_mem
                .root()
                .add_subregion(region, region_base)
                .with_context(|| {
                    format!(
                        "Failed to register region in memory space: offset={},size={}",
                        region_base, region_size
                    )
                })?,
        }

        self.devices.push(dev.clone());
        Ok(())
    }

    pub fn attach_dynamic_device<T: 'static + SysBusDevOps>(
        &mut self,
        dev: &Arc<Mutex<T>>,
    ) -> Result<()> {
        self.devices.push(dev.clone());
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct SysRes {
    pub region_base: u64,
    pub region_size: u64,
    pub irq: i32,
}

impl Default for SysRes {
    fn default() -> Self {
        Self {
            region_base: 0,
            region_size: 0,
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

    pub fn set_sys(&mut self, irq: i32, region_base: u64, region_size: u64) {
        self.res.irq = irq;
        self.res.region_base = region_base;
        self.res.region_size = region_size;
    }
}

/// Operations for sysbus devices.
pub trait SysBusDevOps: Device + Send + AmlBuilder + AsAny {
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

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        None
    }

    fn set_sys_resource(
        &mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        let irq = self.get_irq(sysbus)?;
        let interrupt_evt = self.sysbusdev_base().interrupt_evt.clone();
        let irq_manager = sysbus.irq_manager.clone();

        self.sysbusdev_base_mut().irq_state =
            IrqState::new(irq as u32, interrupt_evt, irq_manager, TriggerMode::Edge);
        let irq_state = &mut self.sysbusdev_base_mut().irq_state;
        irq_state.register_irq()?;

        self.sysbusdev_base_mut()
            .set_sys(irq, region_base, region_size);
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

impl AmlBuilder for SysBus {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut scope = AmlScope::new("_SB");
        self.devices.iter().for_each(|dev| {
            scope.append(&dev.lock().unwrap().aml_bytes());
        });

        scope.aml_bytes()
    }
}
