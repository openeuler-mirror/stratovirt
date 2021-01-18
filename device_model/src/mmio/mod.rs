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

//! # MMIO
//!
//! This mod is used for create MMIO device.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. DeviceType to identify NET,BLK,SERIAL...
//! 2. MMIO device structure.
//! 3. MMIO device trait.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`
use kvm_ioctls::VmFd;
use std::sync::{Arc, Mutex};

mod bus;
mod virtio_mmio;

pub use self::bus::Bus;
pub use self::virtio_mmio::VirtioMmioDevice;
use super::DeviceOps;

use address_space::{AddressSpace, GuestAddress, Region, RegionIoEventFd, RegionOps};
use error_chain::bail;
use machine_manager::config::{BootSource, ConfigCheck, Param};

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            Virtio(crate::virtio::errors::Error, crate::virtio::errors::ErrorKind);
        }
        errors {
            MmioRegister(offset: u64) {
                display("Unsupported mmio register, 0x{:x}", offset)
            }
            DeviceStatus(status: u32) {
                display("Invalid device status 0x{:x}", status)
            }
        }
    }
}
use self::errors::Result;

/// The different type of MMIO Device.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum DeviceType {
    NET,
    BLK,
    SERIAL,
    #[cfg(target_arch = "aarch64")]
    RTC,
    OTHER,
}

/// The requirement of address space and irq number by MMIO device.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct DeviceResource {
    /// Address space start address.
    pub addr: u64,
    /// Address space size.
    pub size: u64,
    /// Interrupt irq number.
    pub irq: u32,
    /// MMIO device type.
    pub dev_type: DeviceType,
}

/// MmioDevice structure which used to register into system address space.
#[derive(Clone)]
pub struct MmioDevice {
    /// MmioDeviceOps used to be invoked in function realize().
    device: Arc<Mutex<dyn MmioDeviceOps>>,
    /// RegionOps used to be registered into system address space.
    region_ops: RegionOps,
    /// The DeviceResource required by this MMIO device.
    resource: Arc<DeviceResource>,
}

impl MmioDevice {
    pub fn new<T: 'static + MmioDeviceOps>(
        device: Arc<Mutex<T>>,
        res: DeviceResource,
    ) -> MmioDevice {
        let device_clone = device.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = device_clone.lock().unwrap();
            device_locked.read(data, addr, offset)
        };

        let device_clone = device.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = device_clone.lock().unwrap();
            device_locked.write(data, addr, offset)
        };

        let region_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        MmioDevice {
            device,
            region_ops,
            resource: Arc::new(res),
        }
    }
    /// Realize this MMIO device for VM.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The file descriptor of VM.
    /// * `bs` - The boot source of VM.
    /// * `sys_mem` - The guest memory to device constructs over.
    pub fn realize(
        &self,
        vm_fd: &VmFd,
        bs: &Arc<Mutex<BootSource>>,
        sys_mem: &Arc<AddressSpace>,
        #[cfg(target_arch = "x86_64")] sys_io: Arc<AddressSpace>,
    ) -> Result<()> {
        self.device.lock().unwrap().realize(vm_fd, *self.resource)?;

        let region = Region::init_io_region(self.resource.size, self.region_ops.clone());
        region.set_ioeventfds(&self.device.lock().unwrap().ioeventfds());
        match self.resource.dev_type {
            DeviceType::SERIAL if cfg!(target_arch = "x86_64") => {
                #[cfg(target_arch = "x86_64")]
                sys_io.root().add_subregion(region, self.resource.addr)?;
            }
            _ => {
                sys_mem.root().add_subregion(region, self.resource.addr)?;
            }
        }

        // add to kernel cmdline
        let cmdline = &mut bs.lock().unwrap().kernel_cmdline;
        if let DeviceType::SERIAL = self.resource.dev_type {
            #[cfg(target_arch = "aarch64")]
            cmdline.push(Param {
                param_type: "earlycon".to_string(),
                value: format!("uart,mmio,0x{:08x}", self.resource.addr),
            });
        } else {
            #[cfg(target_arch = "x86_64")]
            cmdline.push(Param {
                param_type: "virtio_mmio.device".to_string(),
                value: format!(
                    "{}@0x{:08x}:{}",
                    self.resource.size, self.resource.addr, self.resource.irq
                ),
            });
        }

        Ok(())
    }

    /// Get the resource requirement of MMIO device.
    #[cfg(target_arch = "aarch64")]
    pub fn get_resource(&self) -> DeviceResource {
        *self.resource
    }

    /// Update the low level config of MMIO device.
    ///
    /// # Arguments
    ///
    /// * `file_path` - For Block device is image path; For Net device is tap path.
    pub fn update_config(&self, dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        self.device.lock().unwrap().update_config(dev_config)
    }
}

/// Trait for MMIO device.
pub trait MmioDeviceOps: Send + DeviceOps {
    /// Realize this MMIO device for VM.
    fn realize(&mut self, vm_fd: &VmFd, resource: DeviceResource) -> Result<()>;

    /// Get the resource requirement of MMIO device.
    fn get_type(&self) -> DeviceType;

    /// Update the low level config of MMIO device.
    fn update_config(&mut self, _dev_config: Option<Arc<dyn ConfigCheck>>) -> Result<()> {
        bail!("Unsupported to update configuration");
    }

    /// Get IoEventFds of MMIO device.
    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        Vec::new()
    }
}
