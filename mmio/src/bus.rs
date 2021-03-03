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

use address_space::AddressSpace;
use kvm_ioctls::VmFd;
use machine_manager::config::BootSource;

use super::{
    errors::{Result, ResultExt},
    DeviceResource, DeviceType, MmioDevice, MmioDeviceOps,
};

#[cfg(target_arch = "aarch64")]
const IRQ_RANGE: (u32, u32) = (32, 191);
#[cfg(target_arch = "x86_64")]
const IRQ_RANGE: (u32, u32) = (5, 15);

const MMIO_SERIAL_IRQ: u32 = 4;
#[cfg(target_arch = "x86_64")]
const MMIO_SERIAL_ADDR: u64 = 0x3f8;

/// MMIO Bus.
pub struct Bus {
    /// The devices inserted in bus.
    devices: Vec<MmioDevice>,
    /// Base address of resource that MMIO devices can use.
    mmio_base: u64,
    /// The length of address resource for each MMIO device.
    mmio_len: u64,
    /// Address range for serial device.
    #[cfg(target_arch = "aarch64")]
    serial_range: (u64, u64),
    /// Address range for RTC device
    #[cfg(target_arch = "aarch64")]
    rtc_range: (u64, u64),
}

impl Bus {
    /// Initial the MMIO Bus structure.
    ///
    /// # Steps
    ///
    /// 1. Initial MMIO Bus
    /// 2. Prepare the replaceable information of block and network devices.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - guest memory.
    pub fn new(
        mmio_base: u64,
        mmio_len: u64,
        #[cfg(target_arch = "aarch64")] serial_range: (u64, u64),
        #[cfg(target_arch = "aarch64")] rtc_range: (u64, u64),
    ) -> Self {
        Bus {
            devices: Vec::new(),
            mmio_base,
            mmio_len,
            #[cfg(target_arch = "aarch64")]
            serial_range,
            #[cfg(target_arch = "aarch64")]
            rtc_range,
        }
    }

    /// Attach a MMIO device to Bus.
    ///
    /// # Arguments
    ///
    /// * `device` - MMIO device.
    ///
    /// # Errors
    ///
    /// Return Error if irq number exceed the limit as Arch spec defined.
    pub fn attach_device<T: 'static + MmioDeviceOps>(
        &mut self,
        device: Arc<Mutex<T>>,
    ) -> Result<MmioDevice> {
        let device_type = device.lock().unwrap().get_type();
        let index = self.devices.len();

        let resource = match device_type {
            #[cfg(target_arch = "aarch64")]
            DeviceType::RTC => DeviceResource {
                addr: self.rtc_range.0,
                size: self.rtc_range.1,
                irq: IRQ_RANGE.0 + index as u32,
                dev_type: device_type,
            },
            DeviceType::SERIAL => {
                #[cfg(target_arch = "x86_64")]
                {
                    DeviceResource {
                        addr: MMIO_SERIAL_ADDR,
                        size: 8,
                        irq: MMIO_SERIAL_IRQ,
                        dev_type: device_type,
                    }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    DeviceResource {
                        addr: self.serial_range.0,
                        size: self.serial_range.1,
                        irq: MMIO_SERIAL_IRQ,
                        dev_type: device_type,
                    }
                }
            }
            _ => DeviceResource {
                addr: self.mmio_base + index as u64 * self.mmio_len,
                size: self.mmio_len,
                irq: IRQ_RANGE.0 + index as u32,
                dev_type: device_type,
            },
        };

        if resource.irq > IRQ_RANGE.1 {
            bail!(
                "irq {} exceed max value {}, index: {} type: {:?}",
                resource.irq,
                IRQ_RANGE.1,
                index,
                device_type
            );
        }

        let mmio_dev = MmioDevice::new(device, resource);

        self.devices.push(mmio_dev.clone());

        Ok(mmio_dev)
    }

    /// Get the information of all devices inserted in bus.
    #[cfg(target_arch = "aarch64")]
    pub fn get_devices_info(&self) -> Vec<DeviceResource> {
        let mut infos = Vec::new();

        for dev in self.devices.iter() {
            infos.push(dev.get_resource())
        }

        infos
    }

    /// Realize all the devices inserted in this Bus.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The file descriptor of VM.
    /// * `bs` - The boot source of VM.
    /// * `sys_mem` - The guest memory to device constructs over.
    pub fn realize_devices(
        &self,
        vm_fd: &VmFd,
        bs: &Arc<Mutex<BootSource>>,
        sys_mem: &Arc<AddressSpace>,
        #[cfg(target_arch = "x86_64")] sys_io: Arc<AddressSpace>,
    ) -> Result<()> {
        for device in &self.devices {
            device
                .realize(
                    vm_fd,
                    &bs,
                    &sys_mem,
                    #[cfg(target_arch = "x86_64")]
                    sys_io.clone(),
                )
                .chain_err(|| "Failed to realize mmio device")?;
        }

        Ok(())
    }
}
