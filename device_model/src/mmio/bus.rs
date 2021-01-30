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
use machine_manager::config::{BootSource, ConfigCheck};

use super::super::virtio::{Block, Net};
use super::{
    errors::{Result, ResultExt},
    DeviceResource, DeviceType, MmioDevice, MmioDeviceOps, VirtioMmioDevice,
};
use crate::{LayoutEntryType, MEM_LAYOUT};

#[cfg(target_arch = "aarch64")]
const IRQ_RANGE: (u32, u32) = (32, 191);
#[cfg(target_arch = "x86_64")]
const IRQ_RANGE: (u32, u32) = (5, 15);

const MMIO_SERIAL_IRQ: u32 = 4;
#[cfg(target_arch = "x86_64")]
const MMIO_SERIAL_ADDR: u64 = 0x3f8;

const MMIO_BASE: u64 = MEM_LAYOUT[LayoutEntryType::Mmio as usize].0;
const MMIO_LEN: u64 = MEM_LAYOUT[LayoutEntryType::Mmio as usize].1;

/// The replaceable block device maximum count.
pub const MMIO_REPLACEABLE_BLK_NR: usize = 6;
/// The replaceable network device maximum count.
pub const MMIO_REPLACEABLE_NET_NR: usize = 2;

/// The config of replaceable device.
struct MmioReplaceableConfig {
    /// Device id.
    id: String,
    /// The dev_config of the related backend device.
    dev_config: Arc<dyn ConfigCheck>,
}

/// The device information of replaceable device.
struct MmioReplaceableDevInfo {
    /// The related MMIO device.
    device: MmioDevice,
    /// Device id.
    id: String,
    /// Identify if this device is be used.
    used: bool,
}

/// The gather of config, info and count of all replaceable devices.
struct MmioReplaceableInfo {
    /// The arrays of all replaceable configs.
    configs: Arc<Mutex<Vec<MmioReplaceableConfig>>>,
    /// The arrays of all replaceable device information.
    devices: Arc<Mutex<Vec<MmioReplaceableDevInfo>>>,
    /// The count of block device which is plugin.
    block_count: usize,
    /// The count of network device which is plugin.
    net_count: usize,
}

impl MmioReplaceableInfo {
    pub fn new() -> Self {
        MmioReplaceableInfo {
            configs: Arc::new(Mutex::new(Vec::new())),
            devices: Arc::new(Mutex::new(Vec::new())),
            block_count: 0_usize,
            net_count: 0_usize,
        }
    }
}

/// MMIO Bus.
pub struct Bus {
    /// The devices inserted in bus.
    devices: Vec<MmioDevice>,
    /// All replaceable device information.
    replaceable_info: MmioReplaceableInfo,
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
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        let mut bus = Bus {
            devices: Vec::new(),
            replaceable_info: MmioReplaceableInfo::new(),
        };

        for _ in 0..MMIO_REPLACEABLE_BLK_NR {
            let block = Arc::new(Mutex::new(Block::new()));
            let device = Arc::new(Mutex::new(VirtioMmioDevice::new(sys_mem.clone(), block)));
            if let Ok(dev) = bus.attach_device(device.clone()) {
                bus.replaceable_info
                    .devices
                    .lock()
                    .unwrap()
                    .push(MmioReplaceableDevInfo {
                        device: dev,
                        id: "".to_string(),
                        used: false,
                    });
            }
        }

        for _ in 0..MMIO_REPLACEABLE_NET_NR {
            let net = Arc::new(Mutex::new(Net::new()));
            let device = Arc::new(Mutex::new(VirtioMmioDevice::new(sys_mem.clone(), net)));
            if let Ok(dev) = bus.attach_device(device.clone()) {
                bus.replaceable_info
                    .devices
                    .lock()
                    .unwrap()
                    .push(MmioReplaceableDevInfo {
                        device: dev,
                        id: "".to_string(),
                        used: false,
                    });
            }
        }

        bus
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
                addr: MEM_LAYOUT[LayoutEntryType::Rtc as usize].0,
                size: MEM_LAYOUT[LayoutEntryType::Rtc as usize].1,
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
                        addr: MEM_LAYOUT[LayoutEntryType::Uart as usize].0,
                        size: MEM_LAYOUT[LayoutEntryType::Uart as usize].1,
                        irq: MMIO_SERIAL_IRQ,
                        dev_type: device_type,
                    }
                }
            }
            _ => DeviceResource {
                addr: MMIO_BASE + index as u64 * MMIO_LEN,
                size: MMIO_LEN,
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

    /// Get an unused entry of replaceable_info, then fill the fields and mark it as `used`.
    ///
    /// # Arguments
    ///
    /// * `id` - Device id.
    /// * `path` - Related backend device path.
    /// * `dev_type` - MMIO device type.
    ///
    /// # Errors
    ///
    /// Returns Error if the device number exceed the Max count.
    pub fn fill_replaceable_device(
        &mut self,
        id: &str,
        dev_config: Arc<dyn ConfigCheck>,
        dev_type: DeviceType,
    ) -> Result<()> {
        let index = match dev_type {
            DeviceType::BLK => {
                let index = self.replaceable_info.block_count;
                if index >= MMIO_REPLACEABLE_BLK_NR {
                    bail!(
                        "Index {} is out of bounds {} for block to fill replaceable device",
                        index,
                        MMIO_REPLACEABLE_BLK_NR,
                    );
                }
                self.replaceable_info.block_count += 1;
                index
            }
            DeviceType::NET => {
                let index = self.replaceable_info.net_count + MMIO_REPLACEABLE_BLK_NR;
                if index >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
                    bail!(
                        "Index {} is out of bounds {} for net to fill replaceable device",
                        index,
                        MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR,
                    );
                }
                self.replaceable_info.net_count += 1;
                index
            }
            _ => {
                bail!("Unsupported replaceable device type to fill replaceable device, id: {} type: {:?}",
                    id, dev_type);
            }
        };

        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                return Err(format!("The index{} is used, {}", index, id).into());
            } else {
                device_info.id = id.to_string();
                device_info.used = true;
                device_info.device.update_config(Some(dev_config.clone()))?;
            }
        }

        self.add_replaceable_config(id.to_string(), dev_config)?;

        Ok(())
    }

    /// Add new config into replaceable_info configs arrays.
    ///
    /// # Arguments
    ///
    /// * `id` - Device id.
    /// * `path` - Related backend device path.
    pub fn add_replaceable_config(
        &self,
        id: String,
        dev_config: Arc<dyn ConfigCheck>,
    ) -> Result<()> {
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        if configs_lock.len() >= MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR {
            bail!(
                "The size {} of replaceable configs extend the max size {}, id {}.",
                configs_lock.len(),
                MMIO_REPLACEABLE_BLK_NR + MMIO_REPLACEABLE_NET_NR,
                id,
            );
        }

        for config in configs_lock.iter() {
            if config.id == id {
                bail!("Add the id {} repeatedly", id);
            }
        }

        let config = MmioReplaceableConfig { id, dev_config };
        configs_lock.push(config);

        Ok(())
    }

    /// Get an unused entry of replaceable_info which is indexed by `slot`,
    /// then update the fields and mark it as `used`.
    ///
    /// # Arguments
    ///
    /// * `id` - Device id.
    /// * `driver` - Driver type passed in by HotPlug.
    /// * `slot` - The index of replaceable_info entries.
    ///
    /// # Errors
    ///
    /// Returns Error if the entry is already used.
    pub fn add_replaceable_device(&self, id: &str, driver: &str, slot: usize) -> Result<()> {
        let index = if driver.contains("net") {
            if slot >= MMIO_REPLACEABLE_NET_NR {
                bail!(
                    "Index {} is out of bounds {} for net to add replaceable device",
                    slot,
                    MMIO_REPLACEABLE_NET_NR
                );
            }
            slot + MMIO_REPLACEABLE_BLK_NR
        } else if driver.contains("blk") {
            if slot >= MMIO_REPLACEABLE_BLK_NR {
                bail!(
                    "Index {} is out of bounds {} for block to add replaceable device",
                    slot,
                    MMIO_REPLACEABLE_BLK_NR
                );
            }
            slot
        } else {
            bail!(
                "Unsupported replaceable device type to add replaceable device, id: {} driver: {}",
                id,
                driver,
            );
        };

        let configs_lock = self.replaceable_info.configs.lock().unwrap();
        // find the configuration by id
        let mut dev_config = None;
        for config in configs_lock.iter() {
            if config.id == id {
                dev_config = Some(config.dev_config.clone());
            }
        }

        if dev_config.is_none() {
            bail!(
                "Failed to find the configuration to add replaceable device, id: {} driver: {}",
                id,
                driver
            );
        }

        // find the replaceable device and replace it
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        if let Some(device_info) = replaceable_devices.get_mut(index) {
            if device_info.used {
                bail!(
                    "The slot {} is already used for adding replaceable device, {}",
                    slot,
                    id
                );
            } else {
                device_info.id = id.to_string();
                device_info.used = true;
                device_info.device.update_config(dev_config)?;
            }
        }

        Ok(())
    }

    /// Find the entry of replaceable_info which is specified by `id`,
    /// then update the fields and mark it as `unused`.
    ///
    /// # Arguments
    ///
    /// * `id` - Device id.
    pub fn del_replaceable_device(&self, id: &str) -> Result<String> {
        // find the index of configuration by name and remove it
        let mut is_exist = false;
        let mut configs_lock = self.replaceable_info.configs.lock().unwrap();
        for (index, config) in configs_lock.iter().enumerate() {
            if config.id == id {
                configs_lock.remove(index);
                is_exist = true;
                break;
            }
        }

        // set the status of the device to 'unused'
        let mut replaceable_devices = self.replaceable_info.devices.lock().unwrap();
        for device_info in replaceable_devices.iter_mut() {
            if device_info.id == id {
                device_info.id = "".to_string();
                device_info.used = false;
                device_info.device.update_config(None)?;
            }
        }

        if !is_exist {
            bail!("Device {} not found", id);
        }
        Ok(id.to_string())
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

    pub fn unrealize(&self) -> Result<()> {
        for dev in &self.devices {
            dev.unrealize()?;
        }
        Ok(())
    }
}
