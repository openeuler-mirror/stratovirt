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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use address_space::{AddressRange, AddressSpace, GuestAddress, RegionIoEventFd};
use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::VmFd;
#[cfg(target_arch = "x86_64")]
use machine_manager::config::{BootSource, Param};
use sysbus::{SysBus, SysBusDevOps, SysBusDevType, SysRes};
use vmm_sys_util::eventfd::EventFd;

use super::{
    virtio_has_feature, Queue, QueueConfig, VirtioDevice, NOTIFY_REG_OFFSET,
    QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING, VIRTIO_F_RING_PACKED,
};
use crate::errors::{ErrorKind, Result, ResultExt};

/// Registers of virtio-mmio device refer to Virtio Spec.
/// Magic value - Read Only.
const MAGIC_VALUE_REG: u64 = 0x00;
/// Virtio device version - Read Only.
const VERSION_REG: u64 = 0x04;
/// Virtio device ID - Read Only.
const DEVICE_ID_REG: u64 = 0x08;
/// Virtio vendor ID - Read Only.
const VENDOR_ID_REG: u64 = 0x0c;
/// Bitmask of the features supported by the device(host) (32 bits per set) - Read Only.
const DEVICE_FEATURES_REG: u64 = 0x10;
/// Device (host) features set selector - Write Only.
const DEVICE_FEATURES_SEL_REG: u64 = 0x14;
/// Bitmask of features activated by the driver (guest) (32 bits per set) - Write Only.
const DRIVER_FEATURES_REG: u64 = 0x20;
/// Activated features set selector - Write Only.
const DRIVER_FEATURES_SEL_REG: u64 = 0x24;
/// Queue selector - Write Only.
const QUEUE_SEL_REG: u64 = 0x30;
/// Maximum size of the currently selected queue - Read Only.
const QUEUE_NUM_MAX_REG: u64 = 0x34;
/// Queue size for the currently selected queue - Write Only.
const QUEUE_NUM_REG: u64 = 0x38;
/// Ready bit for the currently selected queue - Read Write.
const QUEUE_READY_REG: u64 = 0x44;
/// Interrupt status - Read Only.
const INTERRUPT_STATUS_REG: u64 = 0x60;
/// Interrupt acknowledge - Write Only.
const INTERRUPT_ACK_REG: u64 = 0x64;
/// Device status register - Read Write.
const STATUS_REG: u64 = 0x70;
/// The low 32bit of queue's Descriptor Table address.
const QUEUE_DESC_LOW_REG: u64 = 0x80;
/// The high 32bit of queue's Descriptor Table address.
const QUEUE_DESC_HIGH_REG: u64 = 0x84;
/// The low 32 bit of queue's Available Ring address.
const QUEUE_AVAIL_LOW_REG: u64 = 0x90;
/// The high 32 bit of queue's Available Ring address.
const QUEUE_AVAIL_HIGH_REG: u64 = 0x94;
/// The low 32bit of queue's Used Ring address.
const QUEUE_USED_LOW_REG: u64 = 0xa0;
/// The high 32bit of queue's Used Ring address.
const QUEUE_USED_HIGH_REG: u64 = 0xa4;
/// Configuration atomicity value.
const CONFIG_GENERATION_REG: u64 = 0xfc;

const VENDOR_ID: u32 = 0;
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;

const CONFIG_STATUS_ACKNOWLEDGE: u32 = 0x01;
const CONFIG_STATUS_DRIVER: u32 = 0x02;
const CONFIG_STATUS_DRIVER_OK: u32 = 0x04;
const CONFIG_STATUS_FEATURES_OK: u32 = 0x08;
const CONFIG_STATUS_FAILED: u32 = 0x80;

/// HostNotifyInfo includes the info needed for notifying backend from guest.
pub struct HostNotifyInfo {
    /// Eventfds which notify backend to use the avail ring.
    events: Vec<EventFd>,
}

impl HostNotifyInfo {
    pub fn new(queue_num: usize) -> Self {
        let mut events = Vec::new();
        for _i in 0..queue_num {
            events.push(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        }

        HostNotifyInfo { events }
    }
}

/// The configuration of virtio-mmio device, the fields refer to Virtio Spec.
pub struct VirtioMmioCommonConfig {
    /// Bitmask of the features supported by the device (host)(32 bits per set).
    features_select: u32,
    /// Device (host) feature-setting selector.
    acked_features_select: u32,
    /// Interrupt status.
    interrupt_status: Arc<AtomicU32>,
    /// Device status.
    device_status: u32,
    /// Configuration atomicity value.
    config_generation: u32,
    /// Queue selector.
    queue_select: u32,
    /// The configuration of queues.
    queues_config: Vec<QueueConfig>,
    /// The type of queue, either be split ring or packed ring.
    queue_type: u16,
}

impl VirtioMmioCommonConfig {
    pub fn new(device: &Arc<Mutex<dyn VirtioDevice>>) -> Self {
        let locked_device = device.lock().unwrap();
        let mut queues_config = Vec::new();
        let queue_size = locked_device.queue_size();
        for _ in 0..locked_device.queue_num() {
            queues_config.push(QueueConfig::new(queue_size))
        }

        VirtioMmioCommonConfig {
            features_select: 0,
            acked_features_select: 0,
            interrupt_status: Arc::new(AtomicU32::new(0)),
            device_status: 0,
            config_generation: 0,
            queue_select: 0,
            queues_config,
            queue_type: QUEUE_TYPE_SPLIT_VRING,
        }
    }

    /// Check whether virtio device status is as expected.
    fn check_device_status(&self, set: u32, clr: u32) -> bool {
        self.device_status & (set | clr) == set
    }

    /// Get the status of virtio device
    fn get_device_status(&self) -> u32 {
        self.device_status
    }

    /// Get mutable QueueConfig structure of virtio device.
    fn get_mut_queue_config(&mut self) -> Result<&mut QueueConfig> {
        if self.check_device_status(
            CONFIG_STATUS_FEATURES_OK,
            CONFIG_STATUS_DRIVER_OK | CONFIG_STATUS_FAILED,
        ) {
            let queue_select = self.queue_select;
            self.queues_config
                .get_mut(queue_select as usize)
                .ok_or_else(|| {
                    format!(
                        "Mmio-reg queue_select {} overflows for mutable queue config",
                        queue_select,
                    )
                    .into()
                })
        } else {
            Err(ErrorKind::DevStatErr(self.device_status).into())
        }
    }

    /// Get immutable QueueConfig structure of virtio device.
    fn get_queue_config(&self) -> Result<&QueueConfig> {
        let queue_select = self.queue_select;
        self.queues_config
            .get(queue_select as usize)
            .ok_or_else(|| {
                format!(
                    "Mmio-reg queue_select overflows {} for immutable queue config",
                    queue_select,
                )
                .into()
            })
    }

    /// Read data from the common config of virtio device.
    /// Return the config value in u32.
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    fn read_common_config(
        &self,
        device: &Arc<Mutex<dyn VirtioDevice>>,
        offset: u64,
    ) -> Result<u32> {
        let value = match offset {
            MAGIC_VALUE_REG => MMIO_MAGIC_VALUE,
            VERSION_REG => MMIO_VERSION,
            DEVICE_ID_REG => device.lock().unwrap().device_type() as u32,
            VENDOR_ID_REG => VENDOR_ID,
            DEVICE_FEATURES_REG => {
                let mut features = device
                    .lock()
                    .unwrap()
                    .get_device_features(self.features_select);
                if self.features_select == 1 {
                    features |= 0x1; // enable support of VirtIO Version 1
                }
                features
            }
            QUEUE_NUM_MAX_REG => self
                .get_queue_config()
                .map(|config| u32::from(config.max_size))?,
            QUEUE_READY_REG => self.get_queue_config().map(|config| config.ready as u32)?,
            INTERRUPT_STATUS_REG => self.interrupt_status.load(Ordering::SeqCst),
            STATUS_REG => self.device_status,
            CONFIG_GENERATION_REG => self.config_generation,
            _ => {
                return Err(ErrorKind::MmioRegErr(offset).into());
            }
        };

        Ok(value)
    }

    /// Write data to the common config of virtio device.
    ///
    /// # Arguments
    ///
    /// * `device` - Virtio device entity.
    /// * `offset` - The offset of common config.
    /// * `value` - The value to write.
    ///
    /// # Errors
    ///
    /// Returns Error if the offset is out of bound.
    fn write_common_config(
        &mut self,
        device: &Arc<Mutex<dyn VirtioDevice>>,
        offset: u64,
        value: u32,
    ) -> Result<()> {
        match offset {
            DEVICE_FEATURES_SEL_REG => self.features_select = value,
            DRIVER_FEATURES_REG => {
                if self.check_device_status(
                    CONFIG_STATUS_DRIVER,
                    CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_FAILED,
                ) {
                    device
                        .lock()
                        .unwrap()
                        .set_driver_features(self.acked_features_select, value);
                    if self.acked_features_select == 1
                        && virtio_has_feature(u64::from(value) << 32, VIRTIO_F_RING_PACKED)
                    {
                        self.queue_type = QUEUE_TYPE_PACKED_VRING;
                    }
                } else {
                    return Err(ErrorKind::DevStatErr(self.device_status).into());
                }
            }
            DRIVER_FEATURES_SEL_REG => self.acked_features_select = value,
            QUEUE_SEL_REG => self.queue_select = value,
            QUEUE_NUM_REG => self
                .get_mut_queue_config()
                .map(|config| config.size = value as u16)?,
            QUEUE_READY_REG => self
                .get_mut_queue_config()
                .map(|config| config.ready = value == 1)?,
            INTERRUPT_ACK_REG => {
                if self.check_device_status(CONFIG_STATUS_DRIVER_OK, 0) {
                    self.interrupt_status.fetch_and(!value, Ordering::SeqCst);
                }
            }
            STATUS_REG => self.device_status = value,
            QUEUE_DESC_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | u64::from(value));
            })?,
            QUEUE_DESC_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | (u64::from(value) << 32));
            })?,
            QUEUE_AVAIL_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | u64::from(value));
            })?,
            QUEUE_AVAIL_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | (u64::from(value) << 32));
            })?,
            QUEUE_USED_LOW_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | u64::from(value));
            })?,
            QUEUE_USED_HIGH_REG => self.get_mut_queue_config().map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | (u64::from(value) << 32));
            })?,
            _ => {
                return Err(ErrorKind::MmioRegErr(offset).into());
            }
        };
        Ok(())
    }
}

/// virtio-mmio device structure.
pub struct VirtioMmioDevice {
    // The entity of low level device.
    pub device: Arc<Mutex<dyn VirtioDevice>>,
    // Identify if this device is activated by frontend driver.
    device_activated: bool,
    // EventFd used to send interrupt to VM
    interrupt_evt: EventFd,
    // HostNotifyInfo used for guest notifier
    host_notify_info: HostNotifyInfo,
    // Virtio common config refer to Virtio Spec.
    common_config: VirtioMmioCommonConfig,
    // System address space.
    mem_space: Arc<AddressSpace>,
    // System Resource of device.
    res: SysRes,
}

impl VirtioMmioDevice {
    pub fn new(mem_space: &Arc<AddressSpace>, device: Arc<Mutex<dyn VirtioDevice>>) -> Self {
        let device_clone = device.clone();
        let queue_num = device_clone.lock().unwrap().queue_num();

        VirtioMmioDevice {
            device,
            device_activated: false,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            host_notify_info: HostNotifyInfo::new(queue_num),
            common_config: VirtioMmioCommonConfig::new(&device_clone),
            mem_space: mem_space.clone(),
            res: SysRes::default(),
        }
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        #[cfg(target_arch = "x86_64")] bs: &Arc<Mutex<BootSource>>,
        vm_fd: &VmFd,
    ) -> Result<Arc<Mutex<Self>>> {
        self.device
            .lock()
            .unwrap()
            .realize()
            .chain_err(|| "Failed to realize virtio mmio device.")?;

        if region_base >= sysbus.mmio_region.1 {
            bail!("Mmio region space exhausted.");
        }
        self.set_sys_resource(sysbus, region_base, region_size, vm_fd)?;
        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size)?;

        #[cfg(target_arch = "x86_64")]
        bs.lock().unwrap().kernel_cmdline.push(Param {
            param_type: "virtio_mmio.device".to_string(),
            value: format!(
                "{}@0x{:08x}:{}",
                region_size,
                region_base,
                dev.lock().unwrap().res.irq
            ),
        });
        Ok(dev)
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(&mut self) -> Result<()> {
        let queues_config = &self.common_config.queues_config;
        let mut queues: Vec<Arc<Mutex<Queue>>> = Vec::with_capacity(queues_config.len());
        for q_config in queues_config.iter() {
            let queue = Queue::new(*q_config, self.common_config.queue_type)?;
            if !queue.is_valid(&self.mem_space) {
                bail!("Invalid queue");
            }
            queues.push(Arc::new(Mutex::new(queue)))
        }

        let mut queue_evts = Vec::<EventFd>::new();
        for fd in self.host_notify_info.events.iter() {
            let evt_fd_clone = match fd.try_clone() {
                Ok(fd) => fd,
                Err(e) => {
                    error!("Failed to clone IoEventFd, {}", e);
                    continue;
                }
            };
            queue_evts.push(evt_fd_clone);
        }
        self.device.lock().unwrap().activate(
            self.mem_space.clone(),
            self.interrupt_evt.try_clone().unwrap(),
            self.common_config.interrupt_status.clone(),
            queues,
            queue_evts,
        )?;

        Ok(())
    }
}

impl SysBusDevOps for VirtioMmioDevice {
    /// Read data by virtio driver from VM.
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = match self.common_config.read_common_config(&self.device, offset) {
                    Ok(v) => v,
                    Err(ref e) => {
                        error!(
                            "Failed to read mmio register {}, type: {}, {}",
                            offset,
                            self.device.lock().unwrap().device_type(),
                            error_chain::ChainedError::display_chain(e),
                        );
                        return false;
                    }
                };
                LittleEndian::write_u32(data, value);
            }
            0x100..=0xfff => {
                if let Err(ref e) = self
                    .device
                    .lock()
                    .unwrap()
                    .read_config(offset as u64 - 0x100, data)
                {
                    error!(
                        "Failed to read virtio-dev config space {} type: {} {}",
                        offset as u64 - 0x100,
                        self.device.lock().unwrap().device_type(),
                        error_chain::ChainedError::display_chain(e),
                    );
                    return false;
                }
            }
            _ => {
                warn!(
                    "Failed to read mmio register: overflows, offset is 0x{:x}, type: {}",
                    offset,
                    self.device.lock().unwrap().device_type(),
                );
            }
        };
        true
    }

    /// Write data by virtio driver from VM.
    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = LittleEndian::read_u32(data);
                if let Err(ref e) =
                    self.common_config
                        .write_common_config(&self.device, offset, value)
                {
                    error!(
                        "Failed to write mmio register {}, type: {}, {}",
                        offset,
                        self.device.lock().unwrap().device_type(),
                        error_chain::ChainedError::display_chain(e),
                    );
                    return false;
                }

                if self.common_config.check_device_status(
                    CONFIG_STATUS_ACKNOWLEDGE
                        | CONFIG_STATUS_DRIVER
                        | CONFIG_STATUS_DRIVER_OK
                        | CONFIG_STATUS_FEATURES_OK,
                    CONFIG_STATUS_FAILED,
                ) && !self.device_activated
                {
                    let ret = self.activate().map(|_| self.device_activated = true);
                    if let Err(ref e) = ret {
                        error!(
                            "Failed to activate dev, type: {}, {}",
                            self.device.lock().unwrap().device_type(),
                            error_chain::ChainedError::display_chain(e),
                        );
                    }
                }
            }
            0x100..=0xfff => {
                if self
                    .common_config
                    .check_device_status(CONFIG_STATUS_DRIVER, CONFIG_STATUS_FAILED)
                {
                    if let Err(ref e) = self
                        .device
                        .lock()
                        .unwrap()
                        .write_config(offset as u64 - 0x100, data)
                    {
                        error!(
                            "Failed to write virtio-dev config space {}, type: {}, {}",
                            offset as u64 - 0x100,
                            self.device.lock().unwrap().device_type(),
                            error_chain::ChainedError::display_chain(e),
                        );
                        return false;
                    }
                } else {
                    error!("Failed to write virtio-dev config space: driver is not ready 0x{:X}, type: {}",
                        self.common_config.get_device_status(),
                        self.device.lock().unwrap().device_type(),
                    );
                    return false;
                }
            }
            _ => {
                warn!(
                    "Failed to write mmio register: overflows, offset is 0x{:x} type: {}",
                    offset,
                    self.device.lock().unwrap().device_type(),
                );
                return false;
            }
        }
        true
    }

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        let mut ret = Vec::new();
        for (index, eventfd) in self.host_notify_info.events.iter().enumerate() {
            let addr = u64::from(NOTIFY_REG_OFFSET);
            let eventfd_clone = match eventfd.try_clone() {
                Err(e) => {
                    error!("Failed to clone ioeventfd, error is {}", e);
                    continue;
                }
                Ok(fd) => fd,
            };
            ret.push(RegionIoEventFd {
                fd: eventfd_clone,
                addr_range: AddressRange::from((addr, std::mem::size_of::<u32>() as u64)),
                data_match: true,
                data: index as u64,
            })
        }
        ret
    }

    fn interrupt_evt(&self) -> Option<&EventFd> {
        Some(&self.interrupt_evt)
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::VirtioMmio
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};
    use util::num_ops::{read_u32, write_u32};

    use super::*;
    use crate::VIRTIO_TYPE_BLOCK;

    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36);
        let sys_space = AddressSpace::new(root).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(GuestAddress(0), SYSTEM_SPACE_SIZE, None, false, false).unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone()),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;
    const CONFIG_SPACE_SIZE: usize = 16;
    const QUEUE_NUM: usize = 2;
    const QUEUE_SIZE: u16 = 256;

    pub struct VirtioDeviceTest {
        pub device_features: u64,
        pub driver_features: u64,
        pub config_space: Vec<u8>,
        pub b_active: bool,
        pub b_realized: bool,
    }

    impl VirtioDeviceTest {
        pub fn new() -> Self {
            let mut config_space = Vec::new();
            for i in 0..CONFIG_SPACE_SIZE {
                config_space.push(i as u8);
            }

            VirtioDeviceTest {
                device_features: 0,
                driver_features: 0,
                b_active: false,
                b_realized: false,
                config_space,
            }
        }
    }

    impl VirtioDevice for VirtioDeviceTest {
        fn realize(&mut self) -> Result<()> {
            self.b_realized = true;
            Ok(())
        }

        fn device_type(&self) -> u32 {
            VIRTIO_TYPE_BLOCK
        }

        fn queue_num(&self) -> usize {
            QUEUE_NUM
        }

        fn queue_size(&self) -> u16 {
            QUEUE_SIZE
        }

        fn get_device_features(&self, features_select: u32) -> u32 {
            read_u32(self.device_features, features_select)
        }

        fn set_driver_features(&mut self, page: u32, value: u32) {
            let mut v = write_u32(value, page);
            let unrequested_features = v & !self.device_features;
            if unrequested_features != 0 {
                v &= !unrequested_features;
            }
            self.driver_features |= v;
        }

        fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
            let config_len = self.config_space.len() as u64;
            if offset >= config_len {
                bail!(
                    "The offset{} for reading is more than the length{} of configuration",
                    offset,
                    config_len
                );
            }
            if let Some(end) = offset.checked_add(data.len() as u64) {
                data.write_all(
                    &self.config_space[offset as usize..std::cmp::min(end, config_len) as usize],
                )?;
            }

            Ok(())
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
            let data_len = data.len();
            let config_len = self.config_space.len();
            if offset as usize + data_len > config_len {
                bail!(
                    "The offset{} {}for writing is more than the length{} of configuration",
                    offset,
                    data_len,
                    config_len
                );
            }

            self.config_space[(offset as usize)..(offset as usize + data_len)]
                .copy_from_slice(&data[..]);

            Ok(())
        }

        fn activate(
            &mut self,
            _mem_space: Arc<AddressSpace>,
            _interrupt_evt: EventFd,
            _interrupt_status: Arc<AtomicU32>,
            mut _queues: Vec<Arc<Mutex<Queue>>>,
            mut _queue_evts: Vec<EventFd>,
        ) -> Result<()> {
            self.b_active = true;
            Ok(())
        }
    }

    #[test]
    fn test_virtio_mmio_device_new() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_device_clone = virtio_device.clone();
        let sys_space = address_space_init();

        let virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        assert_eq!(virtio_mmio_device.device_activated, false);
        assert_eq!(
            virtio_mmio_device.host_notify_info.events.len(),
            virtio_device_clone.lock().unwrap().queue_num()
        );
        assert_eq!(virtio_mmio_device.common_config.features_select, 0);
        assert_eq!(virtio_mmio_device.common_config.acked_features_select, 0);
        assert_eq!(virtio_mmio_device.common_config.device_status, 0);
        assert_eq!(virtio_mmio_device.common_config.config_generation, 0);
        assert_eq!(virtio_mmio_device.common_config.queue_select, 0);
        assert_eq!(
            virtio_mmio_device.common_config.queues_config.len(),
            virtio_device_clone.lock().unwrap().queue_num()
        );
        assert_eq!(
            virtio_mmio_device.common_config.queue_type,
            QUEUE_TYPE_SPLIT_VRING
        );
    }

    #[test]
    fn test_virtio_mmio_device_read_01() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_device_clone = virtio_device.clone();
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // read the register of magic value
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, MAGIC_VALUE_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), MMIO_MAGIC_VALUE);

        // read the register of version
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, VERSION_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), MMIO_VERSION);

        // read the register of device id
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, DEVICE_ID_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), VIRTIO_TYPE_BLOCK);

        // read the register of vendor id
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, VENDOR_ID_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), VENDOR_ID);

        // read the register of the features
        // get low 32bit of the features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.features_select = 0;
        virtio_device_clone.lock().unwrap().device_features = 0x0000_00f8_0000_00fe;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, DEVICE_FEATURES_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0x0000_00fe);
        // get high 32bit of the features for device which supports VirtIO Version 1
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.features_select = 1;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, DEVICE_FEATURES_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0x0000_00f9);
    }

    #[test]
    fn test_virtio_mmio_device_read_02() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // read the register representing max size of the queue
        // for queue_select as 0
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 0;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, QUEUE_NUM_MAX_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), QUEUE_SIZE as u32);
        // for queue_select as 1
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 1;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, QUEUE_NUM_MAX_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), QUEUE_SIZE as u32);

        // read the register representing the status of queue
        // for queue_select as 0
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        LittleEndian::write_u32(&mut buf[..], 1);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_READY_REG),
            true
        );
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, QUEUE_READY_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&data[..]), 1);
        // for queue_select as 1
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 1;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, QUEUE_READY_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);

        // read the register representing the status of interrupt
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, INTERRUPT_STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device
            .common_config
            .interrupt_status
            .store(0b10_1111, Ordering::Relaxed);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, INTERRUPT_STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0b10_1111);

        // read the register representing the status of device
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.device_status = 0;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.device_status = 5;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 5);
    }

    #[test]
    fn test_virtio_mmio_device_read_03() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_device_clone = virtio_device.clone();
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // read the configuration atomic value
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, CONFIG_GENERATION_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.config_generation = 10;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, CONFIG_GENERATION_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 10);

        // read the unknown register
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(virtio_mmio_device.read(&mut buf[..], addr, 0xf1), false);
        assert_eq!(virtio_mmio_device.read(&mut buf[..], addr, 0xfff + 1), true);
        assert_eq!(buf, [0xff, 0xff, 0xff, 0xff]);

        // read the configuration space of virtio device
        // write something
        let result: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        virtio_device_clone
            .lock()
            .unwrap()
            .config_space
            .as_mut_slice()
            .copy_from_slice(&result[..]);

        let mut data: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(virtio_mmio_device.read(&mut data[..], addr, 0x100), true);
        assert_eq!(data, result);

        let mut data: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let result: Vec<u8> = vec![9, 10, 11, 12, 13, 14, 15, 16];
        assert_eq!(virtio_mmio_device.read(&mut data[..], addr, 0x108), true);
        assert_eq!(data, result);
    }

    #[test]
    fn test_virtio_mmio_device_write_01() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_device_clone = virtio_device.clone();
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // write the selector for device features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 2);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DEVICE_FEATURES_SEL_REG),
            true
        );
        assert_eq!(virtio_mmio_device.common_config.features_select, 2);

        // write the device features
        // false when the device status is CONFIG_STATUS_FEATURES_OK or CONFIG_STATUS_FAILED isn't CONFIG_STATUS_DRIVER
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FAILED;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        virtio_mmio_device.common_config.device_status =
            CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_FAILED | CONFIG_STATUS_DRIVER;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        // it is ok to write the low 32bit of device features
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_DRIVER;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.acked_features_select = 0;
        LittleEndian::write_u32(&mut buf[..], 0x0000_00fe);
        virtio_device_clone.lock().unwrap().device_features = 0x0000_00fe;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            true
        );
        assert_eq!(
            virtio_device_clone.lock().unwrap().driver_features as u32,
            0x0000_00fe
        );
        // it is ok to write the high 32bit of device features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.acked_features_select = 1;
        LittleEndian::write_u32(&mut buf[..], 0x0000_00ff);
        virtio_device_clone.lock().unwrap().device_features = 0x0000_00ff_0000_0000;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            true
        );
        assert_eq!(
            virtio_mmio_device.common_config.queue_type,
            QUEUE_TYPE_PACKED_VRING
        );
        assert_eq!(
            virtio_device_clone.lock().unwrap().driver_features >> 32 as u32,
            0x0000_00ff
        );

        // write the selector of driver features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0x00ff_0000);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_SEL_REG),
            true
        );
        assert_eq!(
            virtio_mmio_device.common_config.acked_features_select,
            0x00ff_0000
        );

        // write the selector of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0x0000_ff00);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_SEL_REG),
            true
        );
        assert_eq!(virtio_mmio_device.common_config.queue_select, 0x0000_ff00);

        // write the size of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        LittleEndian::write_u32(&mut buf[..], 128);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_NUM_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!(config.size, 128);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_virtio_mmio_device_write_02() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // write the ready status of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        LittleEndian::write_u32(&mut buf[..], 1);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_READY_REG),
            true
        );
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, QUEUE_READY_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&data[..]), 1);

        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        LittleEndian::write_u32(&mut buf[..], 2);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_READY_REG),
            true
        );
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, QUEUE_READY_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&data[..]), 0);

        // write the interrupt status
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_DRIVER_OK;
        virtio_mmio_device
            .common_config
            .interrupt_status
            .store(0b10_1111, Ordering::Relaxed);
        LittleEndian::write_u32(&mut buf[..], 0b111);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, INTERRUPT_ACK_REG),
            true
        );
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, INTERRUPT_STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&data[..]), 0b10_1000);
    }

    #[test]
    fn test_virtio_mmio_device_write_03() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        // write the low 32bit of queue's descriptor table address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xffff_fefe);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_DESC_LOW_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!(config.desc_table.0 as u32, 0xffff_fefe)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's descriptor table address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xfcfc_ffff);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_DESC_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!((config.desc_table.0 >> 32) as u32, 0xfcfc_ffff)
        } else {
            assert!(false);
        }

        // write the low 32bit of queue's available ring address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xfcfc_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_AVAIL_LOW_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!(config.avail_ring.0 as u32, 0xfcfc_fafa)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's available ring address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xecec_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_AVAIL_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!((config.avail_ring.0 >> 32) as u32, 0xecec_fafa)
        } else {
            assert!(false);
        }

        // write the low 32bit of queue's used ring address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xacac_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_USED_LOW_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!(config.used_ring.0 as u32, 0xacac_fafa)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's used ring address
        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xcccc_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_USED_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.common_config.get_queue_config() {
            assert_eq!((config.used_ring.0 >> 32) as u32, 0xcccc_fafa)
        } else {
            assert!(false);
        }
    }

    fn align(size: u64, alignment: u64) -> u64 {
        let align_adjust = if size % alignment != 0 {
            alignment - (size % alignment)
        } else {
            0
        };
        (size + align_adjust) as u64
    }

    #[test]
    fn test_virtio_mmio_device_write_04() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let virtio_device_clone = virtio_device.clone();
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device);
        let addr = GuestAddress(0);

        virtio_mmio_device.common_config.queue_select = 0;
        virtio_mmio_device.common_config.device_status = CONFIG_STATUS_FEATURES_OK;
        if let Ok(config) = virtio_mmio_device.common_config.get_mut_queue_config() {
            config.desc_table = GuestAddress(0);
            config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * 16);
            config.used_ring = GuestAddress(align(
                (QUEUE_SIZE as u64) * 16 + 8 + 2 * (QUEUE_SIZE as u64),
                4096,
            ));
            config.size = QUEUE_SIZE;
            config.ready = true;
        }
        virtio_mmio_device.common_config.queue_select = 1;
        if let Ok(config) = virtio_mmio_device.common_config.get_mut_queue_config() {
            config.desc_table = GuestAddress(0);
            config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * 16);
            config.used_ring = GuestAddress(align(
                (QUEUE_SIZE as u64) * 16 + 8 + 2 * (QUEUE_SIZE as u64),
                4096,
            ));
            config.size = QUEUE_SIZE / 2;
            config.ready = true;
        }

        // write the device status
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], CONFIG_STATUS_ACKNOWLEDGE);
        assert_eq!(virtio_mmio_device.write(&buf[..], addr, STATUS_REG), true);
        assert_eq!(virtio_mmio_device.device_activated, false);
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&data[..]), CONFIG_STATUS_ACKNOWLEDGE);

        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(
            &mut buf[..],
            CONFIG_STATUS_ACKNOWLEDGE
                | CONFIG_STATUS_DRIVER
                | CONFIG_STATUS_DRIVER_OK
                | CONFIG_STATUS_FEATURES_OK,
        );
        assert_eq!(virtio_device_clone.lock().unwrap().b_active, false);
        assert_eq!(virtio_mmio_device.write(&buf[..], addr, STATUS_REG), true);
        assert_eq!(virtio_mmio_device.device_activated, true);
        assert_eq!(virtio_device_clone.lock().unwrap().b_active, true);
        let mut data: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut data[..], addr, STATUS_REG),
            true
        );
        assert_eq!(
            LittleEndian::read_u32(&data[..]),
            CONFIG_STATUS_ACKNOWLEDGE
                | CONFIG_STATUS_DRIVER
                | CONFIG_STATUS_DRIVER_OK
                | CONFIG_STATUS_FEATURES_OK
        );
    }
}
