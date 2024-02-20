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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{debug, error, warn};
use vmm_sys_util::eventfd::EventFd;

use crate::error::VirtioError;
use crate::{
    virtio_has_feature, Queue, VirtioBaseState, VirtioDevice, VirtioInterrupt, VirtioInterruptType,
    CONFIG_STATUS_ACKNOWLEDGE, CONFIG_STATUS_DRIVER, CONFIG_STATUS_DRIVER_OK, CONFIG_STATUS_FAILED,
    CONFIG_STATUS_FEATURES_OK, CONFIG_STATUS_NEEDS_RESET, NOTIFY_REG_OFFSET,
    QUEUE_TYPE_PACKED_VRING, VIRTIO_F_RING_PACKED, VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING,
};
use address_space::{AddressRange, AddressSpace, GuestAddress, RegionIoEventFd};
use devices::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType, SysRes};
use devices::{Device, DeviceBase};
#[cfg(target_arch = "x86_64")]
use machine_manager::config::{BootSource, Param};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

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
/// Shared memory region id.
#[allow(unused)]
const SHM_SEL: u64 = 0xac;
/// Shared memory region 64 bit long length. 64 bits in two halves.
const SHM_LEN_LOW: u64 = 0xb0;
const SHM_LEN_HIGH: u64 = 0xb4;
/// Shared memory region 64 bit long physical address. 64 bits in two halves.
#[allow(unused)]
const SHM_BASE_LOW: u64 = 0xb8;
#[allow(unused)]
const SHM_BASE_HIGH: u64 = 0xbc;
/// Configuration atomicity value.
const CONFIG_GENERATION_REG: u64 = 0xfc;

const VENDOR_ID: u32 = 0;
const MMIO_MAGIC_VALUE: u32 = 0x7472_6976;
const MMIO_VERSION: u32 = 2;

/// HostNotifyInfo includes the info needed for notifying backend from guest.
struct HostNotifyInfo {
    /// Eventfds which notify backend to use the avail ring.
    events: Vec<Arc<EventFd>>,
}

impl HostNotifyInfo {
    fn new(queue_num: usize) -> Self {
        let mut events = Vec::new();
        for _i in 0..queue_num {
            events.push(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()));
        }

        HostNotifyInfo { events }
    }
}

/// The state of virtio-mmio device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VirtioMmioState {
    virtio_base: VirtioBaseState,
}

/// virtio-mmio device structure.
pub struct VirtioMmioDevice {
    base: SysBusDevBase,
    // The entity of low level device.
    pub device: Arc<Mutex<dyn VirtioDevice>>,
    // HostNotifyInfo used for guest notifier
    host_notify_info: HostNotifyInfo,
    // System address space.
    mem_space: Arc<AddressSpace>,
    /// The function for interrupt triggering.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
}

impl VirtioMmioDevice {
    pub fn new(mem_space: &Arc<AddressSpace>, device: Arc<Mutex<dyn VirtioDevice>>) -> Self {
        let device_clone = device.clone();
        let queue_num = device_clone.lock().unwrap().queue_num();

        VirtioMmioDevice {
            base: SysBusDevBase {
                dev_type: SysBusDevType::VirtioMmio,
                interrupt_evt: Some(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap())),
                ..Default::default()
            },
            device,
            host_notify_info: HostNotifyInfo::new(queue_num),
            mem_space: mem_space.clone(),
            interrupt_cb: None,
        }
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        #[cfg(target_arch = "x86_64")] bs: &Arc<Mutex<BootSource>>,
    ) -> Result<Arc<Mutex<Self>>> {
        if region_base >= sysbus.mmio_region.1 {
            bail!("Mmio region space exhausted.");
        }
        self.set_sys_resource(sysbus, region_base, region_size)?;
        self.assign_interrupt_cb();
        self.device
            .lock()
            .unwrap()
            .realize()
            .with_context(|| "Failed to realize virtio.")?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "VirtioMmio")?;

        #[cfg(target_arch = "x86_64")]
        bs.lock().unwrap().kernel_cmdline.push(Param {
            param_type: "virtio_mmio.device".to_string(),
            value: format!(
                "{}@0x{:08x}:{}",
                region_size,
                region_base,
                dev.lock().unwrap().base.res.irq
            ),
        });
        Ok(dev)
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(&mut self) -> Result<()> {
        trace::virtio_tpt_common("activate", &self.base.base.id);
        let mut locked_dev = self.device.lock().unwrap();
        let queue_num = locked_dev.queue_num();
        let queue_type = locked_dev.queue_type();
        let features = locked_dev.virtio_base().driver_features;
        let broken = locked_dev.virtio_base().broken.clone();
        let queues_config = &mut locked_dev.virtio_base_mut().queues_config;

        let mut queues = Vec::with_capacity(queue_num);
        for q_config in queues_config.iter_mut() {
            if !q_config.ready {
                debug!("queue is not ready, please check your init process");
            } else {
                q_config.set_addr_cache(
                    self.mem_space.clone(),
                    self.interrupt_cb.clone().unwrap(),
                    features,
                    &broken,
                );
            }

            let queue = Queue::new(*q_config, queue_type)?;
            if q_config.ready && !queue.is_valid(&self.mem_space) {
                bail!("Failed to activate device: Invalid queue");
            }
            queues.push(Arc::new(Mutex::new(queue)));
        }
        locked_dev.virtio_base_mut().queues = queues;

        let mut queue_evts = Vec::<Arc<EventFd>>::new();
        for fd in self.host_notify_info.events.iter() {
            queue_evts.push(fd.clone());
        }

        if let Some(cb) = self.interrupt_cb.clone() {
            locked_dev.activate(self.mem_space.clone(), cb, queue_evts)?;
        } else {
            bail!("Failed to activate device: No interrupt callback");
        }

        Ok(())
    }

    fn assign_interrupt_cb(&mut self) {
        let irq_state = self.base.irq_state.clone();
        let locked_dev = self.device.lock().unwrap();
        let virtio_base = locked_dev.virtio_base();
        let device_status = virtio_base.device_status.clone();
        let config_generation = virtio_base.config_generation.clone();
        let interrupt_status = virtio_base.interrupt_status.clone();

        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => {
                        if needs_reset {
                            device_status.fetch_or(CONFIG_STATUS_NEEDS_RESET, Ordering::SeqCst);
                        }
                        if device_status.load(Ordering::Acquire) & CONFIG_STATUS_DRIVER_OK == 0 {
                            return Ok(());
                        }
                        config_generation.fetch_add(1, Ordering::SeqCst);
                        // Use (CONFIG | VRING) instead of CONFIG, it can be used to solve the
                        // IO stuck problem by change the device configure.
                        VIRTIO_MMIO_INT_CONFIG | VIRTIO_MMIO_INT_VRING
                    }
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                irq_state.trigger_irq()?;

                Ok(())
            },
        ) as VirtioInterrupt);

        self.interrupt_cb = Some(cb);
    }

    /// Read data from the common config of virtio device.
    /// Return the config value in u32.
    /// # Arguments
    ///
    /// * `offset` - The offset of common config.
    fn read_common_config(&mut self, offset: u64) -> Result<u32> {
        trace::virtio_tpt_read_common_config(&self.base.base.id, offset);
        let locked_device = self.device.lock().unwrap();
        let value = match offset {
            MAGIC_VALUE_REG => MMIO_MAGIC_VALUE,
            VERSION_REG => MMIO_VERSION,
            DEVICE_ID_REG => locked_device.device_type(),
            VENDOR_ID_REG => VENDOR_ID,
            DEVICE_FEATURES_REG => {
                let hfeatures_sel = locked_device.hfeatures_sel();
                let mut features = locked_device.device_features(hfeatures_sel);
                if hfeatures_sel == 1 {
                    features |= 0x1; // enable support of VirtIO Version 1
                }
                features
            }
            QUEUE_NUM_MAX_REG => locked_device
                .queue_config()
                .map(|config| u32::from(config.max_size))?,
            QUEUE_READY_REG => locked_device
                .queue_config()
                .map(|config| config.ready as u32)?,
            INTERRUPT_STATUS_REG => locked_device.interrupt_status(),
            STATUS_REG => locked_device.device_status(),
            CONFIG_GENERATION_REG => locked_device.config_generation() as u32,
            // SHM_SEL is unimplemented. According to the Virtio v1.2 spec: Reading from a non-existent
            // region(i.e. where the ID written to SHMSel is unused) results in a length of -1.
            SHM_LEN_LOW | SHM_LEN_HIGH => u32::MAX,
            _ => {
                return Err(anyhow!(VirtioError::MmioRegErr(offset)));
            }
        };

        Ok(value)
    }

    /// Write data to the common config of virtio device.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset of common config.
    /// * `value` - The value to write.
    ///
    /// # Errors
    ///
    /// Returns Error if the offset is out of bound.
    fn write_common_config(&mut self, offset: u64, value: u32) -> Result<()> {
        trace::virtio_tpt_write_common_config(&self.base.base.id, offset, value);
        let mut locked_device = self.device.lock().unwrap();
        match offset {
            DEVICE_FEATURES_SEL_REG => locked_device.set_hfeatures_sel(value),
            DRIVER_FEATURES_REG => {
                if locked_device.check_device_status(
                    CONFIG_STATUS_DRIVER,
                    CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_FAILED,
                ) {
                    let gfeatures_sel = locked_device.gfeatures_sel();
                    locked_device.set_driver_features(gfeatures_sel, value);
                    if gfeatures_sel == 1
                        && virtio_has_feature(u64::from(value) << 32, VIRTIO_F_RING_PACKED)
                    {
                        locked_device.set_queue_type(QUEUE_TYPE_PACKED_VRING);
                    }
                } else {
                    return Err(anyhow!(VirtioError::DevStatErr(
                        locked_device.device_status()
                    )));
                }
            }
            DRIVER_FEATURES_SEL_REG => locked_device.set_gfeatures_sel(value),
            QUEUE_SEL_REG => locked_device.set_queue_select(value as u16),
            QUEUE_NUM_REG => locked_device
                .queue_config_mut(true)
                .map(|config| config.size = value as u16)?,
            QUEUE_READY_REG => locked_device
                .queue_config_mut(true)
                .map(|config| config.ready = value == 1)?,
            INTERRUPT_ACK_REG => {
                if locked_device.check_device_status(CONFIG_STATUS_DRIVER_OK, 0) {
                    let isr = &locked_device.virtio_base_mut().interrupt_status;
                    isr.fetch_and(!value, Ordering::SeqCst);
                }
            }
            STATUS_REG => locked_device.set_device_status(value),
            QUEUE_DESC_LOW_REG => locked_device.queue_config_mut(true).map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | u64::from(value));
            })?,
            QUEUE_DESC_HIGH_REG => locked_device.queue_config_mut(true).map(|config| {
                config.desc_table = GuestAddress(config.desc_table.0 | (u64::from(value) << 32));
            })?,
            QUEUE_AVAIL_LOW_REG => locked_device.queue_config_mut(true).map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | u64::from(value));
            })?,
            QUEUE_AVAIL_HIGH_REG => locked_device.queue_config_mut(true).map(|config| {
                config.avail_ring = GuestAddress(config.avail_ring.0 | (u64::from(value) << 32));
            })?,
            QUEUE_USED_LOW_REG => locked_device.queue_config_mut(true).map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | u64::from(value));
            })?,
            QUEUE_USED_HIGH_REG => locked_device.queue_config_mut(true).map(|config| {
                config.used_ring = GuestAddress(config.used_ring.0 | (u64::from(value) << 32));
            })?,
            _ => {
                return Err(anyhow!(VirtioError::MmioRegErr(offset)));
            }
        };
        Ok(())
    }
}

impl Device for VirtioMmioDevice {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for VirtioMmioDevice {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    /// Read data by virtio driver from VM.
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        trace::virtio_tpt_read_config(&self.base.base.id, offset, data.len());
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = match self.read_common_config(offset) {
                    Ok(v) => v,
                    Err(ref e) => {
                        error!(
                            "Failed to read mmio register {}, type: {}, {:?}",
                            offset,
                            self.device.lock().unwrap().device_type(),
                            e,
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
                    .read_config(offset - 0x100, data)
                {
                    error!(
                        "Failed to read virtio-dev config space {} type: {} {:?}",
                        offset - 0x100,
                        self.device.lock().unwrap().device_type(),
                        e,
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
        trace::virtio_tpt_write_config(&self.base.base.id, offset, data);
        match offset {
            0x00..=0xff if data.len() == 4 => {
                let value = LittleEndian::read_u32(data);
                if let Err(ref e) = self.write_common_config(offset, value) {
                    error!(
                        "Failed to write mmio register {}, type: {}, {:?}",
                        offset,
                        self.device.lock().unwrap().device_type(),
                        e,
                    );
                    return false;
                }

                let locked_dev = self.device.lock().unwrap();
                if locked_dev.check_device_status(
                    CONFIG_STATUS_ACKNOWLEDGE
                        | CONFIG_STATUS_DRIVER
                        | CONFIG_STATUS_DRIVER_OK
                        | CONFIG_STATUS_FEATURES_OK,
                    CONFIG_STATUS_FAILED,
                ) && !locked_dev.device_activated()
                {
                    drop(locked_dev);
                    if let Err(ref e) = self.activate() {
                        error!(
                            "Failed to activate dev, type: {}, {:?}",
                            self.device.lock().unwrap().device_type(),
                            e,
                        );
                        return false;
                    }
                    self.device.lock().unwrap().set_device_activated(true);
                }
            }
            0x100..=0xfff => {
                let mut locked_device = self.device.lock().unwrap();
                if locked_device.check_device_status(CONFIG_STATUS_DRIVER, CONFIG_STATUS_FAILED) {
                    if let Err(ref e) = locked_device.write_config(offset - 0x100, data) {
                        error!(
                            "Failed to write virtio-dev config space {}, type: {}, {:?}",
                            offset - 0x100,
                            locked_device.device_type(),
                            e,
                        );
                        return false;
                    }
                } else {
                    error!("Failed to write virtio-dev config space: driver is not ready 0x{:X}, type: {}",
                        locked_device.device_status(),
                        locked_device.device_type(),
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
            ret.push(RegionIoEventFd {
                fd: eventfd.clone(),
                addr_range: AddressRange::from((addr, std::mem::size_of::<u32>() as u64)),
                data_match: true,
                data: index as u64,
            })
        }
        ret
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }
}

impl acpi::AmlBuilder for VirtioMmioDevice {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl StateTransfer for VirtioMmioDevice {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = VirtioMmioState {
            virtio_base: self.device.lock().unwrap().virtio_base().get_state(),
        };
        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let s_len = std::mem::size_of::<VirtioMmioState>();
        if state.len() != s_len {
            bail!("Invalid state length {}, expected {}", state.len(), s_len);
        }

        let mut mmio_state = VirtioMmioState::default();
        mmio_state.as_mut_bytes().copy_from_slice(state);

        let mut locked_dev = self.device.lock().unwrap();
        locked_dev.virtio_base_mut().set_state(
            &mmio_state.virtio_base,
            self.mem_space.clone(),
            self.interrupt_cb.clone().unwrap(),
        );
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VirtioMmioState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for VirtioMmioDevice {
    fn resume(&mut self) -> Result<()> {
        let mut locked_dev = self.device.lock().unwrap();
        if !locked_dev.device_activated() {
            return Ok(());
        }

        let mut queue_evts = Vec::<Arc<EventFd>>::new();
        for fd in self.host_notify_info.events.iter() {
            queue_evts.push(fd.clone());
        }

        if let Some(cb) = self.interrupt_cb.clone() {
            if let Err(e) = locked_dev.activate(self.mem_space.clone(), cb, queue_evts) {
                bail!("Failed to resume virtio mmio device: {}", e);
            }
        } else {
            bail!("Failed to resume device: No interrupt callback");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        check_config_space_rw, read_config_default, VirtioBase, QUEUE_TYPE_SPLIT_VRING,
        VIRTIO_TYPE_BLOCK,
    };
    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};

    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36, "sysmem");
        let sys_space = AddressSpace::new(root, "sysmem", None).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                SYSTEM_SPACE_SIZE,
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
                Region::init_ram_region(host_mmap.clone(), "sysmem"),
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
        base: VirtioBase,
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
                base: VirtioBase::new(VIRTIO_TYPE_BLOCK, QUEUE_NUM, QUEUE_SIZE),
                b_active: false,
                b_realized: false,
                config_space,
            }
        }
    }

    impl VirtioDevice for VirtioDeviceTest {
        fn virtio_base(&self) -> &VirtioBase {
            &self.base
        }

        fn virtio_base_mut(&mut self) -> &mut VirtioBase {
            &mut self.base
        }

        fn realize(&mut self) -> Result<()> {
            self.b_realized = true;
            self.init_config_features()?;
            Ok(())
        }

        fn init_config_features(&mut self) -> Result<()> {
            Ok(())
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
            read_config_default(&self.config_space, offset, data)
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
            check_config_space_rw(&self.config_space, offset, data)?;
            let data_len = data.len();
            self.config_space[(offset as usize)..(offset as usize + data_len)]
                .copy_from_slice(&data[..]);
            Ok(())
        }

        fn activate(
            &mut self,
            _mem_space: Arc<AddressSpace>,
            _interrupt_cb: Arc<VirtioInterrupt>,
            mut _queue_evts: Vec<Arc<EventFd>>,
        ) -> Result<()> {
            self.b_active = true;
            Ok(())
        }
    }

    #[test]
    fn test_virtio_mmio_device_new() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());

        let locked_device = virtio_device.lock().unwrap();
        assert_eq!(locked_device.device_activated(), false);
        assert_eq!(
            virtio_mmio_device.host_notify_info.events.len(),
            locked_device.queue_num()
        );
        assert_eq!(locked_device.hfeatures_sel(), 0);
        assert_eq!(locked_device.gfeatures_sel(), 0);
        assert_eq!(locked_device.device_status(), 0);
        assert_eq!(locked_device.config_generation(), 0);
        assert_eq!(locked_device.queue_select(), 0);
        assert_eq!(locked_device.queue_type(), QUEUE_TYPE_SPLIT_VRING);
    }

    #[test]
    fn test_virtio_mmio_device_read_01() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
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
        virtio_device.lock().unwrap().set_hfeatures_sel(0);
        virtio_device.lock().unwrap().base.device_features = 0x0000_00f8_0000_00fe;
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, DEVICE_FEATURES_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0x0000_00fe);
        // get high 32bit of the features for device which supports VirtIO Version 1
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_hfeatures_sel(1);
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
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        // read the register representing max size of the queue
        // for queue_select as 0
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_queue_select(0);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, QUEUE_NUM_MAX_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), QUEUE_SIZE as u32);
        // for queue_select as 1
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_queue_select(1);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, QUEUE_NUM_MAX_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), QUEUE_SIZE as u32);

        // read the register representing the status of queue
        // for queue_select as 0
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
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
        virtio_device.lock().unwrap().set_queue_select(1);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
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
        virtio_device
            .lock()
            .unwrap()
            .set_interrupt_status(0b10_1111);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, INTERRUPT_STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0b10_1111);

        // read the register representing the status of device
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_device_status(0);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_device_status(5);
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, STATUS_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 5);
    }

    #[test]
    fn test_virtio_mmio_device_read_03() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        // read the configuration atomic value
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            virtio_mmio_device.read(&mut buf[..], addr, CONFIG_GENERATION_REG),
            true
        );
        assert_eq!(LittleEndian::read_u32(&buf[..]), 0);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_config_generation(10);
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
        virtio_device
            .lock()
            .unwrap()
            .config_space
            .as_mut_slice()
            .copy_from_slice(&result);

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
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        // write the selector for device features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 2);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DEVICE_FEATURES_SEL_REG),
            true
        );
        assert_eq!(virtio_device.lock().unwrap().hfeatures_sel(), 2);

        // write the device features
        // false when the device status is CONFIG_STATUS_FEATURES_OK or CONFIG_STATUS_FAILED isn't
        // CONFIG_STATUS_DRIVER
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FAILED);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        virtio_device.lock().unwrap().set_device_status(
            CONFIG_STATUS_FEATURES_OK | CONFIG_STATUS_FAILED | CONFIG_STATUS_DRIVER,
        );
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            false
        );
        // it is ok to write the low 32bit of device features
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_DRIVER);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_gfeatures_sel(0);
        LittleEndian::write_u32(&mut buf[..], 0x0000_00fe);
        virtio_device.lock().unwrap().base.device_features = 0x0000_00fe;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            true
        );
        assert_eq!(
            virtio_device.lock().unwrap().base.driver_features as u32,
            0x0000_00fe
        );
        // it is ok to write the high 32bit of device features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_gfeatures_sel(1);
        LittleEndian::write_u32(&mut buf[..], 0x0000_00ff);
        virtio_device.lock().unwrap().base.device_features = 0x0000_00ff_0000_0000;
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_REG),
            true
        );
        assert_eq!(
            virtio_device.lock().unwrap().queue_type(),
            QUEUE_TYPE_PACKED_VRING
        );
        assert_eq!(
            virtio_device.lock().unwrap().base.driver_features >> 32 as u32,
            0x0000_00ff
        );

        // write the selector of driver features
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0x00ff_0000);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, DRIVER_FEATURES_SEL_REG),
            true
        );
        assert_eq!(virtio_device.lock().unwrap().gfeatures_sel(), 0x00ff_0000);

        // write the selector of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0x0000_ff00);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_SEL_REG),
            true
        );
        assert_eq!(virtio_device.lock().unwrap().queue_select(), 0x0000_ff00);

        // write the size of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        LittleEndian::write_u32(&mut buf[..], 128);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_NUM_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!(config.size, 128);
        } else {
            assert!(false);
        };
    }

    #[test]
    fn test_virtio_mmio_device_write_02() {
        let virtio_device = Arc::new(Mutex::new(VirtioDeviceTest::new()));
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        // write the ready status of queue
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
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
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
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
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_DRIVER_OK);
        virtio_device
            .lock()
            .unwrap()
            .set_interrupt_status(0b10_1111);
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
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        // write the low 32bit of queue's descriptor table address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xffff_fefe);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_DESC_LOW_REG),
            true
        );
        if let Ok(config) = virtio_mmio_device.device.lock().unwrap().queue_config() {
            assert_eq!(config.desc_table.0 as u32, 0xffff_fefe)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's descriptor table address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xfcfc_ffff);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_DESC_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!((config.desc_table.0 >> 32) as u32, 0xfcfc_ffff)
        } else {
            assert!(false);
        }

        // write the low 32bit of queue's available ring address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xfcfc_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_AVAIL_LOW_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!(config.avail_ring.0 as u32, 0xfcfc_fafa)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's available ring address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xecec_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_AVAIL_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!((config.avail_ring.0 >> 32) as u32, 0xecec_fafa)
        } else {
            assert!(false);
        }

        // write the low 32bit of queue's used ring address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xacac_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_USED_LOW_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!(config.used_ring.0 as u32, 0xacac_fafa)
        } else {
            assert!(false);
        }

        // write the high 32bit of queue's used ring address
        virtio_device.lock().unwrap().set_queue_select(0);
        virtio_device
            .lock()
            .unwrap()
            .set_device_status(CONFIG_STATUS_FEATURES_OK);
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], 0xcccc_fafa);
        assert_eq!(
            virtio_mmio_device.write(&buf[..], addr, QUEUE_USED_HIGH_REG),
            true
        );
        if let Ok(config) = virtio_device.lock().unwrap().queue_config() {
            assert_eq!((config.used_ring.0 >> 32) as u32, 0xcccc_fafa)
        } else {
            assert!(false);
        };
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
        let sys_space = address_space_init();
        let mut virtio_mmio_device = VirtioMmioDevice::new(&sys_space, virtio_device.clone());
        let addr = GuestAddress(0);

        virtio_mmio_device.assign_interrupt_cb();
        let mut locked_device = virtio_device.lock().unwrap();
        locked_device.set_queue_select(0);
        locked_device.set_device_status(CONFIG_STATUS_FEATURES_OK);
        if let Ok(config) = locked_device.queue_config_mut(true) {
            config.desc_table = GuestAddress(0);
            config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * 16);
            config.used_ring = GuestAddress(align(
                (QUEUE_SIZE as u64) * 16 + 8 + 2 * (QUEUE_SIZE as u64),
                4096,
            ));
            config.size = QUEUE_SIZE;
            config.ready = true;
        }
        locked_device.set_queue_select(1);
        if let Ok(config) = locked_device.queue_config_mut(true) {
            config.desc_table = GuestAddress(0);
            config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * 16);
            config.used_ring = GuestAddress(align(
                (QUEUE_SIZE as u64) * 16 + 8 + 2 * (QUEUE_SIZE as u64),
                4096,
            ));
            config.size = QUEUE_SIZE / 2;
            config.ready = true;
        }
        drop(locked_device);

        // write the device status
        let mut buf: Vec<u8> = vec![0xff, 0xff, 0xff, 0xff];
        LittleEndian::write_u32(&mut buf[..], CONFIG_STATUS_ACKNOWLEDGE);
        assert_eq!(virtio_mmio_device.write(&buf[..], addr, STATUS_REG), true);
        assert_eq!(virtio_device.lock().unwrap().device_activated(), false);
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
        assert_eq!(virtio_device.lock().unwrap().b_active, false);
        assert_eq!(virtio_mmio_device.write(&buf[..], addr, STATUS_REG), true);
        assert_eq!(virtio_device.lock().unwrap().device_activated(), true);
        assert_eq!(virtio_device.lock().unwrap().b_active, true);
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
