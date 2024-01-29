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

use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::{VhostIoHandler, VhostNotify, VhostOps};
use super::{VhostBackend, VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};
use crate::{
    check_config_space_rw, Queue, VirtioBase, VirtioDevice, VirtioError, VirtioInterrupt,
    VirtioInterruptType, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_TYPE_VSOCK,
};
use address_space::AddressSpace;
use machine_manager::config::{VsockConfig, DEFAULT_VIRTQUEUE_SIZE};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;

/// Number of virtqueues.
const QUEUE_NUM_VSOCK: usize = 3;
/// Backend vhost-vsock device path.
const VHOST_PATH: &str = "/dev/vhost-vsock";
/// Event transport reset
const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

trait VhostVsockBackend {
    /// Each guest should have an unique CID which is used to route data to the guest.
    fn set_guest_cid(&self, cid: u64) -> Result<()>;

    fn set_running(&self, start: bool) -> Result<()>;
}

impl VhostVsockBackend for VhostBackend {
    fn set_guest_cid(&self, cid: u64) -> Result<()> {
        // SAFETY: self.fd was created in function new() and the return value will be checked later.
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        if ret < 0 {
            return Err(anyhow!(VirtioError::VhostIoctl(
                "VHOST_VSOCK_SET_GUEST_CID".to_string()
            )));
        }
        Ok(())
    }

    fn set_running(&self, start: bool) -> Result<()> {
        let on: u32 = u32::from(start);
        // SAFETY: self.fd was created in function new() and the return value will be checked later.
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_RUNNING(), &on) };
        if ret < 0 {
            return Err(anyhow!(VirtioError::VhostIoctl(
                "VHOST_VSOCK_SET_RUNNING".to_string()
            )));
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct VsockState {
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Configuration of virtio vsock.
    config_space: [u8; 8],
    /// Last avail idx in vsock backend queue.
    last_avail_idx: [u16; 2],
    /// Device broken status.
    broken: bool,
}

/// Vsock device structure.
pub struct Vsock {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the vsock device.
    vsock_cfg: VsockConfig,
    /// Configuration of virtio vsock.
    config_space: [u8; 8],
    /// Related vhost-vsock kernel device.
    backend: Option<VhostBackend>,
    /// Last avail idx in vsock backend queue.
    last_avail_idx: [u16; 2],
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Event queue for vsock.
    event_queue: Option<Arc<Mutex<Queue>>>,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Save irqfd used for vhost-vsock
    call_events: Vec<Arc<EventFd>>,
}

impl Vsock {
    pub fn new(cfg: &VsockConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Vsock {
            base: VirtioBase::new(VIRTIO_TYPE_VSOCK, QUEUE_NUM_VSOCK, DEFAULT_VIRTQUEUE_SIZE),
            vsock_cfg: cfg.clone(),
            backend: None,
            config_space: Default::default(),
            last_avail_idx: Default::default(),
            mem_space: mem_space.clone(),
            event_queue: None,
            interrupt_cb: None,
            call_events: Vec::new(),
        }
    }

    /// The `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` event indicates that communication has
    /// been interrupted. The driver shuts down established connections and the guest_cid
    /// configuration field is fetched again.
    fn transport_reset(&self) -> Result<()> {
        if let Some(evt_queue) = self.event_queue.as_ref() {
            let mut event_queue_locked = evt_queue.lock().unwrap();
            let element = event_queue_locked
                .vring
                .pop_avail(&self.mem_space, self.base.driver_features)
                .with_context(|| "Failed to get avail ring element.")?;
            if element.desc_num == 0 {
                return Ok(());
            }

            self.mem_space
                .write_object(
                    &VIRTIO_VSOCK_EVENT_TRANSPORT_RESET,
                    element.in_iovec[0].addr,
                )
                .with_context(|| "Failed to write buf for virtio vsock event")?;
            event_queue_locked
                .vring
                .add_used(
                    &self.mem_space,
                    element.index,
                    VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.as_bytes().len() as u32,
                )
                .with_context(|| format!("Failed to add used ring {}", element.index))?;

            if let Some(interrupt_cb) = &self.interrupt_cb {
                interrupt_cb(
                    &VirtioInterruptType::Vring,
                    Some(&*event_queue_locked),
                    false,
                )
                .with_context(|| VirtioError::EventFdWrite)?;
            }
        }

        Ok(())
    }
}

impl VirtioDevice for Vsock {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        let vhost_fd: Option<RawFd> = self.vsock_cfg.vhost_fd;
        let backend = VhostBackend::new(&self.mem_space, VHOST_PATH, vhost_fd)
            .with_context(|| "Failed to create backend for vsock")?;
        backend
            .set_owner()
            .with_context(|| "Failed to set owner for vsock")?;
        self.backend = Some(backend);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let backend = self.backend.as_ref().unwrap();
        let features = backend
            .get_features()
            .with_context(|| "Failed to get features for vsock")?;
        self.base.device_features = features & !(1_u64 << VIRTIO_F_ACCESS_PLATFORM);
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.vsock_cfg.guest_cid),
            0 if data.len() == 4 => {
                LittleEndian::write_u32(data, (self.vsock_cfg.guest_cid & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => LittleEndian::write_u32(
                data,
                ((self.vsock_cfg.guest_cid >> 32) & 0xffff_ffff) as u32,
            ),
            _ => bail!("Failed to read config: offset {} exceeds for vsock", offset),
        }
        Ok(())
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        check_config_space_rw(&self.config_space, offset, data)?;
        let data_len = data.len();
        self.config_space[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        for fd in queue_evts.iter() {
            self.call_events.push(fd.clone());
        }

        Ok(())
    }

    fn activate(
        &mut self,
        _: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let cid = self.vsock_cfg.guest_cid;
        let queues = &self.base.queues;
        // The receive queue and transmit queue will be handled in vhost.
        let vhost_queues = queues[..2].to_vec();
        let mut host_notifies = Vec::new();
        // This event queue will be handled.
        self.event_queue = Some(queues[2].clone());
        self.interrupt_cb = Some(interrupt_cb.clone());

        // Preliminary setup for vhost net.
        let backend = match &self.backend {
            None => return Err(anyhow!("Failed to get backend for vsock")),
            Some(backend_) => backend_,
        };
        backend
            .set_features(self.base.driver_features)
            .with_context(|| "Failed to set features for vsock")?;
        backend
            .set_mem_table()
            .with_context(|| "Failed to set mem table for vsock")?;

        for (queue_index, queue_mutex) in vhost_queues.iter().enumerate() {
            let queue = queue_mutex.lock().unwrap();
            let actual_size = queue.vring.actual_size();
            let queue_config = queue.vring.get_queue_config();

            backend
                .set_vring_num(queue_index, actual_size)
                .with_context(|| {
                    format!("Failed to set vring num for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_addr(&queue_config, queue_index, 0)
                .with_context(|| {
                    format!("Failed to set vring addr for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_base(queue_index, self.last_avail_idx[queue_index])
                .with_context(|| {
                    format!("Failed to set vring base for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_kick(queue_index, queue_evts[queue_index].clone())
                .with_context(|| {
                    format!("Failed to set vring kick for vsock, index: {}", queue_index)
                })?;
            drop(queue);

            let event = if self.call_events.is_empty() {
                let host_notify = VhostNotify {
                    notify_evt: Arc::new(
                        EventFd::new(libc::EFD_NONBLOCK)
                            .with_context(|| VirtioError::EventFdCreate)?,
                    ),
                    queue: queue_mutex.clone(),
                };
                let event = host_notify.notify_evt.clone();
                host_notifies.push(host_notify);
                event
            } else {
                self.call_events[queue_index].clone()
            };
            backend
                .set_vring_call(queue_index, event)
                .with_context(|| {
                    format!("Failed to set vring call for vsock, index: {}", queue_index)
                })?;
        }

        backend.set_guest_cid(cid)?;
        backend.set_running(true)?;

        if self.call_events.is_empty() {
            let handler = VhostIoHandler {
                interrupt_cb: interrupt_cb.clone(),
                host_notifies,
                device_broken: self.base.broken.clone(),
            };
            let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
            register_event_helper(notifiers, None, &mut self.base.deactivate_evts)?;
        }

        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        self.call_events.clear();

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.backend.as_ref().unwrap().set_running(false)
    }
}

impl StateTransfer for Vsock {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        Result::with_context(self.backend.as_ref().unwrap().set_running(false), || {
            "Failed to set vsock backend stopping"
        })?;

        let last_avail_idx_0 = self.backend.as_ref().unwrap().get_vring_base(0).unwrap();
        let last_avail_idx_1 = self.backend.as_ref().unwrap().get_vring_base(1).unwrap();
        let state = VsockState {
            device_features: self.base.device_features,
            driver_features: self.base.driver_features,
            config_space: self.config_space,
            last_avail_idx: [last_avail_idx_0, last_avail_idx_1],
            broken: self.base.broken.load(Ordering::SeqCst),
        };

        Result::with_context(self.backend.as_ref().unwrap().set_running(true), || {
            "Failed to set vsock backend running"
        })?;
        Result::with_context(self.transport_reset(), || {
            "Failed to send vsock transport reset event"
        })?;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let state = VsockState::from_bytes(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("VSOCK"))?;
        self.base.device_features = state.device_features;
        self.base.driver_features = state.driver_features;
        self.base.broken.store(state.broken, Ordering::SeqCst);
        self.config_space = state.config_space;
        self.last_avail_idx = state.last_avail_idx;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&VsockState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for Vsock {
    #[cfg(target_arch = "aarch64")]
    fn resume(&mut self) -> Result<()> {
        Result::with_context(self.transport_reset(), || {
            "Failed to resume virtio vsock device"
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;
    pub use address_space::*;

    fn vsock_address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(u64::max_value(), "sysmem");
        let sys_mem = AddressSpace::new(root, "sysmem", None).unwrap();
        sys_mem
    }

    fn vsock_create_instance() -> Vsock {
        let vsock_conf = VsockConfig {
            id: "test_vsock_1".to_string(),
            guest_cid: 3,
            vhost_fd: None,
        };
        let sys_mem = vsock_address_space_init();
        let vsock = Vsock::new(&vsock_conf, &sys_mem);
        vsock
    }

    #[test]
    fn test_vsock_init() {
        // test vsock new method
        let mut vsock = vsock_create_instance();

        assert_eq!(vsock.base.device_features, 0);
        assert_eq!(vsock.base.driver_features, 0);
        assert!(vsock.backend.is_none());

        assert_eq!(vsock.device_type(), VIRTIO_TYPE_VSOCK);
        assert_eq!(vsock.queue_num(), QUEUE_NUM_VSOCK);
        assert_eq!(vsock.queue_size_max(), DEFAULT_VIRTQUEUE_SIZE);

        // test vsock get_device_features
        vsock.base.device_features = 0x0123_4567_89ab_cdef;
        let features = vsock.device_features(0);
        assert_eq!(features, 0x89ab_cdef);
        let features = vsock.device_features(1);
        assert_eq!(features, 0x0123_4567);
        let features = vsock.device_features(3);
        assert_eq!(features, 0);

        // test vsock set_driver_features
        vsock.base.device_features = 0x0123_4567_89ab_cdef;
        // check for unsupported feature
        vsock.set_driver_features(0, 0x7000_0000);
        assert_eq!(vsock.driver_features(0) as u64, 0_u64);
        assert_eq!(vsock.base.device_features, 0x0123_4567_89ab_cdef);
        // check for supported feature
        vsock.set_driver_features(0, 0x8000_0000);
        assert_eq!(vsock.driver_features(0) as u64, 0x8000_0000_u64);
        assert_eq!(vsock.base.device_features, 0x0123_4567_89ab_cdef);

        // test vsock read_config
        let mut buf: [u8; 8] = [0; 8];
        assert_eq!(vsock.read_config(0, &mut buf).is_ok(), true);
        let value = LittleEndian::read_u64(&buf);
        assert_eq!(value, vsock.vsock_cfg.guest_cid);

        let mut buf: [u8; 4] = [0; 4];
        assert_eq!(vsock.read_config(0, &mut buf).is_ok(), true);
        let value = LittleEndian::read_u32(&buf);
        assert_eq!(value, vsock.vsock_cfg.guest_cid as u32);

        let mut buf: [u8; 4] = [0; 4];
        assert_eq!(vsock.read_config(4, &mut buf).is_ok(), true);
        let value = LittleEndian::read_u32(&buf);
        assert_eq!(value, (vsock.vsock_cfg.guest_cid >> 32) as u32);

        let mut buf: [u8; 4] = [0; 4];
        assert_eq!(vsock.read_config(5, &mut buf).is_err(), true);
        assert_eq!(vsock.read_config(3, &mut buf).is_err(), true);
    }

    #[test]
    fn test_vsock_realize() {
        // test vsock new method
        let mut vsock = vsock_create_instance();

        // if fail to open vsock device, no need to continue.
        if let Err(_e) = std::fs::File::open(VHOST_PATH) {
            return;
        }

        // test vsock realize method
        assert!(vsock.realize().is_ok());
        assert!(vsock.backend.is_some());

        // test vsock set_guest_cid
        let backend = vsock.backend.unwrap();
        assert_eq!(backend.set_guest_cid(3).is_ok(), true);
        assert_eq!(
            backend.set_guest_cid(u32::max_value() as u64).is_ok(),
            false
        );
        assert_eq!(backend.set_guest_cid(2).is_ok(), false);
        assert_eq!(backend.set_guest_cid(0).is_ok(), false);
    }
}
