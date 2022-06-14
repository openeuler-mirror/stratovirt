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

use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use log::warn;
use machine_manager::{config::VsockConfig, event_loop::EventLoop};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::super::errors::{ErrorKind, Result, ResultExt};
use super::super::super::{
    Queue, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_TYPE_VSOCK,
};
use super::super::{VhostNotify, VhostOps};
use super::{VhostBackend, VhostIoHandler, VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};

/// Number of virtqueues.
const QUEUE_NUM_VSOCK: usize = 3;
/// Size of each virtqueue.
const QUEUE_SIZE_VSOCK: u16 = 256;
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
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_GUEST_CID(), &cid) };
        if ret < 0 {
            return Err(ErrorKind::VhostIoctl("VHOST_VSOCK_SET_GUEST_CID".to_string()).into());
        }
        Ok(())
    }

    fn set_running(&self, start: bool) -> Result<()> {
        let on: u32 = if start { 1 } else { 0 };
        let ret = unsafe { ioctl_with_ref(&self.fd, VHOST_VSOCK_SET_RUNNING(), &on) };
        if ret < 0 {
            return Err(ErrorKind::VhostIoctl("VHOST_VSOCK_SET_RUNNING".to_string()).into());
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
}

/// Vsock device structure.
pub struct Vsock {
    /// Configuration of the vsock device.
    vsock_cfg: VsockConfig,
    /// Related vhost-vsock kernel device.
    backend: Option<VhostBackend>,
    /// The status of vsock.
    state: VsockState,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Event queue for vsock.
    event_queue: Option<Arc<Mutex<Queue>>>,
    /// Callback to trigger interrupt.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// EventFd for device deactivate.
    deactivate_evt: EventFd,
}

impl Vsock {
    pub fn new(cfg: &VsockConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Vsock {
            vsock_cfg: cfg.clone(),
            backend: None,
            state: VsockState::default(),
            mem_space: mem_space.clone(),
            event_queue: None,
            interrupt_cb: None,
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }

    /// The `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` event indicates that communication has
    /// been interrupted. The driver shuts down established connections and the guest_cid
    /// configuration field is fetched again.
    fn transport_reset(&self) -> Result<()> {
        let mut event_queue_locked = self.event_queue.as_ref().unwrap().lock().unwrap();
        let element = event_queue_locked
            .vring
            .pop_avail(&self.mem_space, self.state.driver_features)
            .chain_err(|| "Failed to get avail ring element.")?;

        self.mem_space
            .write_object(
                &VIRTIO_VSOCK_EVENT_TRANSPORT_RESET,
                element.in_iovec[0].addr,
            )
            .chain_err(|| "Failed to write buf for virtio vsock event")?;
        event_queue_locked
            .vring
            .add_used(
                &self.mem_space,
                element.index,
                VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.as_bytes().len() as u32,
            )
            .chain_err(|| format!("Failed to add used ring {}", element.index))?;

        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb(&VirtioInterruptType::Vring, Some(&*event_queue_locked))
                .chain_err(|| ErrorKind::EventFdWrite)?;
        }

        Ok(())
    }
}

impl VirtioDevice for Vsock {
    /// Realize vhost virtio vsock device.
    fn realize(&mut self) -> Result<()> {
        let vhost_fd: Option<RawFd> = self.vsock_cfg.vhost_fd;
        let backend = VhostBackend::new(&self.mem_space, VHOST_PATH, vhost_fd)
            .chain_err(|| "Failed to create backend for vsock")?;
        backend
            .set_owner()
            .chain_err(|| "Failed to set owner for vsock")?;
        self.state.device_features = backend
            .get_features()
            .chain_err(|| "Failed to get features for vsock")?;
        self.backend = Some(backend);

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_VSOCK
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_VSOCK
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_VSOCK
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut features = write_u32(value, page);
        let unsupported_features = features & !self.state.device_features;
        if unsupported_features != 0 {
            warn!("Unsupported feature ack (Vsock): {:x}", features);
            features &= !unsupported_features;
        }
        self.state.driver_features |= features;
    }

    /// Read data of config from guest.
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

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_len = self.state.config_space.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        self.state.config_space[(offset as usize)..(offset as usize + data_len)]
            .copy_from_slice(data);
        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        _: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let cid = self.vsock_cfg.guest_cid;
        let mut host_notifies = Vec::new();
        // The receive queue and transmit queue will be handled in vhost.
        let vhost_queues = queues[..2].to_vec();
        // This event queue will be handled.
        self.event_queue = Some(queues[2].clone());
        self.interrupt_cb = Some(interrupt_cb.clone());

        // Preliminary setup for vhost net.
        let backend = match &self.backend {
            None => return Err("Failed to get backend for vsock".into()),
            Some(backend_) => backend_,
        };
        backend
            .set_features(self.state.driver_features)
            .chain_err(|| "Failed to set features for vsock")?;
        backend
            .set_mem_table()
            .chain_err(|| "Failed to set mem table for vsock")?;

        for (queue_index, queue_mutex) in vhost_queues.iter().enumerate() {
            let queue = queue_mutex.lock().unwrap();
            let actual_size = queue.vring.actual_size();
            let queue_config = queue.vring.get_queue_config();

            backend
                .set_vring_num(queue_index, actual_size)
                .chain_err(|| {
                    format!("Failed to set vring num for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_addr(&queue_config, queue_index, 0)
                .chain_err(|| {
                    format!("Failed to set vring addr for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_base(queue_index, self.state.last_avail_idx[queue_index])
                .chain_err(|| {
                    format!("Failed to set vring base for vsock, index: {}", queue_index)
                })?;
            backend
                .set_vring_kick(queue_index, &queue_evts[queue_index])
                .chain_err(|| {
                    format!("Failed to set vring kick for vsock, index: {}", queue_index)
                })?;
            drop(queue);

            let host_notify = VhostNotify {
                notify_evt: EventFd::new(libc::EFD_NONBLOCK)
                    .chain_err(|| ErrorKind::EventFdCreate)?,
                queue: queue_mutex.clone(),
            };
            backend
                .set_vring_call(queue_index, &host_notify.notify_evt)
                .chain_err(|| {
                    format!("Failed to set vring call for vsock, index: {}", queue_index)
                })?;
            host_notifies.push(host_notify);
        }

        backend.set_guest_cid(cid)?;
        backend.set_running(true)?;

        let handler = VhostIoHandler {
            interrupt_cb,
            host_notifies,
            deactivate_evt: self.deactivate_evt.as_raw_fd(),
        };

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
        )?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.deactivate_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)?;

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        // No need to close fd manually, because rust will
        // automatically cleans up variables at the end of the lifecycle.
        self.backend = None;
        self.state = VsockState::default();
        self.event_queue = None;
        self.interrupt_cb = None;

        self.realize()
    }
}

impl StateTransfer for Vsock {
    fn get_state_vec(&self) -> migration::errors::Result<Vec<u8>> {
        let mut state = self.state;
        migration::errors::ResultExt::chain_err(
            self.backend.as_ref().unwrap().set_running(false),
            || "Failed to set vsock backend stopping",
        )?;
        state.last_avail_idx[0] = self.backend.as_ref().unwrap().get_vring_base(0).unwrap();
        state.last_avail_idx[1] = self.backend.as_ref().unwrap().get_vring_base(1).unwrap();
        migration::errors::ResultExt::chain_err(
            self.backend.as_ref().unwrap().set_running(true),
            || "Failed to set vsock backend running",
        )?;
        migration::errors::ResultExt::chain_err(self.transport_reset(), || {
            "Failed to send vsock transport reset event"
        })?;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::errors::Result<()> {
        self.state = *VsockState::from_bytes(state)
            .ok_or(migration::errors::ErrorKind::FromBytesError("VSOCK"))?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&VsockState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for Vsock {
    #[cfg(target_arch = "aarch64")]
    fn resume(&mut self) -> migration::errors::Result<()> {
        migration::errors::ResultExt::chain_err(self.transport_reset(), || {
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
        let root = Region::init_container_region(u64::max_value());
        let sys_mem = AddressSpace::new(root).unwrap();
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

        assert_eq!(vsock.state.device_features, 0);
        assert_eq!(vsock.state.driver_features, 0);
        assert!(vsock.backend.is_none());

        assert_eq!(vsock.device_type(), VIRTIO_TYPE_VSOCK);
        assert_eq!(vsock.queue_num(), QUEUE_NUM_VSOCK);
        assert_eq!(vsock.queue_size(), QUEUE_SIZE_VSOCK);

        // test vsock get_device_features
        vsock.state.device_features = 0x0123_4567_89ab_cdef;
        let features = vsock.get_device_features(0);
        assert_eq!(features, 0x89ab_cdef);
        let features = vsock.get_device_features(1);
        assert_eq!(features, 0x0123_4567);
        let features = vsock.get_device_features(3);
        assert_eq!(features, 0);

        // test vsock set_driver_features
        vsock.state.device_features = 0x0123_4567_89ab_cdef;
        // check for unsupported feature
        vsock.set_driver_features(0, 0x7000_0000);
        assert_eq!(vsock.state.device_features, 0x0123_4567_89ab_cdef);
        // check for supported feature
        vsock.set_driver_features(0, 0x8000_0000);
        assert_eq!(vsock.state.device_features, 0x0123_4567_89ab_cdef);

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
