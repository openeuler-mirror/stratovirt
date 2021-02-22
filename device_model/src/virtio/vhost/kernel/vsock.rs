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

use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::{os::unix::io::RawFd, usize};

use address_space::AddressSpace;
use byteorder::{ByteOrder, LittleEndian};
use machine_manager::{config::VsockConfig, event_loop::EventLoop};
use util::loop_context::EventNotifierHelper;
use util::num_ops::{read_u32, write_u32};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::super::errors::{ErrorKind, Result, ResultExt};
use super::super::super::{Queue, VirtioDevice, VIRTIO_TYPE_VSOCK};
use super::super::{VhostNotify, VhostOps};
use super::{VhostBackend, VhostIoHandler, VHOST_VSOCK_SET_GUEST_CID, VHOST_VSOCK_SET_RUNNING};

/// Number of virtqueues.
const QUEUE_NUM_VSOCK: usize = 3;
/// Size of each virtqueue.
const QUEUE_SIZE_VSOCK: u16 = 256;
/// Size of virtio config space
const VSOCK_CONFIG_SIZE: usize = 8;
/// Backend vhost-vsock device path.
const VHOST_PATH: &str = "/dev/vhost-vsock";

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

/// Vsock device structure.
pub struct Vsock {
    /// Configuration of the vsock device.
    vsock_cfg: VsockConfig,
    /// Related vhost-vsock kernel device.
    backend: Option<VhostBackend>,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Configuration of virtio vsock.
    config_space: Vec<u8>,
    /// System address space.
    mem_space: Arc<AddressSpace>,
}

impl Vsock {
    pub fn new(vsock_cfg: VsockConfig, mem_space: Arc<AddressSpace>) -> Self {
        let config: Vec<u8> = [0; VSOCK_CONFIG_SIZE].to_vec();
        Vsock {
            vsock_cfg,
            backend: None,
            device_features: 0_u64,
            driver_features: 0_u64,
            config_space: config,
            mem_space,
        }
    }
}

impl VirtioDevice for Vsock {
    /// Realize vhost virtio vsock device.
    fn realize(&mut self) -> Result<()> {
        let vhost_fd: Option<RawFd> = self.vsock_cfg.vhost_fd;
        let backend = VhostBackend::new(&self.mem_space, VHOST_PATH, vhost_fd)
            .chain_err(|| "Failed to create backend for vsock")?;

        self.device_features = backend
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
        read_u32(self.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut features = write_u32(value, page);
        let unsupported_features = features & !self.device_features;
        if unsupported_features != 0 {
            warn!("Unsupported feature ack (Vsock): {:x}", features);
            features &= !unsupported_features;
        }
        self.driver_features |= features;
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
        let config_len = self.config_space.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        self.config_space[(offset as usize)..(offset as usize + data_len)]
            .copy_from_slice(&data[..]);

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        _: Arc<AddressSpace>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicU32>,
        queues: Vec<Arc<Mutex<Queue>>>,
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let cid = self.vsock_cfg.guest_cid;
        let mut host_notifies = Vec::new();
        // The third queue is an event-only queue that is not handled by the vhost
        // subsystem (but still needs to exist).  Split it off here.
        let vhost_queues = queues[..2].to_vec();

        // Preliminary setup for vhost net.
        let backend = match &self.backend {
            None => return Err("Failed to get backend for vsock".into()),
            Some(backend_) => backend_,
        };
        backend
            .set_owner()
            .chain_err(|| "Failed to set owner for vsock")?;
        backend
            .set_features(self.driver_features)
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
            backend.set_vring_base(queue_index, 0).chain_err(|| {
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
            interrupt_evt: interrupt_evt.try_clone()?,
            interrupt_status,
            host_notifies,
        };

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
        )?;

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
        let json = r#"
        {
            "vsock_id": "test_vsock_1",
            "guest_cid": 3
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let vsock_conf = VsockConfig::from_value(&value).unwrap();
        let sys_mem = vsock_address_space_init();
        let vsock = Vsock::new(vsock_conf.clone(), sys_mem.clone());
        vsock
    }

    #[test]
    fn test_vsock_init() {
        // test vsock new method
        let mut vsock = vsock_create_instance();

        assert_eq!(vsock.device_features, 0);
        assert_eq!(vsock.driver_features, 0);
        assert!(vsock.backend.is_none());

        assert_eq!(vsock.device_type(), VIRTIO_TYPE_VSOCK);
        assert_eq!(vsock.queue_num(), QUEUE_NUM_VSOCK);
        assert_eq!(vsock.queue_size(), QUEUE_SIZE_VSOCK);

        // test vsock get_device_features
        vsock.device_features = 0x0123_4567_89ab_cdef;
        let features = vsock.get_device_features(0);
        assert_eq!(features, 0x89ab_cdef);
        let features = vsock.get_device_features(1);
        assert_eq!(features, 0x0123_4567);
        let features = vsock.get_device_features(3);
        assert_eq!(features, 0);

        // test vsock set_driver_features
        vsock.device_features = 0x0123_4567_89ab_cdef;
        // check for unsupported feature
        vsock.set_driver_features(0, 0x7000_0000);
        assert_eq!(vsock.device_features, 0x0123_4567_89ab_cdef);
        // check for supported feature
        vsock.set_driver_features(0, 0x8000_0000);
        assert_eq!(vsock.device_features, 0x0123_4567_89ab_cdef);

        // test vsock write_config
        let offset = 0;
        let data: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        vsock.config_space.resize(512, 0);
        assert_eq!(vsock.write_config(offset, &data).is_ok(), true);
        assert_eq!(&vsock.config_space[0..4], data);
        let offset = 512;
        assert_eq!(vsock.write_config(offset, &data).is_ok(), false);

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
