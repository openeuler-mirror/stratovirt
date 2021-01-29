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
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use byteorder::{ByteOrder, LittleEndian};
use machine_manager::{config::VsockConfig, main_loop::MainLoop};
use util::epoll_context::EventNotifierHelper;
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
        Vsock {
            vsock_cfg,
            backend: None,
            device_features: 0_u64,
            driver_features: 0_u64,
            config_space: Vec::new(),
            mem_space,
        }
    }
}

impl VirtioDevice for Vsock {
    /// Realize vhost virtio vsock device.
    fn realize(&mut self) -> Result<()> {
        let vhost_fd: Option<RawFd> = self.vsock_cfg.vhost_fd;
        let backend = VhostBackend::new(&self.mem_space, VHOST_PATH, vhost_fd)?;

        self.device_features = backend.get_features()?;
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
            _ => bail!("Failed to read config: offset {} exceeds", offset),
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
        backend.set_owner()?;
        backend.set_features(self.driver_features)?;
        backend.set_mem_table()?;

        for (queue_index, queue_mutex) in vhost_queues.iter().enumerate() {
            let queue = queue_mutex.lock().unwrap();
            let actual_size = queue.vring.actual_size();
            let queue_config = queue.vring.get_queue_config();

            backend.set_vring_num(queue_index, actual_size)?;
            backend.set_vring_addr(&queue_config, queue_index, 0)?;
            backend.set_vring_base(queue_index, 0)?;
            backend.set_vring_kick(queue_index, &queue_evts[queue_index])?;
            drop(queue);

            let host_notify = VhostNotify {
                notify_evt: EventFd::new(libc::EFD_NONBLOCK)
                    .chain_err(|| ErrorKind::EventFdCreate)?,
                queue: queue_mutex.clone(),
            };
            backend.set_vring_call(queue_index, &host_notify.notify_evt)?;
            host_notifies.push(host_notify);
        }

        backend.set_guest_cid(cid)?;
        backend.set_running(true)?;

        let handler = VhostIoHandler {
            interrupt_evt: interrupt_evt.try_clone()?,
            interrupt_status,
            host_notifies,
        };

        MainLoop::update_event(EventNotifierHelper::internal_notifiers(Arc::new(
            Mutex::new(handler),
        )))?;

        Ok(())
    }
}
