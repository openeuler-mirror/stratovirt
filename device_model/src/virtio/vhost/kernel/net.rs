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

use std::cmp;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::{config::NetworkInterfaceConfig, main_loop::MainLoop};
use util::byte_code::ByteCode;
use util::epoll_context::EventNotifierHelper;
use util::num_ops::{read_u32, write_u32};
use util::tap::Tap;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::super::errors::{ErrorKind, Result, ResultExt};
use super::super::super::{
    net::{build_device_config_space, create_tap, VirtioNetConfig},
    Queue, VirtioDevice, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM,
    VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_TYPE_NET,
};
use super::super::{VhostNotify, VhostOps};
use super::{VhostBackend, VhostIoHandler, VhostVringFile, VHOST_NET_SET_BACKEND};

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;
/// Size of each virtqueue.
const QUEUE_SIZE_NET: u16 = 256;
/// Feature for vhost-net to add virtio_net_hdr for RX, and strip for TX packets.
const VHOST_NET_F_VIRTIO_NET_HDR: u32 = 27;

trait VhostNetBackend {
    /// Attach virtio net ring to a raw socket, or tap device.
    /// The socket must be already bound to an ethernet device, this device will be
    /// used for transmit.  Pass fd -1 to unbind from the socket and the transmit
    /// device.  This can be used to stop the ring (e.g. for migration).
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_backend(&self, queue_index: usize, tap_file: &File) -> Result<()>;
}

impl VhostNetBackend for VhostBackend {
    /// Attach virtio net ring to a raw socket, or tap device.
    fn set_backend(&self, queue_index: usize, tap_file: &File) -> Result<()> {
        let vring_file = VhostVringFile {
            index: queue_index as u32,
            fd: tap_file.as_raw_fd(),
        };

        let ret = unsafe { ioctl_with_ref(self, VHOST_NET_SET_BACKEND(), &vring_file) };
        if ret < 0 {
            return Err(ErrorKind::VhostIoctl("VHOST_NET_SET_BACKEND".to_string()).into());
        }
        Ok(())
    }
}

/// Network device structure.
pub struct Net {
    /// Configuration of the network device.
    net_cfg: NetworkInterfaceConfig,
    /// Tap device opened.
    tap: Option<Tap>,
    /// Related vhost-net kernel device.
    backend: Option<VhostBackend>,
    /// Bit mask of features supported by the backend.
    device_features: u64,
    /// Bit mask of features negotiated by the backend and the frontend.
    driver_features: u64,
    /// Bit mask of features supported by the vhost-net kernel.
    vhost_features: u64,
    /// Virtio net configurations.
    device_config: VirtioNetConfig,
    /// System address space.
    mem_space: Arc<AddressSpace>,
}

impl Net {
    pub fn new(net_cfg: NetworkInterfaceConfig, mem_space: Arc<AddressSpace>) -> Self {
        Net {
            net_cfg,
            tap: None,
            backend: None,
            device_features: 0_u64,
            driver_features: 0_u64,
            vhost_features: 0_u64,
            device_config: VirtioNetConfig::default(),
            mem_space,
        }
    }
}

impl VirtioDevice for Net {
    /// Realize vhost virtio network device.
    fn realize(&mut self) -> Result<()> {
        let backend = VhostBackend::new(&self.mem_space, "/dev/vhost-net", self.net_cfg.vhost_fd)?;
        backend.set_owner()?;

        let mut vhost_features = backend.get_features()?;
        vhost_features &= !(1_u64 << VHOST_NET_F_VIRTIO_NET_HDR);
        vhost_features &= !(1_u64 << VIRTIO_F_ACCESS_PLATFORM);

        let mut device_features = vhost_features;
        device_features |= 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO;

        if let Some(mac) = &self.net_cfg.mac {
            device_features |= build_device_config_space(&mut self.device_config, mac);
        }

        let host_dev_name = match self.net_cfg.host_dev_name.as_str() {
            "" => None,
            _ => Some(self.net_cfg.host_dev_name.as_str()),
        };

        self.tap =
            create_tap(self.net_cfg.tap_fd, host_dev_name).chain_err(|| "Failed to create tap")?;
        self.backend = Some(backend);
        self.device_features = device_features;
        self.vhost_features = vhost_features;

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_NET
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_NET
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_NET
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
            warn!(
                "Received acknowledge request with unsupported feature: {:x}",
                features
            );
            features &= !unsupported_features;
        }
        self.driver_features |= features;
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.device_config.as_bytes();
        let config_size = config_slice.len() as u64;
        if offset >= config_size {
            return Err(ErrorKind::DevConfigOverflow(offset, config_size).into());
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_size) as usize])?;
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.device_config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(ErrorKind::DevConfigOverflow(offset, config_len as u64).into());
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(&data[..]);

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicU32>,
        queues: Vec<Arc<Mutex<Queue>>>,
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let mut host_notifies = Vec::new();
        let backend = match &self.backend {
            None => return Err("Failed to get backend".into()),
            Some(backend_) => backend_,
        };

        backend.set_features(self.vhost_features)?;
        backend.set_mem_table()?;

        for (queue_index, queue_mutex) in queues.iter().enumerate() {
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

            let tap = match &self.tap {
                None => bail!("Failed to get tap"),
                Some(tap_) => tap_,
            };
            backend.set_backend(queue_index, &tap.file)?;
        }

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
