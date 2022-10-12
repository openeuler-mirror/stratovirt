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
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use error_chain::bail;
use log::warn;
use machine_manager::{config::NetworkInterfaceConfig, event_loop::EventLoop};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::num_ops::{read_u32, write_u32};
use util::tap::Tap;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::super::errors::{ErrorKind, Result, ResultExt};
use super::super::super::{
    net::{build_device_config_space, create_tap, VirtioNetConfig, MAC_ADDR_LEN},
    CtrlVirtio, NetCtrlHandler, Queue, VirtioDevice, VirtioInterrupt, VIRTIO_F_ACCESS_PLATFORM,
    VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN,
    VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_MAC_ADDR, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MQ, VIRTIO_TYPE_NET,
};
use super::super::{VhostNotify, VhostOps};
use super::{VhostBackend, VhostIoHandler, VhostVringFile, VHOST_NET_SET_BACKEND};
use crate::virtio_has_feature;

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
    taps: Option<Vec<Tap>>,
    /// Related vhost-net kernel device.
    backends: Option<Vec<VhostBackend>>,
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
    /// EventFd for device deactivate.
    deactivate_evt: EventFd,
}

impl Net {
    pub fn new(cfg: &NetworkInterfaceConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Net {
            net_cfg: cfg.clone(),
            taps: None,
            backends: None,
            device_features: 0_u64,
            driver_features: 0_u64,
            vhost_features: 0_u64,
            device_config: VirtioNetConfig::default(),
            mem_space: mem_space.clone(),
            deactivate_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        }
    }
}

impl VirtioDevice for Net {
    /// Realize vhost virtio network device.
    fn realize(&mut self) -> Result<()> {
        let queue_pairs = self.net_cfg.queues / 2;
        let mut backends = Vec::with_capacity(queue_pairs as usize);
        for index in 0..queue_pairs {
            let fd = if let Some(fds) = self.net_cfg.vhost_fds.as_mut() {
                fds.get(index as usize).copied()
            } else {
                None
            };

            let backend = VhostBackend::new(&self.mem_space, "/dev/vhost-net", fd)
                .chain_err(|| "Failed to create backend for vhost net")?;
            backend
                .set_owner()
                .chain_err(|| "Failed to set owner for vhost net")?;
            backends.push(backend);
        }

        let mut vhost_features = backends[0]
            .get_features()
            .chain_err(|| "Failed to get features for vhost net")?;
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

        if self.net_cfg.mq
            && queue_pairs >= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN
            && queue_pairs <= VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX
        {
            device_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
            device_features |= 1 << VIRTIO_NET_F_MQ;
            self.device_config.max_virtqueue_pairs = queue_pairs;
        }

        if let Some(mac) = &self.net_cfg.mac {
            device_features |= build_device_config_space(&mut self.device_config, mac);
        }

        let host_dev_name = match self.net_cfg.host_dev_name.as_str() {
            "" => None,
            _ => Some(self.net_cfg.host_dev_name.as_str()),
        };

        self.taps = create_tap(self.net_cfg.tap_fds.as_ref(), host_dev_name, queue_pairs)
            .chain_err(|| "Failed to create tap for vhost net")?;
        self.backends = Some(backends);
        self.device_features = device_features;
        self.vhost_features = vhost_features;

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_NET
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        if self.net_cfg.mq {
            (self.net_cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        }
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
                "Received acknowledge request with unsupported feature for vhost net: 0x{:x}",
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

        if !virtio_has_feature(self.driver_features, VIRTIO_NET_F_CTRL_MAC_ADDR)
            && !virtio_has_feature(self.driver_features, VIRTIO_F_VERSION_1)
            && offset == 0
            && data_len == MAC_ADDR_LEN
            && *data != config_slice[0..data_len]
        {
            config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);
        }

        Ok(())
    }

    /// Activate the virtio device, this function is called by vcpu thread when frontend
    /// virtio driver is ready and write `DRIVER_OK` to backend.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let queue_num = queues.len();
        if (self.driver_features & 1 << VIRTIO_NET_F_CTRL_VQ != 0) && (queue_num % 2 != 0) {
            let ctrl_queue = queues[queue_num - 1].clone();
            let ctrl_queue_evt = queue_evts.remove(queue_num - 1);

            let ctrl_handler = NetCtrlHandler {
                ctrl: CtrlVirtio::new(ctrl_queue, ctrl_queue_evt),
                mem_space,
                interrupt_cb: interrupt_cb.clone(),
                driver_features: self.driver_features,
                deactivate_evt: self.deactivate_evt.try_clone().unwrap(),
            };

            EventLoop::update_event(
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler))),
                self.net_cfg.iothread.as_ref(),
            )?;
        }

        let queue_pairs = queue_num / 2;
        for index in 0..queue_pairs {
            let mut host_notifies = Vec::new();
            let backend = match &self.backends {
                None => return Err("Failed to get backend for vhost net".into()),
                Some(backends) => backends
                    .get(index)
                    .chain_err(|| format!("Failed to get index {} vhost backend", index))?,
            };

            backend
                .set_features(self.vhost_features)
                .chain_err(|| "Failed to set features for vhost net")?;
            backend
                .set_mem_table()
                .chain_err(|| "Failed to set mem table for vhost net")?;

            for queue_index in 0..2 {
                let queue_mutex = queues[index * 2 + queue_index].clone();
                let queue = queue_mutex.lock().unwrap();
                let actual_size = queue.vring.actual_size();
                let queue_config = queue.vring.get_queue_config();

                backend
                    .set_vring_num(queue_index, actual_size)
                    .chain_err(|| {
                        format!(
                            "Failed to set vring num for vhost net, index: {} size: {}",
                            queue_index, actual_size,
                        )
                    })?;
                backend
                    .set_vring_addr(&queue_config, queue_index, 0)
                    .chain_err(|| {
                        format!(
                            "Failed to set vring addr for vhost net, index: {}",
                            queue_index,
                        )
                    })?;
                backend.set_vring_base(queue_index, 0).chain_err(|| {
                    format!(
                        "Failed to set vring base for vhost net, index: {}",
                        queue_index,
                    )
                })?;
                backend
                    .set_vring_kick(queue_index, &queue_evts[index * 2 + queue_index])
                    .chain_err(|| {
                        format!(
                            "Failed to set vring kick for vhost net, index: {}",
                            index * 2 + queue_index,
                        )
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
                        format!(
                            "Failed to set vring call for vhost net, index: {}",
                            queue_index,
                        )
                    })?;
                host_notifies.push(host_notify);

                let tap = match &self.taps {
                    None => bail!("Failed to get tap for vhost net"),
                    Some(taps) => taps[index].clone(),
                };
                backend.set_backend(queue_index, &tap.file).chain_err(|| {
                    format!(
                        "Failed to set tap device for vhost net, index: {}",
                        queue_index,
                    )
                })?;
            }

            let handler = VhostIoHandler {
                interrupt_cb: interrupt_cb.clone(),
                host_notifies,
                deactivate_evt: self.deactivate_evt.try_clone().unwrap(),
            };

            EventLoop::update_event(
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
                None,
            )?;
        }
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
        self.backends = None;
        self.taps = None;
        self.device_features = 0_u64;
        self.driver_features = 0_u64;
        self.vhost_features = 0_u64;
        self.device_config = VirtioNetConfig::default();

        self.realize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use address_space::*;
    use std::fs::File;

    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;

    fn vhost_address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36);
        let sys_space = AddressSpace::new(root).unwrap();
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
                Region::init_ram_region(host_mmap.clone()),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    #[test]
    fn test_vhost_net_realize() {
        let net1 = NetworkInterfaceConfig {
            id: "eth1".to_string(),
            host_dev_name: "tap1".to_string(),
            mac: Some("1F:2C:3E:4A:5B:6D".to_string()),
            vhost_type: Some("vhost-kernel".to_string()),
            tap_fds: Some(vec![4]),
            vhost_fds: Some(vec![5]),
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
        };
        let conf = vec![net1];
        let confs = Some(conf);
        let vhost_net_confs = confs.unwrap();
        let vhost_net_conf = vhost_net_confs[0].clone();
        let vhost_net_space = vhost_address_space_init();
        let mut vhost_net = Net::new(&vhost_net_conf, &vhost_net_space);
        // the tap_fd and vhost_fd attribute of vhost-net can't be assigned.
        assert_eq!(vhost_net.realize().is_ok(), false);

        let net1 = NetworkInterfaceConfig {
            id: "eth0".to_string(),
            host_dev_name: "".to_string(),
            mac: Some("1A:2B:3C:4D:5E:6F".to_string()),
            vhost_type: Some("vhost-kernel".to_string()),
            tap_fds: None,
            vhost_fds: None,
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
        };
        let conf = vec![net1];
        let confs = Some(conf);
        let vhost_net_confs = confs.unwrap();
        let vhost_net_conf = vhost_net_confs[0].clone();
        let mut vhost_net = Net::new(&vhost_net_conf, &vhost_net_space);

        // if fail to open vhost-net device, no need to continue.
        if let Err(_e) = File::open("/dev/vhost-net") {
            return;
        }
        // without assigned value of tap_fd and vhost_fd,
        // vhost-net device can be realized successfully.
        assert_eq!(vhost_net.realize().is_ok(), true);

        // test for get/set_driver_features
        vhost_net.device_features = 0;
        let page: u32 = 0x0;
        let value: u32 = 0xff;
        vhost_net.set_driver_features(page, value);
        let new_page = vhost_net.get_device_features(page);
        assert_eq!(new_page, page);

        vhost_net.device_features = 0xffff_ffff_ffff_ffff;
        let page: u32 = 0x0;
        let value: u32 = 0xff;
        vhost_net.set_driver_features(page, value);
        let new_page = vhost_net.get_device_features(page);
        assert_ne!(new_page, page);

        // test for read/write_config
        let device_config = vhost_net.device_config.as_bytes();
        let len = device_config.len() as u64;

        let offset: u64 = 0;
        let data: Vec<u8> = vec![1; len as usize];
        assert_eq!(vhost_net.write_config(offset, &data).is_ok(), true);

        let mut read_data: Vec<u8> = vec![0; len as usize];
        assert_eq!(vhost_net.read_config(offset, &mut read_data).is_ok(), true);
        assert_ne!(read_data, data);

        let offset: u64 = 1;
        let data: Vec<u8> = vec![1; len as usize];
        assert_eq!(vhost_net.write_config(offset, &data).is_ok(), true);

        let offset: u64 = len + 1;
        let mut read_data: Vec<u8> = vec![0; len as usize];
        assert_eq!(vhost_net.read_config(offset, &mut read_data).is_ok(), false);

        let offset: u64 = len - 1;
        let mut read_data: Vec<u8> = vec![0; len as usize];
        assert_eq!(vhost_net.read_config(offset, &mut read_data).is_ok(), true);
    }
}
