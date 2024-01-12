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
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;

use super::super::{VhostIoHandler, VhostNotify, VhostOps};
use super::{VhostBackend, VhostVringFile, VHOST_NET_SET_BACKEND};
use crate::read_config_default;
use crate::{
    device::net::{build_device_config_space, create_tap, CtrlInfo, MAC_ADDR_LEN},
    error::VirtioError,
    virtio_has_feature, CtrlVirtio, NetCtrlHandler, VirtioBase, VirtioDevice, VirtioInterrupt,
    VirtioNetConfig, VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_CTRL_MAC_ADDR,
    VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MQ, VIRTIO_TYPE_NET,
};
use address_space::AddressSpace;
use machine_manager::config::NetworkInterfaceConfig;
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::tap::Tap;

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;
/// Feature for vhost-net to add virtio_net_hdr for RX, and strip for TX packets.
const VHOST_NET_F_VIRTIO_NET_HDR: u32 = 27;

trait VhostNetBackend {
    /// Attach virtio net ring to a raw socket, or tap device.
    /// The socket must be already bound to an ethernet device, this device will be
    /// used for transmit. Pass fd -1 to unbind from the socket and the transmit
    /// device. This can be used to stop the ring (e.g. for migration).
    ///
    /// # Arguments
    /// * `queue_index` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_backend(&self, queue_index: usize, fd: RawFd) -> Result<()>;
}

impl VhostNetBackend for VhostBackend {
    /// Attach virtio net ring to a raw socket, or tap device.
    fn set_backend(&self, queue_index: usize, fd: RawFd) -> Result<()> {
        let vring_file = VhostVringFile {
            index: queue_index as u32,
            fd,
        };

        // SAFETY: self.fd was created in function new() and the return value will be checked later.
        let ret = unsafe { ioctl_with_ref(self, VHOST_NET_SET_BACKEND(), &vring_file) };
        if ret < 0 {
            return Err(anyhow!(VirtioError::VhostIoctl(
                "VHOST_NET_SET_BACKEND".to_string()
            )));
        }
        Ok(())
    }
}

/// Network device structure.
pub struct Net {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the network device.
    net_cfg: NetworkInterfaceConfig,
    /// Virtio net configurations.
    config_space: Arc<Mutex<VirtioNetConfig>>,
    /// Tap device opened.
    taps: Option<Vec<Tap>>,
    /// Related vhost-net kernel device.
    backends: Option<Vec<VhostBackend>>,
    /// Bit mask of features supported by the vhost-net kernel.
    vhost_features: u64,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Save irqfd used for vhost-net.
    call_events: Vec<Arc<EventFd>>,
}

impl Net {
    pub fn new(cfg: &NetworkInterfaceConfig, mem_space: &Arc<AddressSpace>) -> Self {
        let queue_num = if cfg.mq {
            (cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        };
        let queue_size = cfg.queue_size;

        Net {
            base: VirtioBase::new(VIRTIO_TYPE_NET, queue_num, queue_size),
            net_cfg: cfg.clone(),
            config_space: Default::default(),
            taps: None,
            backends: None,
            vhost_features: 0_u64,
            mem_space: mem_space.clone(),
            call_events: Vec::new(),
        }
    }
}

impl VirtioDevice for Net {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

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
                .with_context(|| "Failed to create backend for vhost net")?;
            backend
                .set_owner()
                .with_context(|| "Failed to set owner for vhost net")?;
            backends.push(backend);
        }

        let host_dev_name = match self.net_cfg.host_dev_name.as_str() {
            "" => None,
            _ => Some(self.net_cfg.host_dev_name.as_str()),
        };

        self.taps = create_tap(self.net_cfg.tap_fds.as_ref(), host_dev_name, queue_pairs)
            .with_context(|| "Failed to create tap for vhost net")?;
        self.backends = Some(backends);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let mut vhost_features = self.backends.as_ref().unwrap()[0]
            .get_features()
            .with_context(|| "Failed to get features for vhost net")?;
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

        let mut locked_config = self.config_space.lock().unwrap();

        let queue_pairs = self.net_cfg.queues / 2;
        if self.net_cfg.mq
            && (VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
                .contains(&queue_pairs)
        {
            device_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
            device_features |= 1 << VIRTIO_NET_F_MQ;
            locked_config.max_virtqueue_pairs = queue_pairs;
        }

        if let Some(mac) = &self.net_cfg.mac {
            device_features |= build_device_config_space(&mut locked_config, mac);
        }

        self.base.device_features = device_features;
        self.vhost_features = vhost_features;

        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config_space = self.config_space.lock().unwrap();
        read_config_default(config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let driver_features = self.base.driver_features;
        let mut config_space = self.config_space.lock().unwrap();
        let config_slice = config_space.as_mut_bytes();

        if !virtio_has_feature(driver_features, VIRTIO_NET_F_CTRL_MAC_ADDR)
            && !virtio_has_feature(driver_features, VIRTIO_F_VERSION_1)
            && offset == 0
            && data_len == MAC_ADDR_LEN
            && *data != config_slice[0..data_len]
        {
            config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);
        }

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
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = self.base.queues.clone();
        let queue_num = queues.len();
        let driver_features = self.base.driver_features;
        if (driver_features & 1 << VIRTIO_NET_F_CTRL_VQ != 0) && (queue_num % 2 != 0) {
            let ctrl_queue = queues[queue_num - 1].clone();
            let ctrl_queue_evt = queue_evts[queue_num - 1].clone();
            let ctrl_info = Arc::new(Mutex::new(CtrlInfo::new(self.config_space.clone())));

            let ctrl_handler = NetCtrlHandler {
                ctrl: CtrlVirtio::new(ctrl_queue, ctrl_queue_evt, ctrl_info),
                mem_space,
                interrupt_cb: interrupt_cb.clone(),
                driver_features,
                device_broken: self.base.broken.clone(),
                taps: None,
            };

            let notifiers =
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler)));
            register_event_helper(
                notifiers,
                self.net_cfg.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
        }

        let queue_pairs = queue_num / 2;
        for index in 0..queue_pairs {
            let mut host_notifies = Vec::new();
            let backend = match &self.backends {
                None => return Err(anyhow!("Failed to get backend for vhost net")),
                Some(backends) => backends
                    .get(index)
                    .with_context(|| format!("Failed to get index {} vhost backend", index))?,
            };

            backend
                .set_features(self.vhost_features)
                .with_context(|| "Failed to set features for vhost net")?;
            backend
                .set_mem_table()
                .with_context(|| "Failed to set mem table for vhost net")?;

            for queue_index in 0..2 {
                let queue_mutex = queues[index * 2 + queue_index].clone();
                let queue = queue_mutex.lock().unwrap();
                let actual_size = queue.vring.actual_size();
                let queue_config = queue.vring.get_queue_config();

                backend
                    .set_vring_num(queue_index, actual_size)
                    .with_context(|| {
                        format!(
                            "Failed to set vring num for vhost net, index: {} size: {}",
                            queue_index, actual_size,
                        )
                    })?;
                backend
                    .set_vring_addr(&queue_config, queue_index, 0)
                    .with_context(|| {
                        format!(
                            "Failed to set vring addr for vhost net, index: {}",
                            queue_index,
                        )
                    })?;
                backend.set_vring_base(queue_index, 0).with_context(|| {
                    format!(
                        "Failed to set vring base for vhost net, index: {}",
                        queue_index,
                    )
                })?;
                backend
                    .set_vring_kick(queue_index, queue_evts[index * 2 + queue_index].clone())
                    .with_context(|| {
                        format!(
                            "Failed to set vring kick for vhost net, index: {}",
                            index * 2 + queue_index,
                        )
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
                        format!(
                            "Failed to set vring call for vhost net, index: {}",
                            queue_index,
                        )
                    })?;

                let tap = match &self.taps {
                    None => bail!("Failed to get tap for vhost net"),
                    Some(taps) => taps[index].clone(),
                };
                backend
                    .set_backend(queue_index, tap.file.as_raw_fd())
                    .with_context(|| {
                        format!(
                            "Failed to set tap device for vhost net, index: {}",
                            queue_index,
                        )
                    })?;
            }

            if self.call_events.is_empty() {
                let handler = VhostIoHandler {
                    interrupt_cb: interrupt_cb.clone(),
                    host_notifies,
                    device_broken: self.base.broken.clone(),
                };
                let notifiers =
                    EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
                register_event_helper(
                    notifiers,
                    self.net_cfg.iothread.as_ref(),
                    &mut self.base.deactivate_evts,
                )?;
            }
        }
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(
            self.net_cfg.iothread.as_ref(),
            &mut self.base.deactivate_evts,
        )?;
        self.call_events.clear();

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let queue_pairs = self.net_cfg.queues / 2;
        for index in 0..queue_pairs as usize {
            let backend = match &self.backends {
                None => return Err(anyhow!("Failed to get backend for vhost net")),
                Some(backends) => backends
                    .get(index)
                    .with_context(|| format!("Failed to get index {} vhost backend", index))?,
            };

            // 2 queues: rx and tx.
            for queue_index in 0..2 {
                backend.set_backend(queue_index, -1)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use address_space::*;
    use machine_manager::config::DEFAULT_VIRTQUEUE_SIZE;

    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;

    fn vhost_address_space_init() -> Arc<AddressSpace> {
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
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
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
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
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
        vhost_net.base.device_features = 0;
        let page: u32 = 0x0;
        let value: u32 = 0xff;
        vhost_net.set_driver_features(page, value);
        assert_eq!(vhost_net.driver_features(page) as u64, 0_u64);
        let new_page = vhost_net.device_features(page);
        assert_eq!(new_page, page);

        vhost_net.base.device_features = 0xffff_ffff_ffff_ffff;
        let page: u32 = 0x0;
        let value: u32 = 0xff;
        vhost_net.set_driver_features(page, value);
        assert_eq!(vhost_net.driver_features(page) as u64, 0xff_u64);
        let new_page = vhost_net.device_features(page);
        assert_ne!(new_page, page);

        // test for read/write_config
        let len = vhost_net.config_space.lock().unwrap().as_bytes().len() as u64;
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
        assert_eq!(vhost_net.read_config(offset, &mut read_data).is_ok(), false);
    }
}
