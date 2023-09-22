// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{anyhow, Context, Result};
use vmm_sys_util::eventfd::EventFd;

use super::super::VhostOps;
use super::{listen_guest_notifier, VhostBackendType, VhostUserClient};
use crate::{
    device::net::{build_device_config_space, CtrlInfo, MAC_ADDR_LEN},
    read_config_default, virtio_has_feature, CtrlVirtio, NetCtrlHandler, VirtioBase, VirtioDevice,
    VirtioInterrupt, VirtioNetConfig, VIRTIO_F_RING_EVENT_IDX, VIRTIO_F_VERSION_1,
    VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN, VIRTIO_NET_F_CTRL_MAC_ADDR,
    VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MQ,
    VIRTIO_NET_F_MRG_RXBUF, VIRTIO_TYPE_NET,
};
use address_space::AddressSpace;
use machine_manager::config::NetworkInterfaceConfig;
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;

/// Network device structure.
pub struct Net {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the vhost user network device.
    net_cfg: NetworkInterfaceConfig,
    /// Virtio net configurations.
    config_space: Arc<Mutex<VirtioNetConfig>>,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client.
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// Whether irqfd can be used.
    enable_irqfd: bool,
}

impl Net {
    pub fn new(cfg: &NetworkInterfaceConfig, mem_space: &Arc<AddressSpace>) -> Self {
        let queue_num = if cfg.mq {
            // If support multi-queue, it should add 1 control queue.
            (cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        };
        let queue_size = cfg.queue_size;

        Net {
            base: VirtioBase::new(VIRTIO_TYPE_NET, queue_num, queue_size),
            net_cfg: cfg.clone(),
            config_space: Default::default(),
            mem_space: mem_space.clone(),
            client: None,
            enable_irqfd: false,
        }
    }

    fn delete_event(&mut self) -> Result<()> {
        match &self.client {
            Some(client) => {
                client
                    .lock()
                    .unwrap()
                    .delete_event()
                    .with_context(|| "Failed to delete vhost-user net event")?;
            }
            None => return Err(anyhow!("Failed to get client when stopping event")),
        };
        if !self.base.deactivate_evts.is_empty() {
            unregister_event_helper(
                self.net_cfg.iothread.as_ref(),
                &mut self.base.deactivate_evts,
            )?;
        }

        Ok(())
    }

    fn clean_up(&mut self) -> Result<()> {
        self.delete_event()?;
        self.base.device_features = 0;
        self.base.driver_features = 0;
        self.base.broken.store(false, Ordering::SeqCst);
        self.config_space = Default::default();
        self.client = None;

        Ok(())
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
        let socket_path = self
            .net_cfg
            .socket_path
            .as_ref()
            .with_context(|| "vhost-user: socket path is not found")?;
        let client = VhostUserClient::new(
            &self.mem_space,
            socket_path,
            self.queue_num() as u64,
            VhostBackendType::TypeNet,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user net"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);

        self.init_config_features()?;

        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let client = self.client.as_ref().unwrap();
        self.base.device_features = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for vhost-user net")?;

        let features = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_NET_F_MRG_RXBUF
            | 1 << VIRTIO_F_RING_EVENT_IDX;
        self.base.device_features &= features;

        let mut locked_config = self.config_space.lock().unwrap();

        let queue_pairs = self.net_cfg.queues / 2;
        if self.net_cfg.mq
            && (VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
                .contains(&queue_pairs)
        {
            self.base.device_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
            self.base.device_features |= 1 << VIRTIO_NET_F_MQ;
            locked_config.max_virtqueue_pairs = queue_pairs;
        }

        if let Some(mac) = &self.net_cfg.mac {
            self.base.device_features |= build_device_config_space(&mut locked_config, mac);
        }

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let config_space = self.config_space.lock().unwrap();
        read_config_default(config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let mut config_space = self.config_space.lock().unwrap();
        let driver_features = self.base.driver_features;
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

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user net")),
        };

        let queues = self.base.queues.clone();
        let queue_num = queues.len();
        let mut call_fds_num = queue_num;
        let driver_features = self.base.driver_features;
        let has_control_queue =
            (driver_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0) && (queue_num % 2 != 0);
        if has_control_queue {
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

            call_fds_num -= 1;
            client.set_queues(&queues[..(queue_num - 1)]);
            client.set_queue_evts(&queue_evts[..(queue_num - 1)]);
        } else {
            client.set_queues(&queues);
            client.set_queue_evts(&queue_evts);
        }
        client.features = driver_features & !(1 << VIRTIO_NET_F_MAC);

        if !self.enable_irqfd {
            listen_guest_notifier(
                &mut self.base,
                &mut client,
                self.net_cfg.iothread.as_ref(),
                call_fds_num,
                interrupt_cb,
            )?;
        }
        client.activate_vhost_user()?;
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        self.enable_irqfd = true;
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user net")),
        };

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.clean_up()?;
        self.realize()
    }

    fn reset(&mut self) -> Result<()> {
        self.clean_up()?;
        self.realize()
    }

    fn unrealize(&mut self) -> Result<()> {
        self.delete_event()?;
        self.client = None;

        Ok(())
    }

    fn has_control_queue(&self) -> bool {
        virtio_has_feature(self.base.device_features, VIRTIO_NET_F_CTRL_VQ)
    }
}
