// Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
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

use crate::virtio_has_feature;
use std::cmp;
use std::io::Write;
use std::os::unix::prelude::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::config::NetworkInterfaceConfig;
use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::num_ops::read_u32;
use vmm_sys_util::eventfd::EventFd;

use super::super::super::{
    net::{build_device_config_space, CtrlInfo, VirtioNetState, MAC_ADDR_LEN},
    CtrlVirtio, NetCtrlHandler, Queue, VirtioDevice, VirtioInterrupt, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_VERSION_1, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN,
    VIRTIO_NET_F_CTRL_MAC_ADDR, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MQ, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_TYPE_NET,
};
use super::super::VhostOps;
use super::VhostUserClient;
use crate::error::VirtioError;
use anyhow::{anyhow, Context, Result};

/// Number of virtqueues.
const QUEUE_NUM_NET: usize = 2;

/// Network device structure.
pub struct Net {
    /// Configuration of the vhost user network device.
    net_cfg: NetworkInterfaceConfig,
    /// The status of net device.
    state: Arc<Mutex<VirtioNetState>>,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// The notifier events from host.
    call_events: Vec<EventFd>,
    /// EventFd for deactivate control Queue.
    deactivate_evts: Vec<RawFd>,
    /// Device is broken or not.
    broken: Arc<AtomicBool>,
}

impl Net {
    pub fn new(cfg: &NetworkInterfaceConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Net {
            net_cfg: cfg.clone(),
            state: Arc::new(Mutex::new(VirtioNetState::default())),
            mem_space: mem_space.clone(),
            client: None,
            call_events: Vec::<EventFd>::new(),
            deactivate_evts: Vec::new(),
            broken: Arc::new(AtomicBool::new(false)),
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
            None => return Err(anyhow!("Failed to get client when stoping event")),
        };
        if ((self.state.lock().unwrap().driver_features & (1 << VIRTIO_NET_F_CTRL_VQ)) != 0)
            && self.net_cfg.mq
        {
            unregister_event_helper(self.net_cfg.iothread.as_ref(), &mut self.deactivate_evts)?;
        }

        Ok(())
    }

    fn clean_up(&mut self) -> Result<()> {
        self.delete_event()?;
        let mut locked_state = self.state.lock().unwrap();
        locked_state
            .as_mut_bytes()
            .copy_from_slice(&[0_u8; std::mem::size_of::<VirtioNetState>()]);
        self.client = None;

        Ok(())
    }
}

impl VirtioDevice for Net {
    /// Realize vhost user network device.
    fn realize(&mut self) -> Result<()> {
        let socket_path = self
            .net_cfg
            .socket_path
            .as_ref()
            .map(|path| path.to_string())
            .with_context(|| "vhost-user: socket path is not found")?;
        let client = VhostUserClient::new(&self.mem_space, &socket_path, self.queue_num() as u64)
            .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user net"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;

        let mut locked_state = self.state.lock().unwrap();
        locked_state.device_features = client
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
        locked_state.device_features &= features;

        let queue_pairs = self.net_cfg.queues / 2;
        if self.net_cfg.mq
            && (VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN..=VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX)
                .contains(&queue_pairs)
        {
            locked_state.device_features |= 1 << VIRTIO_NET_F_CTRL_VQ;
            locked_state.device_features |= 1 << VIRTIO_NET_F_MQ;
            locked_state.config_space.max_virtqueue_pairs = queue_pairs;
        }

        self.client = Some(client);

        if let Some(mac) = &self.net_cfg.mac {
            locked_state.device_features |=
                build_device_config_space(&mut locked_state.config_space, mac);
        }

        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_NET
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        if self.net_cfg.mq {
            // If support multi-queue, it should add 1 control queue.
            (self.net_cfg.queues + 1) as usize
        } else {
            QUEUE_NUM_NET
        }
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        self.net_cfg.queue_size
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.lock().unwrap().device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.state.lock().unwrap().driver_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.lock().unwrap().driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let locked_state = self.state.lock().unwrap();
        let config_slice = locked_state.config_space.as_bytes();
        let config_size = config_slice.len() as u64;
        if offset >= config_size {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_size)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_size) as usize])?;
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let mut locked_state = self.state.lock().unwrap();
        let driver_features = locked_state.driver_features;
        let config_slice = locked_state.config_space.as_mut_bytes();

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
        let driver_features = self.state.lock().unwrap().driver_features;
        if ((driver_features & (1 << VIRTIO_NET_F_CTRL_VQ)) != 0) && (queue_num % 2 != 0) {
            let ctrl_queue = queues[queue_num - 1].clone();
            let ctrl_queue_evt = queue_evts.remove(queue_num - 1);
            let ctrl_info = Arc::new(Mutex::new(CtrlInfo::new(self.state.clone())));

            let ctrl_handler = NetCtrlHandler {
                ctrl: CtrlVirtio::new(ctrl_queue, ctrl_queue_evt, ctrl_info),
                mem_space,
                interrupt_cb: interrupt_cb.clone(),
                driver_features,
                device_broken: self.broken.clone(),
            };

            let notifiers =
                EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(ctrl_handler)));
            register_event_helper(
                notifiers,
                self.net_cfg.iothread.as_ref(),
                &mut self.deactivate_evts,
            )?;
        }

        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user net")),
        };

        let features = driver_features & !(1 << VIRTIO_NET_F_MAC);
        client.features = features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);
        client.activate_vhost_user()?;
        self.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// Set guest notifiers for notifying the guest.
    fn set_guest_notifiers(&mut self, queue_evts: &[EventFd]) -> Result<()> {
        for fd in queue_evts.iter() {
            let cloned_evt_fd = fd.try_clone().unwrap();
            self.call_events.push(cloned_evt_fd);
        }

        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user net")),
        };

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.call_events.clear();
        self.clean_up()?;
        self.realize()
    }

    fn reset(&mut self) -> Result<()> {
        self.clean_up()?;
        self.realize()
    }

    fn unrealize(&mut self) -> Result<()> {
        self.delete_event()?;
        self.call_events.clear();
        self.client = None;

        Ok(())
    }

    fn has_control_queue(&mut self) -> bool {
        virtio_has_feature(
            self.state.lock().unwrap().device_features,
            VIRTIO_NET_F_CTRL_VQ,
        )
    }
}
