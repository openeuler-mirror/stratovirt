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

use crate::VirtioError;
use anyhow::{anyhow, bail, Context, Result};
use std::cmp;
use std::io::Write;
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::config::BlkDevConfig;
use machine_manager::event_loop::EventLoop;
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::num_ops::read_u32;
use vmm_sys_util::eventfd::EventFd;

use super::client::VhostUserClient;
use crate::block::VirtioBlkConfig;
use crate::vhost::VhostOps;
use crate::VhostUser::client::{VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ};
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    virtio_has_feature, BlockState, VirtioDevice, VirtioInterrupt, VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO,
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES,
    VIRTIO_F_RING_PACKED, VIRTIO_F_VERSION_1, VIRTIO_TYPE_BLOCK,
};

/// Size of each virtqueue.
const QUEUE_SIZE_BLK: u16 = 256;

pub struct Block {
    /// Configuration of the block device.
    blk_cfg: BlkDevConfig,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Status of block device.
    state: BlockState,
    /// Vhost user client
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// The notifier events from host.
    call_events: Vec<EventFd>,
}

impl Block {
    pub fn new(cfg: &BlkDevConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Block {
            blk_cfg: cfg.clone(),
            state: BlockState::default(),
            mem_space: mem_space.clone(),
            client: None,
            call_events: Vec::<EventFd>::new(),
        }
    }

    fn delete_event(&mut self) -> Result<()> {
        match &self.client {
            Some(client) => {
                client
                    .lock()
                    .unwrap()
                    .delete_event()
                    .with_context(|| "Failed to delete vhost-user blk event")?;
            }
            None => return Err(anyhow!("Failed to get client when stoping event")),
        };

        Ok(())
    }

    fn clean_up(&mut self) -> Result<()> {
        self.delete_event()?;
        self.state.config_space = VirtioBlkConfig::default();
        self.state.device_features = 0u64;
        self.state.driver_features = 0u64;
        self.client = None;

        Ok(())
    }

    /// Connect with spdk and register update event.
    fn init_client(&mut self) -> Result<()> {
        let socket_path = self
            .blk_cfg
            .socket_path
            .as_ref()
            .map(|path| path.to_string())
            .with_context(|| "vhost-user: socket path is not found")?;
        let client = VhostUserClient::new(&self.mem_space, &socket_path, self.queue_num() as u64)
            .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user blk"
        })?;
        let client = Arc::new(Mutex::new(client));
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(client.clone()),
            None,
        )
        .with_context(|| "Failed to update event for client sock")?;
        self.client = Some(client);
        Ok(())
    }

    /// Get config from spdk and setup config space.
    fn setup_device(&mut self) -> Result<()> {
        let client = self.client.as_ref().unwrap();
        let feature = self.state.device_features;

        if virtio_has_feature(feature, VHOST_USER_F_PROTOCOL_FEATURES) {
            let protocol_feature = client
                .lock()
                .unwrap()
                .get_protocol_features()
                .with_context(|| "Failed to get protocol features for vhost-user blk")?;

            if virtio_has_feature(protocol_feature, VHOST_USER_PROTOCOL_F_CONFIG as u32) {
                let config = client
                    .lock()
                    .unwrap()
                    .get_virtio_blk_config()
                    .with_context(|| "Failed to get config for vhost-user blk")?;
                self.state.config_space = config;
            } else {
                bail!(
                    "Failed to get config, spdk doesn't support, spdk protocol feature: {:#b}",
                    protocol_feature
                );
            }

            if virtio_has_feature(protocol_feature, VHOST_USER_PROTOCOL_F_MQ as u32) {
                let max_queue_num = client
                    .lock()
                    .unwrap()
                    .get_max_queue_num()
                    .with_context(|| "Failed to get queue num for vhost-user blk")?;
                if self.queue_num() > max_queue_num as usize {
                    bail!(
                        "Exceed the max queue num that spdk supported ({} queues)",
                        max_queue_num
                    );
                }

                if self.blk_cfg.queues > 1 {
                    self.state.config_space.num_queues = self.blk_cfg.queues;
                }
            } else if self.blk_cfg.queues > 1 {
                bail!(
                    "spdk doesn't support multi queue, spdk protocol feature: {:#b}",
                    protocol_feature
                );
            }
        }
        client
            .lock()
            .unwrap()
            .set_virtio_blk_config(self.state.config_space)
            .with_context(|| "Failed to set config for vhost-user blk")?;
        Ok(())
    }

    /// Negotiate feature with spdk.
    fn negotiate_feature(&mut self) -> Result<()> {
        let client = self.client.as_ref().unwrap();

        let mut feature = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for vhost-user blk")?;

        feature |= 1_u64 << VIRTIO_F_VERSION_1;
        feature |= 1_u64 << VIRTIO_BLK_F_SIZE_MAX;
        feature |= 1_u64 << VIRTIO_BLK_F_TOPOLOGY;
        feature |= 1_u64 << VIRTIO_BLK_F_BLK_SIZE;
        feature |= 1_u64 << VIRTIO_BLK_F_FLUSH;
        feature |= 1_u64 << VIRTIO_BLK_F_DISCARD;
        feature |= 1_u64 << VIRTIO_BLK_F_WRITE_ZEROES;
        feature |= 1_u64 << VIRTIO_BLK_F_SEG_MAX;
        feature &= !(1_u64 << VIRTIO_F_RING_PACKED);

        if self.blk_cfg.read_only {
            feature |= 1_u64 << VIRTIO_BLK_F_RO;
        };
        if self.blk_cfg.queues > 1 {
            feature |= 1_u64 << VIRTIO_BLK_F_MQ;
        }

        self.state.device_features = feature;

        client
            .lock()
            .unwrap()
            .set_features(feature)
            .with_context(|| "Failed to set features for vhost-user blk")?;
        Ok(())
    }
}

impl VirtioDevice for Block {
    /// Realize vhost user blk pci device.
    fn realize(&mut self) -> Result<()> {
        self.init_client()?;
        self.negotiate_feature()?;
        self.setup_device()?;
        Ok(())
    }

    /// Get the virtio device type, refer to Virtio Spec.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_BLOCK
    }

    /// Get the count of virtio device queues.
    fn queue_num(&self) -> usize {
        self.blk_cfg.queues as usize
    }

    /// Get the queue size of virtio device.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_BLK
    }

    /// Get device features from host.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.device_features, features_select)
    }

    /// Set driver features by guest.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.state.driver_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.state.driver_features, features_select)
    }

    /// Read data of config from guest.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let offset = offset as usize;
        let config_slice = self.state.config_space.as_bytes();
        let config_len = config_slice.len();
        if offset >= config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset as u64,
                config_len as u64
            )));
        }
        if let Some(end) = offset.checked_add(data.len()) {
            data.write_all(&config_slice[offset..cmp::min(end, config_len)])?;
        } else {
            bail!("Failed to read config from guest for vhost user blk pci, config space address overflow.")
        }

        Ok(())
    }

    /// Write data to config from guest.
    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let offset = offset as usize;
        let config_slice = self.state.config_space.as_mut_bytes();
        let config_len = config_slice.len();
        if let Some(end) = offset.checked_add(data.len()) {
            if end > config_len {
                return Err(anyhow!(VirtioError::DevConfigOverflow(
                    offset as u64,
                    config_len as u64
                )));
            }
            config_slice[offset..end].copy_from_slice(data);
        } else {
            bail!("Failed to write config to guest for vhost user blk pci, config space address overflow.")
        }

        Ok(())
    }

    /// Activate device.
    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        _interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<crate::Queue>>],
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };
        client.features = self.state.driver_features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);
        client.activate_vhost_user()?;
        Ok(())
    }

    /// Deactivate device.
    fn deactivate(&mut self) -> Result<()> {
        self.call_events.clear();
        self.clean_up()?;
        self.realize()
    }

    /// Reset device.
    fn reset(&mut self) -> Result<()> {
        self.clean_up()?;
        self.realize()
    }

    /// Unrealize device.
    fn unrealize(&mut self) -> Result<()> {
        self.delete_event()?;
        self.call_events.clear();
        self.client = None;
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
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };

        Ok(())
    }
}
