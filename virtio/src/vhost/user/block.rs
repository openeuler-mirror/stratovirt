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

use anyhow::{anyhow, bail, Context, Result};
use std::cmp;
use std::io::Write;
use std::sync::{Arc, Mutex};

use address_space::AddressSpace;
use machine_manager::config::BlkDevConfig;
use util::byte_code::ByteCode;
use vmm_sys_util::eventfd::EventFd;

use super::client::VhostUserClient;
use crate::vhost::VhostOps;
use crate::VhostUser::client::{
    VhostBackendType, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_MQ,
};
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    virtio_has_feature, VirtioBase, VirtioBlkConfig, VirtioDevice, VirtioError, VirtioInterrupt,
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_TOPOLOGY,
    VIRTIO_BLK_F_WRITE_ZEROES, VIRTIO_F_VERSION_1, VIRTIO_TYPE_BLOCK,
};

pub struct Block {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the block device.
    blk_cfg: BlkDevConfig,
    /// Config space of the block device.
    config_space: VirtioBlkConfig,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client
    client: Option<Arc<Mutex<VhostUserClient>>>,
}

impl Block {
    pub fn new(cfg: &BlkDevConfig, mem_space: &Arc<AddressSpace>) -> Self {
        Block {
            base: VirtioBase::new(VIRTIO_TYPE_BLOCK),
            blk_cfg: cfg.clone(),
            config_space: Default::default(),
            mem_space: mem_space.clone(),
            client: None,
        }
    }

    fn delete_event(&mut self) -> Result<()> {
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when stopping event")?
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete vhost-user blk event")?;
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
        let client = VhostUserClient::new(
            &self.mem_space,
            &socket_path,
            self.queue_num() as u64,
            VhostBackendType::TypeBlock,
        )
        .with_context(|| {
            "Failed to create the client which communicates with the server for vhost-user blk"
        })?;
        let client = Arc::new(Mutex::new(client));
        VhostUserClient::add_event(&client)?;
        self.client = Some(client);
        Ok(())
    }

    /// Negotiate features with spdk.
    fn negotiate_features(&mut self) -> Result<()> {
        let locked_client = self.client.as_ref().unwrap().lock().unwrap();
        let features = locked_client
            .get_features()
            .with_context(|| "Failed to get features for vhost-user blk")?;

        if virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
            let protocol_features = locked_client
                .get_protocol_features()
                .with_context(|| "Failed to get protocol features for vhost-user blk")?;
            let supported_protocol_features =
                1 << VHOST_USER_PROTOCOL_F_MQ | 1 << VHOST_USER_PROTOCOL_F_CONFIG;
            locked_client
                .set_protocol_features(supported_protocol_features & protocol_features)
                .with_context(|| "Failed to set protocol features for vhost-user blk")?;

            if virtio_has_feature(protocol_features, VHOST_USER_PROTOCOL_F_CONFIG as u32) {
                let config = locked_client
                    .get_virtio_blk_config()
                    .with_context(|| "Failed to get config for vhost-user blk")?;
                self.config_space = config;
            } else {
                bail!(
                    "Failed to get config, spdk doesn't support, spdk protocol features: {:#b}",
                    protocol_features
                );
            }

            if virtio_has_feature(protocol_features, VHOST_USER_PROTOCOL_F_MQ as u32) {
                let max_queue_num = locked_client
                    .get_max_queue_num()
                    .with_context(|| "Failed to get queue num for vhost-user blk")?;
                if self.queue_num() > max_queue_num as usize {
                    bail!(
                        "Exceed the max queue num that spdk supported ({} queues)",
                        max_queue_num
                    );
                }

                if self.blk_cfg.queues > 1 {
                    self.config_space.num_queues = self.blk_cfg.queues;
                }
            } else if self.blk_cfg.queues > 1 {
                bail!(
                    "spdk doesn't support multi queue, spdk protocol features: {:#b}",
                    protocol_features
                );
            }
        } else {
            bail!("Bad spdk feature: {:#b}", features);
        }
        drop(locked_client);

        self.base.device_features = 1_u64 << VIRTIO_F_VERSION_1
            | 1_u64 << VIRTIO_BLK_F_SIZE_MAX
            | 1_u64 << VIRTIO_BLK_F_TOPOLOGY
            | 1_u64 << VIRTIO_BLK_F_BLK_SIZE
            | 1_u64 << VIRTIO_BLK_F_FLUSH
            | 1_u64 << VIRTIO_BLK_F_DISCARD
            | 1_u64 << VIRTIO_BLK_F_WRITE_ZEROES
            | 1_u64 << VIRTIO_BLK_F_SEG_MAX;
        if self.blk_cfg.read_only {
            self.base.device_features |= 1_u64 << VIRTIO_BLK_F_RO;
        };
        if self.blk_cfg.queues > 1 {
            self.base.device_features |= 1_u64 << VIRTIO_BLK_F_MQ;
        }
        self.base.device_features &= features;

        Ok(())
    }
}

impl VirtioDevice for Block {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        self.init_client()?;
        self.negotiate_features()?;

        Ok(())
    }

    fn queue_num(&self) -> usize {
        self.blk_cfg.queues as usize
    }

    fn queue_size_max(&self) -> u16 {
        self.blk_cfg.queue_size
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let offset = offset as usize;
        let config_slice = self.config_space.as_bytes();
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

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let offset = offset as usize;
        let config_slice = self.config_space.as_mut_bytes();
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

        self.client
            .as_ref()
            .with_context(|| "Failed to get client when writing config")?
            .lock()
            .unwrap()
            .set_virtio_blk_config(self.config_space)
            .with_context(|| "Failed to set config for vhost-user blk")?;

        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        _interrupt_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<crate::Queue>>],
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };
        client.features = self.base.driver_features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);
        client.activate_vhost_user()?;
        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when deactivating device")?
            .lock()
            .unwrap()
            .reset_vhost_user()?;
        self.delete_event()
    }

    fn unrealize(&mut self) -> Result<()> {
        self.delete_event()?;
        self.client = None;
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };

        Ok(())
    }
}
