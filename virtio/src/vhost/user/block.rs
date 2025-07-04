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

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use vmm_sys_util::eventfd::EventFd;

use super::client::VhostUserClient;
use crate::vhost::VhostOps;
use crate::VhostUser::client::{
    VhostBackendType, VHOST_USER_PROTOCOL_F_CONFIG, VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD,
    VHOST_USER_PROTOCOL_F_MQ,
};
use crate::VhostUser::listen_guest_notifier;
use crate::VhostUser::message::VHOST_USER_F_PROTOCOL_FEATURES;
use crate::{
    check_config_space_rw, read_config_default, virtio_has_feature, VirtioBase, VirtioBlkConfig,
    VirtioDevice, VirtioInterrupt, VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH,
    VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX,
    VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_WRITE_ZEROES, VIRTIO_F_VERSION_1, VIRTIO_TYPE_BLOCK,
};
use address_space::AddressSpace;
use machine_manager::config::{
    get_chardev_socket_path, get_pci_df, valid_block_device_virtqueue_size, valid_id,
    ChardevConfig, MAX_VIRTIO_QUEUE,
};
use machine_manager::event_loop::unregister_event_helper;
use util::byte_code::ByteCode;
use util::gen_base_func;

#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct VhostUserBlkDevConfig {
    #[arg(long, value_parser = ["vhost-user-blk-device", "vhost-user-blk-pci"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, alias = "num-queues", value_parser = clap::value_parser!(u16).range(1..=MAX_VIRTIO_QUEUE as i64))]
    pub num_queues: Option<u16>,
    #[arg(long)]
    pub chardev: String,
    #[arg(long, alias = "queue-size", default_value = "256", value_parser = valid_block_device_virtqueue_size)]
    pub queue_size: u16,
    #[arg(long)]
    pub bootindex: Option<u8>,
}

pub struct Block {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the block device.
    blk_cfg: VhostUserBlkDevConfig,
    /// Configuration of the vhost user blk's socket chardev.
    chardev_cfg: ChardevConfig,
    /// Config space of the block device.
    config_space: VirtioBlkConfig,
    /// System address space.
    mem_space: Arc<AddressSpace>,
    /// Vhost user client
    client: Option<Arc<Mutex<VhostUserClient>>>,
    /// Whether irqfd can be used.
    pub enable_irqfd: bool,
    /// Vhost user protocol features.
    protocol_features: u64,
}

impl Block {
    pub fn new(
        cfg: &VhostUserBlkDevConfig,
        chardev_cfg: ChardevConfig,
        mem_space: &Arc<AddressSpace>,
    ) -> Self {
        let queue_num = cfg.num_queues.unwrap_or(1) as usize;
        let queue_size = cfg.queue_size;

        Block {
            base: VirtioBase::new(VIRTIO_TYPE_BLOCK, queue_num, queue_size),
            blk_cfg: cfg.clone(),
            chardev_cfg,
            config_space: Default::default(),
            mem_space: mem_space.clone(),
            client: None,
            enable_irqfd: false,
            protocol_features: 0_u64,
        }
    }

    /// Connect with spdk and register update event.
    fn init_client(&mut self) -> Result<()> {
        let socket_path = get_chardev_socket_path(self.chardev_cfg.clone())?;
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
}

impl VirtioDevice for Block {
    gen_base_func!(virtio_base, virtio_base_mut, VirtioBase, base);

    fn realize(&mut self) -> Result<()> {
        self.init_client()?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        let locked_client = self.client.as_ref().unwrap().lock().unwrap();
        let features = locked_client
            .get_features()
            .with_context(|| "Failed to get features for vhost-user blk")?;

        if virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES) {
            let protocol_features = locked_client
                .get_protocol_features()
                .with_context(|| "Failed to get protocol features for vhost-user blk")?;
            let supported_protocol_features = 1 << VHOST_USER_PROTOCOL_F_MQ
                | 1 << VHOST_USER_PROTOCOL_F_CONFIG
                | 1 << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD;
            self.protocol_features = supported_protocol_features & protocol_features;
            locked_client
                .set_protocol_features(self.protocol_features)
                .with_context(|| "Failed to set protocol features for vhost-user blk")?;

            if virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_CONFIG)) {
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

            if virtio_has_feature(protocol_features, u32::from(VHOST_USER_PROTOCOL_F_MQ)) {
                let max_queue_num = locked_client
                    .get_max_queue_num()
                    .with_context(|| "Failed to get queue num for vhost-user blk")?;
                if self.queue_num() > max_queue_num as usize {
                    bail!(
                        "Exceed the max queue num that spdk supported ({} queues)",
                        max_queue_num
                    );
                }

                if self.blk_cfg.num_queues.unwrap_or(1) > 1 {
                    self.config_space.num_queues = self.blk_cfg.num_queues.unwrap_or(1);
                }
            } else if self.blk_cfg.num_queues.unwrap_or(1) > 1 {
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
            | 1_u64 << VIRTIO_BLK_F_SEG_MAX
            | 1_u64 << VIRTIO_BLK_F_RO;
        if self.blk_cfg.num_queues.unwrap_or(1) > 1 {
            self.base.device_features |= 1_u64 << VIRTIO_BLK_F_MQ;
        }
        self.base.device_features &= features;

        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        read_config_default(self.config_space.as_bytes(), offset, data)
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        check_config_space_rw(self.config_space.as_bytes(), offset, data)?;

        let offset = offset as usize;
        let end = offset + data.len();
        let config_slice = self.config_space.as_mut_bytes();
        config_slice[offset..end].copy_from_slice(data);

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
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };
        client.features = self.base.driver_features;
        client.protocol_features = self.protocol_features;
        client.set_queues(&self.base.queues);
        client.set_queue_evts(&queue_evts);

        if !self.enable_irqfd {
            let queue_num = self.base.queues.len();
            listen_guest_notifier(&mut self.base, &mut client, None, queue_num, interrupt_cb)?;
        }

        client.activate_vhost_user()?;

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        if let Some(client) = &self.client {
            client.lock().unwrap().reset_vhost_user(false);
        }
        unregister_event_helper(None, &mut self.base.deactivate_evts)?;
        Ok(())
    }

    fn unrealize(&mut self) -> Result<()> {
        self.client
            .as_ref()
            .with_context(|| "Failed to get client when stopping event")?
            .lock()
            .unwrap()
            .delete_event()
            .with_context(|| "Failed to delete vhost-user blk event")?;
        self.client = None;
        Ok(())
    }

    fn set_guest_notifiers(&mut self, queue_evts: &[Arc<EventFd>]) -> Result<()> {
        self.enable_irqfd = true;
        match &self.client {
            Some(client) => client.lock().unwrap().set_call_events(queue_evts),
            None => return Err(anyhow!("Failed to get client for vhost-user blk")),
        };

        Ok(())
    }
}
