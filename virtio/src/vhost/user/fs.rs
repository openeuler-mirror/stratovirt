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

// The num of high priority queue
const VIRIOT_FS_HIGH_PRIO_QUEUE_NUM: usize = 1;
// The num of request queue
const VIRTIO_FS_REQ_QUEUES_NUM: usize = 1;
// The size of queue for virtio fs
const VIRTIO_FS_QUEUE_SIZE: u16 = 128;

use crate::VirtioError;
use std::cmp;
use std::io::Write;
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use address_space::AddressSpace;
use machine_manager::{
    config::{FsConfig, MAX_TAG_LENGTH},
    event_loop::EventLoop,
};
use util::byte_code::ByteCode;
use util::loop_context::EventNotifierHelper;
use util::num_ops::read_u32;

use super::super::super::{Queue, VirtioDevice, VIRTIO_TYPE_FS};
use super::super::VhostOps;
use super::VhostUserClient;
use crate::VirtioInterrupt;
use anyhow::{anyhow, Context, Result};

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct VirtioFsConfig {
    tag: [u8; MAX_TAG_LENGTH],
    num_request_queues: u32,
}

impl Default for VirtioFsConfig {
    fn default() -> Self {
        VirtioFsConfig {
            tag: [0; MAX_TAG_LENGTH],
            num_request_queues: 0,
        }
    }
}

impl ByteCode for VirtioFsConfig {}

pub struct Fs {
    fs_cfg: FsConfig,
    config: VirtioFsConfig,
    client: Option<Arc<Mutex<VhostUserClient>>>,
    avail_features: u64,
    acked_features: u64,
    mem_space: Arc<AddressSpace>,
    /// The notifier events from host.
    call_events: Vec<EventFd>,
}

impl Fs {
    pub fn new(fs_cfg: FsConfig, mem_space: Arc<AddressSpace>) -> Self {
        Fs {
            fs_cfg,
            config: VirtioFsConfig::default(),
            client: None,
            avail_features: 0_u64,
            acked_features: 0_u64,
            mem_space,
            call_events: Vec::<EventFd>::new(),
        }
    }
}

impl VirtioDevice for Fs {
    fn realize(&mut self) -> Result<()> {
        let tag_bytes_vec = self.fs_cfg.tag.clone().into_bytes();
        self.config.tag[..tag_bytes_vec.len()].copy_from_slice(tag_bytes_vec.as_slice());
        self.config.num_request_queues = VIRTIO_FS_REQ_QUEUES_NUM as u32;

        let queues_num = VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM;
        let client = VhostUserClient::new(&self.mem_space, &self.fs_cfg.sock, queues_num as u64)
            .with_context(|| {
                "Failed to create the client which communicates with the server for virtio fs"
            })?;
        let client = Arc::new(Mutex::new(client));

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(client.clone()),
            None,
        )
        .with_context(|| "Failed to update event for client sock")?;
        self.avail_features = client
            .lock()
            .unwrap()
            .get_features()
            .with_context(|| "Failed to get features for virtio fs")?;
        self.client = Some(client);

        Ok(())
    }

    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_FS as u32
    }

    fn queue_num(&self) -> usize {
        VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM
    }

    fn queue_size(&self) -> u16 {
        VIRTIO_FS_QUEUE_SIZE
    }

    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.avail_features, features_select)
    }

    fn set_driver_features(&mut self, page: u32, value: u32) {
        self.acked_features = self.checked_driver_features(page, value);
    }

    /// Get driver features by guest.
    fn get_driver_features(&self, features_select: u32) -> u32 {
        read_u32(self.acked_features, features_select)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let config_slice = self.config.as_bytes();
        let config_size = config_slice.len() as u64;
        if offset >= config_size {
            return Err(anyhow!(VirtioError::DevConfigOverflow(offset, config_size)));
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_size) as usize])?;
        }

        Ok(())
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let config_slice = self.config.as_mut_bytes();
        let config_len = config_slice.len();
        if offset as usize + data_len > config_len {
            return Err(anyhow!(VirtioError::DevConfigOverflow(
                offset,
                config_len as u64
            )));
        }

        config_slice[(offset as usize)..(offset as usize + data_len)].copy_from_slice(data);

        Ok(())
    }

    fn activate(
        &mut self,
        _mem_space: Arc<AddressSpace>,
        _interrup_cb: Arc<VirtioInterrupt>,
        queues: &[Arc<Mutex<Queue>>],
        queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        let mut client = match &self.client {
            Some(client) => client.lock().unwrap(),
            None => return Err(anyhow!("Failed to get client for virtio fs")),
        };
        client.features = self.acked_features;
        client.set_queues(queues);
        client.set_queue_evts(&queue_evts);
        client.activate_vhost_user()?;
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
        }
        Ok(())
    }
}
