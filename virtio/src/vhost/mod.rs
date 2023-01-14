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

pub mod kernel;
pub mod user;

use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use super::{Queue, QueueConfig};
use anyhow::Result;

/// Vhost vring call notify structure.
pub struct VhostNotify {
    /// Used to register in vhost kernel, when virtio queue have io request will notify to vhost.
    pub notify_evt: Arc<EventFd>,
    /// The related virtio queue.
    pub queue: Arc<Mutex<Queue>>,
}

pub trait VhostOps {
    /// Set the current process as the (exclusive) owner of file descriptor
    /// of the vhost backend. This must be run before any other vhost commands.
    fn set_owner(&self) -> Result<()>;

    /// Give up ownership, reset the device. Add calling `set_owner` function
    /// later is permitted.
    fn reset_owner(&self) -> Result<()>;

    /// Get a bitmask of supported vhost specific features.
    fn get_features(&self) -> Result<u64>;

    /// Set the vhost backend supported vhost specific features. This should be
    /// a subset of supported features from VHOST_GET_FEATURES.
    ///
    /// # Arguments
    /// * `features` - Bitmask of features to set.
    fn set_features(&self, features: u64) -> Result<()>;

    /// Set memory layout.
    fn set_mem_table(&self) -> Result<()>;

    /// Set number of descriptors in ring. This parameter can not be modified
    /// while ring is running (bound to a device).
    ///
    /// # Arguments
    /// * `queue_idx` - Index of the queue to set.
    /// * `num` - Number of descriptors in the virtqueue.
    fn set_vring_num(&self, queue_idx: usize, num: u16) -> Result<()>;

    /// Set addresses for the vring.
    ///
    /// # Arguments
    /// * `config` - queue configuration.
    fn set_vring_addr(&self, queue: &QueueConfig, index: usize, flags: u32) -> Result<()>;

    /// Set base value where queue looks for available descriptors.
    ///
    /// # Arguments
    /// * `queue_idx` - Index of the queue to set.
    /// * `last_avail_idx` - Index of the available descriptor.
    fn set_vring_base(&self, queue_idx: usize, last_avail_idx: u16) -> Result<()>;

    /// Get address for the vring.
    ///
    /// # Arguments
    /// * `queue_idx` - Index of the queue to get.
    fn get_vring_base(&self, queue_idx: usize) -> Result<u16>;

    /// Set eventfd to signal when buffers have been used.
    ///
    /// # Arguments
    /// * `queue_idx` - Index of the queue to modify.
    /// * `fd` - EventFd to trigger.
    fn set_vring_call(&self, queue_idx: usize, fd: Arc<EventFd>) -> Result<()>;

    /// Set eventfd to poll for added buffers.
    ///
    /// # Arguments
    /// * `queue_idx` - Index of the queue to modify.
    /// * `fd` - EventFd that will be signaled from guest.
    fn set_vring_kick(&self, queue_idx: usize, fd: Arc<EventFd>) -> Result<()>;

    /// Set the status of ring.
    ///
    /// # Arguments
    /// * `_queue_idx` - Index of the queue to set.
    /// * `_status` - Status of the virtqueue.
    fn set_vring_enable(&self, _queue_idx: usize, _status: bool) -> Result<()> {
        Ok(())
    }
}
