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

mod split;

pub use split::*;

use std::sync::Arc;

use anyhow::{bail, Result};
use vmm_sys_util::eventfd::EventFd;

use address_space::{AddressSpace, GuestAddress, RegionCache};

/// Split Virtqueue.
pub const QUEUE_TYPE_SPLIT_VRING: u16 = 1;
/// Packed Virtqueue.
pub const QUEUE_TYPE_PACKED_VRING: u16 = 2;
/// Invalid queue vector num.
pub const INVALID_VECTOR_NUM: u16 = 0xFFFF;

/// This marks a buffer as continuing via the next field.
const VIRTQ_DESC_F_NEXT: u16 = 0x1;
/// This marks a buffer as write-only (otherwise read-only).
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
/// This means the buffer contains a list of buffer descriptors.
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

fn checked_offset_mem(
    mmio_space: &Arc<AddressSpace>,
    base: GuestAddress,
    offset: u64,
) -> Result<GuestAddress> {
    if !mmio_space.address_in_memory(base, offset) {
        bail!(
            "Invalid Address for queue: base 0x{:X}, size {}",
            base.raw_value(),
            offset
        );
    }
    Ok(base.unchecked_add(offset))
}

/// IO vector element which contains the information of a descriptor.
#[derive(Debug, Clone, Copy)]
pub struct ElemIovec {
    /// Guest address of descriptor.
    pub addr: GuestAddress,
    /// Length of descriptor.
    pub len: u32,
}

/// IO request element.
pub struct Element {
    /// Index of the descriptor in the table.
    pub index: u16,
    /// Number of descriptors.
    pub desc_num: u16,
    /// Vector to put host readable descriptors.
    pub out_iovec: Vec<ElemIovec>,
    /// Vector to put host writable descriptors.
    pub in_iovec: Vec<ElemIovec>,
}

impl Element {
    /// Create an IO request element.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of descriptor in the virqueue descriptor table.
    fn new(index: u16) -> Self {
        Element {
            index,
            desc_num: 0,
            out_iovec: Vec::new(),
            in_iovec: Vec::new(),
        }
    }

    pub fn iovec_size(iovec: &[ElemIovec]) -> u64 {
        let mut size: u64 = 0;
        for elem in iovec.iter() {
            size += elem.len as u64;
        }
        size
    }
}

/// Vring operations.
pub trait VringOps {
    /// Return true if the vring is enable by driver.
    fn is_enabled(&self) -> bool;

    /// Return true if the configuration of vring is valid.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    fn is_valid(&self, sys_mem: &Arc<AddressSpace>) -> bool;

    /// Assemble an IO request element with descriptors from the available vring.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `features` - Bit mask of features negotiated by the backend and the frontend.
    fn pop_avail(&mut self, sys_mem: &Arc<AddressSpace>, features: u64) -> Result<Element>;

    /// Rollback the entry which is pop from available queue by `pop_avail`.
    fn push_back(&mut self);

    /// Fill the used vring after processing the IO request.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `index` - Index of descriptor in the virqueue descriptor table.
    /// * `len` - Total length of the descriptor chain which was used (written to).
    fn add_used(&mut self, sys_mem: &Arc<AddressSpace>, index: u16, len: u32) -> Result<()>;

    /// Return true if guest needed to be notified.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `features` - Bit mask of features negotiated by the backend and the frontend.
    fn should_notify(&mut self, sys_mem: &Arc<AddressSpace>, features: u64) -> bool;

    /// Give guest a hint to suppress virtqueue notification.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `features` - Bit mask of features negotiated by the backend and the frontend.
    /// * `suppress` - Suppress virtqueue notification or not.
    fn suppress_queue_notify(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        features: u64,
        suppress: bool,
    ) -> Result<()>;

    /// Get the actual size of the vring.
    fn actual_size(&self) -> u16;

    /// Get the configuration of the vring.
    fn get_queue_config(&self) -> QueueConfig;

    /// The number of descriptor chains in the available ring.
    fn avail_ring_len(&mut self, sys_mem: &Arc<AddressSpace>) -> Result<u16>;

    /// Get the avail index of the vring.
    fn get_avail_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16>;

    /// Get the used index of the vring.
    fn get_used_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16>;

    /// Get the region cache information of the SplitVring.
    fn get_cache(&self) -> &Option<RegionCache>;

    /// Get the available bytes of the vring to read from or write to the guest
    fn get_avail_bytes(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        max_size: usize,
        is_in: bool,
    ) -> Result<usize>;
}

/// Virtio queue.
pub struct Queue {
    /// Vring structure.
    pub vring: Box<dyn VringOps + Send>,
}

impl Queue {
    /// Create a virtqueue.
    ///
    /// # Arguments
    ///
    /// * `queue_config` - Configuration of the vring.
    /// * `queue_type` - Type of virtqueue.
    pub fn new(queue_config: QueueConfig, queue_type: u16) -> Result<Self> {
        let vring: Box<dyn VringOps + Send> = match queue_type {
            QUEUE_TYPE_SPLIT_VRING => Box::new(SplitVring::new(queue_config)),
            _ => {
                bail!("Unsupported queue type {}", queue_type);
            }
        };

        Ok(Queue { vring })
    }

    /// Return true if the virtqueue is enabled by driver.
    pub fn is_enabled(&self) -> bool {
        self.vring.is_enabled()
    }

    /// Return true if the memory layout of the virqueue is valid.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    pub fn is_valid(&self, sys_mem: &Arc<AddressSpace>) -> bool {
        self.vring.is_valid(sys_mem)
    }
}

/// Virt Queue Notify EventFds
#[derive(Clone)]
pub struct NotifyEventFds {
    pub events: Vec<Arc<EventFd>>,
}

impl NotifyEventFds {
    pub fn new(queue_num: usize) -> Self {
        let mut events = Vec::new();
        for _i in 0..queue_num {
            events.push(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()));
        }

        NotifyEventFds { events }
    }
}
