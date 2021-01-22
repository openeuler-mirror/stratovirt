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

use std::cmp::min;
use std::mem::size_of;
use std::num::Wrapping;
use std::sync::atomic::{fence, Ordering};
use std::sync::Arc;

use address_space::{AddressSpace, GuestAddress};
use util::byte_code::ByteCode;

use super::errors::{ErrorKind, Result, ResultExt};
use super::{virtio_has_feature, VIRTIO_F_RING_EVENT_IDX};

/// When host consumes a buffer, don't interrupt the guest.
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// Split Virtqueue.
pub const QUEUE_TYPE_SPLIT_VRING: u16 = 1;
/// Packed Virtqueue.
pub const QUEUE_TYPE_PACKED_VRING: u16 = 2;

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
    base.checked_add(offset).ok_or_else(|| {
        ErrorKind::Msg(format!(
            "Address overflows for queue: base 0x{:X}, size {}",
            base.raw_value(),
            offset
        ))
        .into()
    })
}

/// The configuration of virtqueue.
#[derive(Default, Clone, Copy)]
pub struct QueueConfig {
    /// Guest physical address of the descriptor table.
    pub desc_table: GuestAddress,
    /// Guest physical address of the available ring.
    pub avail_ring: GuestAddress,
    /// Guest physical address of the used ring.
    pub used_ring: GuestAddress,
    /// The maximal size of elements offered by the device.
    pub max_size: u16,
    /// The queue size set by the guest.
    pub size: u16,
    /// Virtual queue ready bit.
    pub ready: bool,
}

impl QueueConfig {
    /// Create configuration for a virtqueue.
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum size of the virtqueue.
    ///
    pub fn new(max_size: u16) -> Self {
        QueueConfig {
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            max_size,
            size: 0,
            ready: false,
        }
    }
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
    pub fn new(index: u16) -> Self {
        Element {
            index,
            desc_num: 0,
            out_iovec: Vec::new(),
            in_iovec: Vec::new(),
        }
    }
}

/// Vring operations.
pub trait VringOps {
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
    fn should_notify(&mut self, system_space: &Arc<AddressSpace>, features: u64) -> bool;

    /// Get the actual size of the vring.
    fn actual_size(&self) -> u16;

    /// Get the configuration of the vring.
    fn get_queue_config(&self) -> QueueConfig;
}

/// Virtio used element.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UsedElem {
    /// Index of descriptor in the virqueue descriptor table.
    id: u32,
    /// Total length of the descriptor chain which was used (written to).
    len: u32,
}

impl ByteCode for UsedElem {}

/// A struct including flags and idx for avail vring and used vring.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SplitVringFlagsIdx {
    flags: u16,
    idx: u16,
}

impl ByteCode for SplitVringFlagsIdx {}

/// The length of used element.
const USEDELEM_LEN: u64 = size_of::<UsedElem>() as u64;
/// The length of avail element.
const AVAILELEM_LEN: u64 = size_of::<u16>() as u64;
/// The length of available ring except array of avail element(flags: u16 idx: u16 used_event: u16).
const VRING_AVAIL_LEN_EXCEPT_AVAILELEM: u64 = (size_of::<u16>() * 3) as u64;
/// The length of used ring except array of used element(flags: u16 idx: u16 avail_event: u16).
const VRING_USED_LEN_EXCEPT_USEDELEM: u64 = (size_of::<u16>() * 3) as u64;
/// The length of flags(u16) and idx(u16).
const VRING_FLAGS_AND_IDX_LEN: u64 = size_of::<SplitVringFlagsIdx>() as u64;
/// The position of idx in the available ring and the used ring.
const VRING_IDX_POSITION: u64 = size_of::<u16>() as u64;
/// This marks a buffer as continuing via the next field.
const VIRTQ_DESC_F_NEXT: u16 = 0x1;
/// This marks a buffer as write-only (otherwise read-only).
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
/// This means the buffer contains a list of buffer descriptors.
const VIRTQ_DESC_F_INDIRECT: u16 = 0x4;

/// Descriptor of split vring.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct SplitVringDesc {
    /// Address (guest-physical).
    pub addr: GuestAddress,
    /// Length.
    pub len: u32,
    /// The flags as indicated above.
    pub flags: u16,
    /// We chain unused descriptors via this, too.
    pub next: u16,
}

/// The length of virtio descriptor.
const DESCRIPTOR_LEN: u64 = size_of::<SplitVringDesc>() as u64;

impl SplitVringDesc {
    /// Create a descriptor of split vring.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `desc_table` - Guest address of virtqueue descriptor table.
    /// * `queue_size` - Size of virtqueue.
    /// * `index` - Index of descriptor in the virqueue descriptor table.
    pub fn new(
        sys_mem: &Arc<AddressSpace>,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Result<Self> {
        if index >= queue_size {
            return Err(ErrorKind::QueueIndex(index, queue_size).into());
        }

        let desc =
            if let Some(desc_addr) = desc_table.checked_add(u64::from(index) * DESCRIPTOR_LEN) {
                sys_mem
                    .read_object::<SplitVringDesc>(desc_addr)
                    .chain_err(|| {
                        format!(
                            "Failed to read object for a descriptor (index: {}, addr: 0x{:X})",
                            index,
                            desc_addr.raw_value()
                        )
                    })?
            } else {
                bail!(
                    "Address overflows for creating a descriptor: addr 0x{:X}, size {}",
                    desc_table.raw_value(),
                    u64::from(index) * DESCRIPTOR_LEN
                );
            };
        if desc.is_valid(sys_mem, queue_size) {
            Ok(desc)
        } else {
            Err(ErrorKind::QueueDescInvalid.into())
        }
    }

    /// Return true if the descriptor is valid.
    fn is_valid(&self, sys_mem: &Arc<AddressSpace>, queue_size: u16) -> bool {
        if let Err(ref e) = checked_offset_mem(&sys_mem, self.addr, u64::from(self.len)) {
            error!(
                "The memory of descriptor is invalid, {} ",
                error_chain::ChainedError::display_chain(e),
            );
            return false;
        }

        if self.has_next() && self.next >= queue_size {
            error!(
                "The next index {} exceed queue size {}",
                self.next, queue_size,
            );
            return false;
        }

        true
    }

    /// Return true if this descriptor has next descriptor.
    fn has_next(&self) -> bool {
        self.flags & VIRTQ_DESC_F_NEXT != 0
    }

    /// Get the next descriptor in descriptor chain.
    fn next_desc(
        sys_mem: &Arc<AddressSpace>,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Result<SplitVringDesc> {
        SplitVringDesc::new(sys_mem, desc_table, queue_size, index)
            .chain_err(|| format!("Failed to find next descriptor {}", index))
    }

    /// Check whether this descriptor is write-only or read-only.
    /// Write-only means that the emulated device can write and the driver can read.
    fn write_only(&self) -> bool {
        self.flags & VIRTQ_DESC_F_WRITE != 0
    }

    /// Return true if this descriptor is a indirect descriptor.
    fn is_indirect_desc(&self) -> bool {
        self.flags & VIRTQ_DESC_F_INDIRECT != 0
    }

    /// Return true if the indirect descriptor is valid.
    /// The len can be divided evenly by the size of descriptor and can not be zero.
    fn is_valid_indirect_desc(&self) -> bool {
        if u64::from(self.len) % DESCRIPTOR_LEN == 0 && self.len != 0 {
            true
        } else {
            error!("The indirect descriptor is invalid, len: {}", self.len);
            false
        }
    }

    /// Get the num of descriptor in the table of indirect descriptor.
    fn get_desc_num(&self) -> u16 {
        (u64::from(self.len) / DESCRIPTOR_LEN) as u16
    }

    /// Get element from descriptor chain.
    fn get_element(
        sys_mem: &Arc<AddressSpace>,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
        mut desc: SplitVringDesc,
    ) -> Result<Element> {
        let mut elem = Element::new(index);

        loop {
            if elem.desc_num >= queue_size {
                break;
            }

            let iovec = ElemIovec {
                addr: desc.addr,
                len: desc.len,
            };

            if desc.write_only() {
                elem.in_iovec.push(iovec);
            } else {
                elem.out_iovec.push(iovec);
            }
            elem.desc_num += 1;

            if desc.has_next() {
                desc = Self::next_desc(sys_mem, desc_table, queue_size, desc.next)?;
            } else {
                break;
            }
        }

        Ok(elem)
    }

    /// Get element from indirect descriptor chain.
    fn get_indirect_desc(&self, sys_mem: &Arc<AddressSpace>, index: u16) -> Result<Element> {
        if !self.is_valid_indirect_desc() {
            return Err(ErrorKind::QueueDescInvalid.into());
        }

        let desc_num = self.get_desc_num();
        let desc_table = self.addr;
        let desc = Self::next_desc(sys_mem, desc_table, desc_num, 0)?;
        Self::get_element(sys_mem, desc_table, desc_num, index, desc)
            .chain_err(||
                format!("Failed to get element from indirect descriptor chain {}, table addr: 0x{:X}, size: {}",
                    index, desc_table.raw_value(), desc_num)
            )
    }

    /// Get element from normal descriptor chain.
    fn get_nonindirect_desc(
        &self,
        sys_mem: &Arc<AddressSpace>,
        desc_table: GuestAddress,
        queue_size: u16,
        index: u16,
    ) -> Result<Element> {
        Self::get_element(sys_mem, desc_table, queue_size, index, *self).chain_err(|| {
            format!(
                "Failed to get element from normal descriptor chain {}, table addr: 0x{:X}, size: {}",
                index, desc_table.raw_value(), queue_size
            )
        })
    }
}

impl ByteCode for SplitVringDesc {}

/// Split vring.
#[derive(Default, Clone, Copy)]
pub struct SplitVring {
    /// Guest physical address of the descriptor table.
    /// The table is composed of descriptors(SplitVringDesc).
    pub desc_table: GuestAddress,

    /// Guest physical address of the available ring.
    /// The ring is composed of flags(u16), idx(u16), ring[size](u16) and used_event(u16).
    pub avail_ring: GuestAddress,

    /// Guest physical address of the used ring.
    /// The ring is composed of flags(u16), idx(u16), used_ring[size](UsedElem) and avail_event(u16).
    pub used_ring: GuestAddress,

    /// Indicate whether the queue configuration is finished.
    pub ready: bool,

    /// The maximal size in elements offered by the device.
    pub max_size: u16,

    /// The queue size set by frontend.
    pub size: u16,

    /// The next index which can be popped in the available vring.
    next_avail: Wrapping<u16>,

    /// The next index which can be pushed in the used vring.
    next_used: Wrapping<u16>,

    /// The index of last descriptor used which has triggered interrupt.
    last_signal_used: Wrapping<u16>,
}

impl SplitVring {
    /// Create a split vring.
    ///
    /// # Arguments
    ///
    /// * `queue_config` - Configuration of the vring.
    pub fn new(queue_config: QueueConfig) -> Self {
        SplitVring {
            desc_table: queue_config.desc_table,
            avail_ring: queue_config.avail_ring,
            used_ring: queue_config.used_ring,
            ready: queue_config.ready,
            max_size: queue_config.max_size,
            size: queue_config.size,
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            last_signal_used: Wrapping(0),
        }
    }

    /// The actual size of the queue.
    fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Get the index of the available ring from guest memory.
    fn get_avail_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
        let avail_flags_idx: SplitVringFlagsIdx = sys_mem
            .read_object::<SplitVringFlagsIdx>(self.avail_ring)
            .chain_err(|| {
                format!(
                    "Failed to get avail idx, avail_ring: 0x{:X}",
                    self.avail_ring.raw_value()
                )
            })?;

        Ok(avail_flags_idx.idx)
    }

    /// Get the flags of the available ring from guest memory.
    fn get_avail_flags(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
        let avail_flags_idx: SplitVringFlagsIdx = sys_mem
            .read_object::<SplitVringFlagsIdx>(self.avail_ring)
            .chain_err(|| {
                format!(
                    "Failed to get avail flags, avail_ring: 0x{:X}",
                    self.avail_ring.raw_value()
                )
            })?;
        Ok(avail_flags_idx.flags)
    }

    /// Get the index of the used ring from guest memory.
    fn get_used_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
        let used_flag_idx: SplitVringFlagsIdx = sys_mem
            .read_object::<SplitVringFlagsIdx>(self.used_ring)
            .chain_err(|| {
                format!(
                    "Failed to get used idx, used_ring: 0x{:X}",
                    self.used_ring.raw_value()
                )
            })?;
        Ok(used_flag_idx.idx)
    }

    /// Set the avail idx to the field of the event index for the available ring.
    fn set_avail_event(&self, sys_mem: &Arc<AddressSpace>) -> Result<()> {
        let avail_event_offset =
            VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * u64::from(self.actual_size());
        let event_idx = self.get_avail_idx(sys_mem)?;

        fence(Ordering::Release);
        sys_mem
            .write_object(
                &event_idx,
                GuestAddress(self.used_ring.0 + avail_event_offset),
            )
            .chain_err(|| {
                format!(
                    "Failed to set avail event idx, used_ring: 0x{:X}, offset: {}",
                    self.used_ring.raw_value(),
                    avail_event_offset,
                )
            })?;

        Ok(())
    }

    /// Get the event index of the used ring from guest memory.
    fn get_used_event(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
        let used_event_offset =
            VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * u64::from(self.actual_size());
        let used_event: u16 =
            if let Some(used_event_addr) = self.avail_ring.checked_add(used_event_offset) {
                sys_mem.read_object::<u16>(used_event_addr).chain_err(|| {
                    format!(
                        "Failed to get used event idx, avail_ring: 0x{:X}, offset: {}",
                        self.avail_ring.raw_value(),
                        used_event_offset,
                    )
                })?
            } else {
                bail!(
                    "Address overflows for getting used event idx: addr 0x{:X}, size {}",
                    self.avail_ring.raw_value(),
                    used_event_offset
                );
            };

        Ok(used_event)
    }

    /// The number of descriptor chains in the available ring.
    fn avail_ring_len(&mut self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
        let avail_idx = self.get_avail_idx(sys_mem).map(Wrapping)?;

        Ok((avail_idx - self.next_avail).0)
    }

    /// Return true if VRING_AVAIL_F_NO_INTERRUPT is set.
    fn is_avail_ring_no_interrupt(&self, sys_mem: &Arc<AddressSpace>) -> bool {
        match self.get_avail_flags(sys_mem) {
            Ok(avail_flags) => (avail_flags & VRING_AVAIL_F_NO_INTERRUPT) != 0,
            Err(ref e) => {
                warn!(
                    "Failed to get the status for VRING_AVAIL_F_NO_INTERRUPT {}",
                    error_chain::ChainedError::display_chain(e)
                );
                false
            }
        }
    }

    /// Return true if it's required to trigger interrupt for the used vring.
    fn used_ring_need_event(&mut self, sys_mem: &Arc<AddressSpace>) -> bool {
        let old = self.last_signal_used;
        let new = match self.get_used_idx(sys_mem) {
            Ok(used_idx) => Wrapping(used_idx),
            Err(ref e) => {
                error!(
                    "Failed to get the status for notifying used vring  {}",
                    error_chain::ChainedError::display_chain(e)
                );
                return false;
            }
        };

        let used_event_idx = match self.get_used_event(sys_mem) {
            Ok(idx) => Wrapping(idx),
            Err(ref e) => {
                error!(
                    "Failed to get the status for notifying used vring  {}",
                    error_chain::ChainedError::display_chain(e)
                );
                return false;
            }
        };

        self.last_signal_used = new;
        (new - used_event_idx - Wrapping(1)) < (new - old)
    }

    fn is_invalid_memory(&self, sys_mem: &Arc<AddressSpace>, actual_size: u64) -> bool {
        let desc_table_end =
            match checked_offset_mem(&sys_mem, self.desc_table, DESCRIPTOR_LEN * actual_size) {
                Ok(addr) => addr,
                Err(ref e) => {
                    error!(
                        "descriptor table is out of bounds: start:0x{:X} size:{} {}",
                        self.desc_table.raw_value(),
                        DESCRIPTOR_LEN * actual_size,
                        error_chain::ChainedError::display_chain(e),
                    );
                    return true;
                }
            };

        let desc_avail_end = match checked_offset_mem(
            &sys_mem,
            self.avail_ring,
            VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * actual_size,
        ) {
            Ok(addr) => addr,
            Err(ref e) => {
                error!(
                    "avail ring is out of bounds: start:0x{:X} size:{} {}",
                    self.avail_ring.raw_value(),
                    VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * actual_size,
                    error_chain::ChainedError::display_chain(e),
                );
                return true;
            }
        };

        if let Err(ref e) = checked_offset_mem(
            &sys_mem,
            self.used_ring,
            VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * actual_size,
        ) {
            error!(
                "used ring is out of bounds: start:0x{:X} size:{} {}",
                self.used_ring.raw_value(),
                VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * actual_size,
                error_chain::ChainedError::display_chain(e),
            );
            return true;
        }

        if self.desc_table >= self.avail_ring
            || self.avail_ring >= self.used_ring
            || desc_table_end > self.avail_ring
            || desc_avail_end > self.used_ring
        {
            error!("The memory of descriptor table: 0x{:X}, avail ring: 0x{:X} or used ring: 0x{:X} is overlapped. queue size:{}",
                   self.desc_table.raw_value(), self.avail_ring.raw_value(), self.used_ring.raw_value(), actual_size);
            return true;
        }

        if self.desc_table.0 & 0xf != 0 {
            error!(
                "descriptor table: 0x{:X} is not aligned",
                self.desc_table.raw_value()
            );
            true
        } else if self.avail_ring.0 & 0x1 != 0 {
            error!(
                "avail ring: 0x{:X} is not aligned",
                self.avail_ring.raw_value()
            );
            true
        } else if self.used_ring.0 & 0x3 != 0 {
            error!(
                "used ring: 0x{:X} is not aligned",
                self.used_ring.raw_value()
            );
            true
        } else {
            false
        }
    }

    fn get_vring_element(&mut self, sys_mem: &Arc<AddressSpace>, features: u64) -> Result<Element> {
        let index_offset = VRING_FLAGS_AND_IDX_LEN
            + AVAILELEM_LEN * u64::from(self.next_avail.0 % self.actual_size());
        let desc_index: u16 =
            if let Some(desc_index_addr) = self.avail_ring.checked_add(index_offset) {
                sys_mem.read_object::<u16>(desc_index_addr).chain_err(|| {
                    format!(
                        "Failed to read the index of descriptor 0x{:X} for popping avail ring",
                        desc_index_addr.raw_value()
                    )
                })?
            } else {
                bail!(
                    "Address overflows for popping avail ring : addr 0x{:X}, size {}",
                    self.avail_ring.raw_value(),
                    index_offset
                );
            };

        if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            self.set_avail_event(sys_mem)
                .chain_err(|| "Failed to set avail event for popping avail ring")?;
        }

        let desc = SplitVringDesc::new(sys_mem, self.desc_table, self.actual_size(), desc_index)?;
        let elem = if desc.is_indirect_desc() {
            if desc.write_only() {
                bail!("Unexpected descriptor for writing only for popping avail ring");
            }

            desc.get_indirect_desc(sys_mem, desc_index)
                .map(|elem| {
                    self.next_avail += Wrapping(1);
                    elem
                })
                .chain_err(|| "Failed to get indirect desc for popping avail ring")?
        } else {
            desc.get_nonindirect_desc(sys_mem, self.desc_table, self.actual_size(), desc_index)
                .map(|elem| {
                    self.next_avail += Wrapping(1);
                    elem
                })?
        };

        Ok(elem)
    }
}

impl VringOps for SplitVring {
    fn is_valid(&self, sys_mem: &Arc<AddressSpace>) -> bool {
        let size = u64::from(self.actual_size());
        if !self.ready {
            error!("The configuration of vring is not ready\n");
            false
        } else if self.size > self.max_size || self.size == 0 || (self.size & (self.size - 1)) != 0
        {
            error!(
                "vring with invalid size:{} max size:{}",
                self.size, self.max_size
            );
            false
        } else {
            !self.is_invalid_memory(sys_mem, size)
        }
    }

    fn pop_avail(&mut self, sys_mem: &Arc<AddressSpace>, features: u64) -> Result<Element> {
        let avail_len = self.avail_ring_len(sys_mem)?;
        if avail_len == 0 {
            bail!("failed to pop avail: empty!");
        }

        match self.get_vring_element(sys_mem, features) {
            Ok(elem) => Ok(elem),
            Err(ref e) => {
                error!(
                    "Failed to get element from split vring, {}",
                    error_chain::ChainedError::display_chain(e),
                );

                Err(e.to_string().into())
            }
        }
    }

    fn add_used(&mut self, sys_mem: &Arc<AddressSpace>, index: u16, len: u32) -> Result<()> {
        if index >= self.size {
            return Err(ErrorKind::QueueIndex(index, self.size).into());
        }

        let used_ring = self.used_ring;
        let next_used = u64::from(self.next_used.0 % self.actual_size());
        let used_elem_addr =
            GuestAddress(used_ring.0 + VRING_FLAGS_AND_IDX_LEN + next_used * USEDELEM_LEN);
        let used_elem = UsedElem {
            id: u32::from(index),
            len,
        };
        sys_mem
            .write_object::<UsedElem>(&used_elem, used_elem_addr)
            .chain_err(|| "Failed to write object for used element")?;

        self.next_used += Wrapping(1);

        fence(Ordering::Release);

        sys_mem
            .write_object(
                &(self.next_used.0 as u16),
                GuestAddress(used_ring.0 + VRING_IDX_POSITION),
            )
            .chain_err(|| "Failed to write next used idx")?;

        Ok(())
    }

    fn should_notify(&mut self, sys_mem: &Arc<AddressSpace>, features: u64) -> bool {
        if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            self.used_ring_need_event(sys_mem)
        } else {
            !self.is_avail_ring_no_interrupt(sys_mem)
        }
    }

    fn actual_size(&self) -> u16 {
        self.actual_size()
    }

    fn get_queue_config(&self) -> QueueConfig {
        QueueConfig {
            desc_table: self.desc_table,
            avail_ring: self.avail_ring,
            used_ring: self.used_ring,
            ready: self.ready,
            max_size: self.max_size,
            size: self.size,
        }
    }
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

    /// Return true if the memory layout of the virqueue is valid.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    pub fn is_valid(&self, sys_mem: &Arc<AddressSpace>) -> bool {
        self.vring.is_valid(sys_mem)
    }
}

#[cfg(test)]
mod tests {
    pub use super::*;
    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};

    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36);
        let sys_space = AddressSpace::new(root).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(GuestAddress(0), SYSTEM_SPACE_SIZE, None, false, false).unwrap(),
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

    trait VringOpsTest {
        fn set_desc(
            &self,
            sys_mem: &Arc<AddressSpace>,
            index: u16,
            addr: GuestAddress,
            len: u32,
            flags: u16,
            next: u16,
        ) -> Result<()>;

        fn set_avail_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()>;

        fn set_avail_ring_flags(&self, sys_mem: &Arc<AddressSpace>, flags: u16) -> Result<()>;

        fn set_avail_ring_elem(
            &self,
            sys_mem: &Arc<AddressSpace>,
            avail_pos: u16,
            index: u16,
        ) -> Result<()>;

        fn get_avail_event(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16>;

        fn get_used_elem(&self, sys_mem: &Arc<AddressSpace>, index: u16) -> Result<UsedElem>;

        fn get_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16>;

        fn set_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()>;

        fn set_used_event_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()>;
    }

    impl VringOpsTest for SplitVring {
        fn set_desc(
            &self,
            sys_mem: &Arc<AddressSpace>,
            index: u16,
            addr: GuestAddress,
            len: u32,
            flags: u16,
            next: u16,
        ) -> Result<()> {
            if index >= self.actual_size() {
                return Err(ErrorKind::QueueIndex(index, self.size).into());
            }

            let desc_addr_offset = DESCRIPTOR_LEN * index as u64;
            let desc = SplitVringDesc {
                addr,
                len,
                flags,
                next,
            };
            sys_mem.write_object::<SplitVringDesc>(
                &desc,
                GuestAddress(self.desc_table.0 + desc_addr_offset),
            )?;

            Ok(())
        }

        fn set_avail_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let avail_idx_offset = 2 as u64;
            sys_mem
                .write_object::<u16>(&idx, GuestAddress(self.avail_ring.0 + avail_idx_offset))?;
            Ok(())
        }

        fn set_avail_ring_flags(&self, sys_mem: &Arc<AddressSpace>, flags: u16) -> Result<()> {
            let avail_idx_offset = 0 as u64;
            sys_mem
                .write_object::<u16>(&flags, GuestAddress(self.avail_ring.0 + avail_idx_offset))?;
            Ok(())
        }

        fn set_avail_ring_elem(
            &self,
            sys_mem: &Arc<AddressSpace>,
            avail_pos: u16,
            desc_index: u16,
        ) -> Result<()> {
            let avail_idx_offset = VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * (avail_pos as u64);
            sys_mem.write_object::<u16>(
                &desc_index,
                GuestAddress(self.avail_ring.0 + avail_idx_offset),
            )?;
            Ok(())
        }

        fn get_avail_event(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
            let avail_event_idx_offset =
                VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * (self.actual_size() as u64);
            let event_idx = sys_mem
                .read_object::<u16>(GuestAddress(self.used_ring.0 + avail_event_idx_offset))?;
            Ok(event_idx)
        }

        fn get_used_elem(&self, sys_mem: &Arc<AddressSpace>, index: u16) -> Result<UsedElem> {
            let used_elem_offset = VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * (index as u64);
            let used_elem = sys_mem
                .read_object::<UsedElem>(GuestAddress(self.used_ring.0 + used_elem_offset))?;
            Ok(used_elem)
        }

        fn get_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
            let used_idx_offset = VRING_IDX_POSITION;
            let idx =
                sys_mem.read_object::<u16>(GuestAddress(self.used_ring.0 + used_idx_offset))?;
            Ok(idx)
        }

        fn set_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let used_idx_offset = VRING_IDX_POSITION;
            sys_mem.write_object::<u16>(&idx, GuestAddress(self.used_ring.0 + used_idx_offset))?;
            Ok(())
        }

        fn set_used_event_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let event_idx_offset =
                VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * (self.actual_size() as u64);
            sys_mem
                .write_object::<u16>(&idx, GuestAddress(self.avail_ring.0 + event_idx_offset))?;
            Ok(())
        }
    }

    fn set_indirect_desc(
        sys_mem: &Arc<AddressSpace>,
        desc_addr: GuestAddress,
        addr: GuestAddress,
        len: u32,
        flags: u16,
        next: u16,
    ) -> Result<()> {
        let desc = SplitVringDesc {
            addr,
            len,
            flags,
            next,
        };
        sys_mem.write_object::<SplitVringDesc>(&desc, desc_addr)?;
        Ok(())
    }

    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;
    const QUEUE_SIZE: u16 = 256 as u16;

    fn align(size: u64, alignment: u64) -> u64 {
        let align_adjust = if size % alignment != 0 {
            alignment - (size % alignment)
        } else {
            0
        };
        (size + align_adjust) as u64
    }

    #[test]
    fn test_valid_queue_01() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);

        // failed when the type of queue is invalid
        let queue = Queue::new(queue_config, 0);
        assert!(queue.is_err());
        let queue = Queue::new(queue_config, QUEUE_TYPE_PACKED_VRING);
        assert!(queue.is_err());

        // it is valid
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the status is not ready
        queue_config.ready = false;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        queue_config.ready = true;

        // it is invalid when the size of virtual ring is more than the max size
        queue_config.size = QUEUE_SIZE + 1;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);

        // it is invalid when the size of virtual ring is zero
        queue_config.size = 0;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);

        // it is invalid when the size of virtual ring isn't power of 2
        queue_config.size = 15;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
    }

    #[test]
    fn test_valid_queue_02() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of descriptor table is out of bound
        queue_config.desc_table =
            GuestAddress(SYSTEM_SPACE_SIZE - (QUEUE_SIZE as u64) * DESCRIPTOR_LEN + 1 as u64);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.desc_table = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of avail ring is out of bound
        queue_config.avail_ring = GuestAddress(
            SYSTEM_SPACE_SIZE
                - (VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * (QUEUE_SIZE as u64))
                + 1 as u64,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of used ring is out of bound
        queue_config.used_ring = GuestAddress(
            SYSTEM_SPACE_SIZE
                - (VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * (QUEUE_SIZE as u64))
                + 1 as u64,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);
    }

    #[test]
    fn test_valid_queue_03() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of descriptor table is equal to the address of avail ring
        queue_config.avail_ring = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of descriptor table is overlapped to the address of avail ring
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN - 1);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of avail ring is equal to the address of used ring
        queue_config.used_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of avail ring is overlapped to the address of used ring
        queue_config.used_ring = GuestAddress(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64)
                - 1,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);
    }

    #[test]
    fn test_valid_queue_04() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of descriptor table is not aligned to 16
        queue_config.desc_table = GuestAddress(15 as u64);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.desc_table = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of avail ring is not aligned to 2
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN + 1);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);

        // it is invalid when the address of used ring is not aligned to 4
        queue_config.used_ring = GuestAddress(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64)
                + 3,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), false);
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert_eq!(queue.is_valid(&sys_space), true);
    }

    #[test]
    fn test_pop_avail_01() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert_eq!(vring.is_valid(&sys_space), true);

        // it is ok when the descriptor chain is normal
        // set the information of index 0 for descriptor
        vring
            .set_desc(&sys_space, 0, GuestAddress(0x111), 16, VIRTQ_DESC_F_NEXT, 1)
            .unwrap();

        // set the information of index 1 for descriptor
        vring
            .set_desc(
                &sys_space,
                1,
                GuestAddress(0x222),
                32,
                VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                2,
            )
            .unwrap();

        // set the information of index 2 for descriptor
        vring
            .set_desc(
                &sys_space,
                2,
                GuestAddress(0x333),
                48,
                VIRTQ_DESC_F_WRITE,
                0,
            )
            .unwrap();

        // set the index 0 of descriptor to the position 0 for the element of avail ring
        vring.set_avail_ring_elem(&sys_space, 0, 0).unwrap();
        // set 1 to the idx of avail ring
        vring.set_avail_ring_idx(&sys_space, 1).unwrap();

        let features = 1 << VIRTIO_F_RING_EVENT_IDX as u64;
        let elem = match vring.pop_avail(&sys_space, features) {
            Ok(ret) => ret,
            Err(_) => Element {
                index: 1,
                desc_num: 0,
                out_iovec: Vec::new(),
                in_iovec: Vec::new(),
            },
        };
        assert_eq!(elem.index, 0);
        assert_eq!(elem.desc_num, 3);
        assert_eq!(elem.out_iovec.len(), 1);
        let elem_iov = elem.out_iovec.get(0).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x111));
        assert_eq!(elem_iov.len, 16);
        assert_eq!(elem.in_iovec.len(), 2);
        let elem_iov = elem.in_iovec.get(0).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x222));
        assert_eq!(elem_iov.len, 32);
        let elem_iov = elem.in_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x333));
        assert_eq!(elem_iov.len, 48);

        // the event idx of avail ring is equal to get_avail_event
        let event_idx = vring.get_avail_event(&sys_space).unwrap();
        assert_eq!(event_idx, 1);
        let avail_idx = vring.get_avail_idx(&sys_space).unwrap();
        assert_eq!(avail_idx, 1);
    }

    #[test]
    fn test_pop_avail_02() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert_eq!(vring.is_valid(&sys_space), true);

        // it is ok when the descriptor chain is indirect
        // set the information for indirect descriptor
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                48,
                VIRTQ_DESC_F_INDIRECT,
                0,
            )
            .unwrap();

        // set the information of index 0 for indirect descriptor chain
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2),
            GuestAddress(0x444),
            100,
            VIRTQ_DESC_F_NEXT,
            1,
        )
        .unwrap();

        // set the information of index 1 for indirect descriptor chain
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN),
            GuestAddress(0x555),
            200,
            VIRTQ_DESC_F_NEXT,
            2,
        )
        .unwrap();

        // set the information of index 2 for indirect descriptor chain
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN * 2),
            GuestAddress(0x666),
            300,
            VIRTQ_DESC_F_WRITE,
            2,
        )
        .unwrap();

        // set the index 0 of descriptor to the position 0 for the element of avail ring
        vring.set_avail_ring_elem(&sys_space, 0, 0).unwrap();
        // set 1 to the idx of avail ring
        vring.set_avail_ring_idx(&sys_space, 1).unwrap();

        let features = 1 << VIRTIO_F_RING_EVENT_IDX as u64;
        let elem = match vring.pop_avail(&sys_space, features) {
            Ok(ret) => ret,
            Err(_) => Element {
                index: 1,
                desc_num: 0,
                out_iovec: Vec::new(),
                in_iovec: Vec::new(),
            },
        };
        assert_eq!(elem.index, 0);
        assert_eq!(elem.desc_num, 3);
        assert_eq!(elem.out_iovec.len(), 2);
        let elem_iov = elem.out_iovec.get(0).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x444));
        assert_eq!(elem_iov.len, 100);
        let elem_iov = elem.out_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x555));
        assert_eq!(elem_iov.len, 200);
        assert_eq!(elem.in_iovec.len(), 1);
        let elem_iov = elem.in_iovec.get(0).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x666));
        assert_eq!(elem_iov.len, 300);
    }

    #[test]
    fn test_pop_avail_03() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert_eq!(vring.is_valid(&sys_space), true);

        // it is error when the idx of avail ring which is equal to next_avail
        // set 0 to the idx of avail ring which is equal to next_avail
        vring.set_avail_ring_idx(&sys_space, 0).unwrap();
        let features = 1 << VIRTIO_F_RING_EVENT_IDX as u64;
        if let Ok(_) = vring.pop_avail(&sys_space, features) {
            assert!(false);
        }

        // it is error when the indirect descriptor is written
        // set the index 0 of descriptor to the position 0 for the element of avail ring
        vring.set_avail_ring_elem(&sys_space, 0, 0).unwrap();
        // set 1 to the idx of avail ring
        vring.set_avail_ring_idx(&sys_space, 1).unwrap();
        // it is false when it sets the indirect descriptor to be written
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(0x11),
                16,
                VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_WRITE,
                0,
            )
            .unwrap();
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(
                err.to_string(),
                "Unexpected descriptor for writing only for popping avail ring"
            );
        } else {
            assert!(false);
        }

        // error comes when the length of indirect descriptor can not be divided by 16
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(0x11),
                17,
                VIRTQ_DESC_F_INDIRECT,
                0,
            )
            .unwrap();
        if let Ok(_) = vring.pop_avail(&sys_space, features) {
            assert!(false);
        }

        // error comes when the length of indirect descriptor is more than the length of descriptor chain
        // set the information of index 0 for descriptor
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                32,
                VIRTQ_DESC_F_INDIRECT,
                0,
            )
            .unwrap();

        // set the information of index 0 for descriptor
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2),
            GuestAddress(0x444),
            100,
            VIRTQ_DESC_F_NEXT,
            1,
        )
        .unwrap();

        // set the information of index 1 for descriptor
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN),
            GuestAddress(0x555),
            200,
            VIRTQ_DESC_F_NEXT,
            2,
        )
        .unwrap();

        // set the information of index 2 for descriptor
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN * 2),
            GuestAddress(0x666),
            300,
            VIRTQ_DESC_F_WRITE,
            2,
        )
        .unwrap();
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(
                err.to_string(),
                "Failed to get indirect desc for popping avail ring"
            );
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_add_used() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert_eq!(vring.is_valid(&sys_space), true);

        // it is false when the index is more than the size of queue
        let err = vring.add_used(&sys_space, QUEUE_SIZE, 100).unwrap_err();
        if let ErrorKind::QueueIndex(offset, size) = err.kind() {
            assert_eq!(*offset, 256);
            assert_eq!(*size, 256);
        }

        assert!(vring.add_used(&sys_space, 10, 100).is_ok());
        let elem = vring.get_used_elem(&sys_space, 0).unwrap();
        assert_eq!(elem.id, 10);
        assert_eq!(elem.len, 100);
        assert_eq!(vring.get_used_ring_idx(&sys_space).unwrap(), 1);
    }

    #[test]
    fn test_should_notify() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress((QUEUE_SIZE as u64) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            (QUEUE_SIZE as u64) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * (QUEUE_SIZE as u64),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert_eq!(vring.is_valid(&sys_space), true);

        // it's true when the feature of event idx and no interrupt for the avail ring  is closed
        let features = 0 as u64;
        assert!(vring.set_avail_ring_flags(&sys_space, 0).is_ok());
        assert_eq!(vring.should_notify(&sys_space, features), true);

        // it's false when the feature of event idx is closed and the feature of no interrupt for the avail ring is open
        let features = 0 as u64;
        assert!(vring
            .set_avail_ring_flags(&sys_space, VRING_AVAIL_F_NO_INTERRUPT)
            .is_ok());
        assert_eq!(vring.should_notify(&sys_space, features), false);

        // it's true when the feature of event idx is open and (new - event_idx - Wrapping(1) < new -old)
        let features = 1 << VIRTIO_F_RING_EVENT_IDX as u64;
        vring.last_signal_used = Wrapping(5); //old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); //new
        assert!(vring.set_used_event_idx(&sys_space, 6).is_ok()); //event_idx
        assert_eq!(vring.should_notify(&sys_space, features), true);

        // it's false when the feature of event idx is open and (new - event_idx - Wrapping(1) > new -old)
        vring.last_signal_used = Wrapping(5); //old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); //new
        assert!(vring.set_used_event_idx(&sys_space, 1).is_ok()); //event_idx
        assert_eq!(vring.should_notify(&sys_space, features), false);

        // it's false when the feature of event idx is open and (new - event_idx - Wrapping(1) = new -old)
        vring.last_signal_used = Wrapping(5); //old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); //new
        assert!(vring.set_used_event_idx(&sys_space, 4).is_ok()); //event_idx
        assert_eq!(vring.should_notify(&sys_space, features), false);
    }
}
