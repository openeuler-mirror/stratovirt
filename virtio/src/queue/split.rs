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
use std::io::Write;
use std::mem::size_of;
use std::num::Wrapping;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{fence, AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use log::{error, warn};

use super::{
    checked_offset_mem, ElemIovec, Element, VringOps, INVALID_VECTOR_NUM, VIRTQ_DESC_F_INDIRECT,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use crate::{
    report_virtio_error, virtio_has_feature, VirtioError, VirtioInterrupt, VIRTIO_F_RING_EVENT_IDX,
};
use address_space::{AddressAttr, AddressSpace, GuestAddress, RegionCache, RegionType};
use migration::{migration::Migratable, MigrationManager};
use util::byte_code::ByteCode;

/// When host consumes a buffer, don't interrupt the guest.
const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;
/// When guest produces a buffer, don't notify the host.
const VRING_USED_F_NO_NOTIFY: u16 = 1;

/// Max total len of a descriptor chain.
const DESC_CHAIN_MAX_TOTAL_LEN: u64 = 1u64 << 32;
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
/// The length of virtio descriptor.
const DESCRIPTOR_LEN: u64 = size_of::<SplitVringDesc>() as u64;

/// Read some data from memory to form an object via host address.
///
/// # Arguments
///
/// * `hoat_addr` - The start host address where the data will be read from.
///
/// # Safety
///
/// Make true that host_addr and std::mem::size_of::<T>() are in the range of ram.
///
/// # Note
/// To use this method, it is necessary to implement `ByteCode` trait for your object.
unsafe fn read_object_direct<T: ByteCode>(host_addr: u64) -> Result<T> {
    trace::virtio_read_object_direct(host_addr, std::mem::size_of::<T>());
    let mut obj = T::default();
    let mut dst = obj.as_mut_bytes();
    let src = std::slice::from_raw_parts_mut(host_addr as *mut u8, std::mem::size_of::<T>());
    dst.write_all(src)
        .with_context(|| "Failed to read object via host address")?;

    Ok(obj)
}

/// Write an object to memory via host address.
///
/// # Arguments
///
/// * `data` - The object that will be written to the memory.
/// * `host_addr` - The start host address where the object will be written to.
///
/// # Safety
///
/// Make true that host_addr and std::mem::size_of::<T>() are in the range of ram.
///
/// # Note
/// To use this method, it is necessary to implement `ByteCode` trait for your object.
unsafe fn write_object_direct<T: ByteCode>(data: &T, host_addr: u64) -> Result<()> {
    trace::virtio_write_object_direct(host_addr, std::mem::size_of::<T>());
    // Mark vmm dirty page manually if live migration is active.
    MigrationManager::mark_dirty_log(host_addr, data.as_bytes().len() as u64);
    let mut dst = std::slice::from_raw_parts_mut(host_addr as *mut u8, std::mem::size_of::<T>());
    dst.write_all(data.as_bytes())
        .with_context(|| "Failed to write object via host address")
}

#[derive(Default, Clone, Copy)]
pub struct VirtioAddrCache {
    /// Host virtual address of the descriptor table.
    pub desc_table_host: u64,
    /// Host virtual address of the available ring.
    pub avail_ring_host: u64,
    /// Host virtual address of the used ring.
    pub used_ring_host: u64,
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
    /// Host address cache.
    pub addr_cache: VirtioAddrCache,
    /// The maximal size of elements offered by the device.
    pub max_size: u16,
    /// The queue size set by the guest.
    pub size: u16,
    /// Virtual queue ready bit.
    pub ready: bool,
    /// Interrupt vector index of the queue for msix
    pub vector: u16,
    /// The next index which can be popped in the available vring.
    next_avail: Wrapping<u16>,
    /// The next index which can be pushed in the used vring.
    next_used: Wrapping<u16>,
    /// The index of last descriptor used which has triggered interrupt.
    last_signal_used: Wrapping<u16>,
    /// The last_signal_used is valid or not.
    signal_used_valid: bool,
}

impl QueueConfig {
    /// Create configuration for a virtqueue.
    ///
    /// # Arguments
    ///
    /// * `max_size` - The maximum size of the virtqueue.
    pub fn new(max_size: u16) -> Self {
        let addr_cache = VirtioAddrCache::default();
        QueueConfig {
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
            addr_cache,
            max_size,
            size: max_size,
            ready: false,
            vector: INVALID_VECTOR_NUM,
            next_avail: Wrapping(0),
            next_used: Wrapping(0),
            last_signal_used: Wrapping(0),
            signal_used_valid: false,
        }
    }

    fn get_desc_size(&self) -> u64 {
        u64::from(min(self.size, self.max_size)) * DESCRIPTOR_LEN
    }

    fn get_used_size(&self, features: u64) -> u64 {
        let size = if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            2_u64
        } else {
            0_u64
        };

        size + VRING_FLAGS_AND_IDX_LEN + u64::from(min(self.size, self.max_size)) * USEDELEM_LEN
    }

    fn get_avail_size(&self, features: u64) -> u64 {
        let size = if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            2_u64
        } else {
            0_u64
        };

        size + VRING_FLAGS_AND_IDX_LEN
            + u64::from(min(self.size, self.max_size)) * (size_of::<u16>() as u64)
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.max_size);
    }

    pub fn set_addr_cache(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        features: u64,
        broken: &Arc<AtomicBool>,
    ) {
        self.addr_cache.desc_table_host = if let Some((addr, size)) =
            mem_space.addr_cache_init(self.desc_table, AddressAttr::Ram)
        {
            if size < self.get_desc_size() {
                report_virtio_error(interrupt_cb.clone(), features, broken);
                0_u64
            } else {
                addr
            }
        } else {
            0_u64
        };

        self.addr_cache.avail_ring_host = if let Some((addr, size)) =
            mem_space.addr_cache_init(self.avail_ring, AddressAttr::Ram)
        {
            if size < self.get_avail_size(features) {
                report_virtio_error(interrupt_cb.clone(), features, broken);
                0_u64
            } else {
                addr
            }
        } else {
            0_u64
        };

        self.addr_cache.used_ring_host = if let Some((addr, size)) =
            mem_space.addr_cache_init(self.used_ring, AddressAttr::Ram)
        {
            if size < self.get_used_size(features) {
                report_virtio_error(interrupt_cb.clone(), features, broken);
                0_u64
            } else {
                addr
            }
        } else {
            0_u64
        };
    }
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

struct DescInfo {
    /// The host virtual address of the descriptor table.
    table_host: u64,
    /// The size of the descriptor table.
    size: u16,
    /// The index of the current descriptor table.
    index: u16,
    /// The descriptor table.
    desc: SplitVringDesc,
}

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

impl SplitVringDesc {
    /// Create a descriptor of split vring.
    ///
    /// # Arguments
    ///
    /// * `sys_mem` - Address space to which the vring belongs.
    /// * `desc_table` - Guest address of virtqueue descriptor table.
    /// * `queue_size` - Size of virtqueue.
    /// * `index` - Index of descriptor in the virqueue descriptor table.
    fn new(
        sys_mem: &Arc<AddressSpace>,
        desc_table_host: u64,
        queue_size: u16,
        index: u16,
        cache: &mut Option<RegionCache>,
    ) -> Result<Self> {
        if index >= queue_size {
            return Err(anyhow!(VirtioError::QueueIndex(index, queue_size)));
        }

        let desc_addr = desc_table_host
            .checked_add(u64::from(index) * DESCRIPTOR_LEN)
            .with_context(|| {
                VirtioError::AddressOverflow(
                    "creating a descriptor",
                    desc_table_host,
                    u64::from(index) * DESCRIPTOR_LEN,
                )
            })?;
        // SAFETY: dest_addr has been checked in SplitVringDesc::is_valid() and is guaranteed to be within the ram range.
        let desc = unsafe {
            read_object_direct::<SplitVringDesc>(desc_addr)
                .with_context(|| VirtioError::ReadObjectErr("a descriptor", desc_addr))
        }?;

        if desc.is_valid(sys_mem, queue_size, cache) {
            Ok(desc)
        } else {
            Err(anyhow!(VirtioError::QueueDescInvalid))
        }
    }

    /// Return true if the descriptor is valid.
    fn is_valid(
        &self,
        sys_mem: &Arc<AddressSpace>,
        queue_size: u16,
        cache: &mut Option<RegionCache>,
    ) -> bool {
        if self.len == 0 {
            error!("Zero sized buffers are not allowed");
            return false;
        }
        let mut miss_cached = true;
        if let Some(reg_cache) = cache {
            let base = self.addr.0;
            let offset = u64::from(self.len);
            let end = match base.checked_add(offset) {
                Some(addr) => addr,
                None => {
                    error!("The memory of descriptor is invalid, range overflows");
                    return false;
                }
            };
            // GPAChecked: the vring desc [addr, addr+len] must locate in guest ram.
            if base > reg_cache.start && end < reg_cache.end {
                miss_cached = false;
            }
        } else {
            let gotten_cache = sys_mem.get_region_cache(self.addr, AddressAttr::Ram);
            if let Some(obtained_cache) = gotten_cache {
                if obtained_cache.reg_type == RegionType::Ram {
                    *cache = gotten_cache;
                }
            }
        }

        if miss_cached {
            // GPAChecked: the vring desc addr must locate in guest ram.
            if let Err(ref e) = checked_offset_mem(sys_mem, self.addr, u64::from(self.len)) {
                error!("The memory of descriptor is invalid, {:?} ", e);
                return false;
            }
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
        desc_table_host: u64,
        queue_size: u16,
        index: u16,
        cache: &mut Option<RegionCache>,
    ) -> Result<SplitVringDesc> {
        SplitVringDesc::new(sys_mem, desc_table_host, queue_size, index, cache)
            .with_context(|| format!("Failed to find next descriptor {}", index))
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
        if self.len == 0
            || u64::from(self.len) % DESCRIPTOR_LEN != 0
            || u64::from(self.len) / DESCRIPTOR_LEN > u64::from(u16::MAX)
        {
            error!("The indirect descriptor is invalid, len: {}", self.len);
            return false;
        }
        if self.has_next() {
            error!("INDIRECT and NEXT flag should not be used together");
            return false;
        }
        true
    }

    /// Get the num of descriptor in the table of indirect descriptor.
    fn get_desc_num(&self) -> u16 {
        (u64::from(self.len) / DESCRIPTOR_LEN) as u16
    }

    /// Get element from descriptor chain.
    fn get_element(
        sys_mem: &Arc<AddressSpace>,
        desc_info: &DescInfo,
        cache: &mut Option<RegionCache>,
        elem: &mut Element,
    ) -> Result<()> {
        let mut desc_table_host = desc_info.table_host;
        let mut desc_size = desc_info.size;
        let mut desc = desc_info.desc;
        elem.index = desc_info.index;
        let mut queue_size = desc_size;
        let mut indirect: bool = false;
        let mut write_elem_count: u32 = 0;
        let mut desc_total_len: u64 = 0;

        loop {
            if elem.desc_num >= desc_size {
                bail!("The element desc number exceeds max allowed");
            }

            if desc.is_indirect_desc() {
                if !desc.is_valid_indirect_desc() {
                    return Err(anyhow!(VirtioError::QueueDescInvalid));
                }
                if !indirect {
                    indirect = true;
                } else {
                    bail!("Found two indirect descriptor elem in one request");
                }
                (desc_table_host, _) = sys_mem
                    .get_host_address_from_cache(desc.addr, cache)
                    .with_context(|| "Failed to get descriptor table entry host address")?;
                queue_size = desc.get_desc_num();
                desc = Self::next_desc(sys_mem, desc_table_host, queue_size, 0, cache)?;
                desc_size = elem
                    .desc_num
                    .checked_add(queue_size)
                    .with_context(|| "The chained desc number overflows")?;
                continue;
            }

            let iovec = ElemIovec {
                addr: desc.addr,
                len: desc.len,
            };

            if desc.write_only() {
                elem.in_iovec.push(iovec);
                write_elem_count += 1;
            } else {
                if write_elem_count > 0 {
                    bail!("Invalid order of the descriptor elem");
                }
                elem.out_iovec.push(iovec);
            }
            elem.desc_num += 1;
            // Note: iovec.addr + iovec.len is located in RAM, and iovec.len is not greater than the
            // VM RAM size. The number of iovec is not greater than 'queue_size * 2 - 1' which with
            // a indirect table. Currently, the max value of queue_size is 1024. So, desc_total_len
            // must not overflow.
            desc_total_len += u64::from(iovec.len);

            if desc.has_next() {
                desc = Self::next_desc(sys_mem, desc_table_host, queue_size, desc.next, cache)?;
            } else {
                break;
            }
        }

        if desc_total_len > DESC_CHAIN_MAX_TOTAL_LEN {
            bail!("Find a descriptor chain longer than 4GB in total");
        }

        Ok(())
    }
}

impl ByteCode for SplitVringDesc {}

/// Split vring.
#[derive(Default, Clone, Copy)]
pub struct SplitVring {
    /// Region cache information.
    cache: Option<RegionCache>,
    /// The configuration of virtqueue.
    queue_config: QueueConfig,
}

impl Deref for SplitVring {
    type Target = QueueConfig;
    fn deref(&self) -> &Self::Target {
        &self.queue_config
    }
}

impl DerefMut for SplitVring {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.queue_config
    }
}

impl SplitVring {
    /// Create a split vring.
    ///
    /// # Arguments
    ///
    /// * `queue_config` - Configuration of the vring.
    pub fn new(queue_config: QueueConfig) -> Self {
        SplitVring {
            cache: None,
            queue_config,
        }
    }

    /// The actual size of the queue.
    fn actual_size(&self) -> u16 {
        min(self.size, self.max_size)
    }

    /// Get the flags and idx of the available ring from guest memory.
    fn get_avail_flags_idx(&self) -> Result<SplitVringFlagsIdx> {
        // SAFETY: avail_ring_host is checked when addr_cache inited.
        unsafe {
            read_object_direct::<SplitVringFlagsIdx>(self.addr_cache.avail_ring_host).with_context(
                || VirtioError::ReadObjectErr("avail flags idx", self.avail_ring.raw_value()),
            )
        }
    }

    /// Get the idx of the available ring from guest memory.
    fn get_avail_idx(&self) -> Result<u16> {
        let flags_idx = self.get_avail_flags_idx()?;
        Ok(flags_idx.idx)
    }

    /// Get the flags of the available ring from guest memory.
    fn get_avail_flags(&self) -> Result<u16> {
        let flags_idx = self.get_avail_flags_idx()?;
        Ok(flags_idx.flags)
    }

    /// Get the flags and idx of the used ring from guest memory.
    fn get_used_flags_idx(&self) -> Result<SplitVringFlagsIdx> {
        // Make sure the idx read from sys_mem is new.
        fence(Ordering::SeqCst);
        // SAFETY: used_ring_host has been checked in set_addr_cache() and is guaranteed to be within the ram range.
        unsafe {
            read_object_direct::<SplitVringFlagsIdx>(self.addr_cache.used_ring_host).with_context(
                || VirtioError::ReadObjectErr("used flags idx", self.used_ring.raw_value()),
            )
        }
    }

    /// Get the index of the used ring from guest memory.
    fn get_used_idx(&self) -> Result<u16> {
        let flag_idx = self.get_used_flags_idx()?;
        Ok(flag_idx.idx)
    }

    /// Set the used flags to suppress virtqueue notification or not
    fn set_used_flags(&self, suppress: bool) -> Result<()> {
        let mut flags_idx = self.get_used_flags_idx()?;

        if suppress {
            flags_idx.flags |= VRING_USED_F_NO_NOTIFY;
        } else {
            flags_idx.flags &= !VRING_USED_F_NO_NOTIFY;
        }
        // SAFETY: used_ring_host has been checked when addr_cache inited.
        unsafe {
            write_object_direct::<SplitVringFlagsIdx>(&flags_idx, self.addr_cache.used_ring_host)
                .with_context(|| {
                    format!(
                        "Failed to set used flags, used_ring: 0x{:X}",
                        self.used_ring.raw_value()
                    )
                })
        }?;
        // Make sure the data has been set.
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Set the avail idx to the field of the event index for the available ring.
    fn set_avail_event(&self, event_idx: u16) -> Result<()> {
        trace::virtqueue_set_avail_event(self as *const _ as u64, event_idx);
        let avail_event_offset =
            VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * u64::from(self.actual_size());
        // SAFETY: used_ring_host has been checked in set_addr_cache().
        unsafe {
            write_object_direct(
                &event_idx,
                self.addr_cache.used_ring_host + avail_event_offset,
            )
            .with_context(|| {
                format!(
                    "Failed to set avail event idx, used_ring: 0x{:X}, offset: {}",
                    self.used_ring.raw_value(),
                    avail_event_offset,
                )
            })
        }?;
        // Make sure the data has been set.
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Get the event index of the used ring from guest memory.
    fn get_used_event(&self) -> Result<u16> {
        let used_event_offset =
            VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * u64::from(self.actual_size());
        // Make sure the event idx read from sys_mem is new.
        fence(Ordering::SeqCst);
        // The GPA of avail_ring_host with avail table length has been checked in
        // is_invalid_memory which must not be overflowed.
        let used_event_addr = self.addr_cache.avail_ring_host + used_event_offset;
        // SAFETY: used_event_addr is protected by virtio calculations and is guaranteed to be within the ram range.
        let used_event = unsafe {
            read_object_direct::<u16>(used_event_addr)
                .with_context(|| VirtioError::ReadObjectErr("used event id", used_event_addr))
        }?;

        Ok(used_event)
    }

    /// Return true if VRING_AVAIL_F_NO_INTERRUPT is set.
    fn is_avail_ring_no_interrupt(&self) -> bool {
        match self.get_avail_flags() {
            Ok(avail_flags) => (avail_flags & VRING_AVAIL_F_NO_INTERRUPT) != 0,
            Err(ref e) => {
                warn!(
                    "Failed to get the status for VRING_AVAIL_F_NO_INTERRUPT {:?}",
                    e
                );
                false
            }
        }
    }

    /// Return true if it's required to trigger interrupt for the used vring.
    fn used_ring_need_event(&mut self) -> bool {
        let old = self.last_signal_used;
        let new = match self.get_used_idx() {
            Ok(used_idx) => Wrapping(used_idx),
            Err(ref e) => {
                error!("Failed to get the status for notifying used vring: {:?}", e);
                return false;
            }
        };

        let used_event_idx = match self.get_used_event() {
            Ok(idx) => Wrapping(idx),
            Err(ref e) => {
                error!("Failed to get the status for notifying used vring: {:?}", e);
                return false;
            }
        };

        let valid = self.signal_used_valid;
        self.signal_used_valid = true;
        self.last_signal_used = new;
        !valid || (new - used_event_idx - Wrapping(1)) < (new - old)
    }

    fn is_overlap(
        start1: GuestAddress,
        end1: GuestAddress,
        start2: GuestAddress,
        end2: GuestAddress,
    ) -> bool {
        !(start1 >= end2 || start2 >= end1)
    }

    fn is_invalid_memory(&self, sys_mem: &Arc<AddressSpace>, actual_size: u64) -> bool {
        // GPAChecked: the desc ring table must locate in guest ram.
        let desc_table_end =
            match checked_offset_mem(sys_mem, self.desc_table, DESCRIPTOR_LEN * actual_size) {
                Ok(addr) => addr,
                Err(ref e) => {
                    error!(
                        "descriptor table is out of bounds: start:0x{:X} size:{} {:?}",
                        self.desc_table.raw_value(),
                        DESCRIPTOR_LEN * actual_size,
                        e
                    );
                    return true;
                }
            };

        // GPAChecked: the avail ring table must locate in guest ram.
        let desc_avail_end = match checked_offset_mem(
            sys_mem,
            self.avail_ring,
            VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * actual_size,
        ) {
            Ok(addr) => addr,
            Err(ref e) => {
                error!(
                    "avail ring is out of bounds: start:0x{:X} size:{} {:?}",
                    self.avail_ring.raw_value(),
                    VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * actual_size,
                    e
                );
                return true;
            }
        };

        // GPAChecked: the used ring table must locate in guest ram.
        let desc_used_end = match checked_offset_mem(
            sys_mem,
            self.used_ring,
            VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * actual_size,
        ) {
            Ok(addr) => addr,
            Err(ref e) => {
                error!(
                    "used ring is out of bounds: start:0x{:X} size:{} {:?}",
                    self.used_ring.raw_value(),
                    VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * actual_size,
                    e,
                );
                return true;
            }
        };

        if SplitVring::is_overlap(
            self.desc_table,
            desc_table_end,
            self.avail_ring,
            desc_avail_end,
        ) || SplitVring::is_overlap(
            self.avail_ring,
            desc_avail_end,
            self.used_ring,
            desc_used_end,
        ) || SplitVring::is_overlap(
            self.desc_table,
            desc_table_end,
            self.used_ring,
            desc_used_end,
        ) {
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

    fn get_desc_info(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        next_avail: Wrapping<u16>,
        features: u64,
    ) -> Result<DescInfo> {
        let index_offset =
            VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * u64::from(next_avail.0 % self.actual_size());
        // The GPA of avail_ring_host with avail table length has been checked in
        // is_invalid_memory which must not be overflowed.
        let desc_index_addr = self.addr_cache.avail_ring_host + index_offset;
        // SAFETY: dest_index_addr is protected by virtio calculations and is guaranteed to be within the ram range.
        let desc_index = unsafe {
            read_object_direct::<u16>(desc_index_addr).with_context(|| {
                VirtioError::ReadObjectErr("the index of descriptor", desc_index_addr)
            })
        }?;

        let desc = SplitVringDesc::new(
            sys_mem,
            self.addr_cache.desc_table_host,
            self.actual_size(),
            desc_index,
            &mut self.cache,
        )?;

        // Suppress queue notification related to current processing desc chain.
        if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            self.set_avail_event((next_avail + Wrapping(1)).0)
                .with_context(|| "Failed to set avail event for popping avail ring")?;
        }

        Ok(DescInfo {
            table_host: self.addr_cache.desc_table_host,
            size: self.actual_size(),
            index: desc_index,
            desc,
        })
    }

    fn get_vring_element(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        features: u64,
        elem: &mut Element,
    ) -> Result<()> {
        let desc_info = self.get_desc_info(sys_mem, self.next_avail, features)?;

        SplitVringDesc::get_element(sys_mem, &desc_info, &mut self.cache, elem).with_context(
            || {
                format!(
                    "Failed to get element from descriptor chain {}, table addr: 0x{:X}, size: {}",
                    desc_info.index, desc_info.table_host, desc_info.size,
                )
            },
        )?;
        self.next_avail += Wrapping(1);

        Ok(())
    }
}

impl VringOps for SplitVring {
    fn is_enabled(&self) -> bool {
        self.ready
    }

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
        let mut element = Element::new(0);
        if !self.is_enabled() || self.avail_ring_len()? == 0 {
            return Ok(element);
        }

        // Make sure descriptor read does not bypass avail index read.
        fence(Ordering::Acquire);

        self.get_vring_element(sys_mem, features, &mut element)
            .with_context(|| "Failed to get vring element")?;

        trace::virtqueue_pop_avail(
            &*self as *const _ as u64,
            element.in_iovec.len(),
            element.out_iovec.len(),
        );

        Ok(element)
    }

    fn push_back(&mut self) {
        self.next_avail -= Wrapping(1);
    }

    fn add_used(&mut self, index: u16, len: u32) -> Result<()> {
        if index >= self.size {
            return Err(anyhow!(VirtioError::QueueIndex(index, self.size)));
        }

        let next_used = u64::from(self.next_used.0 % self.actual_size());
        trace::virtqueue_add_used(&*self as *const _ as u64, next_used, index, len);
        let used_elem_addr =
            self.addr_cache.used_ring_host + VRING_FLAGS_AND_IDX_LEN + next_used * USEDELEM_LEN;
        let used_elem = UsedElem {
            id: u32::from(index),
            len,
        };
        // SAFETY: used_elem_addr is guaranteed to be within ram range.
        unsafe {
            write_object_direct::<UsedElem>(&used_elem, used_elem_addr)
                .with_context(|| "Failed to write object for used element")
        }?;
        // Make sure used element is filled before updating used idx.
        fence(Ordering::Release);

        self.next_used += Wrapping(1);
        // SAFETY: used_ring_host has been checked when addr_cache inited.
        unsafe {
            write_object_direct(
                &(self.next_used.0),
                self.addr_cache.used_ring_host + VRING_IDX_POSITION,
            )
            .with_context(|| "Failed to write next used idx")
        }?;
        // Make sure used index is exposed before notifying guest.
        fence(Ordering::SeqCst);

        // Do we wrap around?
        if self.next_used == self.last_signal_used {
            self.signal_used_valid = false;
        }
        Ok(())
    }

    fn should_notify(&mut self, features: u64) -> bool {
        if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            self.used_ring_need_event()
        } else {
            !self.is_avail_ring_no_interrupt()
        }
    }

    fn suppress_queue_notify(&mut self, features: u64, suppress: bool) -> Result<()> {
        if !self.is_enabled() {
            bail!("queue is not ready");
        }

        if virtio_has_feature(features, VIRTIO_F_RING_EVENT_IDX) {
            self.set_avail_event(self.get_avail_idx()?)?;
        } else {
            self.set_used_flags(suppress)?;
        }
        Ok(())
    }

    fn actual_size(&self) -> u16 {
        self.actual_size()
    }

    fn get_queue_config(&self) -> QueueConfig {
        let mut config = self.queue_config;
        config.signal_used_valid = false;
        config
    }

    /// The number of descriptor chains in the available ring.
    fn avail_ring_len(&mut self) -> Result<u16> {
        let avail_idx = self.get_avail_idx().map(Wrapping)?;

        Ok((avail_idx - self.next_avail).0)
    }

    fn get_avail_idx(&self) -> Result<u16> {
        SplitVring::get_avail_idx(self)
    }

    fn get_used_idx(&self) -> Result<u16> {
        SplitVring::get_used_idx(self)
    }

    fn get_cache(&self) -> &Option<RegionCache> {
        &self.cache
    }

    fn get_avail_bytes(
        &mut self,
        sys_mem: &Arc<AddressSpace>,
        max_size: usize,
        is_in: bool,
    ) -> Result<usize> {
        if !self.is_enabled() {
            return Ok(0);
        }
        fence(Ordering::Acquire);

        let mut avail_bytes = 0_usize;
        let mut avail_idx = self.next_avail;
        let end_idx = self.get_avail_idx().map(Wrapping)?;
        while (end_idx - avail_idx).0 > 0 {
            let desc_info = self.get_desc_info(sys_mem, avail_idx, 0)?;

            let mut elem = Element::new(0);
            SplitVringDesc::get_element(sys_mem, &desc_info, &mut self.cache, &mut elem).with_context(
                || {
                    format!(
                        "Failed to get element from descriptor chain {}, table addr: 0x{:X}, size: {}",
                        desc_info.index, desc_info.table_host, desc_info.size,
                    )
                },
            )?;

            for e in match is_in {
                true => elem.in_iovec,
                false => elem.out_iovec,
            } {
                avail_bytes += e.len as usize;
            }

            if avail_bytes >= max_size {
                return Ok(max_size);
            }
            avail_idx += Wrapping(1);
        }
        Ok(avail_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::address_space_init;
    use crate::{Queue, QUEUE_TYPE_PACKED_VRING, QUEUE_TYPE_SPLIT_VRING};
    use address_space::{AddressAttr, AddressSpace, GuestAddress};

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
                return Err(anyhow!(VirtioError::QueueIndex(index, self.size)));
            }

            let desc_addr_offset = DESCRIPTOR_LEN * u64::from(index);
            let desc = SplitVringDesc {
                addr,
                len,
                flags,
                next,
            };
            sys_mem.write_object::<SplitVringDesc>(
                &desc,
                GuestAddress(self.desc_table.0 + desc_addr_offset),
                AddressAttr::Ram,
            )?;

            Ok(())
        }

        fn set_avail_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let avail_idx_offset = 2_u64;
            sys_mem.write_object::<u16>(
                &idx,
                GuestAddress(self.avail_ring.0 + avail_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(())
        }

        fn set_avail_ring_flags(&self, sys_mem: &Arc<AddressSpace>, flags: u16) -> Result<()> {
            let avail_idx_offset = 0_u64;
            sys_mem.write_object::<u16>(
                &flags,
                GuestAddress(self.avail_ring.0 + avail_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(())
        }

        fn set_avail_ring_elem(
            &self,
            sys_mem: &Arc<AddressSpace>,
            avail_pos: u16,
            desc_index: u16,
        ) -> Result<()> {
            let avail_idx_offset = VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * u64::from(avail_pos);
            sys_mem.write_object::<u16>(
                &desc_index,
                GuestAddress(self.avail_ring.0 + avail_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(())
        }

        fn get_avail_event(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
            let avail_event_idx_offset =
                VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * u64::from(self.actual_size());
            let event_idx = sys_mem.read_object::<u16>(
                GuestAddress(self.used_ring.0 + avail_event_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(event_idx)
        }

        fn get_used_elem(&self, sys_mem: &Arc<AddressSpace>, index: u16) -> Result<UsedElem> {
            let used_elem_offset = VRING_FLAGS_AND_IDX_LEN + USEDELEM_LEN * u64::from(index);
            let used_elem = sys_mem.read_object::<UsedElem>(
                GuestAddress(self.used_ring.0 + used_elem_offset),
                AddressAttr::Ram,
            )?;
            Ok(used_elem)
        }

        fn get_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>) -> Result<u16> {
            let used_idx_offset = VRING_IDX_POSITION;
            let idx = sys_mem.read_object::<u16>(
                GuestAddress(self.used_ring.0 + used_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(idx)
        }

        fn set_used_ring_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let used_idx_offset = VRING_IDX_POSITION;
            sys_mem.write_object::<u16>(
                &idx,
                GuestAddress(self.used_ring.0 + used_idx_offset),
                AddressAttr::Ram,
            )?;
            Ok(())
        }

        fn set_used_event_idx(&self, sys_mem: &Arc<AddressSpace>, idx: u16) -> Result<()> {
            let event_idx_offset =
                VRING_FLAGS_AND_IDX_LEN + AVAILELEM_LEN * u64::from(self.actual_size());
            sys_mem.write_object::<u16>(
                &idx,
                GuestAddress(self.avail_ring.0 + event_idx_offset),
                AddressAttr::Ram,
            )?;
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
        sys_mem.write_object::<SplitVringDesc>(&desc, desc_addr, AddressAttr::Ram)?;
        Ok(())
    }

    const SYSTEM_SPACE_SIZE: u64 = (1024 * 1024) as u64;
    const QUEUE_SIZE: u16 = 256_u16;

    fn align(size: u64, alignment: u64) -> u64 {
        let align_adjust = if size % alignment != 0 {
            alignment - (size % alignment)
        } else {
            0
        };
        size + align_adjust
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
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the status is not ready
        queue_config.ready = false;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        queue_config.ready = true;

        // it is invalid when the size of virtual ring is more than the max size
        queue_config.size = QUEUE_SIZE + 1;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));

        // it is invalid when the size of virtual ring is zero
        queue_config.size = 0;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));

        // it is invalid when the size of virtual ring isn't power of 2
        queue_config.size = 15;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
    }

    #[test]
    fn test_valid_queue_02() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of descriptor table is out of bound
        queue_config.desc_table =
            GuestAddress(SYSTEM_SPACE_SIZE - u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN + 1_u64);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.desc_table = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of avail ring is out of bound
        queue_config.avail_ring = GuestAddress(
            SYSTEM_SPACE_SIZE
                - (VRING_AVAIL_LEN_EXCEPT_AVAILELEM + AVAILELEM_LEN * u64::from(QUEUE_SIZE))
                + 1_u64,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of used ring is out of bound
        queue_config.used_ring = GuestAddress(
            SYSTEM_SPACE_SIZE
                - (VRING_USED_LEN_EXCEPT_USEDELEM + USEDELEM_LEN * u64::from(QUEUE_SIZE))
                + 1_u64,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));
    }

    #[test]
    fn test_valid_queue_03() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of descriptor table is equal to the address of avail ring
        queue_config.avail_ring = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of descriptor table is overlapped to the address of avail
        // ring.
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN - 1);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of avail ring is equal to the address of used ring
        queue_config.used_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of avail ring is overlapped to the address of used ring
        queue_config.used_ring = GuestAddress(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE)
                - 1,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));
    }

    #[test]
    fn test_valid_queue_04() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of descriptor table is not aligned to 16
        queue_config.desc_table = GuestAddress(15_u64);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.desc_table = GuestAddress(0);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of avail ring is not aligned to 2
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN + 1);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));

        // it is invalid when the address of used ring is not aligned to 4
        queue_config.used_ring = GuestAddress(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE)
                + 3,
        );
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(!queue.is_valid(&sys_space));
        // recover the address for valid queue
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING).unwrap();
        assert!(queue.is_valid(&sys_space));
    }

    #[test]
    fn test_pop_avail_01() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

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

        let features = 1 << u64::from(VIRTIO_F_RING_EVENT_IDX);
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
        let elem_iov = elem.out_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x111));
        assert_eq!(elem_iov.len, 16);
        assert_eq!(elem.in_iovec.len(), 2);
        let elem_iov = elem.in_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x222));
        assert_eq!(elem_iov.len, 32);
        let elem_iov = elem.in_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x333));
        assert_eq!(elem_iov.len, 48);

        // the event idx of avail ring is equal to get_avail_event
        let event_idx = vring.get_avail_event(&sys_space).unwrap();
        assert_eq!(event_idx, 1);
        let avail_idx = vring.get_avail_idx().unwrap();
        assert_eq!(avail_idx, 1);
    }

    #[test]
    fn test_pop_avail_02() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

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

        let features = 1 << u64::from(VIRTIO_F_RING_EVENT_IDX);
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
        let elem_iov = elem.out_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x444));
        assert_eq!(elem_iov.len, 100);
        let elem_iov = elem.out_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x555));
        assert_eq!(elem_iov.len, 200);
        assert_eq!(elem.in_iovec.len(), 1);
        let elem_iov = elem.in_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x666));
        assert_eq!(elem_iov.len, 300);
    }

    #[test]
    fn test_pop_avail_03() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

        // it is error when the idx of avail ring which is equal to next_avail
        // set 0 to the idx of avail ring which is equal to next_avail
        vring.set_avail_ring_idx(&sys_space, 0).unwrap();
        let features = 1 << u64::from(VIRTIO_F_RING_EVENT_IDX);
        if let Ok(elem) = vring.pop_avail(&sys_space, features) {
            if elem.desc_num != 0 {
                assert!(false);
            }
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
            assert_eq!(err.to_string(), "Failed to get vring element");
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
        if vring.pop_avail(&sys_space, features).is_ok() {
            assert!(false);
        }

        // error comes when the length of indirect descriptor is more than the length of descriptor
        // chain set the information of index 0 for descriptor.
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
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }

        // The INDIRECT and NEXT flag should not be used together.
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                48,
                VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_NEXT,
                0,
            )
            .unwrap();
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }

        // The device-writable desc elems must behind the device-readable desc elems.
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

        // Set the information of index 0 for indirect descriptor.
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2),
            GuestAddress(0x444),
            100,
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            1,
        )
        .unwrap();
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }

        // The VIRTQ_DESC_F_NEXT must not set to the descriptor in indirect table.
        vring
            .set_desc(
                &sys_space,
                0,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                16,
                VIRTQ_DESC_F_INDIRECT,
                0,
            )
            .unwrap();

        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2),
            GuestAddress(0x444),
            100,
            VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_WRITE,
            1,
        )
        .unwrap();
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_pop_avail_04() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

        // Set the information of index 0 for normal descriptor.
        vring
            .set_desc(&sys_space, 0, GuestAddress(0x111), 16, VIRTQ_DESC_F_NEXT, 1)
            .unwrap();

        // Set the information of index 1 for normal descriptor.
        vring
            .set_desc(&sys_space, 1, GuestAddress(0x222), 32, VIRTQ_DESC_F_NEXT, 2)
            .unwrap();

        // Set the incorrect information of index 2 for normal descriptor.
        // The VIRTQ_DESC_F_INDIRECT and VIRTQ_DESC_F_NEXT flag can not be
        // used together.
        vring
            .set_desc(
                &sys_space,
                2,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                32,
                VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                0,
            )
            .unwrap();

        // Set the information of index 0 for indirect descriptor.
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2),
            GuestAddress(0x444),
            100,
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            1,
        )
        .unwrap();

        // Set the information of index 1 for indirect descriptor.
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN),
            GuestAddress(0x555),
            200,
            VIRTQ_DESC_F_WRITE,
            2,
        )
        .unwrap();

        // Set the index 0 of descriptor to the position 0 for the element of avail ring.
        vring.set_avail_ring_elem(&sys_space, 0, 0).unwrap();
        // Set 1 to the idx of avail ring.
        vring.set_avail_ring_idx(&sys_space, 1).unwrap();

        let features = 1 << u64::from(VIRTIO_F_RING_EVENT_IDX);
        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }

        // Set the correct information of index 2 for normal descriptor.
        vring
            .set_desc(
                &sys_space,
                2,
                GuestAddress(SYSTEM_SPACE_SIZE / 2),
                32,
                VIRTQ_DESC_F_INDIRECT,
                0,
            )
            .unwrap();

        // Set the incorrect information of index 1 for indirect descriptor.
        // The VIRTQ_DESC_F_INDIRECT flag can not be used in indirect descriptor
        // table.
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN),
            GuestAddress(0x555),
            208,
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_INDIRECT,
            2,
        )
        .unwrap();

        if let Err(err) = vring.pop_avail(&sys_space, features) {
            assert_eq!(err.to_string(), "Failed to get vring element");
        } else {
            assert!(false);
        }

        // Set the correct information of index 1 for indirect descriptor.
        set_indirect_desc(
            &sys_space,
            GuestAddress(SYSTEM_SPACE_SIZE / 2 + DESCRIPTOR_LEN),
            GuestAddress(0x555),
            200,
            VIRTQ_DESC_F_WRITE,
            2,
        )
        .unwrap();

        // Check the result of pop_avail(), which has normal and indirect
        // descriptor elem.
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
        assert_eq!(elem.desc_num, 4);

        // Two elem for reading.
        assert_eq!(elem.out_iovec.len(), 2);
        let elem_iov = elem.out_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x111));
        assert_eq!(elem_iov.len, 16);
        let elem_iov = elem.out_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x222));
        assert_eq!(elem_iov.len, 32);

        // Two elem for writing.
        assert_eq!(elem.in_iovec.len(), 2);
        let elem_iov = elem.in_iovec.first().unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x444));
        assert_eq!(elem_iov.len, 100);
        let elem_iov = elem.in_iovec.get(1).unwrap();
        assert_eq!(elem_iov.addr, GuestAddress(0x555));
        assert_eq!(elem_iov.len, 200);

        // The event idx of avail ring is equal to get_avail_event.
        let event_idx = vring.get_avail_event(&sys_space).unwrap();
        assert_eq!(event_idx, 1);
        let avail_idx = vring.get_avail_idx().unwrap();
        assert_eq!(avail_idx, 1);
    }

    #[test]
    fn test_add_used() {
        let sys_space = address_space_init();

        let mut queue_config = QueueConfig::new(QUEUE_SIZE);
        queue_config.desc_table = GuestAddress(0);
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

        // it is false when the index is more than the size of queue
        if let Err(err) = vring.add_used(QUEUE_SIZE, 100) {
            if let Some(e) = err.downcast_ref::<VirtioError>() {
                if let VirtioError::QueueIndex(offset, size) = e {
                    assert_eq!(*offset, 256);
                    assert_eq!(*size, 256);
                }
            }
        }

        assert!(vring.add_used(10, 100).is_ok());
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
        queue_config.addr_cache.desc_table_host = unsafe {
            sys_space
                .get_host_address(queue_config.desc_table, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.avail_ring = GuestAddress(u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN);
        queue_config.addr_cache.avail_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.avail_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.used_ring = GuestAddress(align(
            u64::from(QUEUE_SIZE) * DESCRIPTOR_LEN
                + VRING_AVAIL_LEN_EXCEPT_AVAILELEM
                + AVAILELEM_LEN * u64::from(QUEUE_SIZE),
            4096,
        ));
        queue_config.addr_cache.used_ring_host = unsafe {
            sys_space
                .get_host_address(queue_config.used_ring, AddressAttr::Ram)
                .unwrap()
        };
        queue_config.ready = true;
        queue_config.size = QUEUE_SIZE;
        let mut vring = SplitVring::new(queue_config);
        assert!(vring.is_valid(&sys_space));

        // it's true when the feature of event idx and no interrupt for the avail ring is closed
        let features = 0_u64;
        assert!(vring.set_avail_ring_flags(&sys_space, 0).is_ok());
        assert!(vring.should_notify(features));

        // it's false when the feature of event idx is closed and the feature of no interrupt for
        // the avail ring is open
        let features = 0_u64;
        assert!(vring
            .set_avail_ring_flags(&sys_space, VRING_AVAIL_F_NO_INTERRUPT)
            .is_ok());
        assert!(!vring.should_notify(features));

        // it's true when the feature of event idx is open and
        // (new - event_idx - Wrapping(1) < new -old)
        let features = 1 << u64::from(VIRTIO_F_RING_EVENT_IDX);
        vring.last_signal_used = Wrapping(5); // old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); // new
        assert!(vring.set_used_event_idx(&sys_space, 6).is_ok()); // event_idx
        assert!(vring.should_notify(features));

        // it's false when the feature of event idx is open and
        // (new - event_idx - Wrapping(1) > new - old)
        vring.last_signal_used = Wrapping(5); // old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); // new
        assert!(vring.set_used_event_idx(&sys_space, 1).is_ok()); // event_idx
        assert!(!vring.should_notify(features));

        // it's false when the feature of event idx is open and
        // (new - event_idx - Wrapping(1) = new -old)
        vring.last_signal_used = Wrapping(5); // old
        assert!(vring.set_used_ring_idx(&sys_space, 10).is_ok()); // new
        assert!(vring.set_used_event_idx(&sys_space, 4).is_ok()); // event_idx
        assert!(!vring.should_notify(features));
    }
}
