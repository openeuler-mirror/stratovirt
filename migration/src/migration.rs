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

use std::collections::HashMap;
use std::io::{Read, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use kvm_bindings::kvm_userspace_memory_region as MemorySlot;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::general::Lifecycle;
use crate::manager::MIGRATION_MANAGER;
use crate::protocol::{MemBlock, MigrationStatus, Request, Response, TransStatus};
use crate::MigrationManager;
use hypervisor::kvm::KVM_FDS;
use util::unix::host_page_size;

/// Dirty bitmap information of vmm memory slot.
pub struct DirtyBitmap {
    /// Guest address.
    pub gpa: u64,
    /// Host address.
    pub hva: u64,
    /// length of memory.
    pub len: u64,
    /// Bitmap for vmm memory slot.
    pub map: Vec<AtomicU64>,
    /// Host page size.
    pub page_size: u64,
}

impl DirtyBitmap {
    /// Create a new dirty bitmap for vmm.
    ///
    /// # Arguments
    ///
    /// * `gpa` - Guest physical address of memory slot.
    /// * `hva` - Host virtual address of memory slot.
    /// * `len` - Length of memory slot.
    pub fn new(gpa: u64, hva: u64, len: u64) -> Self {
        let page_size = host_page_size();

        let mut num_pages = len / page_size;
        // Page alignment.
        if len % page_size > 0 {
            num_pages += 1;
        }
        let size = num_pages / 64 + 1;
        let map: Vec<AtomicU64> = (0..size).map(|_| AtomicU64::new(0)).collect();

        DirtyBitmap {
            gpa,
            hva,
            len,
            map,
            page_size,
        }
    }

    /// Mark dirty bitmap for vmm.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest physical address of memory.
    /// * `len` - Length of memory slot.
    pub fn mark_bitmap(&self, addr: u64, len: u64) {
        // Just return if len is 0.
        if len == 0 {
            return;
        }

        let offset = addr - self.gpa;
        let first_bit = offset / self.page_size;
        let last_bit = (offset + len) / self.page_size;
        for n in first_bit..last_bit {
            // Ignore bit that is out of range.
            if n >= self.len {
                break;
            }
            self.map[(n as usize) >> 6].fetch_or(1 << (n & 63), Ordering::SeqCst);
        }
    }

    /// Get and clear dirty bitmap for vmm.
    pub fn get_and_clear_dirty(&self) -> Vec<u64> {
        self.map
            .iter()
            .map(|m| m.fetch_and(0, Ordering::SeqCst))
            .collect()
    }
}

pub trait Migratable {
    /// Start the dirty log in the kvm and vmm.
    fn start_dirty_log() -> Result<()> {
        // Create dirty bitmaps for vmm.
        let mut bitmaps = HashMap::<u32, DirtyBitmap>::new();
        let mem_slots = KVM_FDS.load().get_mem_slots();
        for (_, slot) in mem_slots.lock().unwrap().iter() {
            let bitmap =
                DirtyBitmap::new(slot.guest_phys_addr, slot.userspace_addr, slot.memory_size);
            bitmaps.insert(slot.slot, bitmap);
        }
        let mut vm_bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        *vm_bitmaps = bitmaps;

        // Start logging dirty memory in kvm.
        KVM_FDS.load().start_dirty_log()?;

        Ok(())
    }

    /// Stop the dirty log in the kvm and vmm.
    fn stop_dirty_log() -> Result<()> {
        // Clear dirty bitmaps from vmm.
        let mut vm_bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        *vm_bitmaps = HashMap::new();

        // Stop logging dirty memory in kvm.
        KVM_FDS.load().stop_dirty_log()?;

        Ok(())
    }

    /// Collect the dirty log from kvm and vmm.
    ///
    /// # Arguments
    ///
    /// * `slot` - The memory slot.
    fn get_dirty_log(slot: &MemorySlot) -> Result<Vec<MemBlock>> {
        // Get dirty memory from vmm.
        let mut vmm_dirty_bitmap = Vec::new();
        let bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        for (_, map) in bitmaps.iter() {
            if (slot.guest_phys_addr == map.gpa) && (slot.memory_size == map.len) {
                vmm_dirty_bitmap = map.get_and_clear_dirty();
            }
        }

        // Get dirty memory from kvm.
        let vm_dirty_bitmap = KVM_FDS
            .load()
            .get_dirty_log(slot.slot, slot.memory_size)
            .unwrap();

        // Merge dirty bitmap.
        let dirty_bitmap: Vec<u64> = vm_dirty_bitmap
            .iter()
            .zip(vmm_dirty_bitmap.iter())
            .map(|(x, y)| x | y)
            .collect();

        // Convert dirty bitmaps to memory blocks.
        Ok(Self::sync_dirty_bitmap(dirty_bitmap, slot.guest_phys_addr))
    }

    /// mark the dirty log into vmm.
    ///
    /// # Arguments
    ///
    /// * `addr` - Start address of dirty memory.
    /// * `len` - Length of dirty memory.
    fn mark_dirty_log(addr: u64, len: u64) {
        let bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        for (_, map) in bitmaps.iter() {
            if (addr >= map.hva) && ((addr + len) <= (map.hva + map.len)) {
                map.mark_bitmap(addr - map.hva + map.gpa, len);
            }
        }
    }

    /// sync the dirty log from kvm bitmaps.
    ///
    /// # Arguments
    ///
    /// * `bitmap` - dirty bitmap from kvm.
    /// * `addr` - Start address of memory slot.
    fn sync_dirty_bitmap(bitmap: Vec<u64>, addr: u64) -> Vec<MemBlock> {
        let page_size = host_page_size();
        let mut mem_blocks: Vec<MemBlock> = Vec::new();
        let mut block: Option<MemBlock> = None;

        for (idx, num) in bitmap.iter().enumerate() {
            if *num == 0 {
                continue;
            }

            for bit in 0..64 {
                if ((num >> bit) & 1_u64) == 0 {
                    if let Some(entry) = block.take() {
                        mem_blocks.push(entry);
                    }
                    continue;
                }

                if let Some(e) = &mut block {
                    e.len += page_size;
                } else {
                    let offset = ((idx * 64) + bit) as u64 * page_size;
                    block = Some(MemBlock {
                        gpa: addr + offset,
                        len: page_size,
                    });
                }
            }
        }
        if let Some(entry) = block.take() {
            mem_blocks.push(entry);
        }

        mem_blocks
    }
}

impl Migratable for MigrationManager {}
