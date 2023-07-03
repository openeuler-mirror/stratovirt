// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{cell::RefCell, rc::Rc};

use anyhow::{Context, Result};

use super::ENTRY_BITS;
use crate::qcow2::{
    cache::{CacheTable, Qcow2Cache},
    header::QcowHeader,
    SyncAioInfo, ENTRY_SIZE, L1_TABLE_OFFSET_MASK, L2_TABLE_OFFSET_MASK, QCOW2_OFFSET_COMPRESSED,
    QCOW2_OFLAG_ZERO,
};
use util::num_ops::div_round_up;

// L2 Cache max size is 32M.
const MAX_L2_CACHE_SIZE: u64 = 32 * (1 << 20);

#[derive(PartialEq, Eq, Debug)]
pub enum Qcow2ClusterType {
    /// Cluster is unallocated.
    Unallocated,
    /// Cluster is zero and not allocated.
    ZeroPlain,
    /// cluster is zero and allocated.
    ZeroAlloc,
    /// Cluster is allocated.
    Normal,
    /// Cluster is compressed.
    Compressed,
}

impl Qcow2ClusterType {
    pub fn is_allocated(&self) -> bool {
        self.eq(&Qcow2ClusterType::Compressed)
            || self.eq(&Qcow2ClusterType::Normal)
            || self.eq(&Qcow2ClusterType::ZeroAlloc)
    }

    pub fn is_read_zero(&self) -> bool {
        if self.eq(&Qcow2ClusterType::Unallocated)
            || self.eq(&Qcow2ClusterType::ZeroAlloc)
            || self.eq(&Qcow2ClusterType::ZeroPlain)
        {
            return true;
        }
        false
    }

    /// Get cluster type of l2 table entry.
    pub fn get_cluster_type(l2_entry: u64) -> Self {
        if l2_entry & QCOW2_OFFSET_COMPRESSED != 0 {
            return Qcow2ClusterType::Compressed;
        }
        if l2_entry & QCOW2_OFLAG_ZERO != 0 {
            if l2_entry & L2_TABLE_OFFSET_MASK != 0 {
                return Qcow2ClusterType::ZeroAlloc;
            }
            return Qcow2ClusterType::ZeroPlain;
        }
        if l2_entry & L2_TABLE_OFFSET_MASK == 0 {
            return Qcow2ClusterType::Unallocated;
        }
        Qcow2ClusterType::Normal
    }
}

pub struct Qcow2Table {
    pub cluster_bits: u64,
    pub cluster_size: u64,
    pub l1_table: Vec<u64>,
    pub l2_table_cache: Qcow2Cache,
    sync_aio: Rc<RefCell<SyncAioInfo>>,
    l2_bits: u64,
    l2_size: u64,
}

impl Qcow2Table {
    pub fn new(sync_aio: Rc<RefCell<SyncAioInfo>>) -> Self {
        Self {
            sync_aio,
            cluster_bits: 0,
            cluster_size: 0,
            l1_table: Vec::new(),
            l2_table_cache: Qcow2Cache::default(),
            l2_bits: 0,
            l2_size: 0,
        }
    }

    pub fn init_table(&mut self, header: &QcowHeader) -> Result<()> {
        let max_l2_entries =
            div_round_up(header.size, header.cluster_size()).with_context(|| {
                format!(
                    "Invalid size {} or cluster size {}",
                    header.size,
                    header.cluster_size()
                )
            })?;
        let max_l2_cache = div_round_up(max_l2_entries * ENTRY_SIZE, header.cluster_size())
            .with_context(|| {
                format!(
                    "Invalid l2 entries {} or cluster size {}",
                    max_l2_entries * ENTRY_SIZE,
                    header.cluster_size()
                )
            })?;
        let cache_size = std::cmp::min(max_l2_cache, MAX_L2_CACHE_SIZE / header.cluster_size());
        let l2_table_cache: Qcow2Cache = Qcow2Cache::new(cache_size as usize);
        self.cluster_bits = header.cluster_bits as u64;
        self.cluster_size = header.cluster_size();
        self.l2_bits = header.cluster_bits as u64 - ENTRY_BITS;
        self.l2_size = header.cluster_size() / ENTRY_SIZE;
        self.l2_table_cache = l2_table_cache;
        self.load_l1_table(header)
            .with_context(|| "Failed to load l1 table")?;
        Ok(())
    }

    fn load_l1_table(&mut self, header: &QcowHeader) -> Result<()> {
        self.l1_table = self
            .sync_aio
            .borrow_mut()
            .read_ctrl_cluster(header.l1_table_offset, header.l1_size as u64)?;
        Ok(())
    }

    pub fn save_l1_table(&mut self, header: &QcowHeader) -> Result<()> {
        self.sync_aio
            .borrow_mut()
            .write_ctrl_cluster(header.l1_table_offset, &self.l1_table)
    }

    pub fn get_l1_table_index(&self, guest_offset: u64) -> u64 {
        guest_offset >> (self.cluster_bits + self.l2_bits)
    }

    pub fn get_l2_table_index(&self, guest_offset: u64) -> u64 {
        (guest_offset >> self.cluster_bits) & (self.l2_size - 1)
    }

    pub fn get_l1_table_entry(&self, guest_offset: u64) -> u64 {
        let l1_idx = self.get_l1_table_index(guest_offset);
        self.l1_table[l1_idx as usize]
    }

    pub fn get_l2_table_cache_entry(
        &mut self,
        guest_offset: u64,
    ) -> Option<&Rc<RefCell<CacheTable>>> {
        let l1_entry = self.get_l1_table_entry(guest_offset);
        let l2_entry_addr = l1_entry & L1_TABLE_OFFSET_MASK;
        if l2_entry_addr == 0 {
            None
        } else {
            self.l2_table_cache.get(l2_entry_addr)
        }
    }

    pub fn update_l1_table(&mut self, l1_index: usize, l2_address: u64) {
        self.l1_table[l1_index] = l2_address;
    }

    pub fn update_l2_table(&mut self, l2_table_entry: Rc<RefCell<CacheTable>>) -> Result<()> {
        let l2_entry_addr = l2_table_entry.borrow().addr;
        if self.l2_table_cache.contains_keys(l2_entry_addr as u64) {
            return Ok(());
        }
        if let Some(replaced_entry) = self
            .l2_table_cache
            .lru_replace(l2_entry_addr as u64, l2_table_entry)
        {
            let borrowed_entry = replaced_entry.borrow();
            // Flush the dirty entry.
            if borrowed_entry.dirty_info.is_dirty {
                self.sync_aio.borrow_mut().write_dirty_info(
                    borrowed_entry.addr,
                    borrowed_entry.get_value(),
                    borrowed_entry.dirty_info.start,
                    borrowed_entry.dirty_info.end,
                )?;
            }
        }
        Ok(())
    }

    pub fn flush_l2_table_cache(&self) -> Result<()> {
        for (_idx, entry) in self.l2_table_cache.iter() {
            let mut borrowed_entry = entry.borrow_mut();
            if !borrowed_entry.dirty_info.is_dirty {
                continue;
            }
            self.sync_aio.borrow_mut().write_dirty_info(
                borrowed_entry.addr,
                borrowed_entry.get_value(),
                borrowed_entry.dirty_info.start,
                borrowed_entry.dirty_info.end,
            )?;
            borrowed_entry.dirty_info.clear();
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.flush_l2_table_cache()
    }
}
