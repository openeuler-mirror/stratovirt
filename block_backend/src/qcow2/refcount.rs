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

use anyhow::{bail, Context, Result};
use log::{error, info};

use crate::qcow2::{
    cache::{CacheTable, Qcow2Cache, ENTRY_SIZE_U16},
    header::QcowHeader,
    is_aligned, SyncAioInfo, ENTRY_SIZE,
};

// The max refcount table size default is 4 clusters;
const MAX_REFTABLE_NUM: u32 = 4;

#[derive(Clone)]
pub struct RefCount {
    pub refcount_table: Vec<u64>,
    sync_aio: Rc<RefCell<SyncAioInfo>>,
    refcount_blk_cache: Qcow2Cache,
    free_cluster_index: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    /// Number of refcount table entries.
    refcount_table_size: u64,
    refcount_blk_bits: u32,
    /// Number of refcount block entries.
    refcount_blk_size: u32,
    refcount_max: u64,
    /// Cluster size in bytes.
    cluster_size: u64,
    cluster_bits: u32,
}

impl RefCount {
    pub fn new(sync_aio: Rc<RefCell<SyncAioInfo>>) -> Self {
        RefCount {
            refcount_table: Vec::new(),
            sync_aio,
            refcount_blk_cache: Qcow2Cache::new(MAX_REFTABLE_NUM as usize),
            free_cluster_index: 0,
            refcount_table_offset: 0,
            refcount_table_clusters: 0,
            refcount_table_size: 0,
            refcount_blk_bits: 0,
            refcount_blk_size: 0,
            refcount_max: 0,
            cluster_size: 0,
            cluster_bits: 0,
        }
    }

    pub fn init_refcount_info(&mut self, header: &QcowHeader) {
        self.refcount_table_offset = header.refcount_table_offset;
        self.refcount_table_clusters = header.refcount_table_clusters;
        self.refcount_table_size =
            header.refcount_table_clusters as u64 * header.cluster_size() / ENTRY_SIZE;
        self.refcount_blk_bits = header.cluster_bits + 3 - header.refcount_order;
        self.refcount_blk_size = 1 << self.refcount_blk_bits;
        self.cluster_bits = header.cluster_bits;
        self.cluster_size = header.cluster_size();
        let refcount_bits = 1 << header.refcount_order;
        self.refcount_max = 1 << (refcount_bits - 1);
        self.refcount_max += self.refcount_max - 1;
    }

    fn bytes_to_clusters(&self, size: u64) -> u64 {
        (size + self.cluster_size - 1) >> self.cluster_bits
    }

    fn cluster_in_rc_block(&self, cluster_index: u64) -> u64 {
        cluster_index & (self.refcount_blk_size - 1) as u64
    }

    fn extend_refcount_table(&mut self, header: &mut QcowHeader, cluster_index: u64) -> Result<()> {
        info!("Qcow2 needs to extend the refcount table");
        // Alloc space for new refcount table.
        let mut offset = cluster_index << self.cluster_bits;
        let rcb_offset = self.cluster_in_rc_block(cluster_index);
        let rc_block = vec![0_u8; self.cluster_size as usize];
        let cache_entry = Rc::new(RefCell::new(CacheTable::new(
            offset,
            rc_block,
            ENTRY_SIZE_U16,
        )?));
        let mut borrow_entry = cache_entry.borrow_mut();
        for i in rcb_offset..rcb_offset + self.refcount_table_clusters as u64 + 2 {
            borrow_entry.set_entry_map(i as usize, 1)?;
        }
        self.sync_aio.borrow_mut().write_dirty_info(
            borrow_entry.addr,
            borrow_entry.get_value(),
            0,
            self.cluster_size,
        )?;

        // Write new extended refcount table to disk.
        let size = self.refcount_table.len() + (self.cluster_size / ENTRY_SIZE) as usize;
        let mut new_rc_table = self.refcount_table.clone();
        new_rc_table.resize(size, 0);
        new_rc_table[(cluster_index >> self.refcount_blk_bits) as usize] = offset;
        offset += self.cluster_size;
        self.sync_aio
            .borrow_mut()
            .write_ctrl_cluster(offset, &new_rc_table)?;

        // Update and save qcow2 header to disk.
        let mut new_header = header.clone();
        new_header.refcount_table_offset = offset;
        new_header.refcount_table_clusters += 1;
        self.sync_aio
            .borrow_mut()
            .write_buffer(0, &new_header.to_vec())?;

        // Update qcow2 header in memory.
        header.refcount_table_offset = new_header.refcount_table_offset;
        header.refcount_table_clusters = new_header.refcount_table_clusters;

        // Update refcount information.
        let old_rct_offset = self.refcount_table_offset;
        let old_rct_size = self.refcount_table_size;
        self.refcount_table = new_rc_table;
        self.refcount_table_offset = header.refcount_table_offset;
        self.refcount_table_clusters = header.refcount_table_clusters;
        self.refcount_table_size =
            (self.refcount_table_clusters << self.cluster_bits) as u64 / ENTRY_SIZE;

        // Free the old cluster of refcount table.
        let clusters = self.bytes_to_clusters(old_rct_size as u64);
        self.update_refcount(old_rct_offset, clusters, false, 1)?;
        info!(
            "Qcow2 extends refcount table success, offset 0x{:x} -> 0x{:x}",
            old_rct_offset, self.refcount_table_offset
        );

        Ok(())
    }

    pub fn update_refcount(
        &mut self,
        offset: u64,
        clusters: u64,
        is_add: bool,
        addend: u16,
    ) -> Result<()> {
        let first_cluster = self.bytes_to_clusters(offset);
        let mut rc_vec = Vec::new();
        let mut i = 0;
        while i < clusters {
            let rt_idx = (first_cluster + i) >> self.refcount_blk_bits;
            if rt_idx >= self.refcount_table_size as u64 {
                bail!("Invalid refcount table index {}", rt_idx);
            }
            let rb_addr = self.refcount_table[rt_idx as usize];
            if rb_addr == 0 || self.offset_into_cluster(rb_addr) != 0 {
                bail!(
                    "Invalid refcount block address 0x{:x}, index is {}",
                    rb_addr,
                    rt_idx
                );
            }
            let rb_idx = self.cluster_in_rc_block(i + first_cluster) as usize;
            let num = std::cmp::min(
                self.refcount_blk_size as usize - rb_idx,
                (clusters - i) as usize,
            );
            rc_vec.push((rt_idx, rb_idx as u64, num));
            i += num as u64;
        }

        let idx = self.set_refcount_blocks(&rc_vec, is_add, addend);
        if idx != rc_vec.len() {
            // Revert the updating operation for refount block.
            let rev_idx = self.set_refcount_blocks(&rc_vec[..idx], !is_add, addend);
            let status = if rev_idx == idx { "success" } else { "failed" };
            bail!("Failed to set refcounts, recover {}", status);
        }
        self.flush_reftount_block_cache()
    }

    fn set_refcount_blocks(
        &mut self,
        rc_vec: &[(u64, u64, usize)],
        is_add: bool,
        addend: u16,
    ) -> usize {
        for (i, (rt_idx, rb_idx, num)) in rc_vec.iter().enumerate() {
            let ret = self.set_refcount(*rt_idx, *rb_idx, *num, is_add, addend);
            if let Err(err) = ret {
                error!("Set refcount failed, rt_idx {}, rb_idx {}, clusters {}, is_add {}, addend {}, {}",
                       rt_idx, rb_idx, num, is_add, addend, err.to_string());
                return i;
            }
        }

        rc_vec.len()
    }

    fn flush_reftount_block_cache(&self) -> Result<()> {
        for (_, entry) in self.refcount_blk_cache.iter() {
            let mut borrowed_entry = entry.borrow_mut();
            if !borrowed_entry.dirty_info.is_dirty {
                continue;
            }
            let ret = self.sync_aio.borrow_mut().write_dirty_info(
                borrowed_entry.addr,
                borrowed_entry.get_value(),
                borrowed_entry.dirty_info.start,
                borrowed_entry.dirty_info.end,
            );
            if let Err(err) = ret {
                error!("Flush refcount table cache failed, {}", err.to_string());
            }
            borrowed_entry.dirty_info.clear();
        }
        Ok(())
    }

    fn set_refcount(
        &mut self,
        rt_idx: u64,
        rb_idx: u64,
        clusters: usize,
        is_add: bool,
        addend: u16,
    ) -> Result<()> {
        if !self.refcount_blk_cache.contains_keys(rt_idx) {
            self.load_refcount_block(rt_idx).with_context(|| {
                format!("Failed to get refcount block cache, index is {}", rt_idx)
            })?;
        }
        let cache_entry = self
            .refcount_blk_cache
            .get(rt_idx)
            .with_context(|| format!("Not found refcount block cache, index is {}", rt_idx))?
            .clone();

        let mut rb_vec = Vec::new();
        let mut borrowed_entry = cache_entry.borrow_mut();
        for i in 0..clusters {
            let mut rc_value = borrowed_entry.get_entry_map(rb_idx as usize + i)? as u16;
            rc_value = if is_add {
                rc_value
                    .checked_add(addend)
                    .filter(|&v| v <= self.refcount_max as u16)
                    .with_context(|| {
                        format!(
                            "Refcount {} add {} cause overflows, index is {}",
                            rc_value, addend, i
                        )
                    })?
            } else {
                rc_value.checked_sub(addend).with_context(|| {
                    format!(
                        "Refcount {} sub {} cause overflows, index is {}",
                        rc_value, addend, i
                    )
                })?
            };
            let cluster_idx = rt_idx * self.refcount_blk_size as u64 + rb_idx + i as u64;
            if rc_value == 0 && cluster_idx < self.free_cluster_index {
                self.free_cluster_index = cluster_idx;
            }
            rb_vec.push(rc_value);
        }

        for (idx, rc_value) in rb_vec.iter().enumerate() {
            borrowed_entry.set_entry_map(rb_idx as usize + idx, *rc_value as u64)?;
        }

        Ok(())
    }

    fn offset_into_cluster(&self, offset: u64) -> u64 {
        offset & (self.cluster_size - 1)
    }

    fn alloc_refcount_block(&mut self, rt_idx: u64, free_idx: u64) -> Result<()> {
        let rb_addr = free_idx << self.cluster_bits;
        let rc_block = vec![0_u8; self.cluster_size as usize];

        // Update refcount table.
        self.refcount_table[rt_idx as usize] = rb_addr;
        let start = rt_idx * ENTRY_SIZE;
        let ret = self.save_refcount_table(start, start + ENTRY_SIZE);
        if ret.is_err() {
            self.refcount_table[rt_idx as usize] = 0;
            ret?;
        }

        // Create recount block cache.
        let cache_entry = Rc::new(RefCell::new(CacheTable::new(
            rb_addr,
            rc_block,
            ENTRY_SIZE_U16,
        )?));
        // Update and save refcount block.
        let mut borrow_entry = cache_entry.borrow_mut();
        borrow_entry.set_entry_map(self.cluster_in_rc_block(free_idx) as usize, 1)?;
        self.sync_aio.borrow_mut().write_dirty_info(
            borrow_entry.addr,
            borrow_entry.get_value(),
            0,
            self.cluster_size,
        )?;
        drop(borrow_entry);
        if let Some(replaced_entry) = self.refcount_blk_cache.lru_replace(rt_idx, cache_entry) {
            self.save_refcount_block(&replaced_entry)?;
        }

        Ok(())
    }

    fn find_free_cluster(&mut self, header: &mut QcowHeader, size: u64) -> Result<u64> {
        let clusters = self.bytes_to_clusters(size);
        let mut current_index = self.free_cluster_index;
        let mut i = 0;
        while i < clusters {
            // Check if it needs to extend refcount table.
            let rt_idx = current_index >> self.refcount_blk_bits;
            if rt_idx >= self.refcount_table_size as u64 {
                self.extend_refcount_table(header, current_index)?;
                if current_index > self.free_cluster_index {
                    current_index = self.free_cluster_index;
                } else {
                    current_index += 1;
                }
                i = 0;
                continue;
            }

            // Check if it needs to alloc refcount block.
            let rb_addr = self.refcount_table[rt_idx as usize];
            if rb_addr == 0 {
                // Need to alloc refcount block.
                self.alloc_refcount_block(rt_idx as u64, current_index)?;
                current_index += 1;
                i = 0;
                continue;
            } else if self.offset_into_cluster(rb_addr) != 0 {
                bail!(
                    "Invalid refcount block address 0x{:x}, index is {}",
                    rb_addr,
                    rt_idx
                );
            }

            // Load refcount block from disk which is not in cache.
            if !self.refcount_blk_cache.contains_keys(rt_idx) {
                self.load_refcount_block(rt_idx).with_context(|| {
                    format!("Failed to get refcount block cache, index is {}", rt_idx)
                })?;
            }

            // Check if the cluster of current_index is free.
            let idx = self.cluster_in_rc_block(current_index) as usize;
            let cache_entry = self.refcount_blk_cache.get(rt_idx).unwrap();
            let borrowed_entry = cache_entry.borrow();

            let find_idx = borrowed_entry.find_empty_entry(idx)?;
            if find_idx != idx {
                current_index += (find_idx - idx) as u64;
                i = 0;
                continue;
            }

            i += 1;
            current_index += 1;
        }
        self.free_cluster_index = current_index;
        Ok((current_index - clusters) << self.cluster_bits)
    }

    pub fn alloc_cluster(&mut self, header: &mut QcowHeader, size: u64) -> Result<u64> {
        let addr = self.find_free_cluster(header, size)?;
        let clusters = self.bytes_to_clusters(size as u64);
        self.update_refcount(addr, clusters, true, 1)?;
        Ok(addr)
    }

    fn load_refcount_block(&mut self, rt_idx: u64) -> Result<()> {
        let rb_addr = self.refcount_table[rt_idx as usize];
        if !is_aligned(self.cluster_size, rb_addr) {
            bail!("Refcount block address not aligned {}", rb_addr);
        }
        let mut rc_block = vec![0_u8; self.cluster_size as usize];
        self.sync_aio
            .borrow_mut()
            .read_buffer(rb_addr, &mut rc_block)?;
        let cache_entry = Rc::new(RefCell::new(CacheTable::new(
            rb_addr,
            rc_block,
            ENTRY_SIZE_U16,
        )?));
        if let Some(replaced_entry) = self.refcount_blk_cache.lru_replace(rt_idx, cache_entry) {
            self.save_refcount_block(&replaced_entry)?;
        }
        Ok(())
    }

    fn save_refcount_table(&mut self, start: u64, end: u64) -> Result<()> {
        let vec: Vec<u8> = self
            .refcount_table
            .iter()
            .flat_map(|val| val.to_be_bytes())
            .collect();
        self.sync_aio
            .borrow_mut()
            .write_dirty_info(self.refcount_table_offset, &vec, start, end)
    }

    fn save_refcount_block(&mut self, entry: &Rc<RefCell<CacheTable>>) -> Result<()> {
        let borrowed_entry = entry.borrow();
        if !borrowed_entry.dirty_info.is_dirty {
            return Ok(());
        }
        if !is_aligned(self.cluster_size, borrowed_entry.addr) {
            bail!(
                "Refcount block address is not aligned {}",
                borrowed_entry.addr
            );
        }
        self.sync_aio.borrow_mut().write_dirty_info(
            borrowed_entry.addr,
            borrowed_entry.get_value(),
            borrowed_entry.dirty_info.start,
            borrowed_entry.dirty_info.end,
        )
    }
}
