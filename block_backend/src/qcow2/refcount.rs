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

use crate::{
    qcow2::{
        bytes_to_clusters,
        cache::{CacheTable, Qcow2Cache, ENTRY_SIZE_U16},
        header::QcowHeader,
        is_aligned, SyncAioInfo, ENTRY_SIZE, REFCOUNT_TABLE_OFFSET_MASK,
    },
    BlockProperty,
};
use util::{
    aio::OpCode,
    num_ops::{div_round_up, round_up},
};

// The max refcount table size default is 4 clusters;
const MAX_REFTABLE_NUM: u64 = 4;

#[derive(Eq, PartialEq, Clone)]
pub enum Qcow2DiscardType {
    Never,
    Always,
    Request,
    Snapshot,
    Other,
}

#[derive(Clone, Default)]
pub struct DiscardTask {
    pub offset: u64,
    pub nbytes: u64,
}

impl DiscardTask {
    pub fn is_overlap(&self, task: &DiscardTask) -> bool {
        !(self.offset > task.offset + task.nbytes || task.offset > self.offset + self.nbytes)
    }

    pub fn merge_task(&mut self, task: &DiscardTask) {
        let offset = std::cmp::min(self.offset, task.offset);
        let end_offset = std::cmp::max(self.offset + self.nbytes, task.offset + task.nbytes);
        let nbytes = end_offset - offset;
        self.offset = offset;
        self.nbytes = nbytes;
    }
}

#[derive(Clone)]
pub struct RefCount {
    pub refcount_table: Vec<u64>,
    sync_aio: Rc<RefCell<SyncAioInfo>>,
    pub(crate) refcount_blk_cache: Qcow2Cache,
    pub discard_list: Vec<DiscardTask>,
    /// Pass the discard operation if refcount of cluster decrease to 0.
    pub discard_passthrough: Vec<Qcow2DiscardType>,
    free_cluster_index: u64,
    pub(crate) refcount_table_offset: u64,
    pub(crate) refcount_table_clusters: u32,
    /// Number of refcount table entries.
    pub(crate) refcount_table_size: u64,
    pub(crate) refcount_blk_bits: u32,
    /// Number of refcount block entries.
    pub(crate) refcount_blk_size: u32,
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
            refcount_blk_cache: Qcow2Cache::default(),
            discard_list: Vec::new(),
            discard_passthrough: Vec::new(),
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

    pub fn init_refcount_info(&mut self, header: &QcowHeader, conf: &BlockProperty) {
        // Update discard_pass_through depend on config.
        self.discard_passthrough.push(Qcow2DiscardType::Always);
        if conf.discard {
            self.discard_passthrough.push(Qcow2DiscardType::Request);
            self.discard_passthrough.push(Qcow2DiscardType::Snapshot);
        }

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
        let sz = if let Some(rc_size) = conf.refcount_cache_size {
            rc_size / header.cluster_size()
        } else {
            MAX_REFTABLE_NUM
        };
        info!("Driver {} refcount cache size {}", conf.id, sz);
        self.refcount_blk_cache = Qcow2Cache::new(sz as usize);
    }

    pub fn start_of_cluster(&self, offset: u64) -> u64 {
        offset & !(self.cluster_size - 1)
    }

    fn cluster_in_rc_block(&self, cluster_index: u64) -> u64 {
        cluster_index & (self.refcount_blk_size - 1) as u64
    }

    /// Allocate a continuous space that is not referenced by existing refcount table
    fn alloc_clusters_with_noref(&mut self, size: u64) -> Result<u64> {
        if !self.discard_list.is_empty() {
            self.sync_process_discards(OpCode::Discard);
        }

        let nb_clusters = bytes_to_clusters(size, self.cluster_size).unwrap();
        let mut free_clusters = 0;
        while free_clusters < nb_clusters {
            let offset = self.free_cluster_index << self.cluster_bits;
            self.free_cluster_index += 1;
            if self.get_refcount(offset)? != 0 {
                free_clusters = 0;
            } else {
                free_clusters += 1;
            }
        }

        let cluster_index = self.free_cluster_index - nb_clusters;
        Ok(cluster_index << self.cluster_bits)
    }

    /// Allocate a contiguous space that already has a reference count in the refcount table
    pub fn alloc_clusters_with_ref(&mut self, header: &mut QcowHeader, size: u64) -> Result<u64> {
        if size == 0 {
            bail!("Don't allow to alloc cluster size of 0!");
        }
        let offset = self.alloc_clusters_with_noref(size)?;
        let offset_end = round_up(offset + size, self.cluster_size).unwrap();
        let rt_end = offset_end >> (self.cluster_bits + self.refcount_blk_bits);
        let nb_clusters = bytes_to_clusters(offset_end - offset, self.cluster_size)?;

        if rt_end >= self.refcount_table_size {
            let clusters = self.free_cluster_index;
            let start_idx = self.free_cluster_index;
            let (table, blocks) = refcount_metadata_size(
                clusters,
                self.cluster_size,
                header.refcount_order as u64,
                true,
            )?;
            self.extend_refcount_table(header, start_idx, table, blocks)?;
        }
        self.update_alloc_refcount(offset, nb_clusters, 1, false, &Qcow2DiscardType::Never)?;
        Ok(offset)
    }

    /// Extend refcount table.
    ///
    /// # Arguments
    ///
    /// * `header` - header message of this qower driver.
    /// * `start_idx` - alloc space for the new refcount table starting from the start index.
    /// * `new_table_clusters` - number of clusters for new refcount table.
    /// * `new_block_clusters` - number of clusters for refcount block, the size of refcount blocks
    /// should be guaranteed to record all newly added clusters.
    fn extend_refcount_table(
        &mut self,
        header: &mut QcowHeader,
        start_idx: u64,
        new_table_clusters: u64,
        new_block_clusters: u64,
    ) -> Result<()> {
        info!("Qcow2 needs to extend the refcount table");
        // Alloc space for new refcount table.
        let new_table_size = new_table_clusters * (self.cluster_size / ENTRY_SIZE);
        if new_block_clusters > new_table_size {
            bail!(
                "Refcount block clusters {:?} exceed table size: {:?}",
                new_block_clusters,
                new_table_size
            );
        }
        let mut new_table = self.refcount_table.clone();
        // SAFETY: Upper limit of new_table_size is disk file size.
        new_table.resize(new_table_size as usize, 0);
        let start_offset = start_idx * self.cluster_size;
        let mut table_offset = start_offset;
        for i in 0..new_block_clusters {
            if new_table[i as usize] == 0 {
                new_table[i as usize] = table_offset;
                table_offset += self.cluster_size;
            }
        }
        let end_offset = table_offset + new_table_clusters * self.cluster_size;
        let metadata_clusters = div_round_up(end_offset - start_offset, self.cluster_size).unwrap();

        // Write new extended refcount table to disk.
        self.sync_aio
            .borrow_mut()
            .write_ctrl_cluster(table_offset, &new_table)?;

        // Update and save qcow2 header to disk.
        let mut new_header = header.clone();
        new_header.refcount_table_offset = table_offset;
        new_header.refcount_table_clusters = new_table_clusters as u32;
        self.sync_aio
            .borrow_mut()
            .write_buffer(0, &new_header.to_vec())?;

        // Update qcow2 header in memory.
        header.refcount_table_offset = new_header.refcount_table_offset;
        header.refcount_table_clusters = new_header.refcount_table_clusters;

        // Update refcount information.
        let old_table_offset = self.refcount_table_offset;
        let old_table_clusters = self.refcount_table_clusters;
        self.refcount_table = new_table;
        self.refcount_table_offset = header.refcount_table_offset;
        self.refcount_table_clusters = header.refcount_table_clusters;
        self.refcount_table_size = new_table_size;
        self.free_cluster_index = end_offset / self.cluster_size;

        // Update refcount for metadata.
        self.update_refcount(
            start_offset,
            metadata_clusters,
            1,
            true,
            &Qcow2DiscardType::Never,
        )?;

        // Free the old cluster of refcount table.
        self.update_refcount(
            old_table_offset,
            old_table_clusters as u64,
            -1,
            true,
            &Qcow2DiscardType::Other,
        )?;
        info!(
            "Qcow2 extends refcount table success, offset 0x{:x} -> 0x{:x}",
            old_table_offset, self.refcount_table_offset
        );

        Ok(())
    }

    fn update_alloc_refcount(
        &mut self,
        offset: u64,
        clusters: u64,
        added: i32,
        flush: bool,
        discard_type: &Qcow2DiscardType,
    ) -> Result<()> {
        let start_clusters = div_round_up(offset, self.cluster_size).unwrap();
        for i in start_clusters..start_clusters + clusters {
            let rt_idx = i >> self.refcount_blk_bits;
            if rt_idx >= self.refcount_table_size {
                bail!("Invalid refcount table index {}", rt_idx);
            }

            let rb_addr = self.refcount_table[rt_idx as usize];
            if rb_addr == 0 {
                self.alloc_refcount_block(rt_idx).map_err(|e| {
                    self.refcount_table[rt_idx as usize] = 0;
                    e
                })?;
            }
        }

        self.update_refcount(offset, clusters, added, flush, discard_type)
    }

    pub fn update_refcount(
        &mut self,
        offset: u64,
        clusters: u64,
        added: i32,
        flush: bool,
        discard_type: &Qcow2DiscardType,
    ) -> Result<()> {
        if self.offset_into_cluster(offset) != 0 {
            bail!("Failed to update refcount, offset is not aligned to cluster");
        }
        let first_cluster = bytes_to_clusters(offset, self.cluster_size).unwrap();
        let mut rc_vec = Vec::new();
        let mut i = 0;
        while i < clusters {
            let rt_idx = (first_cluster + i) >> self.refcount_blk_bits;
            if rt_idx >= self.refcount_table_size {
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

        let idx = self.set_refcount_blocks(&rc_vec, added, discard_type);
        if idx != rc_vec.len() {
            // Revert the updating operation for refount block.
            let rev_idx = self.set_refcount_blocks(&rc_vec[..idx], -added, discard_type);
            let status = if rev_idx == idx { "success" } else { "failed" };
            bail!("Failed to set refcounts, recover {}", status);
        }
        if flush {
            self.flush()?;
        }
        Ok(())
    }

    fn set_refcount_blocks(
        &mut self,
        rc_vec: &[(u64, u64, usize)],
        added: i32,
        discard_type: &Qcow2DiscardType,
    ) -> usize {
        for (i, (rt_idx, rb_idx, num)) in rc_vec.iter().enumerate() {
            let ret = self.set_refcount(*rt_idx, *rb_idx, *num, added, discard_type);
            if let Err(err) = ret {
                error!(
                    "Set refcount failed, rt_idx {}, rb_idx {}, clusters {}, added {}, {}",
                    rt_idx,
                    rb_idx,
                    num,
                    added,
                    err.to_string()
                );
                return i;
            }
        }

        rc_vec.len()
    }

    pub fn flush(&mut self) -> Result<()> {
        self.refcount_blk_cache.flush(self.sync_aio.clone())
    }

    fn set_refcount(
        &mut self,
        rt_idx: u64,
        rb_idx: u64,
        clusters: usize,
        added: i32,
        discard_type: &Qcow2DiscardType,
    ) -> Result<()> {
        let is_add = added > 0;
        let added_value = added.unsigned_abs() as u16;
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
        let is_dirty = borrowed_entry.dirty_info.is_dirty;
        for i in 0..clusters {
            let mut rc_value = borrowed_entry.get_entry_map(rb_idx as usize + i)? as u16;
            rc_value = if is_add {
                rc_value
                    .checked_add(added_value)
                    .filter(|&v| v <= self.refcount_max as u16)
                    .with_context(|| {
                        format!(
                            "Refcount {} add {} cause overflows, index is {}",
                            rc_value, added_value, i
                        )
                    })?
            } else {
                rc_value.checked_sub(added_value).with_context(|| {
                    format!(
                        "Refcount {} sub {} cause overflows, index is {}",
                        rc_value, added_value, i
                    )
                })?
            };
            let cluster_idx = rt_idx * self.refcount_blk_size as u64 + rb_idx + i as u64;
            if rc_value == 0 {
                if self.discard_passthrough.contains(discard_type) {
                    // update refcount discard.
                    let offset = cluster_idx * self.cluster_size;
                    let nbytes = self.cluster_size;
                    self.update_discard_list(offset, nbytes)?;
                }

                if cluster_idx < self.free_cluster_index {
                    self.free_cluster_index = cluster_idx;
                }
            }
            rb_vec.push(rc_value);
        }

        for (idx, rc_value) in rb_vec.iter().enumerate() {
            borrowed_entry.set_entry_map(rb_idx as usize + idx, *rc_value as u64)?;
        }
        if !is_dirty {
            self.refcount_blk_cache.add_dirty_table(cache_entry.clone());
        }

        Ok(())
    }

    pub fn get_refcount(&mut self, offset: u64) -> Result<u16> {
        let cluster = offset >> self.cluster_bits;
        let rt_idx = cluster >> self.refcount_blk_bits;
        if rt_idx >= self.refcount_table_size {
            return Ok(0);
        }

        let rb_addr = self.refcount_table[rt_idx as usize] & REFCOUNT_TABLE_OFFSET_MASK;
        if rb_addr == 0 {
            return Ok(0);
        }

        if self.offset_into_cluster(rb_addr) != 0 {
            bail!(
                "Invalid refcount block address 0x{:x}, index is {}",
                rb_addr,
                rt_idx
            );
        }

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

        let rb_idx = self.cluster_in_rc_block(cluster) as usize;
        let rc_value = cache_entry.borrow_mut().get_entry_map(rb_idx).unwrap();

        Ok(rc_value as u16)
    }

    /// Add discard task to the list.
    fn update_discard_list(&mut self, offset: u64, nbytes: u64) -> Result<()> {
        let mut discard_task = DiscardTask { offset, nbytes };
        let len = self.discard_list.len();
        let mut discard_list: Vec<DiscardTask> = Vec::with_capacity(len + 1);
        for task in self.discard_list.iter() {
            if discard_task.is_overlap(task) {
                discard_task.merge_task(task);
            } else {
                discard_list.push(task.clone());
            }
        }
        discard_list.push(discard_task);
        self.discard_list = discard_list;
        Ok(())
    }

    /// Process discards task by sync aio.
    pub fn sync_process_discards(&mut self, opcode: OpCode) {
        for task in self.discard_list.iter() {
            let offset = task.offset;
            let nbytes = task.nbytes;
            let mut borrowed_sync_aio = self.sync_aio.borrow_mut();
            let discard_aio =
                borrowed_sync_aio.package_sync_aiocb(opcode, Vec::new(), offset as usize, nbytes);
            borrowed_sync_aio
                .aio
                .submit_request(discard_aio)
                .unwrap_or_else(|e| error!("Discard failed: {:?}", e));
        }
        self.discard_list.clear();
    }

    pub fn offset_into_cluster(&self, offset: u64) -> u64 {
        offset & (self.cluster_size - 1)
    }

    /// Alloc a new cluster for refcount block. If this new allocated cluster exceed
    /// the refcount table, then return fail.
    fn alloc_refcount_block(&mut self, rt_idx: u64) -> Result<()> {
        if rt_idx >= self.refcount_table_size {
            bail!("The size of refcount table is not enough");
        }

        let alloc_offset = self.alloc_clusters_with_noref(self.cluster_size)?;
        let alloc_cluster_idx = alloc_offset >> self.cluster_bits;
        let alloc_rt_idx = alloc_cluster_idx >> self.refcount_blk_bits;
        // Avoid to resize the refcount table.
        if alloc_rt_idx >= self.refcount_table_size {
            bail!("The size of refcount table is not enough");
        }

        // Update refcount table.
        self.refcount_table[rt_idx as usize] = alloc_offset;
        let rc_block = vec![0_u8; self.cluster_size as usize];
        let cache_entry = Rc::new(RefCell::new(CacheTable::new(
            alloc_offset,
            rc_block,
            ENTRY_SIZE_U16,
        )?));
        if let Some(replaced_entry) = self
            .refcount_blk_cache
            .lru_replace(rt_idx, cache_entry.clone())
        {
            self.save_refcount_block(&replaced_entry)?;
        }

        let mut borrowed_entry = cache_entry.borrow_mut();
        if alloc_rt_idx == rt_idx {
            // Update and save refcount block.
            let alloc_rcb_idx = self.cluster_in_rc_block(alloc_cluster_idx);
            borrowed_entry.set_entry_map(self.cluster_in_rc_block(alloc_rcb_idx) as usize, 1)?;
            borrowed_entry.dirty_info.clear();
        }

        // Sync to disk.
        self.sync_aio.borrow_mut().write_dirty_info(
            borrowed_entry.addr,
            borrowed_entry.get_value(),
            0,
            self.cluster_size,
        )?;
        drop(borrowed_entry);

        if alloc_rt_idx != rt_idx {
            self.update_alloc_refcount(alloc_offset, 1, 1, true, &Qcow2DiscardType::Never)?;
        }

        let start = rt_idx * ENTRY_SIZE;
        self.save_refcount_table(start, start + ENTRY_SIZE)
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
        let mut borrowed_entry = entry.borrow_mut();
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
        )?;
        borrowed_entry.dirty_info.clear();

        Ok(())
    }

    pub fn drop_dirty_caches(&mut self) {
        self.refcount_blk_cache.clean_up_dirty_cache();
    }
}

/// Recalculate the metadata size of refcount to expand the Refcount table,
/// so that it can refcount enough clusters.
///
/// # Arguments
///
/// * `nb_clusters` - number of clusters to refcount.
/// * `cluster_size` - size of cluster in bytes.
/// * `refcount_order` - refcount bits power of 2 exponent.
/// * `is_reserve` - if this parameter set true, the refcount table size
///  will have 50% more entries than necessary, which can avoid growing again soon.
/// Returns: (clusters of new refcount table, clusters of refcount block)
pub fn refcount_metadata_size(
    nb_clusters: u64,
    cluster_size: u64,
    refcount_order: u64,
    mut is_reserve: bool,
) -> Result<(u64, u64)> {
    let reftable_entries = cluster_size / ENTRY_SIZE;
    let refblock_entries = cluster_size * 8 / (1 << refcount_order);
    let mut table = 0;
    let mut blocks = 0;
    let mut clusters = nb_clusters;
    let mut last_clusters;
    let mut total_clusters = 0;

    loop {
        last_clusters = total_clusters;
        blocks = div_round_up(clusters + table + blocks, refblock_entries).unwrap();
        table = div_round_up(blocks, reftable_entries).unwrap();
        total_clusters = table + blocks + clusters;

        if total_clusters == last_clusters {
            if is_reserve {
                clusters += div_round_up(table, 2).unwrap();
                total_clusters = 0;
                is_reserve = false;
            } else {
                break;
            }
        }
    }

    table = total_clusters - nb_clusters - blocks;
    Ok((table, blocks))
}

#[cfg(test)]
mod test {
    use std::{
        fs::{remove_file, File},
        io::{Seek, SeekFrom, Write},
        os::unix::fs::{FileExt, OpenOptionsExt},
        sync::Arc,
    };

    use byteorder::{BigEndian, ByteOrder};

    use crate::qcow2::*;
    use crate::qcow2::{
        header::*,
        refcount::{refcount_metadata_size, Qcow2DiscardType},
    };
    use machine_manager::config::DiskFormat;
    use util::aio::{Aio, WriteZeroesState};

    fn image_create(path: &str, img_bits: u32, cluster_bits: u32) -> File {
        let cluster_sz = 1 << cluster_bits;
        let l1_size: u64 = 1 << (img_bits - (cluster_bits * 2 - ENTRY_SIZE as u32));
        let entry_per_l1_cluster: u64 = 1 << (cluster_bits - ENTRY_BITS as u32);
        let l1_clusters = div_round_up(l1_size, entry_per_l1_cluster).unwrap();
        // Header + l1 table clusters
        let nb_clusters = 1 + l1_clusters;
        let (rct, rcb) = refcount_metadata_size(nb_clusters, cluster_sz, 4, false).unwrap();
        let mut rc_table: Vec<u8> = Vec::new();
        let mut rc_block: Vec<u8> = Vec::new();
        let l1_table = vec![0_u8; (l1_clusters * cluster_sz) as usize];
        let rct_offset = cluster_sz;
        let rcb_offset = (1 + rct) * cluster_sz;
        let l1_table_offset = (1 + rct + rcb) * cluster_sz;
        let total_clusters = nb_clusters + rct + rcb;
        let rc_per_block = cluster_sz / 2;
        let rct_size = div_round_up(total_clusters, rc_per_block).unwrap();
        for i in 0..rct_size {
            let addr = rcb_offset + i * cluster_sz;
            rc_table.append(&mut addr.to_be_bytes().to_vec());
        }
        for _i in 0..total_clusters {
            rc_block.push(0x00);
            rc_block.push(0x01);
        }
        // SAFETY: Upper limit of following value is decided by disk file size.
        rc_table.resize((rct * cluster_sz) as usize, 0);
        rc_block.resize((rcb * cluster_sz) as usize, 0);
        let header = QcowHeader {
            magic: QCOW_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits,
            size: 1 << img_bits,
            crypt_method: 0,
            l1_size: l1_size as u32,
            l1_table_offset,
            refcount_table_offset: rct_offset,
            refcount_table_clusters: rct as u32,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: std::mem::size_of::<QcowHeader>() as u32,
        };
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CREAT | libc::O_TRUNC)
            .open(path)
            .unwrap();
        file.set_len(total_clusters * cluster_sz).unwrap();
        file.write_all(&header.to_vec()).unwrap();

        // Refcount table.
        file.seek(SeekFrom::Start(rct_offset)).unwrap();
        file.write_all(&rc_table).unwrap();

        // Recount block.
        file.seek(SeekFrom::Start(rcb_offset)).unwrap();
        file.write_all(&rc_block).unwrap();

        // L1 table.
        file.seek(SeekFrom::Start(l1_table_offset)).unwrap();
        file.write_all(&l1_table).unwrap();

        file
    }

    fn create_qcow2_driver(
        path: &str,
        img_bits: u32,
        cluster_bits: u32,
    ) -> (Qcow2Driver<()>, File) {
        let file = image_create(path, img_bits, cluster_bits);
        let aio = Aio::new(
            Arc::new(SyncAioInfo::complete_func),
            util::aio::AioEngine::Off,
            None,
        )
        .unwrap();
        let conf = BlockProperty {
            id: path.to_string(),
            format: DiskFormat::Qcow2,
            iothread: None,
            direct: true,
            req_align: 512,
            buf_align: 512,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            l2_cache_size: None,
            refcount_cache_size: None,
        };
        let cloned_file = file.try_clone().unwrap();
        let mut qcow2_driver = Qcow2Driver::new(file, aio, conf.clone()).unwrap();
        qcow2_driver.load_metadata(conf).unwrap();
        (qcow2_driver, cloned_file)
    }

    #[test]
    fn test_alloc_cluster() {
        let path = "/tmp/refcount_case1.qcow2";
        let image_bits = 30;
        let cluster_bits = 16;
        let (mut qcow2, cloned_file) = create_qcow2_driver(path, image_bits, cluster_bits);
        let header = qcow2.header.clone();

        // Alloc one free clusters
        let cluster_sz = 1 << cluster_bits;
        let free_cluster_index =
            3 + ((header.l1_size * ENTRY_SIZE as u32 + cluster_sz as u32 - 1) >> cluster_bits);
        let addr = qcow2.alloc_cluster(1, true).unwrap();
        assert_eq!(addr, cluster_sz * free_cluster_index as u64);
        qcow2.flush().unwrap();
        // Check if the refcount of the cluster is updated to the disk.
        let mut rc_value = [0_u8; 2];
        cloned_file
            .read_at(
                &mut rc_value,
                cluster_sz * 2 + 2 * free_cluster_index as u64,
            )
            .unwrap();
        assert_eq!(1, BigEndian::read_u16(&rc_value));
        remove_file(path).unwrap();
    }

    /// Test function of allocating cluster.
    /// TestStep:
    ///   1. Init qcow2 file driver.
    ///   2. Call alloc function.
    /// Expect:
    /// 1. The refcount on the disk has been updated correctly.
    /// 2. All allocated spaces will not overlap.
    #[test]
    fn test_alloc_cluster_with_refcount_check() {
        let path = "/tmp/test_alloc_cluster_with_refcount_check.qcow2";
        let image_bits = 30;
        let cluster_bits = 9;
        let (mut qcow2, cloned_file) = create_qcow2_driver(path, image_bits, cluster_bits);

        let test_data = vec![1024, 152, 2048, 1, 20000, 65536, 512, 768, 7111, 2000000];
        let cluster_size: u64 = 1 << cluster_bits;
        let mut res_data: Vec<(u64, u64)> = vec![];
        // Call function of alloc_cluster.
        for clusters in test_data {
            let addr = qcow2.alloc_cluster(clusters, true).unwrap();
            res_data.push((addr, clusters * cluster_size));
        }
        // The refcount of all cluster update to disk.
        let image_size: u64 = 1 << image_bits;
        let table_offset = qcow2.header.refcount_table_offset;
        let block_size: u64 = 1 << qcow2.refcount.refcount_blk_bits;
        let table_size = div_round_up(image_size, block_size * cluster_size).unwrap();
        let mut refcount_table = vec![0_u8; table_size as usize * ENTRY_SIZE as usize];
        assert!(cloned_file
            .read_at(&mut refcount_table, table_offset)
            .is_ok());
        for i in 0..table_size {
            let start_idx = i as usize * 8;
            let addr = BigEndian::read_u64(&refcount_table[start_idx..start_idx + 8]);
            assert_ne!(addr, 0);
        }

        // All allocated cluster should not overlap with each other.
        let len = res_data.len();
        for i in 0..len {
            let addr1 = res_data[i].0 as usize;
            let size1 = res_data[i].1 as usize;
            for j in (i + 1)..len {
                let addr2 = res_data[j].0 as usize;
                let size2 = res_data[j].1 as usize;
                assert_eq!(ranges_overlap(addr1, size1, addr2, size2).unwrap(), false);
            }
        }

        remove_file(path).unwrap();
    }

    #[test]
    fn test_extend_refcount_table() {
        let path = "/tmp/refcount_case2.qcow2";
        // Image size is 128MB.
        let image_bits = 27;
        // Cluster size is 1KB.
        let cluster_bits = 10;
        let (mut qcow2, cloned_file) = create_qcow2_driver(path, image_bits, cluster_bits);
        let header = &qcow2.header;
        let rct_offset = header.refcount_table_offset;
        let rct_clusters = header.refcount_table_clusters;

        // Extend refcount table which can not mark all clusters.
        let cluster_sz = 1 << cluster_bits;
        // 3 bit means refcount table entry size(8 Byte)
        // 1 bit means refcount block entry size(2 Byte).
        let mut clusters = 1 << (cluster_bits - 3 + cluster_bits - 1);
        clusters /= 64;
        // Alloc 2 cluster once for all clusters which will cause extending refcount table.
        for _ in 0..clusters + 1 {
            qcow2.alloc_cluster(128, true).unwrap();
        }
        qcow2.flush().unwrap();
        let new_rct_offset = qcow2.header.refcount_table_offset;
        let new_rct_clusters = qcow2.header.refcount_table_clusters;
        assert_ne!(new_rct_offset, rct_offset);
        assert!(qcow2.header.refcount_table_clusters > rct_clusters);

        // Check if the new refcount table contains the old refcount table.
        let old_rct_size = cluster_sz as usize * rct_clusters as usize;
        let new_rct_size = cluster_sz as usize * new_rct_clusters as usize;
        let mut old_rc_table = vec![0_u8; old_rct_size];
        cloned_file.read_at(&mut old_rc_table, rct_offset).unwrap();
        let mut new_rc_table = vec![0_u8; new_rct_size];
        cloned_file
            .read_at(&mut new_rc_table, new_rct_offset as u64)
            .unwrap();
        for i in 0..old_rct_size {
            assert_eq!(old_rc_table[i], new_rc_table[i]);
        }

        // Read the first refcount table entry in the extended cluster of the refcount table.
        let mut rct_entry = vec![0_u8; ENTRY_SIZE as usize];
        cloned_file
            .read_at(&mut rct_entry, new_rct_offset + old_rct_size as u64)
            .unwrap();
        let rcb_offset = BigEndian::read_u64(&rct_entry);

        // Check the refcount block in the extended cluster of the refcount table.
        // It will include the cluster of refcount table and itself.
        let mut rc_table = vec![0_u8; cluster_sz as usize];
        cloned_file.read_at(&mut rc_table, rcb_offset).unwrap();
        for i in 0..new_rct_clusters as usize + 1 {
            let offset = 2 * i;
            assert_eq!(1, BigEndian::read_u16(&rc_table[offset..offset + 2]));
        }

        remove_file(path).unwrap();
    }

    #[test]
    fn test_update_refcount() {
        let path = "/tmp/refcount_case3.qcow2";
        let image_bits = 30;
        let cluster_bits = 16;
        let (qcow2, _) = create_qcow2_driver(path, image_bits, cluster_bits);
        let mut refcount = qcow2.refcount.clone();

        // Add refcount for the first cluster.
        let ret = refcount.update_refcount(0, 1, 1, true, &Qcow2DiscardType::Never);
        assert!(ret.is_ok());

        // Test invalid cluster offset.
        let ret = refcount.update_refcount(1 << 63, 1, 1, true, &Qcow2DiscardType::Never);
        if let Err(err) = ret {
            // 16 bit is cluster bits, 15 is refcount block bits.
            let err_msg = format!("Invalid refcount table index {}", 1_u64 << (63 - 15 - 16));
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test refcount block not in cache.
        let ret = refcount.update_refcount(
            1 << (cluster_bits * 2),
            1,
            1,
            true,
            &Qcow2DiscardType::Never,
        );
        if let Err(err) = ret {
            let err_msg = format!("Invalid refcount block address 0x0, index is 2");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        remove_file(path).unwrap();
    }

    #[test]
    fn test_set_refcount() {
        let path = "/tmp/refcount_case4.qcow2";
        let image_bits = 30;
        let cluster_bits = 16;
        let (qcow2, _) = create_qcow2_driver(path, image_bits, cluster_bits);
        let mut refcount = qcow2.refcount.clone();

        // Add refcount for the first cluster.
        let ret = refcount.set_refcount(0, 0, 1, 1, &Qcow2DiscardType::Never);
        assert!(ret.is_ok());

        // Test refcount overflow.
        let ret = refcount.set_refcount(0, 0, 1, 65535, &Qcow2DiscardType::Never);
        if let Err(err) = ret {
            let err_msg = format!("Refcount 2 add 65535 cause overflows, index is 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        // Test refcount underflow.
        let ret = refcount.set_refcount(0, 0, 1, -65535, &Qcow2DiscardType::Never);
        if let Err(err) = ret {
            let err_msg = format!("Refcount 2 sub 65535 cause overflows, index is 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }

        remove_file(path).unwrap();
    }
}
