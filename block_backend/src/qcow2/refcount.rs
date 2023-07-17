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
use util::aio::OpCode;

use crate::{
    qcow2::{
        bytes_to_clusters,
        cache::{CacheTable, Qcow2Cache, ENTRY_SIZE_U16},
        header::QcowHeader,
        is_aligned, SyncAioInfo, ENTRY_SIZE,
    },
    BlockProperty,
};

// The max refcount table size default is 4 clusters;
const MAX_REFTABLE_NUM: u32 = 4;

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
    refcount_blk_cache: Qcow2Cache,
    pub discard_list: Vec<DiscardTask>,
    /// Pass the discard operation if refcount of cluster decrease to 0.
    pub discard_passthrough: Vec<Qcow2DiscardType>,
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

    pub fn init_refcount_info(&mut self, header: &QcowHeader, conf: BlockProperty) {
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
    }

    pub fn start_of_cluster(&self, offset: u64) -> u64 {
        offset & !(self.cluster_size - 1)
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
        let clusters = bytes_to_clusters(old_rct_size, self.cluster_size).unwrap();
        self.update_refcount(
            old_rct_offset,
            clusters,
            -1,
            true,
            &Qcow2DiscardType::Snapshot,
        )?;
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

        let idx = self.set_refcount_blocks(&rc_vec, added, discard_type);
        if idx != rc_vec.len() {
            // Revert the updating operation for refount block.
            let rev_idx = self.set_refcount_blocks(&rc_vec[..idx], -added, discard_type);
            let status = if rev_idx == idx { "success" } else { "failed" };
            bail!("Failed to set refcounts, recover {}", status);
        }
        if flush {
            self.flush_refcount_block_cache()?;
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

    pub fn flush_refcount_block_cache(&self) -> Result<()> {
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

        Ok(())
    }

    pub fn get_refcount(&mut self, offset: u64) -> Result<u16> {
        let cluster = offset >> self.cluster_bits;
        let rt_idx = cluster >> self.refcount_blk_bits;
        if rt_idx >= self.refcount_table_size as u64 {
            bail!(
                "Invalid refcount table index {}, refcount table size {}",
                rt_idx,
                self.refcount_table_size
            );
        }

        let rb_addr = self.refcount_table[rt_idx as usize];
        if rb_addr == 0 || self.offset_into_cluster(rb_addr) != 0 {
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
        let clusters = bytes_to_clusters(size, self.cluster_size).unwrap();
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
        if size == 0 {
            bail!("Don't allow to alloc 0 size cluster!");
        }
        let addr = self.find_free_cluster(header, size)?;
        let clusters = bytes_to_clusters(size, self.cluster_size).unwrap();
        self.update_refcount(addr, clusters, 1, true, &Qcow2DiscardType::Other)?;
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

#[cfg(test)]
mod test {
    use std::{
        fs::{remove_file, File},
        io::{Seek, SeekFrom, Write},
        os::unix::fs::{FileExt, OpenOptionsExt},
        sync::Arc,
    };

    use anyhow::Result;
    use byteorder::{BigEndian, ByteOrder};

    use crate::qcow2::*;
    use crate::qcow2::{header::*, refcount::Qcow2DiscardType};
    use machine_manager::config::DiskFormat;
    use util::aio::{Aio, AioCb, WriteZeroesState};

    fn stub_func(_: &AioCb<()>, _: i64) -> Result<()> {
        Ok(())
    }

    fn image_create(path: &str, img_bits: u32, cluster_bits: u32) -> File {
        let cluster_sz = 1 << cluster_bits;
        let header = QcowHeader {
            magic: QCOW_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: cluster_bits,
            size: 1 << img_bits,
            crypt_method: 0,
            l1_size: 1 << (img_bits - (cluster_bits * 2 - 3)),
            l1_table_offset: 3 * cluster_sz,
            refcount_table_offset: cluster_sz,
            refcount_table_clusters: 1,
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
        file.set_len(cluster_sz * 3 + header.l1_size as u64 * ENTRY_SIZE)
            .unwrap();
        file.write_all(&header.to_vec()).unwrap();

        // Cluster 1 is the refcount table.
        assert_eq!(header.refcount_table_offset, cluster_sz * 1);
        let mut refcount_table = [0_u8; ENTRY_SIZE as usize];
        BigEndian::write_u64(&mut refcount_table, cluster_sz * 2);
        file.seek(SeekFrom::Start(cluster_sz * 1)).unwrap();
        file.write_all(&refcount_table).unwrap();

        // Clusters which has been allocated.
        assert_eq!(header.refcount_order, 4);
        let clusters =
            3 + ((header.l1_size * ENTRY_SIZE as u32 + cluster_sz as u32 - 1) >> cluster_bits);
        let mut refcount_block = Vec::new();
        for _ in 0..clusters {
            refcount_block.push(0x00);
            refcount_block.push(0x01);
        }
        file.seek(SeekFrom::Start(cluster_sz * 2)).unwrap();
        file.write_all(&refcount_block).unwrap();

        file
    }

    fn create_qcow2_driver(
        path: &str,
        img_bits: u32,
        cluster_bits: u32,
    ) -> (Qcow2Driver<()>, File) {
        let file = image_create(path, img_bits, cluster_bits);
        let aio = Aio::new(Arc::new(stub_func), util::aio::AioEngine::Off).unwrap();
        let conf = BlockProperty {
            format: DiskFormat::Qcow2,
            iothread: None,
            direct: true,
            req_align: 512,
            buf_align: 512,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
        };
        let cloned_file = file.try_clone().unwrap();
        (Qcow2Driver::new(file, aio, conf).unwrap(), cloned_file)
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
        clusters /= 2;
        // Alloc 2 cluster once for all clusters which will cause extending refcount table.
        for _ in 0..clusters + 1 {
            qcow2.alloc_cluster(2, true).unwrap();
        }
        let new_rct_offset = qcow2.header.refcount_table_offset;
        let new_rct_clusters = qcow2.header.refcount_table_clusters;
        assert_ne!(new_rct_offset, rct_offset);
        assert_eq!(qcow2.header.refcount_table_clusters, rct_clusters + 1);

        // Check if the new refcount table contains the old refcount table.
        let old_rct_size = cluster_sz as usize * rct_clusters as usize;
        let mut old_rc_table = vec![0_u8; old_rct_size];
        cloned_file.read_at(&mut old_rc_table, rct_offset).unwrap();
        let mut new_rc_table = vec![0_u8; old_rct_size];
        cloned_file.read_at(&mut new_rc_table, rct_offset).unwrap();
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

    #[test]
    fn test_find_free_cluster() {
        let path = "/tmp/refcount_case5.qcow2";
        let image_bits = 30;
        let cluster_bits = 16;
        let cluster_sz = 1 << 16;
        let (qcow2, _) = create_qcow2_driver(path, image_bits, cluster_bits);
        let mut refcount = qcow2.refcount.clone();
        let mut header = qcow2.header.clone();

        // Test find 1 free cluster.
        let ret = refcount.find_free_cluster(&mut header, cluster_sz);
        assert!(ret.is_ok());

        // Test find 10 continuous free cluster.
        let ret = refcount.find_free_cluster(&mut header, 10 * cluster_sz);
        assert!(ret.is_ok());

        // Test invalid refcount table entry.
        refcount.refcount_table[0] |= 0x1;
        let ret = refcount.find_free_cluster(&mut header, 1 << cluster_bits);
        if let Err(err) = ret {
            let err_msg = format!("Invalid refcount block address 0x20001, index is 0");
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }
        refcount.refcount_table[0] &= !0x1;

        remove_file(path).unwrap();
    }
}
