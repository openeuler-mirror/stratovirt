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
use log::info;

use super::ENTRY_BITS;
use crate::{
    qcow2::{
        cache::{CacheTable, Qcow2Cache},
        header::QcowHeader,
        SyncAioInfo, ENTRY_SIZE, L1_TABLE_OFFSET_MASK, L2_TABLE_OFFSET_MASK,
        QCOW2_OFFSET_COMPRESSED, QCOW2_OFLAG_ZERO,
    },
    BlockProperty,
};
use machine_manager::config::MAX_L2_CACHE_SIZE;
use util::num_ops::div_round_up;

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
    cluster_bits: u64,
    cluster_size: u64,
    pub l1_table: Vec<u64>,
    l1_table_offset: u64,
    l1_size: u32,
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
            l1_table_offset: 0,
            l1_size: 0,
            l2_table_cache: Qcow2Cache::default(),
            l2_bits: 0,
            l2_size: 0,
        }
    }

    pub fn init_table_info(&mut self, header: &QcowHeader, conf: &BlockProperty) -> Result<()> {
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
        let cache_size = if let Some(l2_cache) = conf.l2_cache_size {
            l2_cache / header.cluster_size()
        } else {
            std::cmp::min(max_l2_cache, MAX_L2_CACHE_SIZE / header.cluster_size())
        };
        info!("Driver {} l2 cache size {}", conf.id, cache_size);
        let l2_table_cache: Qcow2Cache = Qcow2Cache::new(cache_size as usize);
        self.cluster_bits = header.cluster_bits as u64;
        self.cluster_size = header.cluster_size();
        self.l2_bits = header.cluster_bits as u64 - ENTRY_BITS;
        self.l2_size = header.cluster_size() / ENTRY_SIZE;
        self.l2_table_cache = l2_table_cache;
        self.l1_table_offset = header.l1_table_offset;
        self.l1_size = header.l1_size;
        Ok(())
    }

    pub fn load_l1_table(&mut self) -> Result<()> {
        self.l1_table = self
            .sync_aio
            .borrow_mut()
            .read_ctrl_cluster(self.l1_table_offset, self.l1_size as u64)?;
        Ok(())
    }

    pub fn save_l1_table(&mut self) -> Result<()> {
        self.sync_aio
            .borrow_mut()
            .write_ctrl_cluster(self.l1_table_offset, &self.l1_table)
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

    /// Get max data remaining size after the offset which indexed by l2 table.
    pub fn get_l2_table_max_remain_size(&self, guest_offset: u64, offset_in_cluster: u64) -> u64 {
        (self.l2_size - self.get_l2_table_index(guest_offset)) * self.cluster_size
            - offset_in_cluster
    }

    pub fn update_l1_table(&mut self, l1_index: usize, l2_address: u64) {
        self.l1_table[l1_index] = l2_address;
    }

    pub fn update_l2_table(
        &mut self,
        table: Rc<RefCell<CacheTable>>,
        index: usize,
        entry: u64,
    ) -> Result<()> {
        let is_dirty = table.borrow().dirty_info.is_dirty;
        table.borrow_mut().set_entry_map(index, entry)?;
        if !is_dirty {
            self.l2_table_cache.add_dirty_table(table);
        }

        Ok(())
    }

    pub fn cache_l2_table(&mut self, l2_table_entry: Rc<RefCell<CacheTable>>) -> Result<()> {
        let l2_entry_addr = l2_table_entry.borrow().addr;
        if self.l2_table_cache.contains_keys(l2_entry_addr) {
            self.l2_table_cache.cache_map.remove(&l2_entry_addr);
        }
        if let Some(replaced_entry) = self
            .l2_table_cache
            .lru_replace(l2_entry_addr, l2_table_entry)
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

    pub fn flush(&mut self) -> Result<()> {
        self.l2_table_cache.flush(self.sync_aio.clone())
    }

    pub fn drop_dirty_caches(&mut self) {
        self.l2_table_cache.clean_up_dirty_cache();
    }
}

#[cfg(test)]
mod test {
    use std::{
        cell::RefCell,
        io::{Read, Seek, SeekFrom},
        rc::Rc,
    };

    use crate::qcow2::{
        cache::{CacheTable, ENTRY_SIZE_U64},
        test::create_qcow2,
    };

    #[test]
    fn test_update_l2_table() {
        let path = "/tmp/block_backend_test_update_l2_table.qcow2";
        let (mut image, mut qcow2) = create_qcow2(path);
        let cluster_size = qcow2.header.cluster_size() as usize;
        let addr = qcow2.alloc_cluster(1, true).unwrap();
        let l2_cluster: Vec<u8> = vec![0_u8; cluster_size];
        let l2_table = Rc::new(RefCell::new(
            CacheTable::new(addr, l2_cluster.clone(), ENTRY_SIZE_U64).unwrap(),
        ));
        qcow2.table.cache_l2_table(l2_table.clone()).unwrap();

        let test_val1 = 0xff00ff00_u64;
        qcow2
            .table
            .update_l2_table(l2_table.clone(), 0, test_val1)
            .unwrap();
        let res = l2_table.borrow_mut().get_entry_map(0).unwrap();
        assert_eq!(res, test_val1);

        image.file.seek(SeekFrom::Start(addr)).unwrap();
        let mut buf = vec![0_u8; ENTRY_SIZE_U64];
        image.file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0_u8; ENTRY_SIZE_U64]);

        let test_val2 = 0x00ff00ff_u64;
        qcow2
            .table
            .update_l2_table(l2_table.clone(), 8191, test_val2)
            .unwrap();
        let res = l2_table.borrow_mut().get_entry_map(8191).unwrap();
        assert_eq!(res, test_val2);

        qcow2.table.flush().unwrap();
        image.file.seek(SeekFrom::Start(addr)).unwrap();
        let mut buf = vec![0_u8; ENTRY_SIZE_U64];
        image.file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, test_val1.to_be_bytes());

        let offset = addr + ENTRY_SIZE_U64 as u64 * 8191;
        image.file.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = vec![0_u8; ENTRY_SIZE_U64];
        image.file.read_exact(&mut buf).unwrap();
        assert_eq!(buf, test_val2.to_be_bytes());
    }
}
