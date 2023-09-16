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

use std::{cell::RefCell, cmp::Ordering, mem::size_of, rc::Rc};

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};

use crate::qcow2::{
    bytes_to_clusters,
    cache::{CacheTable, ENTRY_SIZE_U16, ENTRY_SIZE_U64},
    header::QcowHeader,
    is_aligned,
    refcount::Qcow2DiscardType,
    snapshot::{QcowSnapshotHeader, QCOW2_MAX_SNAPSHOTS},
    table::Qcow2ClusterType,
    Qcow2Driver, SyncAioInfo, ENTRY_BITS, ENTRY_SIZE, L1_RESERVED_MASK, L1_TABLE_OFFSET_MASK,
    L2_STD_RESERVED_MASK, L2_TABLE_OFFSET_MASK, METADATA_OVERLAP_CHECK_ACTIVEL2,
    METADATA_OVERLAP_CHECK_INACTIVEL2, QCOW2_MAX_L1_SIZE, QCOW2_OFFSET_COPIED, QCOW2_OFLAG_ZERO,
    REFCOUNT_TABLE_OFFSET_MASK, REFCOUNT_TABLE_RESERVED_MASK,
};
use crate::{output_msg, CheckResult, FIX_ERRORS, FIX_LEAKS};
use util::{
    aio::{raw_write_zeroes, OpCode},
    byte_code::ByteCode,
    num_ops::div_round_up,
    offset_of,
};

pub struct Qcow2Check {
    pub res: CheckResult,
    pub refblock: RefcountBlock,
    pub fix: u64,
    pub quite: bool,
}

impl Qcow2Check {
    pub fn new(fix: u64, quite: bool, entry_bytes: usize, table_size: usize) -> Self {
        Self {
            res: CheckResult::default(),
            refblock: RefcountBlock::new(entry_bytes, table_size),
            fix,
            quite,
        }
    }
}

pub struct RefcountBlock {
    data: Vec<u8>,
    table_size: usize,
    entry_bytes: usize,
    max_refcount: u64,
    nb_clusters: u64,
}

impl RefcountBlock {
    fn new(entry_bytes: usize, table_size: usize) -> Self {
        Self {
            data: vec![0_u8; table_size * entry_bytes],
            table_size,
            entry_bytes,
            max_refcount: ((1 << (entry_bytes * 8)) - 1) as u64,
            nb_clusters: table_size as u64,
        }
    }

    fn reset(&mut self) {
        self.data.fill(0);
    }

    fn extend_table(&mut self, new_size: usize) {
        if new_size <= self.table_size {
            return;
        };
        let new_table_bytes = new_size * self.entry_bytes;
        self.data.resize(new_table_bytes, 0);
        self.table_size = new_size;
        self.nb_clusters = new_size as u64;
    }

    fn get_data(&mut self, start: usize, size: usize) -> Vec<u8> {
        let mut start_bytes = start * self.entry_bytes;
        let mut end_bytes = (start + size) * self.entry_bytes;
        start_bytes = std::cmp::min(start_bytes, self.data.len());
        end_bytes = std::cmp::min(end_bytes, self.data.len());
        self.data[start_bytes..end_bytes].to_vec()
    }

    #[inline(always)]
    fn get_refcount(&mut self, idx: usize) -> Result<u64> {
        if idx >= self.table_size {
            return Ok(0);
        }

        let start_bytes = idx * self.entry_bytes;
        let end_bytes = start_bytes + self.entry_bytes;
        let value = match self.entry_bytes {
            ENTRY_SIZE_U16 => BigEndian::read_u16(&self.data[start_bytes..end_bytes]) as u64,
            ENTRY_SIZE_U64 => BigEndian::read_u64(&self.data[start_bytes..end_bytes]),
            _ => bail!("Entry size is unsupported"),
        };
        Ok(value)
    }

    #[inline(always)]
    fn set_refcount(&mut self, idx: usize, value: u64) -> Result<()> {
        if idx >= self.table_size {
            bail!("Idx {:?} exceed table size {}", idx, self.table_size)
        }

        let start_bytes = idx * self.entry_bytes;
        let end_bytes = start_bytes + self.entry_bytes;
        match self.entry_bytes {
            ENTRY_SIZE_U16 => {
                BigEndian::write_u16(&mut self.data[start_bytes..end_bytes], value as u16)
            }
            ENTRY_SIZE_U64 => BigEndian::write_u64(&mut self.data[start_bytes..end_bytes], value),
            _ => bail!("Entry size is unsupported"),
        }
        Ok(())
    }

    /// Alloc blocks based on reference recorded in the refcount block, and the reference
    /// of these clusters should be updated later by calling set_refcount function.
    ///
    /// # Arguments
    ///
    /// * `total_counts` - Total number of consecutive clusters that need to be allocated.
    /// * `cluster_bits` - Bits of cluster.
    /// * `first_free_cluster` - Alloc consecutive free data from first_free_cluster.
    /// * `sync_aio` - The newly allocated data block needs to reset to 0 on disk.
    fn alloc_clusters(
        &mut self,
        total_counts: u64,
        cluster_bits: u64,
        first_free_cluster: &mut usize,
        sync_aio: Rc<RefCell<SyncAioInfo>>,
    ) -> Result<u64> {
        let cluster_size = 1 << cluster_bits;
        let mut first_update: bool = true;
        let mut cluster_idx = *first_free_cluster;
        let mut continue_clusters: usize = 0;
        while continue_clusters < total_counts as usize {
            if self.get_refcount(cluster_idx as usize)? == 0 {
                continue_clusters += 1;
                if first_update {
                    *first_free_cluster = cluster_idx;
                    first_update = false;
                }
            } else {
                continue_clusters = 0;
            }

            cluster_idx += 1;
        }

        if cluster_idx > self.table_size {
            self.extend_table(cluster_idx);
        }

        let start_idx = cluster_idx - total_counts as usize;
        let zero_buf = vec![0_u8; cluster_size];
        for i in 0..total_counts {
            let cluster_offset = (start_idx as u64 + i) << cluster_bits;
            self.set_refcount(start_idx + i as usize, 1)?;
            // Write zero to disk
            let ret = raw_write_zeroes(
                sync_aio.borrow_mut().fd,
                cluster_offset as usize,
                cluster_size as u64,
            );
            if ret < 0 {
                sync_aio
                    .borrow_mut()
                    .write_buffer(cluster_offset, &zero_buf)?;
            }
        }

        Ok((start_idx as u64) << cluster_bits)
    }
}

#[cfg(test)]
mod test {
    use super::RefcountBlock;

    #[test]
    fn test_refcount_block_basic() {
        let mut refblock = RefcountBlock::new(2, 10);
        assert!(refblock.set_refcount(10, 1).is_err());
        assert_eq!(refblock.max_refcount, 65535);
        assert_eq!(refblock.table_size, 10);
        assert!(refblock.set_refcount(0, 1).is_ok());
        assert!(refblock.set_refcount(1, 7).is_ok());
        assert!(refblock.set_refcount(9, 9).is_ok());

        // Get inner dat
        let mut vec_1 = (1 as u16).to_be_bytes().to_vec();
        let mut vec_2 = (7 as u16).to_be_bytes().to_vec();
        vec_1.append(&mut vec_2);
        let buf = refblock.get_data(0, 2);
        assert_eq!(buf, vec_1);

        // Get refcount
        let count = refblock.get_refcount(0).unwrap();
        assert_eq!(count, 1);
        let count = refblock.get_refcount(9).unwrap();
        assert_eq!(count, 9);

        refblock.extend_table(10);
        refblock.extend_table(11);
        let count = refblock.get_refcount(10).unwrap();
        assert_eq!(count, 0);

        refblock.reset();
        let count = refblock.get_refcount(9).unwrap();
        assert_eq!(count, 0);
    }
}
