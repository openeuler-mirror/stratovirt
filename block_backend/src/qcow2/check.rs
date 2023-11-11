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
        // SAFETY: Upper limit of new_table_bytes is decided by disk file size.
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
            if self.get_refcount(cluster_idx)? == 0 {
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

impl<T: Clone + 'static> Qcow2Driver<T> {
    /// Read the snapshot table from the disk and verify it.
    pub(crate) fn check_read_snapshot_table(
        &mut self,
        res: &mut CheckResult,
        quite: bool,
        fix: u64,
    ) -> Result<()> {
        let mut extra_data_dropped: i32 = 0;
        let mut nb_clusters_reduced: i32 = 0;
        let mut nb_snapshots = self.header.nb_snapshots;

        // Validate the number of snapshots.
        if nb_snapshots as usize > QCOW2_MAX_SNAPSHOTS {
            if fix & FIX_ERRORS == 0 {
                res.err_num += 1;
                bail!("You can force-remove all {} overhanging snapshots with \"stratovirt-img check -r all\"",nb_snapshots as usize - QCOW2_MAX_SNAPSHOTS);
            }

            output_msg!(
                quite,
                "Discarding {} overhanging snapshots",
                nb_snapshots as usize - QCOW2_MAX_SNAPSHOTS
            );
            nb_clusters_reduced += (nb_snapshots as usize - QCOW2_MAX_SNAPSHOTS) as i32;
            nb_snapshots = QCOW2_MAX_SNAPSHOTS as u32;
        }

        let snapshot_table_length = size_of::<QcowSnapshotHeader>() as u64;
        let snapshot_table_offset = self.header.snapshots_offset;
        // Validate snapshot table.
        if (u64::MAX - nb_snapshots as u64 * snapshot_table_length) < snapshot_table_offset
            || !is_aligned(self.header.cluster_size(), snapshot_table_offset)
        {
            res.err_num += 1;
            self.header.snapshots_offset = 0;
            self.header.nb_snapshots = 0;
            bail!("Snapshot table can't exceeds the limit and it's offset must be aligned to cluster size {}", self.header.cluster_size());
        }

        match self.snapshot.load_snapshot_table(
            snapshot_table_offset,
            nb_snapshots,
            fix & FIX_ERRORS != 0,
        ) {
            Ok((cluster_reduced, data_dropped)) => {
                nb_clusters_reduced += cluster_reduced;
                extra_data_dropped += data_dropped;
            }
            Err(e) => {
                res.err_num += 1;
                self.snapshot.snapshot_table_offset = 0;
                self.snapshot.nb_snapshots = 0;
                bail!("ERROR failed to read the snapshot table: {}", e);
            }
        }
        res.corruptions += nb_clusters_reduced + extra_data_dropped;

        // Update snapshot in header
        // This operations will leaks clusters(extra clusters of snapshot table will be dropped), which will
        // be fixed in function of check_refcounts later.
        if nb_clusters_reduced > 0 {
            let new_nb_snapshots = self.snapshot.nb_snapshots;
            let buf = new_nb_snapshots.as_bytes().to_vec();
            let offset = offset_of!(QcowHeader, nb_snapshots);
            if let Err(e) = self
                .sync_aio
                .borrow_mut()
                .write_buffer(offset as u64, &buf)
                .with_context(|| {
                    "Failed to update the snapshot count in the image header".to_string()
                })
            {
                res.err_num += 1;
                bail!(
                    "Failed to update the snapshot count in the image header: {}",
                    e
                );
            }

            self.header.nb_snapshots = new_nb_snapshots;
            res.corruptions_fixed += nb_clusters_reduced;
            res.corruptions -= nb_clusters_reduced;
        }

        Ok(())
    }

    pub fn check_fix_snapshot_table(
        &mut self,
        res: &mut CheckResult,
        quite: bool,
        fix: u64,
    ) -> Result<()> {
        if res.corruptions != 0 && fix & FIX_ERRORS != 0 {
            if let Err(e) = self.write_snapshots_to_disk() {
                res.err_num += 1;
                output_msg!(quite, "ERROR failed to update snapshot table {:?}", e);
            }

            res.corruptions_fixed += res.corruptions;
            res.corruptions = 0;
        }

        Ok(())
    }

    /// Rebuild a new refcount table according to metadata, including active l1 table, active l2 table,
    /// snapshot table, refcount table and refcount block.
    pub(crate) fn check_refcounts(&mut self, check: &mut Qcow2Check) -> Result<()> {
        let cluster_bits = self.header.cluster_bits as u64;
        let cluster_size = 1 << cluster_bits;
        let virtual_size = self.header.size;
        check.res.disk_frag.total_clusters = div_round_up(virtual_size, cluster_size).unwrap();

        let file_len = self.driver.disk_size()?;
        let nb_clusters = div_round_up(file_len, cluster_size).unwrap();
        if nb_clusters > i32::MAX as u64 {
            check.res.err_num += 1;
            bail!("Number of clusters exceed {:?}", i32::MAX);
        }

        // Rebuild refcount block data in memory
        self.calculate_refcount(check)?;

        // Compare the refcount block in Memory with real refcount block.
        let pre_compare_res = check.res;
        self.compare_refcounts(check)?;

        if check.res.need_rebuild && check.fix & FIX_ERRORS != 0 {
            let old_res = check.res;
            let mut fresh_leak = 0;

            output_msg!(check.quite, "Rebuilding refcount structure");
            self.rebuild_refcount_structure(check)?;

            check.res.corruptions = 0;
            check.res.leaks = 0;
            check.res.need_rebuild = false;
            check.refblock.reset();

            // This operation will leaks the old refcount table, so fix it.
            self.calculate_refcount(check)?;
            if check.fix & FIX_LEAKS != 0 {
                let saved_res = check.res;
                check.res = CheckResult::default();
                self.compare_refcounts(check)?;
                if check.res.need_rebuild {
                    output_msg!(
                        check.quite,
                        "ERROR rebuilt refcount structure is still broken"
                    );
                }
                fresh_leak = check.res.leaks;
                check.res = saved_res;
            }

            if check.res.corruptions < old_res.corruptions {
                check.res.corruptions_fixed += old_res.corruptions - check.res.corruptions;
            }
            if check.res.leaks < old_res.leaks {
                check.res.leaks_fixed += old_res.leaks - check.res.leaks;
            }

            check.res.leaks += fresh_leak;
        } else if check.fix != 0 {
            if check.res.need_rebuild {
                bail!("ERROR need to rebuild refcount structures");
            }

            if check.res.leaks | check.res.corruptions != 0 {
                check.res = pre_compare_res;
                check.fix = 0;
                self.compare_refcounts(check)?;
            }
        }

        // Check OFLAG_COPIED in l1 table and l2 table.
        self.check_oflag_copied(check)
    }

    /// Calculate the reference of all cluster data according to l1 and l2 table.
    fn calculate_refcount(&mut self, check: &mut Qcow2Check) -> Result<()> {
        let file_len = self.driver.disk_size()?;

        // Increase the refcount of qcow2 header.
        self.increase_refcounts(
            0,
            self.header.cluster_size(),
            file_len,
            self.header.cluster_bits as u64,
            check,
        )?;

        // Increase the refcount of active l1 table.
        let active_l1_offset = self.header.l1_table_offset;
        let active_l1_size = self.header.l1_size;
        self.check_refcounts_l1(active_l1_offset, active_l1_size as u64, true, check)?;

        // Increase the refcount of snapshot table.
        for idx in 0..self.header.nb_snapshots {
            let snap = self.snapshot.snapshots[idx as usize].clone();
            let snap_l1_offset = snap.l1_table_offset;
            let snap_l1_size = snap.l1_size;
            if !is_aligned(self.header.cluster_size(), snap_l1_offset) {
                output_msg!(
                    check.quite,
                    "ERROR snapshot {:?}({:?}) l1_offset={:#X} L1 table is not cluster aligned; snapshot table entry corrupted",
                    snap.id, snap.name, snap_l1_offset
                );
                check.res.corruptions += 1;
                continue;
            }

            if snap_l1_size as u64 > QCOW2_MAX_L1_SIZE / ENTRY_SIZE {
                output_msg!(
                    check.quite,
                    "ERROR snapshot {:?}({:?}) l1_size={:?} l1 table is too large; snapshot table entry courropted",
                    snap.id, snap.name, snap_l1_size
                );
                check.res.corruptions += 1;
                continue;
            }

            self.check_refcounts_l1(snap_l1_offset, snap_l1_size as u64, false, check)?;
        }

        let snap_table_offset = self.header.snapshots_offset;
        let snap_table_size = self.snapshot.snapshot_size;
        if snap_table_offset != 0 && snap_table_size != 0 {
            self.increase_refcounts(
                snap_table_offset,
                snap_table_size,
                file_len,
                self.header.cluster_bits as u64,
                check,
            )?;
        }

        let reftable_offset = self.header.refcount_table_offset;
        let reftable_bytes =
            self.header.refcount_table_clusters as u64 * self.header.cluster_size();
        self.increase_refcounts(
            reftable_offset,
            reftable_bytes,
            file_len,
            self.header.cluster_bits as u64,
            check,
        )?;

        self.check_refcount_block(check)
    }

    /// Traverse all l1 tables and data blocks indexed by l1 table and calculate the real
    /// reference of these clusters, and performs some checks as well.
    fn check_refcounts_l1(
        &mut self,
        l1_offset: u64,
        l1_size: u64,
        is_active: bool,
        check: &mut Qcow2Check,
    ) -> Result<()> {
        if l1_offset == 0 || l1_size == 0 {
            return Ok(());
        }

        let l1_size_bytes = l1_size * ENTRY_SIZE;
        let file_len = self.driver.disk_size()?;
        // Increase the refcount of cluster which l1 table is located.
        self.increase_refcounts(
            l1_offset,
            l1_size_bytes,
            file_len,
            self.header.cluster_bits as u64,
            check,
        )?;
        let l1_table = self
            .sync_aio
            .borrow_mut()
            .read_ctrl_cluster(l1_offset, l1_size)?;

        // Entry in l1 table
        for idx in 0..l1_size {
            let l1_entry = match l1_table.get(idx as usize) {
                Some(v) => v,
                None => continue,
            };

            if l1_entry == &0 {
                continue;
            }

            // The error in reserved field of l1 entry not need to be fixed, as it not effect the basic functions
            if l1_entry & L1_RESERVED_MASK != 0 {
                output_msg!(
                    check.quite,
                    "ERROR found L1 entry with reserved bits set {:#X}",
                    l1_entry
                );
                check.res.corruptions += 1;
            }

            let l2_offset = l1_entry & L1_TABLE_OFFSET_MASK;
            self.increase_refcounts(
                l2_offset,
                self.header.cluster_size(),
                file_len,
                self.header.cluster_bits as u64,
                check,
            )?;

            if !is_aligned(self.header.cluster_size(), l2_offset) {
                output_msg!(
                    check.quite,
                    "ERROR l2_offset={:#X}: Table is not \n\
                    cluster aligned; l1 entry corrupted",
                    l2_offset
                );
                check.res.corruptions += 1;
            }

            self.check_refcount_l2(l2_offset, is_active, file_len, check)?;
        }

        // The l2 entry on disk may be modified.
        if check.fix & FIX_ERRORS != 0 {
            self.table.l2_table_cache.clear_cache();
        }

        Ok(())
    }

    fn check_refcount_l2(
        &mut self,
        l2_offset: u64,
        is_active: bool,
        file_len: u64,
        check: &mut Qcow2Check,
    ) -> Result<()> {
        let cluster_bits = self.header.cluster_bits as u64;
        let cluster_size = 1 << cluster_bits;
        let l2_size = cluster_size >> ENTRY_BITS;

        // Read l2 table from disk
        let mut l2_table: Vec<u64>;
        match self
            .sync_aio
            .borrow_mut()
            .read_ctrl_cluster(l2_offset, l2_size)
        {
            Ok(buf) => l2_table = buf,
            Err(e) => {
                check.res.err_num += 1;
                bail!("ERROR: I/O error in reading l2 table {}", e);
            }
        };

        let err_flag = if check.fix & FIX_ERRORS != 0 {
            "Repairing".to_string()
        } else {
            "ERROR".to_string()
        };
        let mut next_continue_offset: u64 = 0;
        for l2_idx in 0..l2_size {
            let l2_entry = match l2_table.get(l2_idx as usize) {
                Some(value) => *value,
                None => continue,
            };
            let cluster_type = Qcow2ClusterType::get_cluster_type(l2_entry);
            // The error in reserved field of l2 entry not need to be fixed, as it not effect the basic functions
            if cluster_type != Qcow2ClusterType::Compressed && l2_entry & L2_STD_RESERVED_MASK != 0
            {
                output_msg!(
                    check.quite,
                    "ERROR found l2 entry with reserved bits set: {:#X}",
                    l2_entry
                );
                check.res.corruptions += 1;
            }

            match cluster_type {
                Qcow2ClusterType::Compressed => {
                    output_msg!(check.quite, "Compressed is not supported");
                }
                Qcow2ClusterType::ZeroPlain | Qcow2ClusterType::Unallocated => continue,
                Qcow2ClusterType::ZeroAlloc | Qcow2ClusterType::Normal => {
                    let cluster_offset = l2_entry & L1_TABLE_OFFSET_MASK;

                    if !is_aligned(cluster_size, cluster_offset) {
                        check.res.corruptions += 1;
                        let contains_data = l2_entry & QCOW2_OFLAG_ZERO != 0;
                        if !contains_data {
                            output_msg!(
                                check.quite,
                                "{} offset={:#X}: Preallocated cluster is not properly aligned; L2 entry corrupted.",
                                err_flag, cluster_offset
                            );
                            if check.fix & FIX_ERRORS != 0 {
                                self.repair_l2_entry(
                                    &mut l2_table,
                                    l2_offset,
                                    l2_idx,
                                    is_active,
                                    check,
                                )?;
                            }
                            continue;
                        } else {
                            output_msg!(
                                check.quite,
                                "ERROR offset={:#X}: Data cluster is not properly aligned; L2 entry corrupted.",
                                cluster_offset
                            );
                        }
                    }

                    // Disk Fragmentation
                    check.res.disk_frag.allocated_clusters += 1;
                    if next_continue_offset != 0 && next_continue_offset != cluster_offset {
                        check.res.disk_frag.fragments += 1;
                    }
                    next_continue_offset = cluster_offset + cluster_size;

                    // Mark cluster in refcount table.
                    self.increase_refcounts(
                        cluster_offset,
                        cluster_size,
                        file_len,
                        cluster_bits,
                        check,
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Fix l2 entry with oflag zero.
    fn repair_l2_entry(
        &mut self,
        l2_table: &mut [u64],
        l2_offset: u64,
        l2_idx: u64,
        is_active: bool,
        check: &mut Qcow2Check,
    ) -> Result<()> {
        let ignore = if is_active {
            METADATA_OVERLAP_CHECK_ACTIVEL2
        } else {
            METADATA_OVERLAP_CHECK_INACTIVEL2
        };
        let l2e_offset = l2_offset + l2_idx * ENTRY_SIZE;
        l2_table[l2_idx as usize] = QCOW2_OFLAG_ZERO;

        let ret = self.check_overlap(ignore, l2e_offset, ENTRY_SIZE);
        if ret != 0 {
            bail!("ERROR: Overlap check failed");
        }

        // Write sync to disk
        let buf = QCOW2_OFLAG_ZERO.to_be_bytes().to_vec();
        if let Err(e) = self.sync_aio.borrow_mut().write_buffer(l2e_offset, &buf) {
            bail!("ERROR: Failed to overwrite L2 table entry: {:?}", e);
        };

        check.res.corruptions -= 1;
        check.res.corruptions_fixed += 1;
        Ok(())
    }

    fn check_refcount_block(&mut self, check: &mut Qcow2Check) -> Result<()> {
        let cluster_bits = self.header.cluster_bits as u64;
        let cluster_size = 1 << cluster_bits;
        let file_len = self.driver.disk_size()?;
        let nb_clusters = bytes_to_clusters(file_len, cluster_size)?;
        let err_flag = if check.fix & FIX_ERRORS != 0 {
            "Repairing".to_string()
        } else {
            "ERROR".to_string()
        };

        let reftable = self.refcount.refcount_table.clone();
        for (idx, reftable_entry) in reftable.iter().enumerate() {
            let refblock_offset = reftable_entry & REFCOUNT_TABLE_OFFSET_MASK;
            let cluster_idx = refblock_offset >> cluster_bits;
            if reftable_entry & REFCOUNT_TABLE_RESERVED_MASK != 0 {
                output_msg!(
                    check.quite,
                    "ERROR refcount table entry {:?} has reserved bits set",
                    idx
                );
                check.res.corruptions += 1;
                check.res.need_rebuild = true;
                continue;
            }

            if !is_aligned(cluster_size, refblock_offset) {
                output_msg!(
                    check.quite,
                    "ERROR refcount block {:?} is not cluster aligned; refcount table entry corrupted",
                    idx
                );
                check.res.corruptions += 1;
                check.res.need_rebuild = true;
                continue;
            }

            if cluster_idx >= nb_clusters {
                output_msg!(
                    check.quite,
                    "{} refcount block {} is outside image",
                    err_flag,
                    cluster_idx
                );
                check.res.corruptions += 1;

                if check.fix & FIX_ERRORS != 0 {
                    // Need to try resize the image size.
                    check.res.need_rebuild = true;
                }
                continue;
            }

            if refblock_offset != 0 {
                self.increase_refcounts(
                    refblock_offset,
                    cluster_size,
                    file_len,
                    cluster_bits,
                    check,
                )?;
                let rc_value = check.refblock.get_refcount(cluster_idx as usize)?;
                // The refcount for data clusters of refcount block must be 1
                if rc_value != 1 {
                    output_msg!(
                        check.quite,
                        "ERROR refcount block {:?}, refcount={:?}",
                        idx,
                        rc_value
                    );
                    check.res.need_rebuild = true;
                }
            }
        }

        Ok(())
    }

    /// Compare the real references of clusters with the references recorded on the disk,
    /// and choose whether to repair it on the disk.
    pub(crate) fn compare_refcounts(&mut self, check: &mut Qcow2Check) -> Result<()> {
        self.table.load_l1_table()?;
        self.table.l2_table_cache.clear_cache();
        self.load_refcount_table()?;
        self.refcount.refcount_blk_cache.clear_cache();

        let mut rc_value_1: u16;
        let mut rc_value_2: u16;
        let cluster_bits = self.header.cluster_bits;
        let file_len = self.driver.disk_size()?;
        let nb_clusters = div_round_up(file_len, self.header.cluster_size()).unwrap();
        for cluster_idx in 0..nb_clusters {
            match self.refcount.get_refcount(cluster_idx << cluster_bits) {
                Err(e) => {
                    output_msg!(check.quite, "Cant't get refcount for cluster {:?}", e);
                    check.res.err_num += 1;
                    continue;
                }
                Ok(value) => rc_value_1 = value,
            };
            rc_value_2 = check.refblock.get_refcount(cluster_idx as usize)? as u16;

            if rc_value_1 != 0 || rc_value_2 != 0 {
                check.res.image_end_offset = (cluster_idx + 1) << cluster_bits;
            }

            if rc_value_1 != rc_value_2 {
                let mut need_fixed: bool = false;
                if rc_value_1 == 0 {
                    // The refcount block may not have assigned cluster,
                    // so need to rebuild refcount structure.
                    check.res.need_rebuild = true;
                } else if (rc_value_1 > rc_value_2 && check.fix & FIX_LEAKS != 0)
                    || (rc_value_1 < rc_value_2 && check.fix & FIX_ERRORS != 0)
                {
                    need_fixed = true;
                }
                let err_flag = if need_fixed {
                    "Repairing"
                } else if rc_value_1 > rc_value_2 {
                    "Leaked"
                } else {
                    "ERROR"
                };
                output_msg!(
                    check.quite,
                    "{} cluster {:?} refcount={:?} reference={:?}",
                    err_flag,
                    cluster_idx,
                    rc_value_1,
                    rc_value_2
                );

                if need_fixed {
                    let added = rc_value_2 as i32 - rc_value_1 as i32;
                    let cluster_offset = cluster_idx << cluster_bits;
                    self.refcount.update_refcount(
                        cluster_offset,
                        1,
                        added,
                        false,
                        &Qcow2DiscardType::Always,
                    )?;
                    if added < 0 {
                        check.res.leaks_fixed += 1;
                    } else {
                        check.res.corruptions_fixed += 1;
                    }
                    continue;
                }

                match rc_value_1.cmp(&rc_value_2) {
                    Ordering::Less => check.res.corruptions += 1,
                    Ordering::Greater => check.res.leaks += 1,
                    Ordering::Equal => {}
                };
            }
        }

        if !self.refcount.discard_list.is_empty() {
            self.refcount.sync_process_discards(OpCode::Discard);
        }
        self.refcount.flush()?;

        Ok(())
    }

    // For the entry in active table, the reference equals to 1 means don't need to copy on write,
    // So the oflag of copied must set to nonzero.
    fn check_oflag_copied(&mut self, check: &mut Qcow2Check) -> Result<()> {
        let l1_size = self.table.l1_table.len();
        let l2_size = div_round_up(self.header.cluster_size(), ENTRY_SIZE).unwrap();
        let mut l1_dirty = false;
        let mut l1_corruptions: i32 = 0;
        let mut l1_corruptions_fixed: i32 = 0;

        let repair = if check.fix & FIX_ERRORS != 0 {
            true
        } else if check.fix & FIX_LEAKS != 0 {
            check.res.err_num == 0 && check.res.corruptions == 0 && check.res.leaks == 0
        } else {
            false
        };

        for l1_idx in 0..l1_size {
            let l1_entry = self.table.l1_table[l1_idx];
            let l2_offset = l1_entry & L1_TABLE_OFFSET_MASK;
            if l2_offset == 0 {
                continue;
            }
            let rc_value = self.refcount.get_refcount(l2_offset)?;
            if (rc_value == 1) ^ (l1_entry & QCOW2_OFFSET_COPIED != 0) {
                l1_corruptions += 1;
                output_msg!(
                    check.quite,
                    "{} OFLAG_COPIED L2 cluster: l1_index={} l1_entry={:#X} refcount={}",
                    if repair { "Repairing" } else { "ERROR" },
                    l1_idx,
                    l1_entry,
                    rc_value
                );
                if repair {
                    let new_l1_entry = if rc_value == 1 {
                        l1_entry | QCOW2_OFFSET_COPIED
                    } else {
                        l1_entry & !QCOW2_OFFSET_COPIED
                    };
                    self.table.l1_table[l1_idx] = new_l1_entry;
                    l1_dirty = true;
                    l1_corruptions -= 1;
                    l1_corruptions_fixed += 1;
                }
            }

            let mut num_repaired = 0;
            let l2_buf = self.load_cluster(l2_offset)?;
            let l2_table = Rc::new(RefCell::new(CacheTable::new(
                l2_offset,
                l2_buf,
                ENTRY_SIZE_U64,
            )?));

            for l2_idx in 0..l2_size {
                let cluster_entry = l2_table.borrow_mut().get_entry_map(l2_idx as usize)?;
                let cluster_offset = cluster_entry & L2_TABLE_OFFSET_MASK;
                let cluster_type = Qcow2ClusterType::get_cluster_type(cluster_entry);

                if cluster_type == Qcow2ClusterType::Normal
                    || cluster_type == Qcow2ClusterType::ZeroAlloc
                {
                    let rc_value = match self.refcount.get_refcount(cluster_offset) {
                        Ok(value) => value,
                        Err(_) => continue,
                    };

                    if (rc_value == 1) ^ (cluster_entry & QCOW2_OFFSET_COPIED != 0) {
                        check.res.corruptions += 1;
                        output_msg!(
                            check.quite,
                            "{} OFLAG_COPIED data cluster: l2_entry={:#X} refcount={:?}",
                            if repair { "Repairing" } else { "ERROR" },
                            cluster_entry,
                            rc_value
                        );
                        if repair {
                            let new_cluster_entry = if rc_value == 1 {
                                cluster_entry | QCOW2_OFFSET_COPIED
                            } else {
                                cluster_entry & !QCOW2_OFFSET_COPIED
                            };
                            num_repaired += 1;
                            l2_table
                                .borrow_mut()
                                .set_entry_map(l2_idx as usize, new_cluster_entry)?;
                        }
                    }
                }
            }

            let mut borrowed_l2 = l2_table.borrow_mut();
            if num_repaired != 0 && borrowed_l2.dirty_info.is_dirty {
                if self.check_overlap(
                    METADATA_OVERLAP_CHECK_ACTIVEL2,
                    l2_offset,
                    self.header.cluster_size(),
                ) != 0
                {
                    bail!("ERROR: Could not write L2 table; metadata overlap check failed");
                }

                self.sync_aio.borrow_mut().write_dirty_info(
                    borrowed_l2.addr,
                    borrowed_l2.get_value(),
                    borrowed_l2.dirty_info.start,
                    borrowed_l2.dirty_info.end,
                )?;
                borrowed_l2.dirty_info.clear();
            }
            drop(borrowed_l2);
            check.res.corruptions -= num_repaired;
            check.res.corruptions_fixed += num_repaired;
        }

        if l1_dirty && repair {
            if let Err(e) = self.table.save_l1_table() {
                check.res.err_num += 1;
                return Err(e);
            }
        }
        check.res.corruptions += l1_corruptions;
        check.res.corruptions_fixed += l1_corruptions_fixed;

        // The entry on disk may not be consistent with the cache.
        self.table.l2_table_cache.clear_cache();
        Ok(())
    }

    /// The error in refcount block can't be fixed, so has to rebuild the structure of refcount table
    fn rebuild_refcount_structure(&mut self, check: &mut Qcow2Check) -> Result<()> {
        let mut cluster_idx: u64 = 0;
        let mut first_free_cluster: u64 = 0;
        let mut reftable_offset: u64 = 0;
        let mut new_reftable: Vec<u64> = Vec::new();
        let mut reftable_clusters: u64 = 0;
        let cluster_bits = self.header.cluster_bits as u64;
        let refblock_bits: u64 = cluster_bits + 3 - self.header.refcount_order as u64;
        let refblock_size: u64 = 1 << refblock_bits;

        // self.refblock.nb_clusters means the maximum number of clusters that can be represented by
        // the refcount table in memory. During this loop, this value may increase as the Refcount table expands.
        // This operation will leaks old refcount table and old refcount block table, and it will be fixed later.
        while cluster_idx < check.refblock.nb_clusters {
            if check.refblock.get_refcount(cluster_idx as usize)? == 0 {
                cluster_idx += 1;
                continue;
            }
            let refblock_idx = (cluster_idx >> refblock_bits) as usize;
            let refblock_start = (refblock_idx << refblock_bits) as u64;
            // Refblock data with index smaller than refblock_start has been written to disk.
            first_free_cluster = std::cmp::max(refblock_start, first_free_cluster);

            // Alloc a new cluster from first_free_cluster.
            let refblock_offset = check.refblock.alloc_clusters(
                1,
                cluster_bits,
                &mut (first_free_cluster as usize),
                self.sync_aio.clone(),
            )?;

            // Extend the refcount table
            if new_reftable.len() <= refblock_idx {
                // SAFETY: Upper limit of refblock_idx is decided by disk file size.
                new_reftable.resize(refblock_idx + 1, 0);
                // Need to reallocate clusters for new refcount table.
                reftable_offset = 0;
            }
            new_reftable[refblock_idx] = refblock_offset;

            // Alloc clusters for new refcount table.
            if refblock_idx + 1 >= (check.refblock.nb_clusters >> refblock_bits) as usize
                && reftable_offset == 0
            {
                let reftable_size = new_reftable.len() as u64;
                reftable_clusters =
                    bytes_to_clusters(reftable_size * ENTRY_SIZE, self.header.cluster_size())?;
                reftable_offset = check.refblock.alloc_clusters(
                    reftable_clusters,
                    cluster_bits,
                    &mut (first_free_cluster as usize),
                    self.sync_aio.clone(),
                )?;
            }

            // New allocated refblock offset is overlap with other matedata.
            if self.check_overlap(0, refblock_offset, self.header.cluster_size()) != 0 {
                bail!("ERROR writing refblock");
            }

            // Refcount block data written back to disk
            let start = refblock_idx * refblock_size as usize;
            let size = refblock_size;
            let refblock_buf = check.refblock.get_data(start, size as usize);
            self.sync_aio
                .borrow_mut()
                .write_buffer(refblock_offset, &refblock_buf)?;

            // All data of this refcount block has been written to disk, so go to the next refcount block.
            cluster_idx = refblock_start + refblock_size;
        }

        if reftable_offset == 0 {
            bail!("ERROR allocating reftable");
        }

        // Write new refcount table to disk
        let reftable_size = new_reftable.len();
        if self.check_overlap(0, reftable_offset, reftable_size as u64 * ENTRY_SIZE) != 0 {
            bail!("ERROR writing reftable");
        }
        self.sync_aio
            .borrow_mut()
            .write_ctrl_cluster(reftable_offset, &new_reftable)?;

        // Update header message to disk
        // Inclust reftable offset and reftable cluster
        let mut new_header = self.header.clone();
        new_header.refcount_table_offset = reftable_offset;
        new_header.refcount_table_clusters = reftable_clusters as u32;
        let header_buf = new_header.to_vec();
        self.sync_aio.borrow_mut().write_buffer(0, &header_buf)?;
        self.header.refcount_table_offset = new_header.refcount_table_offset;
        self.header.refcount_table_clusters = new_header.refcount_table_clusters;

        // Update the info of refcount table
        self.refcount.refcount_table_offset = new_header.refcount_table_offset;
        self.refcount.refcount_table_clusters = new_header.refcount_table_clusters;
        self.refcount.refcount_table_size = new_reftable.len() as u64;
        self.refcount.refcount_table = new_reftable;
        self.refcount.refcount_blk_cache.clear_cache();

        Ok(())
    }

    /// Increase the refcounts for a range of clusters.
    fn increase_refcounts(
        &mut self,
        offset: u64,
        size: u64,
        file_len: u64,
        cluster_bits: u64,
        check: &mut Qcow2Check,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        let cluster_size = 1 << cluster_bits;
        if offset + size > file_len && offset + size - file_len >= cluster_size {
            check.res.corruptions += 1;
            bail!(
                "ERROR: counting reference for region exceeding the end of the file by one cluster or more: offset {:#X} size {:#X}",
                offset, size
            );
        }

        let mut offset_beg = offset & !(cluster_size - 1);
        let offset_end = (offset + size - 1) & !(cluster_size - 1);
        while offset_beg <= offset_end {
            let cluster_idx = offset_beg >> cluster_bits;
            let rc_value = check.refblock.get_refcount(cluster_idx as usize)?;
            if rc_value == check.refblock.max_refcount {
                output_msg!(
                    check.quite,
                    "ERROR: overflow cluster offset={:#X}",
                    offset_beg
                );
                check.res.corruptions += 1;
                offset_beg += cluster_size;
                continue;
            }
            check
                .refblock
                .set_refcount(cluster_idx as usize, rc_value + 1)?;
            offset_beg += cluster_size;
        }
        Ok(())
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
