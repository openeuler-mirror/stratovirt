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

mod cache;
mod header;
mod refcount;
mod snapshot;
mod table;

use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    mem::size_of,
    os::unix::io::{AsRawFd, RawFd},
    rc::Rc,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info};
use once_cell::sync::Lazy;

use self::{cache::ENTRY_SIZE_U64, refcount::Qcow2DiscardType};
use crate::{
    file::{CombineRequest, FileDriver},
    qcow2::{
        cache::CacheTable,
        header::QcowHeader,
        refcount::RefCount,
        snapshot::{InternalSnapshot, QcowSnapshot, QcowSnapshotExtraData, QCOW2_MAX_SNAPSHOTS},
        table::{Qcow2ClusterType, Qcow2Table},
    },
    BlockDriverOps, BlockIoErrorCallback, BlockProperty, BlockStatus,
};
use machine_manager::qmp::qmp_schema::SnapshotInfo;
use util::{
    aio::{get_iov_size, iov_from_buf_direct, iovecs_split, Aio, AioCb, AioEngine, Iovec, OpCode},
    num_ops::{div_round_up, round_down, round_up},
    time::{get_format_time, gettime},
};

// The L1/L2/Refcount table entry size.
const ENTRY_SIZE: u64 = 1 << ENTRY_BITS;
const ENTRY_BITS: u64 = 3;
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const REFCOUNT_TABLE_OFFSET_MASK: u64 = 0xffff_ffff_ffff_fe00;
const QCOW2_OFLAG_ZERO: u64 = 1 << 0;
const QCOW2_OFFSET_COMPRESSED: u64 = 1 << 62;
const QCOW2_OFFSET_COPIED: u64 = 1 << 63;
const DEFAULT_SECTOR_SIZE: u64 = 512;

const METADATA_OVERLAP_CHECK_MAINHEADER: u64 = 1 << 0;
const METADATA_OVERLAP_CHECK_ACTIVEL1: u64 = 1 << 1;
const METADATA_OVERLAP_CHECK_ACTIVEL2: u64 = 1 << 2;
const METADATA_OVERLAP_CHECK_REFCOUNTTABLE: u64 = 1 << 3;
const METADATA_OVERLAP_CHECK_REFCOUNTBLOCK: u64 = 1 << 4;
const METADATA_OVERLAP_CHECK_SNAPSHOTTABLE: u64 = 1 << 5;
const METADATA_OVERLAP_CHECK_INACTIVEL1: u64 = 1 << 6;
#[allow(unused)]
const METADATA_OVERLAP_CHECK_INACTIVEL2: u64 = 1 << 7;
#[allow(unused)]
const METADATA_OVERLAP_CHECK_BITMAPDIRECTORY: u64 = 1 << 8;

const DEFAULT_QCOW2_METADATA_OVERLAP_CHECK: u64 = METADATA_OVERLAP_CHECK_MAINHEADER
    | METADATA_OVERLAP_CHECK_ACTIVEL1
    | METADATA_OVERLAP_CHECK_ACTIVEL2
    | METADATA_OVERLAP_CHECK_REFCOUNTTABLE
    | METADATA_OVERLAP_CHECK_REFCOUNTBLOCK
    | METADATA_OVERLAP_CHECK_SNAPSHOTTABLE
    | METADATA_OVERLAP_CHECK_INACTIVEL1;

type Qcow2ListType = Lazy<Arc<Mutex<HashMap<String, Arc<Mutex<dyn InternalSnapshotOps>>>>>>;
/// Record the correspondence between disk drive ID and the qcow2 struct.
pub static QCOW2_LIST: Qcow2ListType = Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub enum HostOffset {
    DataNotInit,
    DataAddress(u64),
}

pub struct SyncAioInfo {
    /// Aio for sync read/write metadata.
    aio: Aio<()>,
    fd: RawFd,
    prop: BlockProperty,
}

impl SyncAioInfo {
    fn new(fd: RawFd, prop: BlockProperty) -> Result<Self> {
        fn stub_func(_: &AioCb<()>, _: i64) -> Result<()> {
            Ok(())
        }
        Ok(Self {
            aio: Aio::new(Arc::new(stub_func), AioEngine::Off)?,
            fd,
            prop,
        })
    }

    fn package_sync_aiocb(
        &self,
        opcode: OpCode,
        iovec: Vec<Iovec>,
        offset: usize,
        nbytes: u64,
    ) -> AioCb<()> {
        AioCb {
            direct: self.prop.direct,
            req_align: self.prop.req_align,
            buf_align: self.prop.buf_align,
            file_fd: self.fd,
            opcode,
            iovec,
            offset,
            nbytes,
            user_data: 0,
            iocompletecb: (),
            discard: self.prop.discard,
            write_zeroes: self.prop.write_zeroes,
            combine_req: None,
        }
    }

    fn read_buffer(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let ptr = buf.as_mut_ptr() as u64;
        let cnt = buf.len() as u64;
        let aiocb = self.package_sync_aiocb(
            OpCode::Preadv,
            vec![Iovec::new(ptr, cnt)],
            offset as usize,
            cnt,
        );
        self.aio.submit_request(aiocb)
    }

    fn write_buffer(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let ptr = buf.as_ptr() as u64;
        let cnt = buf.len() as u64;
        let aiocb = self.package_sync_aiocb(
            OpCode::Pwritev,
            vec![Iovec::new(ptr, cnt)],
            offset as usize,
            cnt,
        );
        self.aio.submit_request(aiocb)
    }

    fn write_ctrl_cluster(&mut self, addr: u64, buf: &[u64]) -> Result<()> {
        let output: Vec<u8> = buf.iter().flat_map(|val| val.to_be_bytes()).collect();
        self.write_buffer(addr, &output)
    }

    fn read_ctrl_cluster(&mut self, addr: u64, sz: u64) -> Result<Vec<u64>> {
        let mut buf = vec![0; sz as usize];
        let vec_len = size_of::<u64>() * sz as usize;
        let mut vec = vec![0_u8; vec_len];
        self.read_buffer(addr, vec.as_mut_slice())?;
        for i in 0..buf.len() {
            buf[i] = BigEndian::read_u64(&vec[(size_of::<u64>() * i)..]);
        }
        Ok(buf)
    }

    fn write_dirty_info(&mut self, addr: u64, buf: &[u8], start: u64, end: u64) -> Result<()> {
        let start = round_down(start, DEFAULT_SECTOR_SIZE)
            .with_context(|| format!("Round down failed, value is {}", start))?;
        let end = round_up(end, DEFAULT_SECTOR_SIZE)
            .with_context(|| format!("Round up failed, value is {}", end))?;
        self.write_buffer(addr + start, &buf[start as usize..end as usize])
    }
}

pub struct Qcow2Driver<T: Clone + 'static> {
    driver: FileDriver<T>,
    sync_aio: Rc<RefCell<SyncAioInfo>>,
    header: QcowHeader,
    table: Qcow2Table,
    refcount: RefCount,
    snapshot: InternalSnapshot,
    status: Arc<Mutex<BlockStatus>>,
}

impl<T: Clone + 'static> Drop for Qcow2Driver<T> {
    fn drop(&mut self) {
        self.flush()
            .unwrap_or_else(|e| error!("Flush failed: {:?}", e));
    }
}

impl<T: Clone + 'static> Qcow2Driver<T> {
    pub fn new(file: File, aio: Aio<T>, conf: BlockProperty) -> Result<Self> {
        let fd = file.as_raw_fd();
        let sync_aio = Rc::new(RefCell::new(SyncAioInfo::new(fd, conf.clone())?));
        let mut qcow2 = Self {
            driver: FileDriver::new(file, aio, conf.clone()),
            sync_aio: sync_aio.clone(),
            header: QcowHeader::default(),
            table: Qcow2Table::new(sync_aio.clone()),
            refcount: RefCount::new(sync_aio.clone()),
            snapshot: InternalSnapshot::new(sync_aio),
            status: Arc::new(Mutex::new(BlockStatus::Init)),
        };
        qcow2
            .load_header()
            .with_context(|| "Failed to load header")?;
        qcow2.check().with_context(|| "Invalid header")?;
        qcow2
            .table
            .init_table(&qcow2.header)
            .with_context(|| "Failed to create qcow2 table")?;
        qcow2.refcount.init_refcount_info(&qcow2.header, conf);
        qcow2
            .load_refcount_table()
            .with_context(|| "Failed to load refcount table")?;
        qcow2.snapshot.set_cluster_size(qcow2.header.cluster_size());
        qcow2
            .snapshot
            .load_snapshot_table(qcow2.header.snapshots_offset, qcow2.header.nb_snapshots)
            .with_context(|| "Failed to load snapshot table")?;

        Ok(qcow2)
    }

    fn check(&self) -> Result<()> {
        let file_sz = self
            .driver
            .meta_len()
            .with_context(|| "Failed to get metadata len")?;
        self.header.check(file_sz)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.table.flush()
    }

    fn load_header(&mut self) -> Result<()> {
        let mut buf = vec![0; QcowHeader::len()];
        self.sync_aio.borrow_mut().read_buffer(0, &mut buf)?;
        self.header = QcowHeader::from_vec(&buf)?;
        Ok(())
    }

    fn load_refcount_table(&mut self) -> Result<()> {
        let sz = self.header.refcount_table_clusters as u64
            * (self.header.cluster_size() / ENTRY_SIZE as u64);
        self.refcount.refcount_table = self
            .sync_aio
            .borrow_mut()
            .read_ctrl_cluster(self.header.refcount_table_offset, sz)?;
        Ok(())
    }

    fn host_offset_for_read(&mut self, guest_offset: u64) -> Result<HostOffset> {
        let l2_address = self.table.get_l1_table_entry(guest_offset) & L1_TABLE_OFFSET_MASK;
        if l2_address == 0 {
            return Ok(HostOffset::DataNotInit);
        }

        let cluster_addr: u64;
        let cluster_type: Qcow2ClusterType;
        let l2_index = self.table.get_l2_table_index(guest_offset);
        if let Some(entry) = self.table.get_l2_table_cache_entry(guest_offset) {
            let l2_entry = entry.borrow_mut().get_entry_map(l2_index as usize)?;
            cluster_type = Qcow2ClusterType::get_cluster_type(l2_entry);
            cluster_addr = l2_entry & L2_TABLE_OFFSET_MASK;
        } else {
            let l2_cluster = self.load_cluster(l2_address)?;
            let l2_table = Rc::new(RefCell::new(CacheTable::new(
                l2_address,
                l2_cluster,
                ENTRY_SIZE_U64,
            )?));
            let l2_entry = l2_table.borrow_mut().get_entry_map(l2_index as usize)?;
            cluster_type = Qcow2ClusterType::get_cluster_type(l2_entry);
            cluster_addr = l2_entry & L2_TABLE_OFFSET_MASK;
            self.table.update_l2_table(l2_table)?;
        }

        if cluster_addr == 0 || cluster_type.is_read_zero() {
            Ok(HostOffset::DataNotInit)
        } else {
            Ok(HostOffset::DataAddress(
                cluster_addr + self.offset_into_cluster(guest_offset),
            ))
        }
    }

    fn host_offset_for_write(&mut self, guest_offset: u64) -> Result<HostOffset> {
        let l2_index = self.table.get_l2_table_index(guest_offset);
        let l2_table = self.get_table_cluster(guest_offset)?;
        let mut l2_entry = l2_table.borrow_mut().get_entry_map(l2_index as usize)?;
        l2_entry &= !QCOW2_OFLAG_ZERO;
        let mut cluster_addr = l2_entry & L2_TABLE_OFFSET_MASK;
        if cluster_addr == 0 {
            let new_addr = self.alloc_cluster(1, true)?;
            l2_entry = new_addr | QCOW2_OFFSET_COPIED;
            cluster_addr = new_addr & L2_TABLE_OFFSET_MASK;
        } else if l2_entry & QCOW2_OFFSET_COPIED == 0 {
            // Copy on write for data cluster.
            let new_data_addr = self.alloc_cluster(1, false)?;
            let data = self.load_cluster(cluster_addr)?;
            self.sync_aio
                .borrow_mut()
                .write_buffer(new_data_addr, &data)?;
            self.refcount
                .update_refcount(cluster_addr, 1, -1, true, &Qcow2DiscardType::Other)?;
            l2_entry = new_data_addr | QCOW2_OFFSET_COPIED;
            cluster_addr = new_data_addr & L2_TABLE_OFFSET_MASK;
        }
        l2_table
            .borrow_mut()
            .set_entry_map(l2_index as usize, l2_entry)?;
        Ok(HostOffset::DataAddress(
            cluster_addr + self.offset_into_cluster(guest_offset),
        ))
    }

    /// Obtaining the target entry for guest offset.
    /// If the corresponding entry didn't cache, it will be read from the disk synchronously.
    /// Input: guest offset.
    /// Output: target entry.
    fn get_table_cluster(&mut self, guest_offset: u64) -> Result<Rc<RefCell<CacheTable>>> {
        let l1_index = self.table.get_l1_table_index(guest_offset);
        if l1_index >= self.header.l1_size as u64 {
            bail!("Need to grow l1 table size.");
        }

        let l1_entry = self.table.get_l1_table_entry(guest_offset);
        let mut l2_address = l1_entry & L1_TABLE_OFFSET_MASK;
        // Align to cluster size.
        if (l2_address & (self.header.cluster_size() - 1)) != 0 {
            bail!(
                "L2 table offset {} unaligned(L1 index: {})",
                l2_address,
                l1_index
            );
        }

        if l1_entry & QCOW2_OFFSET_COPIED == 0 {
            // Alloc a new l2_table.
            let old_l2_offset = l1_entry & L1_TABLE_OFFSET_MASK;
            let new_l2_offset = self.alloc_cluster(1, true)?;
            let l2_cluster: Vec<u8> =
                if let Some(entry) = self.table.get_l2_table_cache_entry(guest_offset) {
                    entry.borrow().get_value().to_vec()
                } else if old_l2_offset != 0 {
                    self.load_cluster(l2_address)?
                } else {
                    vec![0_u8; self.header.cluster_size() as usize]
                };
            self.sync_aio
                .borrow_mut()
                .write_buffer(new_l2_offset, &l2_cluster)?;
            let l2_cache_entry = Rc::new(RefCell::new(CacheTable::new(
                new_l2_offset,
                l2_cluster,
                ENTRY_SIZE_U64,
            )?));
            self.table.update_l2_table(l2_cache_entry)?;

            // Update l1_table.
            self.table
                .update_l1_table(l1_index as usize, new_l2_offset | QCOW2_OFFSET_COPIED);
            self.table.save_l1_table(&self.header)?;

            // Decrease the refcount of the old table.
            if old_l2_offset != 0 {
                self.refcount.update_refcount(
                    old_l2_offset,
                    1,
                    -1,
                    true,
                    &Qcow2DiscardType::Other,
                )?;
            }
            // Get the offset of the newly-allocated l2 table.
            l2_address = new_l2_offset;
        }

        // Cache hit.
        if let Some(entry) = self.table.l2_table_cache.get(l2_address) {
            return Ok(entry.clone());
        }
        // Cache miss.
        let l2_cluster = self.load_cluster(l2_address)?;
        let l2_table_entry = Rc::new(RefCell::new(CacheTable::new(
            l2_address,
            l2_cluster,
            ENTRY_SIZE_U64,
        )?));
        self.table.update_l2_table(l2_table_entry.clone())?;
        Ok(l2_table_entry)
    }

    /// Write back to disk synchronously, with a range no greater than cluster size.
    fn sync_write_bytes(&mut self, guest_offset: u64, buf: &[u8]) -> Result<()> {
        if buf.len() > self.header.cluster_size() as usize
            || guest_offset as usize + buf.len() > self.virtual_disk_size() as usize
        {
            bail!("Buffer size: is out of range",);
        }
        // Return if the address is not allocated.
        if let HostOffset::DataAddress(host_offset) = self.host_offset_for_write(guest_offset)? {
            self.sync_aio.borrow_mut().write_buffer(host_offset, buf)?;
        }
        Ok(())
    }

    /// Write zero data to cluster data as many as possible, and return the total number of
    /// cluster.
    /// Note: the guest offset should align to cluster size.
    fn zero_in_l2_slice(&mut self, guest_offset: u64, nb_cluster: u64) -> Result<u64> {
        // Zero flag is only support by version 3.
        // If this flag is not supported, then  transfer write_zero to discard.
        if self.header.version < 3 {
            return self.discard_in_l2_slice(guest_offset, nb_cluster, &Qcow2DiscardType::Request);
        }

        let l2_index = self.table.get_l2_table_index(guest_offset);
        let l2_slice_size = self.header.cluster_size() >> ENTRY_BITS;
        let nb_cluster = std::cmp::min(nb_cluster, l2_slice_size - l2_index);
        let table_entry = self.get_table_cluster(guest_offset)?;
        for i in 0..nb_cluster {
            let new_l2_index = l2_index + i;
            let old_l2_entry = table_entry
                .borrow_mut()
                .get_entry_map(new_l2_index as usize)?;
            let entry_type = Qcow2ClusterType::get_cluster_type(old_l2_entry);
            let mut new_l2_entry = old_l2_entry;
            let unmap: bool = entry_type.is_allocated();
            if unmap {
                new_l2_entry = 0;
            }
            new_l2_entry |= QCOW2_OFLAG_ZERO;

            if new_l2_entry == old_l2_entry {
                continue;
            }

            table_entry
                .borrow_mut()
                .set_entry_map(new_l2_index as usize, new_l2_entry)?;
            if unmap {
                self.qcow2_free_cluster(old_l2_entry, &Qcow2DiscardType::Request)?;
            }
        }
        Ok(nb_cluster)
    }

    /// Discard the data as many as possibale, and return the total number of cluster.
    /// Note: the guest_offset should align to cluster size.
    fn discard_in_l2_slice(
        &mut self,
        guest_offset: u64,
        nb_cluster: u64,
        discard_type: &Qcow2DiscardType,
    ) -> Result<u64> {
        let l2_index = self.table.get_l2_table_index(guest_offset);
        let l2_slice_size = self.header.cluster_size() >> ENTRY_BITS;
        let nb_cluster = std::cmp::min(nb_cluster, l2_slice_size - l2_index);
        let table_entry = self.get_table_cluster(guest_offset)?;
        for i in 0..nb_cluster {
            let new_l2_index = l2_index + i;
            let old_l2_entry = table_entry
                .borrow_mut()
                .get_entry_map(new_l2_index as usize)?;
            let entry_type = Qcow2ClusterType::get_cluster_type(old_l2_entry);
            let mut new_l2_entry = old_l2_entry;

            if entry_type.is_allocated() {
                new_l2_entry = if self.header.version >= 3 {
                    QCOW2_OFLAG_ZERO
                } else {
                    0
                };
            }
            if new_l2_entry == old_l2_entry {
                continue;
            }

            // Update l2 entry.
            table_entry
                .borrow_mut()
                .set_entry_map(new_l2_index as usize, new_l2_entry)?;
            // Decrease the refcount.
            self.qcow2_free_cluster(old_l2_entry, discard_type)?;
        }
        Ok(nb_cluster)
    }

    /// Update refount of cluster, if the value is equal to 0,
    /// then clear the cluster.
    pub fn qcow2_free_cluster(
        &mut self,
        l2_entry: u64,
        discard_type: &Qcow2DiscardType,
    ) -> Result<()> {
        let cluster_type = Qcow2ClusterType::get_cluster_type(l2_entry);
        match cluster_type {
            Qcow2ClusterType::ZeroAlloc | Qcow2ClusterType::Normal => {
                let offset = l2_entry & L2_TABLE_OFFSET_MASK;
                let nbytes = self.header.cluster_size();
                // Align to cluster size.
                if !is_aligned(nbytes, offset) {
                    bail!(
                        "Host offset {} is unaligned to cluster size {}",
                        offset,
                        nbytes
                    );
                }
                self.free_cluster(offset, 1, discard_type)?;
            }
            Qcow2ClusterType::Compressed => {
                bail!("Compressed is not supported");
            }
            _ => {}
        }
        Ok(())
    }

    fn offset_into_cluster(&self, guest_offset: u64) -> u64 {
        guest_offset & (self.header.cluster_size() - 1)
    }

    fn load_cluster(&mut self, addr: u64) -> Result<Vec<u8>> {
        if !is_aligned(self.header.cluster_size(), addr) {
            bail!("Cluster address not aligned {}", addr);
        }
        let mut buf = vec![0_u8; self.header.cluster_size() as usize];
        self.sync_aio.borrow_mut().read_buffer(addr, &mut buf)?;
        Ok(buf)
    }

    fn virtual_disk_size(&self) -> u64 {
        self.header.size
    }

    fn cluster_aligned_bytes(&self, addr: u64, cnt: u64) -> u64 {
        let offset = self.offset_into_cluster(addr);
        std::cmp::min(cnt, self.header.cluster_size() - offset)
    }

    fn alloc_cluster(&mut self, clusters: u64, write_zero: bool) -> Result<u64> {
        if !self.refcount.discard_list.is_empty() {
            self.refcount.sync_process_discards(OpCode::Discard);
        }

        let size = clusters * self.header.cluster_size();
        let addr = self.refcount.alloc_cluster(&mut self.header, size)?;
        if write_zero && addr < self.driver.disk_size()? {
            // Clean the cluster.
            let zero = vec![0_u8; self.header.cluster_size() as usize];
            self.sync_aio.borrow_mut().write_buffer(addr, &zero)?;
        }
        self.driver.extend_len(addr + size)?;
        Ok(addr)
    }

    fn check_request(&self, offset: usize, nbytes: u64) -> Result<()> {
        if offset as u64 > self.virtual_disk_size() {
            bail!("Invalid offset {}", offset);
        }
        let end = (offset as u64)
            .checked_add(nbytes)
            .with_context(|| format!("Invalid offset {} or size {}", offset, nbytes))?;
        if end > self.virtual_disk_size() {
            bail!("Request over limit {}", end);
        }
        Ok(())
    }

    fn free_cluster(
        &mut self,
        addr: u64,
        clusters: u64,
        discard_type: &Qcow2DiscardType,
    ) -> Result<()> {
        self.refcount
            .update_refcount(addr, clusters, -1, true, discard_type)
    }

    fn get_snapshot_by_name(&mut self, name: &String) -> i32 {
        self.snapshot.find_snapshot(name)
    }

    fn qcow2_delete_snapshot(&mut self, name: String) -> Result<SnapshotInfo> {
        let snapshot_idx = self.get_snapshot_by_name(&name);
        if snapshot_idx < 0 {
            bail!("Snapshot with name {} does not exist", name);
        }

        // Alloc new snapshot table. Delete the new snapshot from the snapshot table
        // and write new snapshot table to file.
        let cluster_size = self.header.cluster_size();
        let snap = self.snapshot.del_snapshot(snapshot_idx as usize);
        let new_snapshots_table_clusters =
            bytes_to_clusters(self.snapshot.snapshot_size, cluster_size).unwrap();
        let l1_table_clusters =
            bytes_to_clusters(snap.l1_size as u64 * ENTRY_SIZE, cluster_size).unwrap();
        let mut new_snapshot_table_offset = 0_u64;
        let mut err_msg: String = "".to_string();
        let mut error_stage = 0;

        // Using loop for error handling.
        #[allow(clippy::never_loop)]
        loop {
            if new_snapshots_table_clusters != 0 {
                new_snapshot_table_offset = self
                    .alloc_cluster(new_snapshots_table_clusters, true)
                    .unwrap_or_else(|e| {
                        err_msg = format!("{:?}", e);
                        error_stage = 1;
                        0
                    });

                if new_snapshot_table_offset == 0 {
                    break;
                }

                if let Err(e) = self.snapshot.save_snapshot_table(new_snapshot_table_offset) {
                    err_msg = format!("{:?}", e);
                    error_stage = 2;
                    break;
                }
            }

            // Decrease the refcounts of clusters referenced by the snapshot.
            if let Err(e) = self.qcow2_update_snapshot_refcount(snap.l1_table_offset, -1) {
                err_msg = format!("{:?}", e);
                error_stage = 2;
                break;
            }

            // Free the snaphshot L1 table.
            if let Err(e) = self.refcount.update_refcount(
                snap.l1_table_offset,
                l1_table_clusters,
                -1,
                false,
                &Qcow2DiscardType::Snapshot,
            ) {
                err_msg = format!("{:?}", e);
                error_stage = 3;
                break;
            }

            // Update the copied flag on the current cluster offsets.
            if let Err(e) = self.qcow2_update_snapshot_refcount(self.header.l1_table_offset, 0) {
                err_msg = format!("{:?}", e);
                error_stage = 4;
                break;
            }

            if let Err(e) = self.refcount.update_refcount(
                self.header.snapshots_offset,
                1,
                -1,
                true,
                &Qcow2DiscardType::Snapshot,
            ) {
                err_msg = format!("{:?}", e);
                error_stage = 5;
                break;
            }

            if let Err(e) = self.refcount.flush_refcount_block_cache() {
                err_msg = format!("{:?}", e);
                error_stage = 5;
                break;
            }

            let mut new_header = self.header.clone();
            new_header.snapshots_offset = new_snapshot_table_offset;
            new_header.nb_snapshots -= 1;
            if let Err(e) = self
                .sync_aio
                .borrow_mut()
                .write_buffer(0, &new_header.to_vec())
            {
                err_msg = format!("{:?}", e);
                error_stage = 6;
                break;
            }
            self.header.snapshots_offset = new_header.snapshots_offset;
            self.header.nb_snapshots = new_header.nb_snapshots;
            self.refcount.sync_process_discards(OpCode::Discard);

            return Ok(SnapshotInfo {
                id: snap.id.to_string(),
                name: snap.name.clone(),
                vm_state_size: snap.vm_state_size as u64,
                date_sec: snap.date_sec,
                date_nsec: snap.date_nsec,
                vm_clock_nsec: snap.vm_clock_nsec,
                icount: snap.icount,
            });
        }

        // Error handling, to revert some operation.
        if error_stage >= 6 {
            self.refcount.update_refcount(
                self.header.snapshots_offset,
                1,
                1,
                true,
                &Qcow2DiscardType::Never,
            )?;
        }
        if error_stage >= 4 {
            self.refcount.update_refcount(
                snap.l1_table_offset,
                l1_table_clusters,
                1,
                true,
                &Qcow2DiscardType::Never,
            )?;
        }
        if error_stage >= 3 {
            self.qcow2_update_snapshot_refcount(snap.l1_table_offset, 1)?;
            if error_stage >= 5 {
                self.qcow2_update_snapshot_refcount(self.header.l1_table_offset, 0)?;
            }
        }
        if error_stage >= 2 && new_snapshots_table_clusters != 0 {
            self.free_cluster(
                new_snapshot_table_offset,
                new_snapshots_table_clusters,
                &Qcow2DiscardType::Never,
            )?;
        }
        if error_stage >= 1 {
            self.snapshot.insert_snapshot(snap, snapshot_idx as usize)
        }

        bail!("{}", err_msg);
    }

    fn qcow2_create_snapshot(&mut self, name: String, vm_clock_nsec: u64) -> Result<()> {
        if self.get_snapshot_by_name(&name) >= 0 {
            bail!("Snapshot {} exists!", name);
        }
        if self.snapshot.snapshots_number() > QCOW2_MAX_SNAPSHOTS {
            bail!(
                "The number of snapshots exceed the maximum limit {}",
                QCOW2_MAX_SNAPSHOTS
            );
        }

        // Alloc cluster and copy L1 table for snapshot.
        let l1_table_len = self.header.l1_size as u64 * ENTRY_SIZE;
        let cluster_size = self.header.cluster_size();
        let l1_table_clusters = bytes_to_clusters(l1_table_len, cluster_size).unwrap();
        let new_l1_table_offset = self.alloc_cluster(l1_table_clusters, true)?;

        let old_snapshots_table_len = self.snapshot.snapshot_size;
        let old_snapshots_table_clusters =
            bytes_to_clusters(old_snapshots_table_len, cluster_size).unwrap();
        let mut err_msg: String = "".to_string();
        let mut new_snapshot_table_offset = 0_u64;
        let mut error_stage = 0;

        // Using loop for error handling.
        #[allow(clippy::never_loop)]
        loop {
            // Check if l1 table offset is overlap.
            if self.qcow2_pre_write_overlap_check(0, new_l1_table_offset, l1_table_len) != 0 {
                err_msg = format!(
                    "Allocated snapshot L1 table addr {:x} is illegal!",
                    new_l1_table_offset
                );
                error_stage = 1;
                break;
            }

            // Write L1 table to file.
            if let Err(e) = self
                .sync_aio
                .borrow_mut()
                .write_ctrl_cluster(new_l1_table_offset, &self.table.l1_table)
            {
                error_stage = 1;
                err_msg = format!("{:?}", e);
                break;
            }

            // Increase the refcounts of all clusters searched by L1 table.
            if let Err(e) = self.qcow2_update_snapshot_refcount(self.header.l1_table_offset, 1) {
                error_stage = 1;
                err_msg = format!("{:?}", e);
                break;
            }

            // Alloc new snapshot table.
            let (date_sec, date_nsec) = gettime();
            let snap = QcowSnapshot {
                l1_table_offset: new_l1_table_offset,
                l1_size: self.header.l1_size,
                id: self.snapshot.find_new_snapshot_id(),
                name,
                disk_size: self.virtual_disk_size(),
                vm_state_size: 0,
                date_sec,
                date_nsec,
                vm_clock_nsec,
                icount: u64::MAX,
                extra_data_size: size_of::<QcowSnapshotExtraData>() as u32,
            };
            let new_snapshots_table_clusters =
                bytes_to_clusters(old_snapshots_table_len + snap.get_size(), cluster_size).unwrap();
            new_snapshot_table_offset = self
                .alloc_cluster(new_snapshots_table_clusters, true)
                .unwrap_or_else(|e| {
                    error_stage = 2;
                    err_msg = format!("{:?}", e);
                    0
                });
            if new_snapshot_table_offset == 0 {
                break;
            }
            info!(
                "Snapshot table offset: old(0x{:x}) -> new(0x{:x})",
                self.header.snapshots_offset, new_snapshot_table_offset,
            );

            // Append the new snapshot to the snapshot table and write new snapshot table to file.
            self.snapshot.add_snapshot(snap);
            if let Err(e) = self.snapshot.save_snapshot_table(new_snapshot_table_offset) {
                error_stage = 3;
                err_msg = format!("{:?}", e);
                break;
            }
            self.snapshot.snapshot_table_offset = new_snapshot_table_offset;

            // Free the old snapshot table cluster if snapshot exists.
            if self.header.snapshots_offset != 0 {
                if let Err(e) = self.refcount.update_refcount(
                    self.header.snapshots_offset,
                    old_snapshots_table_clusters,
                    -1,
                    true,
                    &Qcow2DiscardType::Snapshot,
                ) {
                    error_stage = 4;
                    err_msg = format!("{:?}", e);
                    break;
                }
            }

            // Update snapshot offset and num in qcow2 header.
            let mut new_header = self.header.clone();
            new_header.snapshots_offset = new_snapshot_table_offset;
            new_header.nb_snapshots += 1;
            if let Err(e) = self
                .sync_aio
                .borrow_mut()
                .write_buffer(0, &new_header.to_vec())
            {
                error_stage = 5;
                err_msg = format!("{:?}", e);
                break;
            }
            self.header.snapshots_offset = new_header.snapshots_offset;
            self.header.nb_snapshots = new_header.nb_snapshots;
            self.refcount.sync_process_discards(OpCode::Discard);

            return Ok(());
        }

        // Error handling, to revert some operation.
        if error_stage >= 5 && self.header.snapshots_offset != 0 {
            self.refcount.update_refcount(
                self.header.snapshots_offset,
                old_snapshots_table_clusters,
                1,
                true,
                &Qcow2DiscardType::Never,
            )?;
        }

        if error_stage >= 4 {
            self.snapshot.snapshot_table_offset = self.header.snapshots_offset;
        }
        if error_stage >= 3 {
            // Delete new added snapshot.
            let num_clusters =
                bytes_to_clusters(self.snapshot.snapshot_size, cluster_size).unwrap();
            self.snapshot
                .del_snapshot(self.snapshot.snapshots_number() - 1);
            self.free_cluster(
                new_snapshot_table_offset,
                num_clusters,
                &Qcow2DiscardType::Snapshot,
            )?;
        }
        if error_stage >= 2 {
            self.qcow2_update_snapshot_refcount(self.header.l1_table_offset, -1)?;
        }
        if error_stage >= 1 {
            self.free_cluster(
                new_l1_table_offset,
                l1_table_clusters,
                &Qcow2DiscardType::Snapshot,
            )?;
        }

        bail!("{}", err_msg);
    }

    /// Update the refcounts of all clusters searched by l1_table_offset.
    fn qcow2_update_snapshot_refcount(&mut self, l1_table_offset: u64, added: i32) -> Result<()> {
        let l1_table_size = self.header.l1_size as usize;
        let mut l1_table = self.table.l1_table.clone();
        let mut l1_changed = false;
        debug!(
            "Update snapshot refcount: l1 table offset {:x}, active header l1 table addr {:x}, add {}",
            l1_table_offset,
            self.header.l1_table_offset,
            added
        );

        if l1_table_offset != self.header.l1_table_offset {
            // Read snapshot l1 table from qcow2 file.
            l1_table = self
                .sync_aio
                .borrow_mut()
                .read_ctrl_cluster(l1_table_offset, l1_table_size as u64)?;
        }

        let mut old_l2_table_offset: u64;
        for (i, l1_entry) in l1_table.iter_mut().enumerate().take(l1_table_size) {
            let mut l2_table_offset = *l1_entry;
            if l2_table_offset == 0 {
                // No l2 table.
                continue;
            }
            old_l2_table_offset = l2_table_offset;
            l2_table_offset &= L1_TABLE_OFFSET_MASK;

            if self.refcount.offset_into_cluster(l2_table_offset) != 0 {
                bail!(
                    "L2 table offset {:x} unaligned (L1 index {})!",
                    l2_table_offset,
                    i
                );
            }

            if !self
                .table
                .l2_table_cache
                .contains_keys(l2_table_offset as u64)
            {
                let l2_cluster = self.load_cluster(l2_table_offset)?;
                let l2_table_entry = Rc::new(RefCell::new(CacheTable::new(
                    l2_table_offset,
                    l2_cluster,
                    ENTRY_SIZE_U64,
                )?));
                self.table.update_l2_table(l2_table_entry)?;
            }

            let cached_l2_table = self.table.l2_table_cache.get(l2_table_offset).unwrap();
            let mut borrowed_table = cached_l2_table.borrow_mut();

            for idx in 0..borrowed_table.get_entry_num() {
                let l2_entry = borrowed_table.get_entry_map(idx)?;
                let mut new_l2_entry = l2_entry & !QCOW2_OFFSET_COPIED;
                let data_cluster_offset = new_l2_entry & L2_TABLE_OFFSET_MASK;
                if data_cluster_offset == 0 {
                    // Unallocated data cluster.
                    continue;
                }
                if self.refcount.offset_into_cluster(data_cluster_offset) != 0 {
                    bail!(
                        "Cluster offset 0x{:x} unaligned, (L2 table offset 0x{:x}, L2 index {})!",
                        data_cluster_offset,
                        l2_table_offset,
                        idx
                    );
                }

                if added != 0 {
                    // Update Data Cluster refcount.
                    self.refcount.update_refcount(
                        data_cluster_offset,
                        1,
                        added,
                        false,
                        &Qcow2DiscardType::Snapshot,
                    )?;
                }

                let refcount = self.refcount.get_refcount(data_cluster_offset)?;
                if refcount == 1 {
                    new_l2_entry |= QCOW2_OFFSET_COPIED;
                }
                if l2_entry != new_l2_entry {
                    borrowed_table.set_entry_map(idx, new_l2_entry)?;
                }
            }
            self.sync_aio
                .borrow_mut()
                .write_buffer(l2_table_offset, borrowed_table.get_value())?;
            drop(borrowed_table);

            if added != 0 {
                // Update L2 table cluster refcount.
                self.refcount.update_refcount(
                    l2_table_offset,
                    1,
                    added,
                    false,
                    &Qcow2DiscardType::Snapshot,
                )?;
            }

            let refcount = self.refcount.get_refcount(l2_table_offset)?;
            if refcount == 1 {
                l2_table_offset |= QCOW2_OFFSET_COPIED;
            }
            if l2_table_offset != old_l2_table_offset {
                *l1_entry = l2_table_offset;
                l1_changed = true;
                if l1_table_offset == self.header.l1_table_offset {
                    self.table.update_l1_table(i, l2_table_offset);
                }
            }
        }
        self.refcount.flush_refcount_block_cache()?;
        if l1_changed {
            self.sync_aio
                .borrow_mut()
                .write_ctrl_cluster(l1_table_offset, &l1_table)?;
        }

        Ok(())
    }

    fn qcow2_list_snapshots(&self) -> String {
        let mut snap_strs = format!(
            "{:<10}{:<17}{:>8}{:>20}{:>13}{:>11}\r\n",
            "ID", "TAG", "VM SIZE", "DATE", "VM CLOCK", "ICOUNT"
        );
        for snap in &self.snapshot.snapshots {
            let id_str = snap.id.to_string();
            let name_str = snap.name.clone();
            // Note: vm state size is not needed in disk snapshot, so it's "0 B".
            let vm_size_str = snap.vm_state_size.to_string();
            let icount_str = match snap.icount {
                u64::MAX => "".to_string(),
                _ => snap.icount.to_string(),
            };

            let date = get_format_time(snap.date_sec as i64);
            let date_str = format!(
                "{:04}-{:02}-{:02} {:02}-{:02}-{:02}",
                date[0], date[1], date[2], date[3], date[4], date[5]
            );

            let vm_clock_secs = snap.vm_clock_nsec / 1_000_000_000;
            let vm_clock_str = format!(
                "{:02}:{:02}:{:02}.{:02}",
                vm_clock_secs / 3600,
                (vm_clock_secs / 3600) % 60,
                vm_clock_secs % 60,
                (vm_clock_secs / 1_000_000) % 1000
            );

            let snap_str = format!(
                "{:<9} {:<16} {:>6} B{:>20}{:>13}{:>11}\r\n",
                id_str, name_str, vm_size_str, date_str, vm_clock_str, icount_str
            );
            snap_strs += &snap_str;
        }
        snap_strs
    }

    // Check if there exist intersection between given address range and qcow2 mede data.
    fn qcow2_pre_write_overlap_check(&self, ignore: u64, offset: u64, size: u64) -> i64 {
        let check = DEFAULT_QCOW2_METADATA_OVERLAP_CHECK | !ignore;
        if check == 0 {
            return 0;
        }

        if check & METADATA_OVERLAP_CHECK_MAINHEADER != 0 && offset < self.header.cluster_size() {
            return METADATA_OVERLAP_CHECK_MAINHEADER as i64;
        }

        let size = round_up(
            self.refcount.offset_into_cluster(offset) + size,
            self.header.cluster_size(),
        )
        .unwrap();
        let offset = self.refcount.start_of_cluster(offset);
        if u64::MAX - offset < size {
            // Ensure there exist no overflow.
            return -1;
        }

        if check & METADATA_OVERLAP_CHECK_ACTIVEL1 != 0
            && self.header.l1_size != 0
            && check_overlaps(
                offset,
                size,
                self.header.l1_table_offset,
                self.header.l1_size as u64 * ENTRY_SIZE,
            )
        {
            return METADATA_OVERLAP_CHECK_ACTIVEL1 as i64;
        }

        if check & METADATA_OVERLAP_CHECK_ACTIVEL2 != 0 {
            for l1_entry in &self.table.l1_table {
                if check_overlaps(
                    offset,
                    size,
                    l1_entry & L1_TABLE_OFFSET_MASK,
                    self.header.cluster_size(),
                ) {
                    return METADATA_OVERLAP_CHECK_ACTIVEL2 as i64;
                }
            }
        }

        if check & METADATA_OVERLAP_CHECK_REFCOUNTTABLE != 0
            && check_overlaps(
                offset,
                size,
                self.header.refcount_table_offset,
                self.header.refcount_table_clusters as u64 * self.header.cluster_size(),
            )
        {
            return METADATA_OVERLAP_CHECK_REFCOUNTTABLE as i64;
        }

        if check & METADATA_OVERLAP_CHECK_REFCOUNTBLOCK != 0 {
            for block_offset in &self.refcount.refcount_table {
                if check_overlaps(
                    offset,
                    size,
                    block_offset & REFCOUNT_TABLE_OFFSET_MASK,
                    self.header.cluster_size(),
                ) {
                    return METADATA_OVERLAP_CHECK_REFCOUNTBLOCK as i64;
                }
            }
        }

        if check & METADATA_OVERLAP_CHECK_SNAPSHOTTABLE != 0
            && check_overlaps(
                offset,
                size,
                self.snapshot.snapshot_table_offset,
                self.snapshot.snapshot_size,
            )
        {
            return METADATA_OVERLAP_CHECK_SNAPSHOTTABLE as i64;
        }

        if check & METADATA_OVERLAP_CHECK_INACTIVEL1 != 0 {
            for snap in &self.snapshot.snapshots {
                if check_overlaps(
                    offset,
                    size,
                    snap.l1_table_offset,
                    snap.l1_size as u64 * ENTRY_SIZE,
                ) {
                    return METADATA_OVERLAP_CHECK_INACTIVEL1 as i64;
                }
            }
        }

        0
    }
}

pub fn bytes_to_clusters(size: u64, cluster_sz: u64) -> Result<u64> {
    div_round_up(size, cluster_sz)
        .with_context(|| format!("Failed to div round up, size is {}", size))
}

// Check if there is an intersection between two addresses. Return true if there is a crossover.
fn check_overlaps(addr1: u64, size1: u64, addr2: u64, size2: u64) -> bool {
    // Note: ensure that there is no overflow at the calling function.
    if addr1 + size1 == 0 || addr2 + size2 == 0 {
        return false;
    }

    let last1 = addr1 + size1 - 1;
    let last2 = addr2 + size2 - 1;

    !(last1 < addr2 || last2 < addr1)
}

pub trait InternalSnapshotOps: Send + Sync {
    fn create_snapshot(&mut self, name: String, vm_clock_nsec: u64) -> Result<()>;
    fn delete_snapshot(&mut self, name: String) -> Result<SnapshotInfo>;
    fn list_snapshots(&self) -> String;
    fn get_status(&self) -> Arc<Mutex<BlockStatus>>;
}

impl<T: Clone + 'static> InternalSnapshotOps for Qcow2Driver<T> {
    fn create_snapshot(&mut self, name: String, vm_clock_nsec: u64) -> Result<()> {
        self.qcow2_create_snapshot(name, vm_clock_nsec)
    }

    fn delete_snapshot(&mut self, name: String) -> Result<SnapshotInfo> {
        self.qcow2_delete_snapshot(name)
    }

    fn list_snapshots(&self) -> String {
        self.qcow2_list_snapshots()
    }

    fn get_status(&self) -> Arc<Mutex<BlockStatus>> {
        self.status.clone()
    }
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type in Aio.
// We use Arc<Mutex<Qcow2Driver<T>>> to allow used in multi-threading.
unsafe impl<T: Clone + 'static> Send for Qcow2Driver<T> {}
unsafe impl<T: Clone + 'static> Sync for Qcow2Driver<T> {}

impl<T: Clone + Send + Sync> Qcow2Driver<T> {
    fn qcow2_cluster_discard(&mut self, offset: u64, nbytes: u64, args: T) -> Result<()> {
        let cluster_bits = self.header.cluster_bits;
        let cluster_size = self.header.cluster_size();
        let mut nb_cluster = nbytes >> cluster_bits;
        let mut host_offset = offset;

        while nb_cluster > 0 {
            match self.discard_in_l2_slice(host_offset, nb_cluster, &Qcow2DiscardType::Request) {
                Ok(cleared) => {
                    nb_cluster -= cleared;
                    host_offset += cleared * cluster_size;
                }
                Err(e) => {
                    error!("Discard in l2 slice: {:?}", e);
                    break;
                }
            }
        }

        self.table
            .flush_l2_table_cache()
            .unwrap_or_else(|e| error!("Flush l2 table cache failed: {:?}", e));
        self.process_discards(args, OpCode::Discard, false)
    }

    /// Align to cluster size and write zeroes.
    fn qcow2_cluster_write_zeroes(&mut self, offset: u64, nbytes: u64) -> Result<()> {
        // Offset and offset + nbytes should align to cluster size.
        if !is_aligned(self.header.cluster_size(), offset | nbytes) {
            return Ok(());
        }

        let mut nb_cluster = bytes_to_clusters(nbytes, self.header.cluster_size())?;
        let mut guest_offset = offset;
        while nb_cluster > 0 {
            match self.zero_in_l2_slice(guest_offset, nb_cluster) {
                Ok(cleared) => {
                    nb_cluster -= cleared;
                    guest_offset += cleared * self.header.cluster_size();
                }
                Err(e) => {
                    error!("Write zero: {:?}", e);
                    break;
                }
            }
        }

        self.table
            .flush_l2_table_cache()
            .unwrap_or_else(|e| error!("Flush l2 table cache failed: {:?}", e));
        Ok(())
    }

    fn process_discards(&mut self, completecb: T, opcode: OpCode, unmap: bool) -> Result<()> {
        let mut req_list = Vec::new();
        for task in self.refcount.discard_list.iter() {
            req_list.push(CombineRequest {
                iov: Vec::new(),
                offset: task.offset,
                nbytes: task.nbytes,
            })
        }

        match opcode {
            OpCode::Discard => {
                self.driver
                    .discard(req_list, completecb)
                    .unwrap_or_else(|e| error!("Discard failed: {}", e));
            }
            OpCode::WriteZeroes => {
                self.driver
                    .write_zeroes(req_list, completecb, unmap)
                    .unwrap_or_else(|e| error!("Write zero failed: {}", e));
            }
            _ => {
                bail!("Unsuppoerted opcode: {:?}", opcode);
            }
        }
        self.refcount.discard_list.clear();
        Ok(())
    }
}

impl<T: Clone + Send + Sync> BlockDriverOps<T> for Qcow2Driver<T> {
    fn read_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(iovec);
        self.check_request(offset, nbytes)
            .with_context(|| " Invalid read request")?;

        let mut left = iovec.to_vec();
        let total = std::cmp::min(nbytes, self.virtual_disk_size() - offset as u64);
        let mut req_list = Vec::new();
        let mut copyed = 0;
        while copyed < total {
            let pos = offset as u64 + copyed;
            let count = self.cluster_aligned_bytes(pos, total - copyed);
            let (begin, end) = iovecs_split(left, count);
            left = end;
            if let HostOffset::DataAddress(host_offset) = self.host_offset_for_read(pos)? {
                let nbytes = get_iov_size(&begin);
                req_list.push(CombineRequest {
                    iov: begin,
                    offset: host_offset,
                    nbytes,
                });
            } else {
                iov_from_buf_direct(&begin, &vec![0_u8; count as usize])?;
            }
            copyed += count;
        }

        self.driver.read_vectored(req_list, completecb)
    }

    fn write_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(iovec);
        self.check_request(offset, nbytes)
            .with_context(|| " Invalid write request")?;

        let mut left = iovec.to_vec();
        let total = std::cmp::min(nbytes, self.virtual_disk_size() - offset as u64);
        let mut req_list = Vec::new();
        let mut copyed = 0;
        while copyed < total {
            let pos = offset as u64 + copyed;
            let count = self.cluster_aligned_bytes(pos, total - copyed);
            let (begin, end) = iovecs_split(left, count);
            left = end;
            if let HostOffset::DataAddress(host_offset) = self.host_offset_for_write(pos)? {
                let nbytes = get_iov_size(&begin);
                req_list.push(CombineRequest {
                    iov: begin,
                    offset: host_offset,
                    nbytes,
                });
                copyed += count;
            }
        }

        if req_list.is_empty() {
            bail!("Request list is empty!");
        }
        self.driver.write_vectored(req_list, completecb)
    }

    fn datasync(&mut self, completecb: T) -> Result<()> {
        self.driver.datasync(completecb)
    }

    fn disk_size(&mut self) -> Result<u64> {
        Ok(self.virtual_disk_size())
    }

    fn discard(&mut self, offset: usize, nbytes: u64, completecb: T) -> Result<()> {
        // Align to cluster_size.
        let file_size = self.header.size;
        let align_size = self.header.cluster_size();
        let mut offset_start = std::cmp::min(offset as u64, file_size);
        let offset_end = std::cmp::min(offset as u64 + nbytes, file_size);
        let mut bytes = offset_end
            .checked_sub(offset_start)
            .with_context(|| format!("Discard :{} out of range: {}", offset_end, file_size))?;
        let head_align = (align_size - offset_start % align_size) % align_size;
        let tail_align = offset_end % align_size;
        if head_align + tail_align >= bytes {
            bytes = 0;
        } else {
            bytes -= head_align;
            bytes -= tail_align;
        }
        offset_start += head_align;

        self.qcow2_cluster_discard(offset_start, bytes, completecb)
    }

    fn write_zeroes(
        &mut self,
        offset: usize,
        nbytes: u64,
        completecb: T,
        unmap: bool,
    ) -> Result<()> {
        let file_size = self.header.size;
        let align_size = self.header.cluster_size();
        let mut offset_start = std::cmp::min(offset as u64, file_size);
        let offset_end = std::cmp::min(offset_start + nbytes, file_size);
        let mut total_bytes = offset_end.checked_sub(offset_start).with_context(|| {
            format!(
                "Write zeroes: ofset: {} nbytes: {} out of range",
                offset, nbytes
            )
        })?;
        let mut head = offset_start % align_size;
        let tail = offset_end % align_size;

        while total_bytes > 0 {
            let mut num = total_bytes;
            if head != 0 {
                num = std::cmp::min(num, align_size - head);
                head = (head + num) % align_size;
            } else if tail != 0 && num > align_size {
                num -= tail;
            }

            // Writing buffer with zero to disk for the addr that
            // is not aligned with cluster size.
            // The write order is: head -> offset align to cluster size -> tail.
            if !is_aligned(self.header.cluster_size(), offset_start | num) {
                let buf: Vec<u8> = vec![0; num as usize];
                if let Err(e) = self.sync_write_bytes(offset_start, &buf) {
                    error!("Write zero failed: {:?}", e);
                    break;
                }
            } else if let Err(e) = self.qcow2_cluster_write_zeroes(offset_start, num) {
                error!("Write zero failed: {:?}", e);
                break;
            }

            total_bytes -= num;
            offset_start += num;
        }
        self.process_discards(completecb, OpCode::WriteZeroes, unmap)
    }

    fn flush_request(&mut self) -> Result<()> {
        self.flush()?;
        self.driver.flush_request()
    }

    fn drain_request(&self) {
        self.driver.drain_request();
    }

    fn register_io_event(
        &mut self,
        broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()> {
        self.driver.register_io_event(broken, error_cb)
    }

    fn unregister_io_event(&mut self) -> Result<()> {
        self.driver.unregister_io_event()
    }

    fn get_status(&mut self) -> Arc<Mutex<BlockStatus>> {
        self.status.clone()
    }
}

pub fn is_aligned(cluster_sz: u64, offset: u64) -> bool {
    offset & (cluster_sz - 1) == 0
}

#[cfg(test)]
mod test {
    use std::{
        fs::remove_file,
        io::{Seek, SeekFrom, Write},
        os::unix::fs::OpenOptionsExt,
        process::Command,
    };

    use machine_manager::config::DiskFormat;
    use util::{
        aio::{iov_to_buf_direct, WriteZeroesState},
        file::get_file_alignment,
    };

    use super::*;

    const CLUSTER_SIZE: u64 = 64 * 1024;

    struct TestImage {
        pub img_bits: u64,
        pub cluster_bits: u64,
        pub path: String,
        pub file: File,
    }

    impl TestImage {
        fn new(path: &str, img_bits: u64, cluster_bits: u64) -> TestImage {
            let cluster_sz: u64 = 1 << cluster_bits;
            let img_size: u64 = 1 << img_bits;
            let l1_entry_size: u64 = 1 << (cluster_bits * 2 - 3);
            let l1_size = (img_size + l1_entry_size - 1) / l1_entry_size;
            let header = QcowHeader {
                magic: crate::qcow2::header::QCOW_MAGIC,
                version: 3,
                backing_file_offset: 0,
                backing_file_size: 0,
                cluster_bits: cluster_bits as u32,
                size: 1 << img_bits,
                crypt_method: 0,
                l1_size: l1_size as u32,
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

            TestImage {
                img_bits,
                cluster_bits,
                path: path.to_string(),
                file,
            }
        }

        fn create_qcow2_driver(&self, conf: BlockProperty) -> Qcow2Driver<()> {
            fn stub_func(_: &AioCb<()>, _: i64) -> Result<()> {
                Ok(())
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .unwrap();
            let aio = Aio::new(Arc::new(stub_func), util::aio::AioEngine::Off).unwrap();
            Qcow2Driver::new(file, aio, conf).unwrap()
        }
    }

    impl Drop for TestImage {
        fn drop(&mut self) {
            remove_file(&self.path).unwrap()
        }
    }

    fn execute_cmd(cmd: String) -> Vec<u8> {
        let args = cmd.split(' ').collect::<Vec<&str>>();
        if args.len() <= 0 {
            return vec![];
        }

        let mut cmd_exe = Command::new(args[0]);
        for i in 1..args.len() {
            cmd_exe.arg(args[i]);
        }

        let output = cmd_exe
            .output()
            .expect(format!("Failed to execute {}", cmd).as_str());
        println!("{:?}, output: {:?}", args, output);
        assert!(output.status.success());
        output.stdout
    }

    fn get_disk_size(img_path: Rc<String>) -> u64 {
        let out = execute_cmd(format!("du -shk {}", img_path));
        let str_out = std::str::from_utf8(&out)
            .unwrap()
            .split('\t')
            .collect::<Vec<&str>>();
        serde_json::from_str::<u64>(str_out[0]).unwrap()
    }

    fn vec_is_zero(vec: &[u8]) -> bool {
        for elem in vec {
            if elem != &0 {
                return false;
            }
        }
        true
    }

    struct TestData {
        data: u8,
        sz: usize,
    }

    impl TestData {
        fn new(data: u8, sz: usize) -> Self {
            Self { data, sz }
        }
    }

    struct TestRwCase {
        riovec: Vec<Iovec>,
        wiovec: Vec<Iovec>,
        data: Vec<TestData>,
        offset: usize,
        sz: u64,
    }

    fn create_qcow2(path: &str) -> (TestImage, Qcow2Driver<()>) {
        let mut image = TestImage::new(path, 30, 16);
        fn stub_func(_: &AioCb<()>, _: i64) -> Result<()> {
            Ok(())
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let aio = Aio::new(Arc::new(stub_func), util::aio::AioEngine::Off).unwrap();
        let (req_align, buf_align) = get_file_alignment(&image.file, true);
        let conf = BlockProperty {
            format: DiskFormat::Qcow2,
            iothread: None,
            direct: true,
            req_align,
            buf_align,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
        };
        image.file = file.try_clone().unwrap();
        (image, Qcow2Driver::new(file, aio, conf).unwrap())
    }

    fn qcow2_read(qcow2: &mut Qcow2Driver<()>, buf: &mut [u8], offset: usize) -> Result<()> {
        qcow2.read_vectored(
            &[Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            }],
            offset,
            (),
        )
    }

    fn qcow2_write(qcow2: &mut Qcow2Driver<()>, buf: &[u8], offset: usize) -> Result<()> {
        qcow2.write_vectored(
            &[Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            }],
            offset,
            (),
        )
    }

    #[test]
    fn test_read_zero() {
        let path = "/tmp/block_backend_test_read_zero.qcow2";
        let (mut image, mut qcow2) = create_qcow2(path);
        let org_len = image.file.seek(SeekFrom::End(0)).unwrap();

        let mut buf = vec![1_u8; 128];
        qcow2_read(&mut qcow2, &mut buf, 40).unwrap();
        assert_eq!(buf, vec![0; 128]);
        let mut buf = vec![2_u8; 512];
        qcow2_read(&mut qcow2, &mut buf, 65536).unwrap();
        assert_eq!(buf, vec![0; 512]);
        let mut buf = vec![3_u8; 600];
        qcow2_read(&mut qcow2, &mut buf, 655350).unwrap();
        assert_eq!(buf, vec![0; 600]);

        let len = image.file.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(org_len, len);
    }

    #[test]
    fn test_write_single_cluster() {
        let path = "/tmp/block_backend_test_write_single_cluster.qcow2";
        let (_, mut qcow2) = create_qcow2(path);

        let wbuf = vec![7_u8; CLUSTER_SIZE as usize];
        qcow2_write(&mut qcow2, &wbuf, 0).unwrap();
        let mut rbuf = vec![0_u8; CLUSTER_SIZE as usize];
        qcow2_read(&mut qcow2, &mut rbuf, 0).unwrap();
        assert_eq!(rbuf, wbuf);

        let wbuf = vec![5_u8; 1000];
        qcow2_write(&mut qcow2, &wbuf, 2000).unwrap();
        let mut rbuf = vec![0_u8; 1000];
        qcow2_read(&mut qcow2, &mut rbuf, 2000).unwrap();
        assert_eq!(rbuf, wbuf);
    }

    #[test]
    fn test_write_multi_cluster() {
        let path = "/tmp/block_backend_test_write_multi_cluster.qcow2";
        let (_, mut qcow2) = create_qcow2(path);

        let mut offset = 0;
        let cnt: u8 = 2;
        let sz = 100 * 1000;
        for i in 0..cnt {
            let buf = vec![i + 1; sz];
            qcow2_write(&mut qcow2, &buf, offset).unwrap();
            offset += buf.len();
        }
        let mut offset = 0;
        for i in 0..cnt {
            let mut buf = vec![i + 1; sz];
            qcow2_read(&mut qcow2, &mut buf, offset).unwrap();
            for (_, item) in buf.iter().enumerate() {
                assert_eq!(item, &(i + 1));
            }
            offset += buf.len();
        }
    }

    #[test]
    fn test_invalid_read_write() {
        let path = "/tmp/block_backend_test_invalid_read_write.qcow2";
        let (_, mut qcow2) = create_qcow2(path);

        let mut buf = vec![0_u8; 100];
        let disk_size = qcow2.disk_size().unwrap();
        let res = qcow2_write(&mut qcow2, &buf, disk_size as usize + 1);
        assert!(res.is_err());

        let res = qcow2_read(&mut qcow2, &mut buf, disk_size as usize + 100);
        assert!(res.is_err());
    }

    fn generate_iovecs(
        buf_list: &mut Vec<Vec<u8>>,
        list: &Vec<TestData>,
    ) -> (Vec<Iovec>, Vec<Iovec>) {
        let mut riovec = Vec::new();
        let mut wiovec = Vec::new();
        for item in list {
            let buf = vec![0_u8; item.sz];
            riovec.push(Iovec::new(buf.as_ptr() as u64, buf.len() as u64));
            buf_list.push(buf);
            let buf = vec![item.data; item.sz];
            wiovec.push(Iovec::new(buf.as_ptr() as u64, buf.len() as u64));
            buf_list.push(buf);
        }
        (riovec, wiovec)
    }

    fn generate_rw_case_list() -> (Vec<TestRwCase>, Vec<Vec<u8>>) {
        let mut list = Vec::new();
        let mut buf_list = Vec::new();
        let test_data = vec![
            TestData::new(1, 100_000),
            TestData::new(2, 100_000),
            TestData::new(3, 100_000),
        ];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 12590,
            sz: 100_000 * 3,
        });

        let test_data = vec![
            TestData::new(1, 1_000),
            TestData::new(2, 100_000),
            TestData::new(3, 10_000),
            TestData::new(4, 20_000),
            TestData::new(5, 80_000),
        ];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 8935201,
            sz: 211_000,
        });

        (list, buf_list)
    }

    #[test]
    fn test_read_write_vectored() {
        let path = "/tmp/block_backend_test_read_write_vectored.qcow2";
        let (_, mut qcow2) = create_qcow2(path);
        let (case_list, _buf_list) = generate_rw_case_list();
        for case in &case_list {
            qcow2.write_vectored(&case.wiovec, case.offset, ()).unwrap();
            qcow2.read_vectored(&case.riovec, case.offset, ()).unwrap();

            let mut wbuf = vec![0; case.sz as usize];
            let mut rbuf = vec![0; case.sz as usize];
            let wsz = iov_to_buf_direct(&case.wiovec, 0, &mut wbuf).unwrap();
            let rsz = iov_to_buf_direct(&case.riovec, 0, &mut rbuf).unwrap();
            assert_eq!(wsz, case.sz as usize);
            assert_eq!(rsz, case.sz as usize);
            assert_eq!(wbuf, rbuf);
        }
    }

    fn generate_rw_random_list() -> (Vec<TestRwCase>, Vec<Vec<u8>>) {
        let mut list = Vec::new();
        let mut buf_list = Vec::new();
        let test_data = vec![TestData::new(1, CLUSTER_SIZE as usize)];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 0,
            sz: CLUSTER_SIZE,
        });
        let test_data = vec![TestData::new(2, CLUSTER_SIZE as usize)];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 2 * CLUSTER_SIZE as usize,
            sz: CLUSTER_SIZE,
        });
        let test_data = vec![TestData::new(3, CLUSTER_SIZE as usize)];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 4 * CLUSTER_SIZE as usize,
            sz: CLUSTER_SIZE,
        });
        let test_data = vec![TestData::new(4, CLUSTER_SIZE as usize)];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 1 * CLUSTER_SIZE as usize,
            sz: CLUSTER_SIZE,
        });
        let test_data = vec![TestData::new(5, CLUSTER_SIZE as usize)];
        let (riovec, wiovec) = generate_iovecs(&mut buf_list, &test_data);
        list.push(TestRwCase {
            riovec,
            wiovec,
            data: test_data,
            offset: 3 * CLUSTER_SIZE as usize,
            sz: CLUSTER_SIZE,
        });

        (list, buf_list)
    }

    #[test]
    fn test_read_write_random() {
        let path = "/tmp/block_backend_test_read_write_random.qcow2";
        let (_, mut qcow2) = create_qcow2(path);
        let (mut case_list, _buf_list) = generate_rw_random_list();
        for case in &case_list {
            qcow2.write_vectored(&case.wiovec, case.offset, ()).unwrap();
            qcow2.read_vectored(&case.riovec, case.offset, ()).unwrap();

            let mut wbuf = vec![0; case.sz as usize];
            let mut rbuf = vec![0; case.sz as usize];
            let wsz = iov_to_buf_direct(&case.wiovec, 0, &mut wbuf).unwrap();
            let rsz = iov_to_buf_direct(&case.riovec, 0, &mut rbuf).unwrap();
            assert_eq!(wsz, case.sz as usize);
            assert_eq!(rsz, case.sz as usize);
            assert_eq!(wbuf, rbuf);
        }

        // read all write data once.
        let buf = vec![0_u8; 5 * CLUSTER_SIZE as usize];
        let riovecs = vec![Iovec::new(buf.as_ptr() as u64, 5 * CLUSTER_SIZE)];
        qcow2.read_vectored(&riovecs, 0, ()).unwrap();

        case_list.sort_by(|a, b| a.offset.cmp(&b.offset));
        let mut idx = 0;
        for case in case_list.iter() {
            for item in case.data.iter() {
                assert_eq!(buf[idx..(idx + item.sz)].to_vec(), vec![item.data; item.sz]);
                idx += item.sz;
            }
        }
    }

    #[test]
    fn test_discard_basic() {
        let path = "/tmp/discard.qcow2";
        // Create a new image, with size = 16M, cluster_size = 64K.
        let image_bits = 24;
        let cluster_bits = 16;
        let conf = BlockProperty {
            format: DiskFormat::Qcow2,
            iothread: None,
            direct: true,
            req_align: 512,
            buf_align: 512,
            discard: true,
            write_zeroes: WriteZeroesState::Off,
        };
        let image = TestImage::new(path, image_bits, cluster_bits);
        let mut qcow2_driver = image.create_qcow2_driver(conf);
        // Full the disk.
        let offset_start = 0;
        for i in 0..1 << (image.img_bits - image.cluster_bits) {
            let offset = offset_start + i * (1 << image.cluster_bits);
            let buf = vec![0_u8; 1 << image.cluster_bits];
            assert!(qcow2_write(&mut qcow2_driver, &buf, offset as usize).is_ok());
        }
        let image_size_1 = get_disk_size(Rc::new(path.to_string()));
        assert!(qcow2_driver.discard(0, 1 << image_bits, ()).is_ok());
        let image_size_2 = get_disk_size(Rc::new(path.to_string()));
        assert_eq!(image_size_1, image_size_2 + (1 << image_bits) / 1024);
    }

    #[test]
    fn test_write_zero_basic() {
        // Create a new image, with size = 16M, cluster_size = 64K.
        let path = "/tmp/discard_write_zero.qcow2";
        let image_bits = 24;
        let cluster_bits = 16;
        let conf = BlockProperty {
            format: DiskFormat::Qcow2,
            iothread: None,
            direct: true,
            req_align: 512,
            buf_align: 512,
            discard: true,
            write_zeroes: WriteZeroesState::On,
        };
        let image = TestImage::new(path, image_bits, cluster_bits);
        let mut qcow2_driver = image.create_qcow2_driver(conf);

        // Test 1.
        let mut test_buf: Vec<u8> = vec![1_u8; 65536 * 6];
        let test_data = vec![
            TestData::new(0, 65536),
            TestData::new(0, 65536 + 32768),
            TestData::new(0, 65536 * 2),
            TestData::new(0, 65536 + 32768),
        ];
        let offset_start = 0;
        let mut guest_offset = offset_start;
        assert!(qcow2_write(&mut qcow2_driver, &test_buf, offset_start).is_ok());
        for data in test_data.iter() {
            assert!(qcow2_driver
                .write_zeroes(guest_offset, data.sz as u64, (), true)
                .is_ok());
            let mut tmp_buf = vec![1_u8; data.sz];
            assert!(qcow2_read(&mut qcow2_driver, &mut tmp_buf, guest_offset).is_ok());
            assert!(vec_is_zero(&tmp_buf));
            guest_offset += data.sz;
        }
        assert!(qcow2_read(&mut qcow2_driver, &mut test_buf, offset_start).is_ok());
        assert!(vec_is_zero(&test_buf));

        // Test 2.
        let mut test_buf: Vec<u8> = vec![1_u8; 65536 * 6];
        let test_data = vec![
            TestData::new(0, 65536),
            TestData::new(0, 65536 + 32768),
            TestData::new(0, 65536 * 2),
            TestData::new(0, 65536 + 32768),
        ];
        let offset_start = 459752;
        let mut guest_offset = offset_start;
        assert!(qcow2_write(&mut qcow2_driver, &test_buf, offset_start).is_ok());
        for data in test_data.iter() {
            assert!(qcow2_driver
                .write_zeroes(guest_offset, data.sz as u64, (), true)
                .is_ok());
            let mut tmp_buf = vec![1_u8; data.sz];
            assert!(qcow2_read(&mut qcow2_driver, &mut tmp_buf, guest_offset).is_ok());
            assert!(vec_is_zero(&tmp_buf));
            guest_offset += data.sz;
        }
        assert!(qcow2_read(&mut qcow2_driver, &mut test_buf, offset_start).is_ok());
        assert!(vec_is_zero(&test_buf));
    }
}
