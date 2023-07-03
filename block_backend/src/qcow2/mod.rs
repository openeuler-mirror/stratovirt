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
mod table;

use std::{
    cell::RefCell,
    fs::File,
    mem::size_of,
    os::unix::io::{AsRawFd, RawFd},
    rc::Rc,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ByteOrder};
use log::error;

use self::cache::ENTRY_SIZE_U64;
use crate::{
    file::{CombineRequest, FileDriver},
    qcow2::{
        cache::CacheTable,
        header::QcowHeader,
        refcount::RefCount,
        table::{Qcow2ClusterType, Qcow2Table},
    },
    BlockDriverOps, BlockIoErrorCallback, BlockProperty,
};
use util::aio::{
    get_iov_size, iov_from_buf_direct, iovecs_split, Aio, AioCb, AioEngine, Iovec, OpCode,
};
use util::num_ops::{round_down, round_up};

// The L1/L2/Refcount table entry size.
const ENTRY_SIZE: u64 = 1 << ENTRY_BITS;
const ENTRY_BITS: u64 = 3;
const L1_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_TABLE_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const QCOW2_OFLAG_ZERO: u64 = 1 << 0;
const QCOW2_OFFSET_COMPRESSED: u64 = 1 << 62;
const QCOW2_OFFSET_COPIED: u64 = 1 << 63;
const DEFAULT_SECTOR_SIZE: u64 = 512;

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
            driver: FileDriver::new(file, aio, conf),
            sync_aio: sync_aio.clone(),
            header: QcowHeader::default(),
            table: Qcow2Table::new(sync_aio.clone()),
            refcount: RefCount::new(sync_aio),
        };
        qcow2
            .load_header()
            .with_context(|| "Failed to load header")?;
        qcow2.check().with_context(|| "Invalid header")?;
        qcow2
            .table
            .init_table(&qcow2.header)
            .with_context(|| "Failed to create qcow2 table")?;
        qcow2.refcount.init_refcount_info(&qcow2.header);
        qcow2
            .load_refcount_table()
            .with_context(|| "Failed to load refcount table")?;
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

    fn flush(&mut self) -> Result<()> {
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
            let l2_cluster = self.load_l2_cluster(l2_address)?;
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
            // Step 1: Alloc a new l2_table.
            let old_l2_offset = l1_entry & L1_TABLE_OFFSET_MASK;
            let new_l2_offset = self.alloc_cluster(1, true)?;
            // Step 2: Update l1_table and l2 table cache.
            self.table.update_l1_table(
                l1_index as usize,
                new_l2_offset | QCOW2_OFFSET_COPIED,
                &self.header,
            )?;
            let zero_cluster: Vec<u8> = vec![0_u8; self.header.cluster_size() as usize];
            let l2_table_entry = Rc::new(RefCell::new(CacheTable::new(
                new_l2_offset,
                zero_cluster,
                ENTRY_SIZE_U64,
            )?));
            self.table.update_l2_table(l2_table_entry)?;
            // Step 3: Decrease the refcount of the old table.
            if old_l2_offset != 0 {
                self.refcount.update_refcount(old_l2_offset, 1, false, 1)?;
            }
            // Step 4. Get the offset of the newly-allocated l2 table.
            l2_address = new_l2_offset;
        }

        // Cache hit.
        if let Some(entry) = self.table.l2_table_cache.get(l2_address) {
            return Ok(entry.clone());
        }
        // Cache miss.
        let l2_cluster = self.load_l2_cluster(l2_address)?;
        let l2_table_entry = Rc::new(RefCell::new(CacheTable::new(
            l2_address,
            l2_cluster,
            ENTRY_SIZE_U64,
        )?));
        self.table.update_l2_table(l2_table_entry.clone())?;
        Ok(l2_table_entry)
    }

    fn offset_into_cluster(&self, guest_offset: u64) -> u64 {
        guest_offset & (self.header.cluster_size() - 1)
    }

    fn load_l2_cluster(&mut self, addr: u64) -> Result<Vec<u8>> {
        if !is_aligned(self.header.cluster_size(), addr) {
            bail!("L2 cluster address not aligned {}", addr);
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
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type in Aio.
// We use Arc<Mutex<Qcow2Driver<T>>> to allow used in multi-threading.
unsafe impl<T: Clone + 'static> Send for Qcow2Driver<T> {}
unsafe impl<T: Clone + 'static> Sync for Qcow2Driver<T> {}

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
                req_list.push(CombineRequest {
                    iov: begin,
                    offset: host_offset,
                });
            } else {
                iov_from_buf_direct(&begin, &vec![0_u8; count as usize])?;
            }
            copyed += count;
        }
        if req_list.is_empty() {
            // Not submitting an AIO request, call callback directly.
            self.driver
                .complete_read_request(iovec, offset, nbytes, completecb)
        } else {
            self.driver.read_vectored(req_list, completecb)
        }
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
                req_list.push(CombineRequest {
                    iov: begin,
                    offset: host_offset,
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

    fn discard(&mut self, _offset: usize, _nbytes: u64, _completecb: T) -> Result<()> {
        bail!("discard not supported now");
    }

    fn write_zeroes(
        &mut self,
        _offset: usize,
        _nbytes: u64,
        _completecb: T,
        _unmap: bool,
    ) -> Result<()> {
        bail!("write zero not supported now");
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
    };

    use machine_manager::config::DiskFormat;
    use util::{
        aio::{iov_to_buf_direct, WriteZeroesState},
        file::get_file_alignment,
    };

    use super::*;

    const CLUSTER_SIZE: u64 = 64 * 1024;

    struct TestImage {
        pub path: String,
        pub file: File,
    }

    impl TestImage {
        fn new(path: &str, img_bits: u32, cluster_bits: u32) -> TestImage {
            let cluster_sz = 1 << cluster_bits;
            let header = QcowHeader {
                magic: crate::qcow2::header::QCOW_MAGIC,
                version: 3,
                backing_file_offset: 0,
                backing_file_size: 0,
                cluster_bits,
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
            TestImage {
                path: path.to_string(),
                file,
            }
        }
    }

    impl Drop for TestImage {
        fn drop(&mut self) {
            remove_file(&self.path).unwrap()
        }
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
            .custom_flags(libc::O_DIRECT)
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
}
