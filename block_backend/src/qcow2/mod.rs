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

use anyhow::{Context, Result};
use byteorder::{BigEndian, ByteOrder};

use self::{header::QcowHeader, refcount::RefCount, table::Qcow2Table};

use super::BlockDriverOps;
use crate::{file::FileDriver, BlockIoErrorCallback, BlockProperty};
use util::{
    aio::{Aio, AioCb, AioEngine, Iovec, OpCode},
    num_ops::{round_down, round_up},
};

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

impl<T: Clone + 'static> Qcow2Driver<T> {
    pub fn new(file: File, aio: Aio<T>, conf: BlockProperty) -> Result<Self> {
        let fd = file.as_raw_fd();
        let sync_aio = Rc::new(RefCell::new(SyncAioInfo::new(fd, conf.clone())?));
        let qcow2 = Self {
            driver: FileDriver::new(file, aio, conf),
            sync_aio: sync_aio.clone(),
            header: QcowHeader::default(),
            table: Qcow2Table::new(sync_aio.clone()),
            refcount: RefCount::new(sync_aio),
        };
        Ok(qcow2)
    }
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type in Aio.
// We use Arc<Mutex<Qcow2Driver<T>>> to allow used in multi-threading.
unsafe impl<T: Clone + 'static> Send for Qcow2Driver<T> {}
unsafe impl<T: Clone + 'static> Sync for Qcow2Driver<T> {}

impl<T: Clone + Send + Sync> BlockDriverOps<T> for Qcow2Driver<T> {
    fn read_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        todo!()
    }

    fn write_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        todo!()
    }

    fn datasync(&mut self, args: T) -> Result<()> {
        todo!()
    }

    fn disk_size(&mut self) -> Result<u64> {
        todo!()
    }

    fn discard(&mut self, _offset: usize, _nbytes: u64, _completecb: T) -> Result<()> {
        todo!()
    }

    fn write_zeroes(
        &mut self,
        _offset: usize,
        _nbytes: u64,
        _completecb: T,
        _unmap: bool,
    ) -> Result<()> {
        todo!()
    }

    fn flush_request(&mut self) -> Result<()> {
        todo!()
    }

    fn drain_request(&self) {
        todo!()
    }

    fn register_io_event(
        &mut self,
        broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()> {
        todo!()
    }

    fn unregister_io_event(&mut self) -> Result<()> {
        todo!()
    }
}

pub fn is_aligned(cluster_sz: u64, offset: u64) -> bool {
    offset & (cluster_sz - 1) == 0
}
