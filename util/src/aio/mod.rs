// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

mod libaio;
mod raw;
mod threads;
mod uring;

pub use raw::*;

use std::clone::Clone;
use std::io::Write;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::{cmp, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use libc::c_void;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use uring::IoUringContext;
use vmm_sys_util::eventfd::EventFd;

use super::link_list::{List, Node};
use crate::num_ops::{round_down, round_up};
use crate::thread_pool::ThreadPool;
use crate::unix::host_page_size;
use libaio::LibaioContext;
use threads::ThreadsAioContext;

type CbList<T> = List<AioCb<T>>;
type CbNode<T> = Node<AioCb<T>>;

/// None aio type.
const AIO_OFF: &str = "off";
/// Native aio type.
const AIO_NATIVE: &str = "native";
/// Io-uring aio type.
const AIO_IOURING: &str = "io_uring";
/// Aio implemented by thread pool.
const AIO_THREADS: &str = "threads";
/// Max bytes of bounce buffer for IO.
const MAX_LEN_BOUNCE_BUFF: u64 = 1 << 20;

#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum AioEngine {
    #[serde(alias = "off")]
    #[default]
    Off = 0,
    #[serde(alias = "native")]
    Native = 1,
    #[serde(alias = "iouring")]
    IoUring = 2,
    #[serde(alias = "threads")]
    Threads = 3,
}

impl FromStr for AioEngine {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            AIO_OFF => Ok(AioEngine::Off),
            AIO_NATIVE => Ok(AioEngine::Native),
            AIO_IOURING => Ok(AioEngine::IoUring),
            AIO_THREADS => Ok(AioEngine::Threads),
            _ => Err(()),
        }
    }
}

impl ToString for AioEngine {
    fn to_string(&self) -> String {
        match *self {
            AioEngine::Off => "off".to_string(),
            AioEngine::Native => "native".to_string(),
            AioEngine::IoUring => "io_uring".to_string(),
            AioEngine::Threads => "threads".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WriteZeroesState {
    Off,
    On,
    Unmap,
}

impl FromStr for WriteZeroesState {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "off" => Ok(WriteZeroesState::Off),
            "on" => Ok(WriteZeroesState::On),
            "unmap" => Ok(WriteZeroesState::Unmap),
            _ => Err(anyhow!("Unknown write zeroes state {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

impl Iovec {
    pub fn new(base: u64, len: u64) -> Self {
        Iovec {
            iov_base: base,
            iov_len: len,
        }
    }

    pub fn is_none(&self) -> bool {
        self.iov_base == 0 && self.iov_len == 0
    }
}

pub fn get_iov_size(iovecs: &[Iovec]) -> u64 {
    let mut sum = 0;
    for iov in iovecs {
        sum += iov.iov_len;
    }
    sum
}

/// The trait for Asynchronous IO operation.
trait AioContext<T: Clone> {
    /// Submit IO requests to the OS, the nr submitted is returned.
    fn submit(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize>;
    /// Submit Io requests to the thread pool, the nr submitted is returned.
    fn submit_threads_pool(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize>;
    /// Get the IO events of the requests submitted earlier.
    fn get_events(&mut self) -> &[AioEvent];
}

#[derive(Clone)]
pub struct AioEvent {
    pub user_data: u64,
    pub status: i64,
    pub res: i64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OpCode {
    Noop = 0,
    Preadv = 1,
    Pwritev = 2,
    Fdsync = 3,
    Discard = 4,
    WriteZeroes = 5,
    WriteZeroesUnmap = 6,
}

pub struct AioCb<T: Clone> {
    pub direct: bool,
    pub req_align: u32,
    pub buf_align: u32,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
    pub file_fd: RawFd,
    pub opcode: OpCode,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
    pub nbytes: u64,
    pub user_data: u64,
    pub iocompletecb: T,
    pub combine_req: Option<(Arc<AtomicU32>, Arc<AtomicI64>)>,
}

pub enum AioReqResult {
    Inflight,
    Error(i64),
    Done,
}

impl<T: Clone> AioCb<T> {
    pub fn req_is_completed(&self, ret: i64) -> AioReqResult {
        if let Some((cnt, res)) = self.combine_req.as_ref() {
            if ret < 0 {
                // Store error code in res.
                if let Err(v) = res.compare_exchange(0, ret, Ordering::SeqCst, Ordering::SeqCst) {
                    warn!("Error already existed, old {} new {}", v, ret);
                }
            }
            if cnt.fetch_sub(1, Ordering::SeqCst) > 1 {
                // Request is not completed.
                return AioReqResult::Inflight;
            }
            let v = res.load(Ordering::SeqCst);
            if v < 0 {
                return AioReqResult::Error(v);
            }
        }
        AioReqResult::Done
    }

    pub fn rw_sync(&self) -> i32 {
        let mut ret = match self.opcode {
            OpCode::Preadv => raw_readv(self.file_fd, &self.iovec, self.offset),
            OpCode::Pwritev => raw_writev(self.file_fd, &self.iovec, self.offset),
            _ => -1,
        };
        if ret < 0 {
            error!("Failed to do sync read/write.");
        } else if ret as u64 != self.nbytes {
            error!("Incomplete sync read/write.");
            ret = -1;
        }
        ret as i32
    }

    fn flush_sync(&self) -> i32 {
        let ret = raw_datasync(self.file_fd);
        if ret < 0 {
            error!("Failed to do sync flush.");
        }
        ret as i32
    }

    fn discard_sync(&self) -> i32 {
        let ret = raw_discard(self.file_fd, self.offset, self.nbytes);
        if ret < 0 && ret != -libc::ENOTSUP {
            error!("Failed to do sync discard.");
        }
        ret
    }

    fn write_zeroes_sync(&mut self) -> i32 {
        let mut ret;
        if self.opcode == OpCode::WriteZeroesUnmap {
            ret = raw_discard(self.file_fd, self.offset, self.nbytes);
            if ret == 0 {
                return ret;
            }
        }
        ret = raw_write_zeroes(self.file_fd, self.offset, self.nbytes);
        if ret == -libc::ENOTSUP && !self.iovec.is_empty() {
            self.opcode = OpCode::Pwritev;
            return self.rw_sync();
        }

        if ret < 0 {
            error!("Failed to do sync write zeroes.");
        }

        ret
    }

    // If the buffer is full with zero and the operation is Pwritev,
    // It's equal to write zero operation.
    fn try_convert_to_write_zero(&mut self) {
        if self.opcode == OpCode::Pwritev
            && self.write_zeroes != WriteZeroesState::Off
            && iovec_is_zero(&self.iovec)
        {
            self.opcode = OpCode::WriteZeroes;
            if self.write_zeroes == WriteZeroesState::Unmap && self.discard {
                self.opcode = OpCode::WriteZeroesUnmap;
            }
        }
    }

    pub fn is_misaligned(&self) -> bool {
        if self.direct && (self.opcode == OpCode::Preadv || self.opcode == OpCode::Pwritev) {
            if (self.offset as u64) & (self.req_align as u64 - 1) != 0 {
                return true;
            }
            for iov in self.iovec.iter() {
                if iov.iov_base & (self.buf_align as u64 - 1) != 0 {
                    return true;
                }
                if iov.iov_len & (self.req_align as u64 - 1) != 0 {
                    return true;
                }
            }
        }
        false
    }

    pub fn handle_misaligned(&mut self) -> Result<i32> {
        let max_len = round_down(
            self.nbytes + self.req_align as u64 * 2,
            self.req_align as u64,
        )
        .with_context(|| "Failed to round down request length.")?;
        // Set upper limit of buffer length to avoid OOM.
        let buff_len = std::cmp::min(max_len, MAX_LEN_BOUNCE_BUFF);
        let bounce_buffer =
        // SAFETY: We allocate aligned memory and free it later. Alignment is set to
        // host page size to decrease the count of allocated pages.
        unsafe { libc::memalign(host_page_size() as usize, buff_len as usize) };
        if bounce_buffer.is_null() {
            bail!("Failed to alloc memory for misaligned read/write.");
        }

        let res = match self.handle_misaligned_rw(bounce_buffer, buff_len) {
            Ok(()) => self.nbytes as i32,
            Err(e) => {
                error!("{:?}", e);
                -1
            }
        };

        // SAFETY: the memory is allocated by us and will not be used anymore.
        unsafe { libc::free(bounce_buffer) };
        Ok(res)
    }

    pub fn handle_misaligned_rw(
        &mut self,
        bounce_buffer: *mut c_void,
        buffer_len: u64,
    ) -> Result<()> {
        let offset_align = round_down(self.offset as u64, self.req_align as u64)
            .with_context(|| "Failed to round down request offset.")?;
        let high = self.offset as u64 + self.nbytes;
        let high_align = round_up(high, self.req_align as u64)
            .with_context(|| "Failed to round up request high edge.")?;

        match self.opcode {
            OpCode::Preadv => {
                let mut offset = offset_align;
                let mut iovecs = &mut self.iovec[..];
                loop {
                    // Step1: Read file to bounce buffer.
                    let nbytes = cmp::min(high_align - offset, buffer_len);
                    let len = raw_read(
                        self.file_fd,
                        bounce_buffer as u64,
                        nbytes as usize,
                        offset as usize,
                    );
                    if len < 0 {
                        bail!("Failed to do raw read for misaligned read.");
                    }

                    let real_offset = cmp::max(offset, self.offset as u64);
                    let real_high = cmp::min(offset + nbytes, high);
                    let real_nbytes = real_high - real_offset;
                    if (len as u64) < real_high - offset {
                        bail!(
                            "misaligned read len {} less than the nbytes {}",
                            len,
                            real_high - offset
                        );
                    }
                    // SAFETY: the memory is allocated by us.
                    let src = unsafe {
                        std::slice::from_raw_parts(
                            (bounce_buffer as u64 + real_offset - offset) as *const u8,
                            real_nbytes as usize,
                        )
                    };

                    // Step2: Copy bounce buffer to iovec.
                    iov_from_buf_direct(iovecs, src).and_then(|v| {
                        if v == real_nbytes as usize {
                            Ok(())
                        } else {
                            Err(anyhow!("Failed to copy iovs to buff for misaligned read"))
                        }
                    })?;

                    // Step3: Adjust offset and iovec for next loop.
                    offset += nbytes;
                    if offset >= high_align {
                        break;
                    }
                    iovecs = iov_discard_front_direct(iovecs, real_nbytes)
                        .with_context(|| "Failed to adjust iovec for misaligned read")?;
                }
                Ok(())
            }
            OpCode::Pwritev => {
                // Load the head from file before fill iovec to buffer.
                let mut head_loaded = false;
                if self.offset as u64 > offset_align {
                    let len = raw_read(
                        self.file_fd,
                        bounce_buffer as u64,
                        self.req_align as usize,
                        offset_align as usize,
                    );
                    if len < 0 || len as u32 != self.req_align {
                        bail!("Failed to load head for misaligned write.");
                    }
                    head_loaded = true;
                }
                // Is head and tail in the same alignment section?
                let same_section = (offset_align + self.req_align as u64) >= high;
                let need_tail = !(same_section && head_loaded) && (high_align > high);

                let mut offset = offset_align;
                let mut iovecs = &mut self.iovec[..];
                loop {
                    // Step1: Load iovec to bounce buffer.
                    let nbytes = cmp::min(high_align - offset, buffer_len);

                    let real_offset = cmp::max(offset, self.offset as u64);
                    let real_high = cmp::min(offset + nbytes, high);
                    let real_nbytes = real_high - real_offset;

                    if real_high == high && need_tail {
                        let len = raw_read(
                            self.file_fd,
                            bounce_buffer as u64 + nbytes - self.req_align as u64,
                            self.req_align as usize,
                            (offset + nbytes) as usize - self.req_align as usize,
                        );
                        if len < 0 || len as u32 != self.req_align {
                            bail!("Failed to load tail for misaligned write.");
                        }
                    }

                    // SAFETY: the memory is allocated by us.
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(
                            (bounce_buffer as u64 + real_offset - offset) as *mut u8,
                            real_nbytes as usize,
                        )
                    };
                    iov_to_buf_direct(iovecs, 0, dst).and_then(|v| {
                        if v == real_nbytes as usize {
                            Ok(())
                        } else {
                            Err(anyhow!("Failed to copy iovs to buff for misaligned write"))
                        }
                    })?;

                    // Step2: Write bounce buffer to file.
                    let len = raw_write(
                        self.file_fd,
                        bounce_buffer as u64,
                        nbytes as usize,
                        offset as usize,
                    );
                    if len < 0 || len as u64 != nbytes {
                        bail!("Failed to do raw write for misaligned write.");
                    }

                    // Step3: Adjuest offset and iovec for next loop.
                    offset += nbytes;
                    if offset >= high_align {
                        break;
                    }
                    iovecs = iov_discard_front_direct(iovecs, real_nbytes)
                        .with_context(|| "Failed to adjust iovec for misaligned write")?;
                }
                Ok(())
            }
            _ => bail!("Failed to do misaligned rw: unknown cmd type"),
        }
    }
}

pub type AioCompleteFunc<T> = fn(&AioCb<T>, i64) -> Result<()>;

pub struct Aio<T: Clone + 'static> {
    ctx: Option<Box<dyn AioContext<T>>>,
    engine: AioEngine,
    pub fd: EventFd,
    aio_in_queue: CbList<T>,
    aio_in_flight: CbList<T>,
    /// IO in aio_in_queue and aio_in_flight.
    pub incomplete_cnt: Arc<AtomicU64>,
    max_events: usize,
    pub complete_func: Arc<AioCompleteFunc<T>>,
}

pub fn aio_probe(engine: AioEngine) -> Result<()> {
    match engine {
        AioEngine::Native => {
            let ctx = LibaioContext::probe(1)?;
            // SAFETY: if no err, ctx is valid.
            unsafe { libc::syscall(libc::SYS_io_destroy, ctx) };
        }
        AioEngine::IoUring => {
            IoUringContext::probe(1)?;
        }
        _ => {}
    }
    Ok(())
}

impl<T: Clone + 'static> Aio<T> {
    pub fn new(
        func: Arc<AioCompleteFunc<T>>,
        engine: AioEngine,
        thread_pool: Option<Arc<ThreadPool>>,
    ) -> Result<Self> {
        let max_events: usize = 128;
        let fd = EventFd::new(libc::EFD_NONBLOCK)?;
        let ctx: Option<Box<dyn AioContext<T>>> = if let Some(pool) = thread_pool {
            let threads_aio_ctx = ThreadsAioContext::new(max_events as u32, &fd, pool);
            match engine {
                AioEngine::Native => Some(Box::new(LibaioContext::new(
                    max_events as u32,
                    threads_aio_ctx,
                    &fd,
                )?)),
                AioEngine::IoUring => Some(Box::new(IoUringContext::new(
                    max_events as u32,
                    threads_aio_ctx,
                    &fd,
                )?)),
                AioEngine::Threads => Some(Box::new(threads_aio_ctx)),
                _ => bail!("Aio type {:?} does not support thread pools", engine),
            }
        } else if engine == AioEngine::Off {
            None
        } else {
            bail!("Aio type {:?} is lack of thread pool context", engine);
        };

        Ok(Aio {
            ctx,
            engine,
            fd,
            aio_in_queue: List::new(),
            aio_in_flight: List::new(),
            incomplete_cnt: Arc::new(AtomicU64::new(0)),
            max_events,
            complete_func: func,
        })
    }

    pub fn get_engine(&self) -> AioEngine {
        self.engine
    }

    pub fn submit_request(&mut self, mut cb: AioCb<T>) -> Result<()> {
        trace::aio_submit_request(cb.file_fd, &cb.opcode, cb.offset, cb.nbytes);
        if self.ctx.is_none() {
            return self.handle_sync_request(cb);
        }

        if cb.is_misaligned() {
            return self.submit_thread_pool_async(cb);
        }

        cb.try_convert_to_write_zero();

        if self.engine != AioEngine::Threads
            && [OpCode::Preadv, OpCode::Pwritev, OpCode::Fdsync].contains(&cb.opcode)
        {
            return self.submit_async(cb);
        }

        self.submit_thread_pool_async(cb)
    }

    fn handle_sync_request(&mut self, mut cb: AioCb<T>) -> Result<()> {
        if cb.is_misaligned() {
            let ret = match cb.handle_misaligned() {
                Ok(ret) => ret,
                Err(e) => {
                    error!("{:?}", e);
                    -1
                }
            };
            return (self.complete_func)(&cb, ret as i64);
        }

        cb.try_convert_to_write_zero();

        let ret = match cb.opcode {
            OpCode::Preadv | OpCode::Pwritev => cb.rw_sync(),
            OpCode::Fdsync => cb.flush_sync(),
            OpCode::Discard => cb.discard_sync(),
            OpCode::WriteZeroes | OpCode::WriteZeroesUnmap => cb.write_zeroes_sync(),
            OpCode::Noop => return Err(anyhow!("Aio opcode is not specified.")),
        };
        (self.complete_func)(&cb, ret as i64)
    }

    pub fn flush_request(&mut self) -> Result<()> {
        if self.ctx.is_some() {
            self.process_list()
        } else {
            Ok(())
        }
    }

    pub fn handle_complete(&mut self) -> Result<bool> {
        let mut done = false;
        if self.ctx.is_none() {
            warn!("Can not handle aio complete with invalid ctx.");
            return Ok(done);
        }
        for evt in self.ctx.as_mut().unwrap().get_events() {
            // SAFETY: evt.data is specified by submit and not dropped at other place.
            unsafe {
                let node = evt.user_data as *mut CbNode<T>;
                let res = if (evt.status == 0) && (evt.res == (*node).value.nbytes as i64) {
                    done = true;
                    evt.res
                } else {
                    error!(
                        "Async IO request failed, status {} res {}",
                        evt.status, evt.res
                    );
                    -1
                };

                let res = (self.complete_func)(&(*node).value, res);
                self.aio_in_flight.unlink(&(*node));
                self.incomplete_cnt.fetch_sub(1, Ordering::SeqCst);
                // Construct Box to free mem automatically.
                drop(Box::from_raw(node));
                res?;
            }
        }
        self.process_list()?;
        Ok(done)
    }

    fn process_list(&mut self) -> Result<()> {
        if self.ctx.is_none() {
            warn!("Can not process aio list with invalid ctx.");
            return Ok(());
        }
        while self.aio_in_queue.len > 0 && self.aio_in_flight.len < self.max_events {
            let mut iocbs = Vec::new();

            for _ in self.aio_in_flight.len..self.max_events {
                match self.aio_in_queue.pop_tail() {
                    Some(node) => {
                        iocbs.push(&node.value as *const AioCb<T>);
                        self.aio_in_flight.add_head(node);
                    }
                    None => break,
                }
            }

            // The iocbs must not be empty.
            let (nr, is_err) = match self.ctx.as_mut().unwrap().submit(&iocbs) {
                Ok(nr) => (nr, false),
                Err(e) => {
                    error!("{:?}", e);
                    (0, true)
                }
            };

            // Push back unsubmitted requests. This should rarely happen, so the
            // trade off is acceptable.
            let mut index = nr;
            while index < iocbs.len() {
                if let Some(node) = self.aio_in_flight.pop_head() {
                    self.aio_in_queue.add_tail(node);
                }
                index += 1;
            }

            if is_err {
                // Fail one request, retry the rest.
                if let Some(node) = self.aio_in_queue.pop_tail() {
                    self.incomplete_cnt.fetch_sub(1, Ordering::SeqCst);
                    (self.complete_func)(&(node).value, -1)?;
                }
            } else if nr == 0 {
                // If can't submit any request, break the loop
                // and the method handle() will try again.
                break;
            }
        }
        Ok(())
    }

    fn submit_thread_pool_async(&mut self, cb: AioCb<T>) -> Result<()> {
        let mut node = Box::new(Node::new(cb));
        node.value.user_data = (&mut (*node) as *mut CbNode<T>) as u64;

        self.ctx
            .as_mut()
            .unwrap()
            .submit_threads_pool(&[&node.value as *const AioCb<T>])?;
        self.aio_in_flight.add_head(node);
        self.incomplete_cnt.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn submit_async(&mut self, cb: AioCb<T>) -> Result<()> {
        let mut node = Box::new(Node::new(cb));
        node.value.user_data = (&mut (*node) as *mut CbNode<T>) as u64;

        self.aio_in_queue.add_head(node);
        self.incomplete_cnt.fetch_add(1, Ordering::SeqCst);
        if self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            self.process_list()?;
        }

        Ok(())
    }
}

pub fn mem_from_buf(buf: &[u8], hva: u64) -> Result<()> {
    // SAFETY: all callers have valid hva address.
    let mut slice = unsafe { std::slice::from_raw_parts_mut(hva as *mut u8, buf.len()) };
    (&mut slice)
        .write(buf)
        .with_context(|| format!("Failed to write buf to hva:{})", hva))?;
    Ok(())
}

/// Write buf to iovec and return the written number of bytes.
pub fn iov_from_buf_direct(iovec: &[Iovec], buf: &[u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for iov in iovec.iter() {
        end = cmp::min(start + iov.iov_len as usize, buf.len());
        mem_from_buf(&buf[start..end], iov.iov_base)?;
        if end >= buf.len() {
            break;
        }
        start = end;
    }
    Ok(end)
}

pub fn mem_to_buf(mut buf: &mut [u8], hva: u64) -> Result<()> {
    // SAFETY: all callers have valid hva address.
    let slice = unsafe { std::slice::from_raw_parts(hva as *const u8, buf.len()) };
    buf.write(slice)
        .with_context(|| format!("Failed to read buf from hva:{})", hva))?;
    Ok(())
}

/// Read iovec to buf and return the read number of bytes.
pub fn iov_to_buf_direct(iovec: &[Iovec], offset: u64, buf: &mut [u8]) -> Result<usize> {
    let mut iovec2: Option<&[Iovec]> = None;
    let mut start: usize = 0;
    let mut end: usize = 0;

    if offset == 0 {
        iovec2 = Some(iovec);
    } else {
        let mut offset = offset;
        for (index, iov) in iovec.iter().enumerate() {
            if iov.iov_len > offset {
                end = cmp::min((iov.iov_len - offset) as usize, buf.len());
                mem_to_buf(&mut buf[..end], iov.iov_base + offset)?;
                if end >= buf.len() || index >= (iovec.len() - 1) {
                    return Ok(end);
                }
                start = end;
                iovec2 = Some(&iovec[index + 1..]);
                break;
            }
            offset -= iov.iov_len;
        }
        if iovec2.is_none() {
            return Ok(0);
        }
    }

    for iov in iovec2.unwrap() {
        end = cmp::min(start + iov.iov_len as usize, buf.len());
        mem_to_buf(&mut buf[start..end], iov.iov_base)?;
        if end >= buf.len() {
            break;
        }
        start = end;
    }
    Ok(end)
}

/// Discard "size" bytes of the front of iovec.
pub fn iov_discard_front_direct(iovec: &mut [Iovec], mut size: u64) -> Option<&mut [Iovec]> {
    for (index, iov) in iovec.iter_mut().enumerate() {
        if iov.iov_len > size {
            iov.iov_base += size;
            iov.iov_len -= size;
            return Some(&mut iovec[index..]);
        }
        size -= iov.iov_len;
    }
    None
}

fn iovec_is_zero(iovecs: &[Iovec]) -> bool {
    let size = std::mem::size_of::<u64>() as u64;
    for iov in iovecs {
        if iov.iov_len % size != 0 {
            return false;
        }
        // SAFETY: iov_base and iov_len has been checked in pop_avail().
        let slice = unsafe {
            std::slice::from_raw_parts(iov.iov_base as *const u64, (iov.iov_len / size) as usize)
        };
        for val in slice.iter() {
            if *val != 0 {
                return false;
            }
        }
    }
    true
}

pub fn iovecs_split(iovecs: Vec<Iovec>, mut size: u64) -> (Vec<Iovec>, Vec<Iovec>) {
    let mut begin = Vec::new();
    let mut end = Vec::new();
    for iov in iovecs {
        if size == 0 {
            end.push(iov);
            continue;
        }
        if iov.iov_len > size {
            begin.push(Iovec::new(iov.iov_base, size));
            end.push(Iovec::new(iov.iov_base + size, iov.iov_len - size));
            size = 0;
        } else {
            size -= iov.iov_len;
            begin.push(iov);
        }
    }
    (begin, end)
}

pub fn iovec_write_zero(iovec: &[Iovec]) {
    for iov in iovec.iter() {
        // SAFETY: all callers have valid hva address.
        unsafe {
            std::ptr::write_bytes(iov.iov_base as *mut u8, 0, iov.iov_len as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::prelude::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn perform_sync_rw(
        fsize: usize,
        offset: usize,
        nbytes: u64,
        opcode: OpCode,
        direct: bool,
        align: u32,
    ) {
        assert!(opcode == OpCode::Preadv || opcode == OpCode::Pwritev);
        // Init a file with special content.
        let mut content = vec![0u8; fsize];
        for (index, elem) in content.as_mut_slice().into_iter().enumerate() {
            *elem = index as u8;
        }
        let tmp_file = TempFile::new().unwrap();
        let mut file = tmp_file.into_file();
        file.write_all(&content).unwrap();

        // Prepare rw buf.
        let mut buf = vec![0xEF; nbytes as usize / 3];
        let mut buf2 = vec![0xFE; nbytes as usize - buf.len()];
        let iovec = vec![
            Iovec {
                iov_base: buf.as_mut_ptr() as u64,
                iov_len: buf.len() as u64,
            },
            Iovec {
                iov_base: buf2.as_mut_ptr() as u64,
                iov_len: buf2.len() as u64,
            },
        ];

        // Perform aio rw.
        let file_fd = file.as_raw_fd();
        let aiocb = AioCb {
            direct,
            req_align: align,
            buf_align: align,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            file_fd,
            opcode,
            iovec,
            offset,
            nbytes,
            user_data: 0,
            iocompletecb: 0,
            combine_req: None,
        };
        let mut aio = Aio::new(
            Arc::new(|_: &AioCb<i32>, _: i64| -> Result<()> { Ok(()) }),
            AioEngine::Off,
            None,
        )
        .unwrap();
        aio.submit_request(aiocb).unwrap();

        // Get actual file content.
        let mut new_content = vec![0u8; fsize];
        let ret = raw_read(
            file_fd,
            new_content.as_mut_ptr() as u64,
            new_content.len(),
            0,
        );
        assert_eq!(ret, fsize as i64);
        if opcode == OpCode::Pwritev {
            // The expected file content.
            let ret = (&mut content[offset..]).write(&buf).unwrap();
            assert_eq!(ret, buf.len());
            let ret = (&mut content[offset + buf.len()..]).write(&buf2).unwrap();
            assert_eq!(ret, buf2.len());
            for index in 0..fsize {
                assert_eq!(new_content[index], content[index]);
            }
        } else {
            for index in 0..buf.len() {
                assert_eq!(buf[index], new_content[offset + index]);
            }
            for index in 0..buf2.len() {
                assert_eq!(buf2[index], new_content[offset + buf.len() + index]);
            }
        }
    }

    fn test_sync_rw(opcode: OpCode, direct: bool, align: u32) {
        assert!(align >= 512);
        let fsize: usize = 2 << 20;

        // perform sync rw in the same alignment section.
        let minor_align = align as u64 - 100;
        perform_sync_rw(fsize, 0, minor_align, opcode, direct, align);
        perform_sync_rw(fsize, 50, minor_align, opcode, direct, align);
        perform_sync_rw(fsize, 100, minor_align, opcode, direct, align);

        // perform sync rw across alignment sections.
        let minor_size = fsize as u64 - 100;
        perform_sync_rw(fsize, 0, minor_size, opcode, direct, align);
        perform_sync_rw(fsize, 50, minor_size, opcode, direct, align);
        perform_sync_rw(fsize, 100, minor_size, opcode, direct, align);
    }

    fn test_sync_rw_all_align(opcode: OpCode, direct: bool) {
        let basic_align = 512;
        test_sync_rw(opcode, direct, basic_align << 0);
        test_sync_rw(opcode, direct, basic_align << 1);
        test_sync_rw(opcode, direct, basic_align << 2);
        test_sync_rw(opcode, direct, basic_align << 3);
    }

    #[test]
    fn test_direct_sync_rw() {
        test_sync_rw_all_align(OpCode::Preadv, true);
        test_sync_rw_all_align(OpCode::Pwritev, true);
    }

    #[test]
    fn test_indirect_sync_rw() {
        test_sync_rw_all_align(OpCode::Preadv, false);
        test_sync_rw_all_align(OpCode::Pwritev, false);
    }

    #[test]
    fn test_iovecs_split() {
        let iovecs = vec![Iovec::new(0, 100), Iovec::new(200, 100)];
        let (left, right) = iovecs_split(iovecs, 0);
        assert_eq!(left, vec![]);
        assert_eq!(right, vec![Iovec::new(0, 100), Iovec::new(200, 100)]);

        let iovecs = vec![Iovec::new(0, 100), Iovec::new(200, 100)];
        let (left, right) = iovecs_split(iovecs, 50);
        assert_eq!(left, vec![Iovec::new(0, 50)]);
        assert_eq!(right, vec![Iovec::new(50, 50), Iovec::new(200, 100)]);

        let iovecs = vec![Iovec::new(0, 100), Iovec::new(200, 100)];
        let (left, right) = iovecs_split(iovecs, 100);
        assert_eq!(left, vec![Iovec::new(0, 100)]);
        assert_eq!(right, vec![Iovec::new(200, 100)]);

        let iovecs = vec![Iovec::new(0, 100), Iovec::new(200, 100)];
        let (left, right) = iovecs_split(iovecs, 150);
        assert_eq!(left, vec![Iovec::new(0, 100), Iovec::new(200, 50)]);
        assert_eq!(right, vec![Iovec::new(250, 50)]);

        let iovecs = vec![Iovec::new(0, 100), Iovec::new(200, 100)];
        let (left, right) = iovecs_split(iovecs, 300);
        assert_eq!(left, vec![Iovec::new(0, 100), Iovec::new(200, 100)]);
        assert_eq!(right, vec![]);
    }

    #[test]
    fn test_iovec_write_zero() {
        let buf1 = vec![0x1_u8; 100];
        let buf2 = vec![0x1_u8; 40];
        let iovecs = vec![
            Iovec::new(buf1.as_ptr() as u64, buf1.len() as u64),
            Iovec::new(buf2.as_ptr() as u64, buf2.len() as u64),
        ];

        iovec_write_zero(&iovecs);
        assert_eq!(buf1, vec![0_u8; 100]);
        assert_eq!(buf2, vec![0_u8; 40]);
    }
}
