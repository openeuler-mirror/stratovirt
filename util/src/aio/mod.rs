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
mod uring;

use std::clone::Clone;
use std::io::Write;
use std::os::unix::io::RawFd;
use std::sync::Arc;
use std::{cmp, str::FromStr};

use libc::c_void;
use log::{error, warn};
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use super::link_list::{List, Node};
use crate::num_ops::{round_down, round_up};
use crate::unix::host_page_size;
use anyhow::{anyhow, bail, Context, Result};
use libaio::LibaioContext;
pub use raw::*;
use uring::IoUringContext;

type CbList<T> = List<AioCb<T>>;
type CbNode<T> = Node<AioCb<T>>;

/// None aio type.
const AIO_OFF: &str = "off";
/// Native aio type.
const AIO_NATIVE: &str = "native";
/// Io-uring aio type.
const AIO_IOURING: &str = "io_uring";
/// Max bytes of bounce buffer for misaligned IO.
const MAX_LEN_BOUNCE_BUFF: u64 = 1 << 20;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum AioEngine {
    Off = 0,
    Native = 1,
    IoUring = 2,
}

impl FromStr for AioEngine {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            AIO_OFF => Ok(AioEngine::Off),
            AIO_NATIVE => Ok(AioEngine::Native),
            AIO_IOURING => Ok(AioEngine::IoUring),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

/// The trait for Asynchronous IO operation.
trait AioContext<T: Clone> {
    /// Submit IO requests to the OS, the nr submitted is returned.
    fn submit(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize>;
    /// Get the IO events of the requests sumbitted earlier.
    fn get_events(&mut self) -> &[AioEvent];
}

pub struct AioEvent {
    pub user_data: u64,
    pub status: i64,
    pub res: i64,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum OpCode {
    Noop = 0,
    Preadv = 1,
    Pwritev = 2,
    Fdsync = 3,
}

pub struct AioCb<T: Clone> {
    pub direct: bool,
    pub req_align: u32,
    pub buf_align: u32,
    pub file_fd: RawFd,
    pub opcode: OpCode,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
    pub nbytes: u64,
    pub user_data: u64,
    pub iocompletecb: T,
}

pub type AioCompleteFunc<T> = fn(&AioCb<T>, i64) -> Result<()>;

pub struct Aio<T: Clone + 'static> {
    ctx: Option<Box<dyn AioContext<T>>>,
    engine: AioEngine,
    pub fd: EventFd,
    pub aio_in_queue: CbList<T>,
    pub aio_in_flight: CbList<T>,
    max_events: usize,
    complete_func: Arc<AioCompleteFunc<T>>,
}

pub fn aio_probe(engine: AioEngine) -> Result<()> {
    match engine {
        AioEngine::Off => {}
        AioEngine::Native => {
            let ctx = LibaioContext::probe(1)?;
            // SAFETY: if no err, ctx is valid.
            unsafe { libc::syscall(libc::SYS_io_destroy, ctx) };
        }
        AioEngine::IoUring => {
            IoUringContext::probe(1)?;
        }
    }
    Ok(())
}

impl<T: Clone + 'static> Aio<T> {
    pub fn new(func: Arc<AioCompleteFunc<T>>, engine: AioEngine) -> Result<Self> {
        let max_events: usize = 128;
        let fd = EventFd::new(libc::EFD_NONBLOCK)?;
        let ctx: Option<Box<dyn AioContext<T>>> = match engine {
            AioEngine::Off => None,
            AioEngine::Native => Some(Box::new(LibaioContext::new(max_events as u32, &fd)?)),
            AioEngine::IoUring => Some(Box::new(IoUringContext::new(max_events as u32, &fd)?)),
        };

        Ok(Aio {
            ctx,
            engine,
            fd,
            aio_in_queue: List::new(),
            aio_in_flight: List::new(),
            max_events,
            complete_func: func,
        })
    }

    pub fn get_engine(&self) -> AioEngine {
        self.engine
    }

    pub fn submit_request(&mut self, mut cb: AioCb<T>) -> Result<()> {
        if self.request_misaligned(&cb) {
            let max_len = round_down(cb.nbytes + cb.req_align as u64 * 2, cb.req_align as u64)
                .ok_or_else(|| anyhow!("Failed to round down request length."))?;
            // Set upper limit of buffer length to avoid OOM.
            let buff_len = cmp::min(max_len, MAX_LEN_BOUNCE_BUFF);
            // SAFETY: we allocate aligned memory and free it later. Alignment is set to
            // host page size to decrease the count of allocated pages.
            let bounce_buffer =
                unsafe { libc::memalign(host_page_size() as usize, buff_len as usize) };
            if bounce_buffer.is_null() {
                error!("Failed to alloc memory for misaligned read/write.");
                return (self.complete_func)(&cb, -1);
            }

            let res = match self.handle_misaligned_rw(&mut cb, bounce_buffer, buff_len) {
                Ok(()) => 0,
                Err(e) => {
                    error!("{:?}", e);
                    -1
                }
            };

            // SAFETY: the memory is allocated by us and will not be used anymore.
            unsafe { libc::free(bounce_buffer) };
            return (self.complete_func)(&cb, res);
        }

        match cb.opcode {
            OpCode::Preadv | OpCode::Pwritev => {
                if self.ctx.is_some() {
                    self.rw_async(cb)
                } else {
                    self.rw_sync(cb)
                }
            }
            OpCode::Fdsync => {
                if self.ctx.is_some() {
                    self.flush_async(cb)
                } else {
                    self.flush_sync(cb)
                }
            }
            OpCode::Noop => Err(anyhow!("Aio opcode is not specified.")),
        }
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

                (self.complete_func)(&(*node).value, res)?;
                self.aio_in_flight.unlink(&(*node));
                // Construct Box to free mem automatically.
                drop(Box::from_raw(node));
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

    fn rw_async(&mut self, cb: AioCb<T>) -> Result<()> {
        let mut node = Box::new(Node::new(cb));
        node.value.user_data = (&mut (*node) as *mut CbNode<T>) as u64;

        self.aio_in_queue.add_head(node);
        if self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            self.process_list()?;
        }

        Ok(())
    }

    fn rw_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let mut ret = match cb.opcode {
            OpCode::Preadv => raw_readv(cb.file_fd, &cb.iovec, cb.offset),
            OpCode::Pwritev => raw_writev(cb.file_fd, &cb.iovec, cb.offset),
            _ => -1,
        };
        if ret < 0 {
            error!("Failed to do sync read/write.");
        } else if ret as u64 != cb.nbytes {
            error!("Incomplete sync read/write.");
            ret = -1;
        }
        (self.complete_func)(&cb, ret)
    }

    fn request_misaligned(&self, cb: &AioCb<T>) -> bool {
        if cb.direct && (cb.opcode == OpCode::Preadv || cb.opcode == OpCode::Pwritev) {
            if (cb.offset as u64) & (cb.req_align as u64 - 1) != 0 {
                return true;
            }
            for iov in cb.iovec.iter() {
                if iov.iov_base & (cb.buf_align as u64 - 1) != 0 {
                    return true;
                }
                if iov.iov_len & (cb.req_align as u64 - 1) != 0 {
                    return true;
                }
            }
        }
        false
    }

    fn handle_misaligned_rw(
        &mut self,
        cb: &mut AioCb<T>,
        bounce_buffer: *mut c_void,
        buffer_len: u64,
    ) -> Result<()> {
        let offset_align = round_down(cb.offset as u64, cb.req_align as u64)
            .ok_or_else(|| anyhow!("Failed to round down request offset."))?;
        let high = cb.offset as u64 + cb.nbytes;
        let high_align = round_up(high, cb.req_align as u64)
            .ok_or_else(|| anyhow!("Failed to round up request high edge."))?;

        match cb.opcode {
            OpCode::Preadv => {
                let mut offset = offset_align;
                let mut iovecs = &mut cb.iovec[..];
                loop {
                    // Step1: Read file to bounce buffer.
                    let nbytes = cmp::min(high_align - offset, buffer_len);
                    let len = raw_read(
                        cb.file_fd,
                        bounce_buffer as u64,
                        nbytes as usize,
                        offset as usize,
                    );
                    if len < 0 || len as u64 != nbytes {
                        bail!("Failed to do raw read for misaligned read.");
                    }

                    let real_offset = cmp::max(offset, cb.offset as u64);
                    let real_high = cmp::min(offset + nbytes, high);
                    let real_nbytes = real_high - real_offset;
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
                        .ok_or_else(|| anyhow!("Failed to adjust iovec for misaligned read"))?;
                }
                Ok(())
            }
            OpCode::Pwritev => {
                // Load the head from file before fill iovec to buffer.
                if cb.offset as u64 > offset_align {
                    let len = raw_read(
                        cb.file_fd,
                        bounce_buffer as u64,
                        cb.req_align as usize,
                        offset_align as usize,
                    );
                    if len < 0 || len as u32 != cb.req_align {
                        bail!("Failed to load head for misaligned write.");
                    }
                }
                // Is head and tail in the same alignment section?
                let tail_loaded = (offset_align + cb.req_align as u64) >= high;
                let need_tail = !tail_loaded && (high_align > high);

                let mut offset = offset_align;
                let mut iovecs = &mut cb.iovec[..];
                loop {
                    // Step1: Load iovec to bounce buffer.
                    let nbytes = cmp::min(high_align - offset, buffer_len);

                    let real_offset = cmp::max(offset, cb.offset as u64);
                    let real_high = cmp::min(offset + nbytes, high);
                    let real_nbytes = real_high - real_offset;

                    if real_high == high && need_tail {
                        let len = raw_read(
                            cb.file_fd,
                            bounce_buffer as u64 + nbytes - cb.req_align as u64,
                            cb.req_align as usize,
                            (offset + nbytes) as usize - cb.req_align as usize,
                        );
                        if len < 0 || len as u32 != cb.req_align {
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
                    iov_to_buf_direct(iovecs, dst).and_then(|v| {
                        if v == real_nbytes as usize {
                            Ok(())
                        } else {
                            Err(anyhow!("Failed to copy iovs to buff for misaligned write"))
                        }
                    })?;

                    // Step2: Write bounce buffer to file.
                    let len = raw_write(
                        cb.file_fd,
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
                        .ok_or_else(|| anyhow!("Failed to adjust iovec for misaligned write"))?;
                }
                Ok(())
            }
            _ => bail!("Failed to do misaligned rw: unknown cmd type"),
        }
    }

    fn flush_async(&mut self, cb: AioCb<T>) -> Result<()> {
        self.rw_async(cb)
    }

    fn flush_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = raw_datasync(cb.file_fd);
        if ret < 0 {
            error!("Failed to do sync flush.");
        }
        (self.complete_func)(&cb, ret)
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

/// Write buf to iovec and return the writed number of bytes.
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

/// Read iovec to buf and return the readed number of bytes.
pub fn iov_to_buf_direct(iovec: &[Iovec], buf: &mut [u8]) -> Result<usize> {
    let mut start: usize = 0;
    let mut end: usize = 0;

    for iov in iovec {
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
        if iov.iov_len as u64 > size {
            iov.iov_base += size;
            iov.iov_len -= size as u64;
            return Some(&mut iovec[index..]);
        }
        size -= iov.iov_len as u64;
    }
    None
}
