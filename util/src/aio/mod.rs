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

use log::{error, warn};
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use super::link_list::{List, Node};
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
    pub last_aio: bool,
    pub direct: bool,
    pub sector_size: u64,
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

    pub fn submit_request(&mut self, cb: AioCb<T>) -> Result<()> {
        if cb.direct && (cb.opcode == OpCode::Preadv || cb.opcode == OpCode::Pwritev) {
            for iov in cb.iovec.iter() {
                if iov.iov_base % cb.sector_size != 0 || iov.iov_len % cb.sector_size != 0 {
                    let res = self.handle_misaligned_rw(&cb).map_or_else(
                        |e| {
                            error!("{:?}", e);
                            -1
                        },
                        |_| 0,
                    );
                    return (self.complete_func)(&cb, res);
                }
            }
        }

        match cb.opcode {
            OpCode::Preadv | OpCode::Pwritev => {
                if self.ctx.is_some() {
                    self.rw_aio(cb)
                } else {
                    self.rw_sync(cb)
                }
            }
            OpCode::Fdsync => self.flush_sync(cb),
            OpCode::Noop => Err(anyhow!("Aio opcode is not specified.")),
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

    fn rw_aio(&mut self, cb: AioCb<T>) -> Result<()> {
        let last_aio = cb.last_aio;
        let mut node = Box::new(Node::new(cb));
        node.value.user_data = (&mut (*node) as *mut CbNode<T>) as u64;

        self.aio_in_queue.add_head(node);
        if last_aio || self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            self.process_list()?;
        }

        Ok(())
    }

    fn rw_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = match cb.opcode {
            OpCode::Preadv => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_read(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)
                        .unwrap_or_else(|e| {
                            error!("Failed to do sync read, {:?}", e);
                            -1
                        });
                    if r < 0 {
                        break;
                    }
                    off += iov.iov_len as usize;
                }
                r
            }
            OpCode::Pwritev => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_write(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)
                        .unwrap_or_else(|e| {
                            error!("Failed to do sync write, {:?}", e);
                            -1
                        });
                    if r < 0 {
                        break;
                    }
                    off += iov.iov_len as usize;
                }
                r
            }
            _ => -1,
        };
        (self.complete_func)(&cb, ret)
    }

    fn handle_misaligned_rw(&mut self, cb: &AioCb<T>) -> Result<()> {
        // SAFETY: only get the host page size.
        let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        match cb.opcode {
            OpCode::Preadv => {
                // SAFETY: we allocate aligned memory and free it later.
                // Alignment is set to host page size to decrease the count of allocated pages.
                let aligned_buffer =
                    unsafe { libc::memalign(host_page_size as usize, cb.nbytes as usize) };
                if aligned_buffer.is_null() {
                    bail!("Failed to alloc memory for misaligned read");
                }
                raw_read(
                    cb.file_fd,
                    aligned_buffer as u64,
                    cb.nbytes as usize,
                    cb.offset,
                )
                .map_err(|e| {
                    // SAFETY: the memory is allocated by us and will not be used anymore.
                    unsafe { libc::free(aligned_buffer) };
                    anyhow!("Failed to do raw read for misaligned read, {:?}", e)
                })?;

                // SAFETY: the memory is allocated by us.
                let src = unsafe {
                    std::slice::from_raw_parts(aligned_buffer as *const u8, cb.nbytes as usize)
                };
                let res = iov_from_buf_direct(&cb.iovec, src).and_then(|v| {
                    if v == cb.nbytes as usize {
                        Ok(())
                    } else {
                        Err(anyhow!("Failed to copy iovs to buff for misaligned read"))
                    }
                });
                // SAFETY: the memory is allocated by us and will not be used anymore.
                unsafe { libc::free(aligned_buffer) };
                res
            }
            OpCode::Pwritev => {
                // SAFETY: we allocate aligned memory and free it later.
                let aligned_buffer =
                    unsafe { libc::memalign(host_page_size as usize, cb.nbytes as usize) };
                if aligned_buffer.is_null() {
                    bail!("Failed to alloc memory for misaligned write");
                }
                // SAFETY: the memory is allocated by us.
                let dst = unsafe {
                    std::slice::from_raw_parts_mut(aligned_buffer as *mut u8, cb.nbytes as usize)
                };
                if let Err(e) = iov_to_buf_direct(&cb.iovec, dst).and_then(|v| {
                    if v == cb.nbytes as usize {
                        Ok(())
                    } else {
                        Err(anyhow!("Failed to copy iovs to buff for misaligned write"))
                    }
                }) {
                    // SAFETY: the memory is allocated by us and will not be used anymore.
                    unsafe { libc::free(aligned_buffer) };
                    return Err(e);
                }

                let res = raw_write(
                    cb.file_fd,
                    aligned_buffer as u64,
                    cb.nbytes as usize,
                    cb.offset,
                )
                .map(|_| {})
                .map_err(|e| anyhow!("Failed to do raw write for misaligned write, {:?}", e));
                // SAFETY: the memory is allocated by us and will not be used anymore.
                unsafe { libc::free(aligned_buffer) };
                res
            }
            _ => bail!("Failed to do misaligned rw: unknown cmd type"),
        }
    }

    fn flush_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = raw_datasync(cb.file_fd).unwrap_or_else(|e| {
            error!("Failed to do sync flush, {:?}", e);
            -1
        });
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
