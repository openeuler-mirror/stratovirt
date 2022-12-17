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
use std::cmp;
use std::io::Write;
use std::marker::{Send, Sync};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use log::error;
use vmm_sys_util::eventfd::EventFd;

use super::link_list::{List, Node};
use anyhow::{anyhow, bail, Context, Result};
pub use libaio::*;
pub use raw::*;
use uring::IoUringContext;

type CbList<T> = List<AioCb<T>>;
type CbNode<T> = Node<AioCb<T>>;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default, Clone)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

/// Io-uring aio type.
pub const AIO_IOURING: &str = "io_uring";
/// Native aio type.
pub const AIO_NATIVE: &str = "native";

/// The trait for Asynchronous IO operation.
trait AioContext {
    /// Submit IO requests to the OS, the nr submitted is returned.
    fn submit(&mut self, nr: i64, iocbp: &mut [*mut IoCb]) -> Result<usize>;
    /// Get the IO events of the requests sumbitted earlier.
    fn get_events(&mut self) -> &[IoEvent];
}

pub type AioCompleteFunc<T> = Box<dyn Fn(&AioCb<T>, i64) -> Result<()> + Sync + Send>;

pub struct AioCb<T: Clone> {
    pub last_aio: bool,
    pub file_fd: RawFd,
    pub opcode: IoCmd,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
    pub nbytes: u64,
    pub process: bool,
    pub iocb: Option<Box<IoCb>>,
    pub iocompletecb: T,
}

impl<T: Clone> AioCb<T> {
    pub fn new(cb: T) -> Self {
        AioCb {
            last_aio: true,
            file_fd: 0,
            opcode: IoCmd::Noop,
            iovec: Vec::new(),
            offset: 0,
            nbytes: 0,
            process: false,
            iocb: None,
            iocompletecb: cb,
        }
    }
}

pub struct Aio<T: Clone + 'static> {
    ctx: Arc<Mutex<dyn AioContext>>,
    pub fd: EventFd,
    pub aio_in_queue: CbList<T>,
    pub aio_in_flight: CbList<T>,
    max_events: usize,
    complete_func: Arc<AioCompleteFunc<T>>,
}

impl<T: Clone + 'static> Aio<T> {
    pub fn new(func: Arc<AioCompleteFunc<T>>, engine: Option<&String>) -> Result<Self> {
        let max_events: usize = 128;
        let fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let aio = if let Some(engine) = engine {
            engine
        } else {
            AIO_NATIVE
        };

        let ctx: Arc<Mutex<dyn AioContext>> = if aio == AIO_IOURING {
            Arc::new(Mutex::new(IoUringContext::new(
                max_events as u32,
                &fd,
                func.clone(),
            )?))
        } else {
            Arc::new(Mutex::new(LibaioContext::new(max_events as i32)?))
        };

        Ok(Aio {
            ctx,
            fd,
            aio_in_queue: List::new(),
            aio_in_flight: List::new(),
            max_events,
            complete_func: func,
        })
    }

    pub fn handle(&mut self) -> Result<bool> {
        let mut done = false;
        let mut ctx = self.ctx.lock().unwrap();

        for evt in ctx.get_events() {
            unsafe {
                let node = evt.data as *mut CbNode<T>;
                let res = if (evt.res2 == 0) && (evt.res == (*node).value.nbytes as i64) {
                    done = true;
                    evt.res
                } else {
                    error!("Async IO request failed, res2 {} res {}", evt.res2, evt.res);
                    -1
                };

                (self.complete_func)(&(*node).value, res)?;
                self.aio_in_flight.unlink(&(*node));
                // Construct Box to free mem automatically.
                drop(Box::from_raw(node));
            }
        }
        // Drop reference of 'ctx', so below 'process_list' can work.
        drop(ctx);
        self.process_list()?;
        Ok(done)
    }

    fn process_list(&mut self) -> Result<()> {
        while self.aio_in_queue.len > 0 && self.aio_in_flight.len < self.max_events {
            let mut iocbs = Vec::new();

            for _ in self.aio_in_flight.len..self.max_events {
                match self.aio_in_queue.pop_tail() {
                    Some(mut node) => {
                        let iocb = node.value.iocb.as_mut().unwrap();
                        iocbs.push(&mut **iocb as *mut IoCb);
                        self.aio_in_flight.add_head(node);
                    }
                    None => break,
                }
            }

            // The iocbs must not be empty.
            let (nr, is_err) = match self
                .ctx
                .lock()
                .unwrap()
                .submit(iocbs.len() as i64, &mut iocbs)
                .map_err(|e| {
                    error!("{}", e);
                    e
                }) {
                Ok(nr) => (nr, false),
                Err(_) => (0, true),
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

    pub fn rw_aio(&mut self, cb: AioCb<T>, sector_size: u64, direct: bool) -> Result<()> {
        if direct {
            for iov in cb.iovec.iter() {
                if iov.iov_base % sector_size != 0 || iov.iov_len % sector_size != 0 {
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

        let mut iocb = IoCb {
            aio_lio_opcode: cb.opcode as u16,
            aio_fildes: cb.file_fd as u32,
            aio_buf: (*cb.iovec).as_ptr() as u64,
            aio_nbytes: cb.iovec.len() as u64,
            aio_offset: cb.offset as u64,
            aio_flags: IOCB_FLAG_RESFD,
            aio_resfd: self.fd.as_raw_fd() as u32,
            ..Default::default()
        };
        let last_aio = cb.last_aio;
        let mut node = Box::new(Node::new(cb));
        iocb.data = (&mut (*node) as *mut CbNode<T>) as u64;
        node.value.iocb = Some(Box::new(iocb));

        self.aio_in_queue.add_head(node);
        if last_aio || self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            self.process_list()?;
        }

        Ok(())
    }

    pub fn rw_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = match cb.opcode {
            IoCmd::Preadv => {
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
            IoCmd::Pwritev => {
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
        // Safe because we only get the host page size.
        let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        match cb.opcode {
            IoCmd::Preadv => {
                // Safe because we allocate aligned memory and free it later.
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
                    // Safe because the memory is allocated by us and will not be used anymore.
                    unsafe { libc::free(aligned_buffer) };
                    anyhow!("Failed to do raw read for misaligned read, {:?}", e)
                })?;

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
                unsafe { libc::free(aligned_buffer) };
                res
            }
            IoCmd::Pwritev => {
                let aligned_buffer =
                    unsafe { libc::memalign(host_page_size as usize, cb.nbytes as usize) };
                if aligned_buffer.is_null() {
                    bail!("Failed to alloc memory for misaligned write");
                }
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
                unsafe { libc::free(aligned_buffer) };
                res
            }
            _ => bail!("Failed to do misaligned rw: unknown cmd type"),
        }
    }

    pub fn flush_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = raw_datasync(cb.file_fd).unwrap_or_else(|e| {
            error!("Failed to do sync flush, {:?}", e);
            -1
        });
        (self.complete_func)(&cb, ret)
    }
}

fn mem_from_buf(buf: &[u8], hva: u64) -> Result<()> {
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
