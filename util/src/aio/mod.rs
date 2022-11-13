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
use std::marker::{Send, Sync};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use vmm_sys_util::eventfd::EventFd;

use super::link_list::{List, Node};
use anyhow::Result;
pub use libaio::*;
pub use raw::*;
use uring::IoUringContext;

type CbList<T> = List<AioCb<T>>;
type CbNode<T> = Node<AioCb<T>>;

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default)]
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
    /// Submit IO requests to the OS.
    fn submit(&mut self, nr: i64, iocbp: &mut [*mut IoCb]) -> Result<()>;
    /// Get the IO events of the requests sumbitted earlier.
    fn get_events(&mut self) -> (&[IoEvent], u32, u32);
}

pub type AioCompleteFunc<T> = Box<dyn Fn(&AioCb<T>, i64) + Sync + Send>;

pub struct AioCb<T: Clone> {
    pub last_aio: bool,
    pub file_fd: RawFd,
    pub opcode: IoCmd,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
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
        let (evts, start, end) = ctx.get_events();

        for e in start..end {
            if evts[e as usize].res2 == 0 {
                done = true;
                unsafe {
                    let node = evts[e as usize].data as *mut CbNode<T>;

                    (self.complete_func)(&(*node).value, evts[e as usize].res);
                    self.aio_in_flight.unlink(&(*node));
                    // Construct Box to free mem automatically.
                    Box::from_raw(node);
                }
            }
        }
        // Drop reference of 'ctx', so below 'process_list' can work.
        drop(ctx);
        self.process_list().map(|_v| Ok(done))?
    }

    fn process_list(&mut self) -> Result<()> {
        if self.aio_in_queue.len > 0 && self.aio_in_flight.len < self.max_events {
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

            if !iocbs.is_empty() {
                return self
                    .ctx
                    .lock()
                    .unwrap()
                    .submit(iocbs.len() as i64, &mut iocbs);
            }
        }

        Ok(())
    }

    pub fn rw_aio(&mut self, cb: AioCb<T>, sector_size: u64, direct: bool) -> Result<()> {
        let mut misaligned = false;
        if direct {
            for iov in cb.iovec.iter() {
                if iov.iov_base % sector_size != 0 || iov.iov_len % sector_size != 0 {
                    misaligned = true;
                    break;
                }
            }
        }
        if direct && misaligned {
            return self.handle_misaligned_aio(cb);
        }

        let last_aio = cb.last_aio;
        let opcode = cb.opcode;
        let file_fd = cb.file_fd;
        let iovec = (&*cb.iovec).as_ptr() as u64;
        let sg_size = cb.iovec.len();
        let offset = cb.offset;

        let mut node = Box::new(Node::new(cb));
        let iocb = IoCb {
            aio_lio_opcode: opcode as u16,
            aio_fildes: file_fd as u32,
            aio_buf: iovec,
            aio_nbytes: sg_size as u64,
            aio_offset: offset as u64,
            aio_flags: IOCB_FLAG_RESFD,
            aio_resfd: self.fd.as_raw_fd() as u32,
            data: (&mut (*node) as *mut CbNode<T>) as u64,
            ..Default::default()
        };
        node.value.iocb = Some(Box::new(iocb));

        self.aio_in_queue.add_head(node);
        if last_aio || self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            return self.process_list();
        }

        Ok(())
    }

    pub fn rw_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = match cb.opcode {
            IoCmd::Preadv => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_read(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;
                }
                r
            }
            IoCmd::Pwritev => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_write(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;
                }
                r
            }
            IoCmd::Fdsync => raw_datasync(cb.file_fd)?,
            _ => -1,
        };
        (self.complete_func)(&cb, ret);

        Ok(())
    }

    fn handle_misaligned_aio(&mut self, cb: AioCb<T>) -> Result<()> {
        // Safe because we only get the host page size.
        let host_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let mut ret = 0_i64;

        match cb.opcode {
            IoCmd::Preadv => {
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    // Safe because we allocate aligned memory and free it later.
                    // Alignment is set to host page size to decrease the count of allocated pages.
                    let aligned_buffer =
                        unsafe { libc::memalign(host_page_size as usize, iov.iov_len as usize) };
                    ret = raw_read(cb.file_fd, aligned_buffer as u64, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;

                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(
                            iov.iov_base as *mut u8,
                            iov.iov_len as usize,
                        )
                    };
                    let src = unsafe {
                        std::slice::from_raw_parts(
                            aligned_buffer as *const u8,
                            iov.iov_len as usize,
                        )
                    };
                    dst.copy_from_slice(src);
                    // Safe because the memory is allocated by us and will not be used anymore.
                    unsafe { libc::free(aligned_buffer) };
                }
            }
            IoCmd::Pwritev => {
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    let aligned_buffer =
                        unsafe { libc::memalign(host_page_size as usize, iov.iov_len as usize) };
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut(
                            aligned_buffer as *mut u8,
                            iov.iov_len as usize,
                        )
                    };
                    let src = unsafe {
                        std::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len as usize)
                    };
                    dst.copy_from_slice(src);

                    ret = raw_write(cb.file_fd, aligned_buffer as u64, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;
                    unsafe { libc::free(aligned_buffer) };
                }
            }
            IoCmd::Fdsync => ret = raw_datasync(cb.file_fd)?,
            _ => {}
        };
        (self.complete_func)(&cb, ret);

        Ok(())
    }
}
