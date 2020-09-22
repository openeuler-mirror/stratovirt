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

use std::clone::Clone;
use std::marker::{Send, Sync};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use super::errors::Result;
use super::link_list::{List, Node};
pub use libaio::*;
pub use raw::*;

type CbList<T> = List<AioCb<T>>;
type CbNode<T> = Node<AioCb<T>>;

pub type AioCompleteFunc<T> = Box<dyn Fn(&AioCb<T>, i64) + Sync + Send>;

pub struct AioCb<T: Clone> {
    pub last_aio: bool,
    pub file_fd: RawFd,
    pub opcode: IoCmd,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
    pub process: bool,
    pub iocb: Option<std::ptr::NonNull<IoCb>>,
    pub iocompletecb: T,
}

impl<T: Clone> AioCb<T> {
    pub fn new(cb: T) -> Self {
        AioCb {
            last_aio: true,
            file_fd: 0,
            opcode: IoCmd::NOOP,
            iovec: Vec::new(),
            offset: 0,
            process: false,
            iocb: None,
            iocompletecb: cb,
        }
    }
}

pub struct Aio<T: Clone + 'static> {
    pub ctx: Arc<LibaioContext>,
    pub fd: EventFd,
    pub aio_in_queue: CbList<T>,
    pub aio_in_flight: CbList<T>,
    max_events: usize,
    complete_func: Arc<AioCompleteFunc<T>>,
}

impl<T: Clone + 'static> Aio<T> {
    pub fn new(func: Arc<AioCompleteFunc<T>>) -> Result<Self> {
        let max_events = 128;

        Ok(Aio {
            ctx: Arc::new(LibaioContext::new(max_events as i32)?),
            fd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            aio_in_queue: List::new(),
            aio_in_flight: List::new(),
            max_events,
            complete_func: func,
        })
    }

    pub fn handle(&mut self) -> Result<()> {
        let evts = self.ctx.get_events()?;
        for e in evts.events.iter().take(evts.nr) {
            if e.res2 == 0 {
                unsafe {
                    let node = e.data as *mut CbNode<T>;

                    (self.complete_func)(&(*node).value, e.res);
                    self.aio_in_flight.unlink(&(*node));

                    // free mem
                    if let Some(i) = (*node).value.iocb {
                        libc::free((*node).value.iovec.as_ptr() as *mut libc::c_void);
                        libc::free(i.as_ptr() as *mut libc::c_void);
                    };
                    libc::free(node as *mut libc::c_void);
                }
            }
        }
        self.process_list()
    }

    fn process_list(&mut self) -> Result<()> {
        if self.aio_in_queue.len > 0 && self.aio_in_flight.len < self.max_events {
            let mut iocbs = Vec::new();

            for _ in self.aio_in_flight.len..self.max_events {
                match self.aio_in_queue.pop_tail() {
                    Some(node) => {
                        iocbs.push(node.value.iocb.unwrap().as_ptr());
                        self.aio_in_flight.add_head(node);
                    }
                    None => break,
                }
            }

            if !iocbs.is_empty() {
                return self.ctx.submit(iocbs.len() as i64, &mut iocbs);
            }
        }

        Ok(())
    }

    pub fn rw_aio(&mut self, cb: AioCb<T>) -> Result<()> {
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
        node.value.iocb = std::ptr::NonNull::new(Box::into_raw(Box::new(iocb)));

        self.aio_in_queue.add_head(node);
        if last_aio || self.aio_in_queue.len + self.aio_in_flight.len >= self.max_events {
            return self.process_list();
        }

        Ok(())
    }

    pub fn rw_sync(&mut self, cb: AioCb<T>) -> Result<()> {
        let ret = match cb.opcode {
            IoCmd::PREADV => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_read(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;
                }
                r
            }
            IoCmd::PWRITEV => {
                let mut r = 0;
                let mut off = cb.offset;
                for iov in cb.iovec.iter() {
                    r = raw_write(cb.file_fd, iov.iov_base, iov.iov_len as usize, off)?;
                    off += iov.iov_len as usize;
                }
                r
            }
            IoCmd::FDSYNC => raw_datasync(cb.file_fd)?,
            _ => -1,
        };
        (self.complete_func)(&cb, ret);

        Ok(())
    }
}
