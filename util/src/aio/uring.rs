// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::os::unix::io::AsRawFd;

use anyhow::{bail, Context};
use io_uring::{opcode, squeue, types, IoUring};
use libc;
use vmm_sys_util::eventfd::EventFd;

use super::threads::ThreadsAioContext;
use super::{AioCb, AioContext, AioEvent, OpCode, Result};

/// The io-uring context.
pub(crate) struct IoUringContext {
    ring: IoUring,
    threads_aio_ctx: ThreadsAioContext,
    events: Vec<AioEvent>,
}

impl IoUringContext {
    pub fn probe(entries: u32) -> Result<IoUring> {
        IoUring::new(entries).with_context(|| "Failed to create io_uring instance.")
    }

    pub fn new(
        entries: u32,
        threads_aio_ctx: ThreadsAioContext,
        eventfd: &EventFd,
    ) -> Result<Self> {
        let tmp_entries = entries as i32;
        // Ensure the power of 2.
        if (tmp_entries & -tmp_entries) != tmp_entries || tmp_entries == 0 {
            bail!("Entries must be the power of 2 and larger than 0");
        }
        let ring = Self::probe(entries)?;

        ring.submitter()
            .register_eventfd(eventfd.as_raw_fd())
            .with_context(|| "Failed to register event fd")?;
        let events = Vec::with_capacity(entries as usize);
        Ok(IoUringContext {
            ring,
            threads_aio_ctx,
            events,
        })
    }
}

impl<T: Clone> AioContext<T> for IoUringContext {
    fn submit(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize> {
        for iocb in iocbp.iter() {
            // SAFETY: iocb is valid until request is finished.
            let cb = unsafe { &*(*iocb) };
            let offset = cb.offset as u64;
            let data = cb.user_data;
            let len = cb.iovec.len();
            let iovs = cb.iovec.as_ptr();
            let fd = types::Fd(cb.file_fd);
            let entry = match cb.opcode {
                OpCode::Preadv => opcode::Readv::new(fd, iovs as *const libc::iovec, len as u32)
                    .offset(offset)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                OpCode::Pwritev => opcode::Writev::new(fd, iovs as *const libc::iovec, len as u32)
                    .offset(offset)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                OpCode::Fdsync => opcode::Fsync::new(fd)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                _ => {
                    bail!("Invalid entry code");
                }
            };
            // SAFETY: parameters of the entry are valid until request is finished.
            unsafe {
                self.ring
                    .submission()
                    .push(&entry)
                    .with_context(|| "Failed to push entry")?;
            }
        }
        self.ring.submit().with_context(|| "Failed to submit sqe")
    }

    fn submit_threads_pool(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize> {
        self.threads_aio_ctx.submit(iocbp)
    }

    fn get_events(&mut self) -> &[AioEvent] {
        let mut locked_list = self.threads_aio_ctx.complete_list.lock().unwrap();
        self.events = locked_list.drain(0..).collect();
        drop(locked_list);

        let queue = self.ring.completion();
        for cqe in queue {
            self.events.push(AioEvent {
                user_data: cqe.user_data(),
                status: 0,
                res: cqe.result() as i64,
            });
        }
        &self.events
    }
}
