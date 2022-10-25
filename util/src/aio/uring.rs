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

use libc;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use error_chain::bail;
use io_uring::{opcode, squeue, types, IoUring};
use vmm_sys_util::eventfd::EventFd;

use super::libaio::{IoCb, IoCmd};
use super::{AioCb, AioCompleteFunc, AioContext, CbNode, IoEvent, Result, ResultExt};

/// The io-uring context.
pub(crate) struct IoUringContext<T: Clone + 'static> {
    ring: IoUring,
    events: Vec<IoEvent>,

    #[allow(dead_code)]
    // Only used to refering type T.
    func: Arc<AioCompleteFunc<T>>,
}

impl<T: Clone + 'static> IoUringContext<T> {
    pub fn new(entries: u32, eventfd: &EventFd, func: Arc<AioCompleteFunc<T>>) -> Result<Self> {
        let tmp_entries = entries as i32;
        // Ensure the power of 2.
        if (tmp_entries & -tmp_entries) != tmp_entries || tmp_entries == 0 {
            bail!("Entries must be the power of 2 and larger than 0");
        }
        let ring =
            IoUring::new(entries as u32).chain_err(|| "Failed to create io_uring instance")?;

        ring.submitter()
            .register_eventfd(eventfd.as_raw_fd())
            .chain_err(|| "Failed to register event fd")?;
        let events = Vec::with_capacity(entries as usize);
        Ok(IoUringContext { ring, func, events })
    }
}

impl<T: Clone + 'static> AioContext for IoUringContext<T> {
    #[allow(clippy::zero_ptr)]
    /// Submit requests to OS.
    fn submit(&mut self, nr: i64, iocbp: &mut [*mut IoCb]) -> Result<()> {
        for iocb in iocbp.iter() {
            let offset = unsafe { (*(*iocb)).aio_offset as libc::off_t };
            let node = unsafe { (*(*iocb)).data as *mut CbNode<T> };
            let aiocb = unsafe { &mut (*node).value as *mut AioCb<T> };
            let raw_fd = unsafe { (*(*iocb)).aio_fildes as i32 };
            let data = unsafe { (*(*iocb)).data };
            let code = unsafe { (*aiocb).opcode };
            let len = unsafe { (*(*iocb)).aio_nbytes };
            let iovs = unsafe { (*(*iocb)).aio_buf };
            let fd = types::Fd(raw_fd);
            let entry = match code {
                IoCmd::Preadv => opcode::Readv::new(fd, iovs as *const libc::iovec, len as u32)
                    .offset(offset)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                IoCmd::Pwritev => opcode::Writev::new(fd, iovs as *const libc::iovec, len as u32)
                    .offset(offset)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                IoCmd::Fdsync => opcode::Fsync::new(fd)
                    .build()
                    .flags(squeue::Flags::ASYNC)
                    .user_data(data),
                _ => {
                    bail!("Invalid entry code");
                }
            };
            unsafe {
                self.ring
                    .submission()
                    .push(&entry)
                    .chain_err(|| "Failed to push entry")?;
            }
        }
        self.ring
            .submit_and_wait(nr as usize)
            .chain_err(|| "Failed to submit sqe")?;
        Ok(())
    }

    /// Get the events.
    fn get_events(&mut self) -> (&[IoEvent], u32, u32) {
        let mut queue = self.ring.completion();
        self.events.clear();
        let l = queue.len();
        for _i in 0..l {
            match queue.next() {
                None => break,
                Some(cqe) => {
                    let event = IoEvent {
                        data: cqe.user_data(),
                        obj: 0,
                        res: cqe.result() as i64,
                        res2: 0,
                    };
                    self.events.push(event);
                }
            }
        }
        (&self.events, 0, self.events.len() as u32)
    }
}
