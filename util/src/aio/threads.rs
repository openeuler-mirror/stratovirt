// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::{Arc, Mutex};

use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::aio::{AioCb, AioContext, AioEvent, Iovec, OpCode, Result, WriteZeroesState};
use crate::thread_pool::{TaskOperation, ThreadPool};

pub struct ThreadsTasks {
    io_data: IoData,
    pub complete_lists: Arc<Mutex<Vec<AioEvent>>>,
    notify_event: Arc<Mutex<EventFd>>,
}

pub struct IoData {
    pub direct: bool,
    pub req_align: u32,
    pub buf_align: u32,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
    pub file_fd: i32,
    pub opcode: OpCode,
    pub iovec: Vec<Iovec>,
    pub offset: usize,
    pub nbytes: u64,
    pub user_data: u64,
}

impl IoData {
    fn package_aiocb(&self) -> AioCb<()> {
        AioCb {
            direct: self.direct,
            req_align: self.req_align,
            buf_align: self.buf_align,
            discard: self.discard,
            write_zeroes: self.write_zeroes,
            file_fd: self.file_fd,
            opcode: self.opcode,
            iovec: self.iovec.clone(),
            offset: self.offset,
            nbytes: self.nbytes,
            user_data: self.user_data,
            iocompletecb: (),
            combine_req: None,
        }
    }
}

impl ThreadsTasks {
    fn complete_func(&self, task: &IoData, res: i32) {
        let aio_event = AioEvent {
            user_data: task.user_data,
            status: 0,
            res: res as i64,
        };
        self.complete_lists.lock().unwrap().push(aio_event);
        self.notify_event
            .lock()
            .unwrap()
            .write(1)
            .unwrap_or_else(|e| error!("{:?}", e));
    }
}

impl TaskOperation for ThreadsTasks {
    fn run(&mut self) {
        let mut cb = self.io_data.package_aiocb();

        // Direct io needs to be aligned before io operation.
        if cb.is_misaligned() {
            let ret = match cb.handle_misaligned() {
                Ok(ret) => ret,
                Err(e) => {
                    error!("{:?}", e);
                    -1
                }
            };
            self.complete_func(&self.io_data, ret);
            return;
        }

        let mut ret = match cb.opcode {
            OpCode::Preadv | OpCode::Pwritev => cb.rw_sync(),
            OpCode::Discard => cb.discard_sync(),
            OpCode::WriteZeroes | OpCode::WriteZeroesUnmap => cb.write_zeroes_sync(),
            OpCode::Fdsync => cb.flush_sync(),
            _ => -1,
        };

        if [
            OpCode::Discard,
            OpCode::WriteZeroes,
            OpCode::WriteZeroesUnmap,
            OpCode::Fdsync,
        ]
        .contains(&cb.opcode)
            && ret == 0
        {
            ret = self.io_data.nbytes as i32;
        }

        self.complete_func(&self.io_data, ret);
    }
}

pub struct ThreadsAioContext {
    pool: Arc<ThreadPool>,
    events: Vec<AioEvent>,
    pub complete_list: Arc<Mutex<Vec<AioEvent>>>,
    notify_event: Arc<Mutex<EventFd>>,
}

impl ThreadsAioContext {
    pub fn new(max_size: u32, eventfd: &EventFd, thread_pool: Arc<ThreadPool>) -> Self {
        Self {
            pool: thread_pool,
            complete_list: Arc::new(Mutex::new(Vec::new())),
            notify_event: Arc::new(Mutex::new((*eventfd).try_clone().unwrap())),
            events: Vec::with_capacity(max_size as usize),
        }
    }
}

impl<T: Clone> AioContext<T> for ThreadsAioContext {
    fn submit(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize> {
        for iocb in iocbp {
            // SAFETY: iocb is valid until request is finished.
            let cb = unsafe { &*(*iocb) };

            let io_data = IoData {
                opcode: cb.opcode,
                file_fd: cb.file_fd,
                offset: cb.offset,
                nbytes: cb.nbytes,
                iovec: cb.iovec.clone(),
                direct: cb.direct,
                buf_align: cb.buf_align,
                req_align: cb.req_align,
                discard: cb.discard,
                write_zeroes: cb.write_zeroes,
                user_data: cb.user_data,
            };
            let task = ThreadsTasks {
                io_data,
                complete_lists: self.complete_list.clone(),
                notify_event: self.notify_event.clone(),
            };

            ThreadPool::submit_task(self.pool.clone(), Box::new(task))?;
        }

        Ok(iocbp.len())
    }

    fn submit_threads_pool(&mut self, iocbp: &[*const AioCb<T>]) -> Result<usize> {
        self.submit(iocbp)
    }

    fn get_events(&mut self) -> &[AioEvent] {
        let mut locked_list = self.complete_list.lock().unwrap();
        self.events = locked_list.drain(0..).collect();
        drop(locked_list);

        &self.events
    }
}
