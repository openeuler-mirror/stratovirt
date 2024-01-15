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

use vmm_sys_util::eventfd::EventFd;

use crate::aio::{AioCb, AioContext, AioEvent, Result};
use crate::thread_pool::ThreadPool;

pub struct ThreadsAioContext {
    _pool: Arc<ThreadPool>,
    _events: Vec<AioEvent>,
    _complete_list: Arc<Mutex<Vec<AioEvent>>>,
    _notify_event: Arc<Mutex<EventFd>>,
}

impl ThreadsAioContext {
    pub fn new(max_size: u32, eventfd: &EventFd, thread_pool: Arc<ThreadPool>) -> Self {
        Self {
            _pool: thread_pool,
            _complete_list: Arc::new(Mutex::new(Vec::new())),
            _notify_event: Arc::new(Mutex::new((*eventfd).try_clone().unwrap())),
            _events: Vec::with_capacity(max_size as usize),
        }
    }
}

impl<T: Clone> AioContext<T> for ThreadsAioContext {
    fn submit(&mut self, _iocbp: &[*const AioCb<T>]) -> Result<usize> {
        todo!()
    }

    fn submit_threads_pool(&mut self, _iocbp: &[*const AioCb<T>]) -> Result<usize> {
        todo!()
    }

    fn get_events(&mut self) -> &[AioEvent] {
        todo!()
    }
}
