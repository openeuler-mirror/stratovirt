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
// See the Mulan PSL v2 for moe details.

extern crate vmm_sys_util;

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

const READY_EVENT_MAX: usize = 128;

pub type NotifierCallback = dyn Fn(EventSet, RawFd) + Send + Sync;

/// Epoll Event Notifier Entry.
pub struct EventNotifier {
    /// Raw file descriptor
    pub raw_fd: RawFd,
    /// The types of events for which we use this fd
    pub event: EventSet,
    /// Event Handler List, one fd event may have many handlers
    pub handler: Arc<Mutex<Box<NotifierCallback>>>,
}

impl EventNotifier {
    pub fn new(raw_fd: i32, event: EventSet, handler: Arc<Mutex<Box<NotifierCallback>>>) -> Self {
        EventNotifier {
            raw_fd,
            event,
            handler,
        }
    }
}

/// Epoll Context
pub struct EpollContext {
    /// Epoll file descriptor.
    epoll: Epoll,
    /// The Event handler
    events: Arc<Mutex<BTreeMap<RawFd, Box<EventNotifier>>>>,
}

impl EpollContext {
    pub fn new() -> Self {
        EpollContext {
            epoll: Epoll::new().unwrap(),
            events: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn add_event(&mut self, event: EventNotifier) {
        let mut events = self.events.lock().unwrap();
        let raw_fd = event.raw_fd;
        events.insert(raw_fd, Box::new(event));

        let event = events.get(&raw_fd).unwrap();
        self.epoll
            .ctl(
                ControlOperation::Add,
                raw_fd,
                EpollEvent::new(event.event, &**event as *const _ as u64),
            )
            .unwrap();
    }

    pub fn run(&self) -> bool {
        let mut ready_events = vec![EpollEvent::default(); READY_EVENT_MAX];

        let ev_count = match self.epoll.wait(READY_EVENT_MAX, -1, &mut ready_events[..]) {
            Ok(ev_count) => ev_count,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(_e) => return false,
        };

        for ready_event in ready_events.iter().take(ev_count) {
            let event = unsafe {
                let event_ptr = ready_event.data() as *const EventNotifier;
                &*event_ptr as &EventNotifier
            };
            let handler = event.handler.lock().unwrap();
            handler(ready_event.event_set(), event.raw_fd);
        }

        true
    }
}
