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

extern crate vmm_sys_util;

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex, RwLock};

use libc::{c_void, read};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use crate::errors::{ErrorKind, Result};

const READY_EVENT_MAX: usize = 256;

#[derive(Debug)]
pub enum NotifierOperation {
    /// Add a file descriptor to the event table, and bind a notifier to
    /// it, when some event happened on it, notice the only one notifiers.
    AddExclusion = 1,
    /// Try to add a notifier to a file descriptor, when some event
    /// also notice me, the file descriptor must be read.
    AddShared = 2,
    /// Change the settings associated with a file descriptor.
    Modify = 4,
    /// Delete a file descriptor from the event table, if has one more notifiers,
    /// file descriptor not closed.
    Delete = 8,
}

enum EventStatus {
    /// Event is currently monitored in epoll.
    Alive = 0,
    /// Event is parked, temporarily not monitored.
    Parked = 1,
    /// Event is removed.
    Removed = 2,
}
pub type NotifierCallback = dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>;
/// Epoll Event Notifier Entry.
pub struct EventNotifier {
    /// Raw file descriptor
    pub raw_fd: i32,
    /// Notifier operation
    pub op: NotifierOperation,
    /// Parked fd, temporarily removed from epoll
    pub parked_fd: Option<i32>,
    /// The types of events for which we use this fd
    pub event: EventSet,
    /// Event Handler List, one fd event may have many handlers
    pub handlers: Vec<Arc<Mutex<Box<NotifierCallback>>>>,
    /// Event status
    status: EventStatus,
}

impl EventNotifier {
    /// Constructs a new `EventNotifier`.
    pub fn new(
        op: NotifierOperation,
        raw_fd: i32,
        parked_fd: Option<i32>,
        event: EventSet,
        handlers: Vec<Arc<Mutex<Box<NotifierCallback>>>>,
    ) -> Self {
        EventNotifier {
            raw_fd,
            op,
            parked_fd,
            event,
            handlers,
            status: EventStatus::Alive,
        }
    }
}

/// `EventNotifier` Factory
///
/// When an object have some `EventNotifier` wants
/// to add to main loop, the object need to implement
/// `InternalNotifiers` trait, so `MainLoop` would be
/// easy to get notifiers, and add to epoll context.
pub trait EventNotifierHelper {
    fn internal_notifiers(_: Arc<Mutex<Self>>) -> Vec<EventNotifier>;
}

/// MainLoop manager, advise continue running or stop running
pub trait MainLoopManager {
    fn main_loop_should_exit(&self) -> bool;
    fn main_loop_cleanup(&self) -> Result<()>;
}

/// Main Epoll Loop Context
#[allow(clippy::vec_box)]
pub struct MainLoopContext {
    /// Epoll file descriptor.
    epoll: Epoll,
    /// Control epoll loop running.
    manager: Option<Arc<dyn MainLoopManager>>,
    /// Fds registered to the `MainLoop`.
    events: Arc<RwLock<BTreeMap<i32, Box<EventNotifier>>>>,
    /// Events abandoned are stored in garbage collector.
    gc: Arc<RwLock<Vec<Box<EventNotifier>>>>,
    /// Temp events vector, store wait returned events.
    ready_events: Vec<EpollEvent>,
}

impl MainLoopContext {
    /// Constructs a new `MainLoopContext`.
    pub fn new() -> Self {
        MainLoopContext {
            epoll: Epoll::new().unwrap(),
            manager: None,
            events: Arc::new(RwLock::new(BTreeMap::new())),
            gc: Arc::new(RwLock::new(Vec::new())),
            ready_events: vec![EpollEvent::default(); READY_EVENT_MAX],
        }
    }

    pub fn set_manager(&mut self, manager: Arc<dyn MainLoopManager>) {
        self.manager = Some(manager);
    }

    fn clear_gc(&mut self) {
        let mut gc = self.gc.write().unwrap();
        gc.clear();
    }

    fn add_event(&mut self, event: EventNotifier) -> Result<()> {
        // If there is one same alive event monitored, update the handlers.
        // If there is one same parked event, update the handlers but warn.
        // If there is no event in the map, insert the event and park the related.
        let mut events_map = self.events.write().unwrap();
        if let Some(notifier) = events_map.get_mut(&event.raw_fd) {
            if let NotifierOperation::AddExclusion = event.op {
                return Err(ErrorKind::BadNotifierOperation.into());
            }

            let mut event = event;
            notifier.handlers.append(&mut event.handlers);
            if let EventStatus::Parked = notifier.status {
                warn!("Parked event updated!");
            }
            return Ok(());
        }

        let raw_fd = event.raw_fd;
        events_map.insert(raw_fd, Box::new(event));
        let event = events_map.get(&raw_fd).unwrap();
        self.epoll.ctl(
            ControlOperation::Add,
            event.raw_fd,
            EpollEvent::new(event.event, &**event as *const _ as u64),
        )?;

        if let Some(parked_fd) = event.parked_fd {
            if let Some(parked) = events_map.get_mut(&parked_fd) {
                self.epoll
                    .ctl(ControlOperation::Delete, parked_fd, EpollEvent::default())?;
                parked.status = EventStatus::Parked;
            } else {
                return Err(ErrorKind::NoParkedFd(parked_fd).into());
            }
        }

        Ok(())
    }

    fn rm_event(&mut self, event: &EventNotifier) -> Result<()> {
        // If there is one same parked event, return Error.
        // If there is no event in the map, return Error.
        // If there is one same alive event monitored, put the event in gc and reactivate the parked event.
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                if let EventStatus::Parked = notifier.status {
                    return Err(ErrorKind::RemoveParked(event.raw_fd).into());
                }

                if let Err(error) = self.epoll.ctl(
                    ControlOperation::Delete,
                    notifier.raw_fd,
                    EpollEvent::default(),
                ) {
                    let error_num = error.raw_os_error().unwrap();
                    if error_num != libc::EBADF && error_num != libc::ENOENT {
                        return Err(ErrorKind::BadSyscall(error).into());
                    }
                }
                notifier.status = EventStatus::Removed;

                if let Some(parked_fd) = notifier.parked_fd {
                    if let Some(parked) = events_map.get_mut(&parked_fd) {
                        self.epoll.ctl(
                            ControlOperation::Add,
                            parked_fd,
                            EpollEvent::new(parked.event, &**parked as *const _ as u64),
                        )?;
                        parked.status = EventStatus::Alive;
                    } else {
                        return Err(ErrorKind::NoParkedFd(parked_fd).into());
                    }
                }

                let event = events_map.remove(&event.raw_fd).unwrap();
                self.gc.write().unwrap().push(event);
            }
            None => {
                return Err(ErrorKind::NoRegisterFd(event.raw_fd).into());
            }
        }

        Ok(())
    }

    /// update fds registered to `MainLoop` according to the operation type.
    ///
    /// # Arguments
    ///
    /// * `notifiers` - event notifiers wanted to add to or remove from `MainLoop`.
    pub fn update_events(&mut self, notifiers: Vec<EventNotifier>) -> Result<()> {
        for en in notifiers {
            match en.op {
                NotifierOperation::AddExclusion | NotifierOperation::AddShared => {
                    self.add_event(en)?;
                }
                NotifierOperation::Delete => {
                    self.rm_event(&en)?;
                }
                _ => {
                    return Err(ErrorKind::UnExpectedOperationType.into());
                }
            }
        }

        Ok(())
    }

    /// Executes `epoll.wait()` to wait for events, and call the responding callbacks.
    pub fn run(&mut self) -> Result<bool> {
        match &self.manager {
            Some(manager) => {
                if manager.main_loop_should_exit() {
                    manager.main_loop_cleanup()?;
                    return Ok(false);
                }
            }
            None => {}
        }

        let ev_count = match self
            .epoll
            .wait(READY_EVENT_MAX, -1, &mut self.ready_events[..])
        {
            Ok(ev_count) => ev_count,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(e) => return Err(ErrorKind::EpollWait(e).into()),
        };

        for i in 0..ev_count {
            // It`s safe because elements in self.events_map never get released in other functions
            let event = unsafe {
                let event_ptr = self.ready_events[i].data() as *const EventNotifier;
                &*event_ptr as &EventNotifier
            };
            if let EventStatus::Alive = event.status {
                let mut notifiers = Vec::new();
                for i in 0..event.handlers.len() {
                    let handle = event.handlers[i].lock().unwrap();
                    match handle(self.ready_events[i].event_set(), event.raw_fd) {
                        None => {}
                        Some(mut notifier) => {
                            notifiers.append(&mut notifier);
                        }
                    }
                }
                self.update_events(notifiers)?;
            }
        }

        self.clear_gc();

        Ok(true)
    }
}

impl Default for MainLoopContext {
    fn default() -> Self {
        Self::new()
    }
}

pub fn read_fd(fd: RawFd) -> u64 {
    let mut value: u64 = 0;

    let ret = unsafe {
        read(
            fd,
            &mut value as *mut u64 as *mut c_void,
            std::mem::size_of::<u64>(),
        )
    };

    if ret == -1 {
        error!("Failed to read fd");
    }

    value
}

#[cfg(test)]
mod test {
    use super::*;
    use libc::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

    impl MainLoopContext {
        fn check_existence(&self, fd: RawFd) -> Option<bool> {
            let events_map = self.events.read().unwrap();
            match events_map.get(&fd) {
                None => {
                    return None;
                }
                Some(notifier) => {
                    if let EventStatus::Alive = notifier.status {
                        Some(true)
                    } else {
                        Some(false)
                    }
                }
            }
        }

        fn create_event(&mut self) -> i32 {
            let fd = EventFd::new(EFD_NONBLOCK).unwrap();
            let result = fd.as_raw_fd();
            let event = EventNotifier::new(
                NotifierOperation::AddShared,
                fd.as_raw_fd(),
                None,
                EventSet::OUT,
                Vec::new(),
            );
            self.update_events(vec![event]).unwrap();
            result
        }
    }

    fn generate_handler(related_fd: i32) -> Box<NotifierCallback> {
        Box::new(move |_, _| {
            let mut notifiers = Vec::new();
            let event = EventNotifier::new(
                NotifierOperation::AddShared,
                related_fd,
                None,
                EventSet::IN,
                Vec::new(),
            );
            notifiers.push(event);
            Some(notifiers)
        })
    }

    #[test]
    fn basic_test() {
        let mut mainloop = MainLoopContext::new();
        let mut notifiers = Vec::new();
        let fd1 = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd1_related = EventFd::new(EFD_NONBLOCK).unwrap();

        let handler1 = generate_handler(fd1_related.as_raw_fd());
        let mut handlers = Vec::new();
        handlers.push(Arc::new(Mutex::new(handler1)));
        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            handlers.clone(),
        );

        notifiers.push(event1);
        mainloop.update_events(notifiers).unwrap();
        mainloop.run().unwrap();
        // Event1 is OUT event, so its handler would be executed immediately.
        // Event1's handler is to add a fd1_related event, thus checking fd1 and fd1_relate would
        // make a basic function test.
        assert!(mainloop.check_existence(fd1.as_raw_fd()).unwrap());
        assert!(mainloop.check_existence(fd1_related.as_raw_fd()).unwrap());
    }

    #[test]
    fn parked_event_test() {
        let mut mainloop = MainLoopContext::new();
        let mut notifiers = Vec::new();
        let fd1 = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd2 = EventFd::new(EFD_NONBLOCK).unwrap();

        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            Vec::new(),
        );
        let event2 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd2.as_raw_fd(),
            Some(fd1.as_raw_fd()),
            EventSet::OUT,
            Vec::new(),
        );

        notifiers.push(event1);
        notifiers.push(event2);
        mainloop.update_events(notifiers).unwrap();
        mainloop.run().unwrap();

        // For the reason that event1 is the parked event of event2, when event2 added, event1 would
        // be set to parked.
        assert!(!mainloop.check_existence(fd1.as_raw_fd()).unwrap());
        assert!(mainloop.check_existence(fd2.as_raw_fd()).unwrap());

        let event2_remove = EventNotifier::new(
            NotifierOperation::Delete,
            fd2.as_raw_fd(),
            Some(fd1.as_raw_fd()),
            EventSet::OUT,
            Vec::new(),
        );
        mainloop.update_events(vec![event2_remove]).unwrap();

        // Then we remove event2, event1 will be re-activated and event2 will be deleted (removed
        // from events_map to gc).
        assert!(mainloop.check_existence(fd1.as_raw_fd()).unwrap());
        assert!(mainloop.check_existence(fd2.as_raw_fd()).is_none());
    }

    #[test]
    fn event_handler_test() {
        let mut mainloop = MainLoopContext::new();
        let mut notifiers = Vec::new();
        let fd1 = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd1_related = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd1_related_update = EventFd::new(EFD_NONBLOCK).unwrap();

        let handler1 = generate_handler(fd1_related.as_raw_fd());
        let handler1_update = generate_handler(fd1_related_update.as_raw_fd());
        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            vec![Arc::new(Mutex::new(handler1))],
        );

        let event1_update = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            vec![Arc::new(Mutex::new(handler1_update))],
        );

        notifiers.push(event1);
        notifiers.push(event1_update);
        mainloop.update_events(notifiers).unwrap();
        mainloop.run().unwrap();

        // Firstly, event1 with handler1 would be added. Then, event1's handlers would append
        // handler1_update, which would register fd1_related_update in  mainloop.
        assert!(mainloop.check_existence(fd1_related.as_raw_fd()).unwrap());
        assert!(mainloop
            .check_existence(fd1_related_update.as_raw_fd())
            .unwrap());
    }

    #[test]
    fn error_operation_test() {
        let mut mainloop = MainLoopContext::new();
        let fd1 = EventFd::new(EFD_NONBLOCK).unwrap();
        let leisure_fd = EventFd::new(EFD_NONBLOCK).unwrap();

        // Delete unexist event
        let event1 = EventNotifier::new(
            NotifierOperation::Delete,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            Vec::new(),
        );
        assert!(mainloop.update_events(vec![event1]).is_err());

        // Add event with unexist parked event
        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            Some(leisure_fd.as_raw_fd()),
            EventSet::OUT,
            Vec::new(),
        );
        assert!(mainloop.update_events(vec![event1]).is_err());

        // Delete event with unexist parked event
        let event1_delete = EventNotifier::new(
            NotifierOperation::Delete,
            fd1.as_raw_fd(),
            Some(leisure_fd.as_raw_fd()),
            EventSet::OUT,
            Vec::new(),
        );
        assert!(mainloop.update_events(vec![event1_delete]).is_err());
    }

    #[test]
    fn error_parked_operation_test() {
        let mut mainloop = MainLoopContext::new();
        let fd1 = EventFd::new(EFD_NONBLOCK).unwrap();
        let fd2 = EventFd::new(EFD_NONBLOCK).unwrap();

        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            Vec::new(),
        );
        mainloop.update_events(vec![event1]).unwrap();

        let event2 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd2.as_raw_fd(),
            Some(fd1.as_raw_fd()),
            EventSet::OUT,
            Vec::new(),
        );
        mainloop.update_events(vec![event2]).unwrap();

        // Delete parked event
        let event1 = EventNotifier::new(
            NotifierOperation::Delete,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            Vec::new(),
        );
        assert!(mainloop.update_events(vec![event1]).is_err());
    }

    #[test]
    fn fd_released_test() {
        let mut mainloop = MainLoopContext::new();
        let fd = mainloop.create_event();

        // In this case, fd is already closed. But program was wrote to ignore the error.
        let event = EventNotifier::new(
            NotifierOperation::Delete,
            fd,
            None,
            EventSet::OUT,
            Vec::new(),
        );

        assert!(mainloop.update_events(vec![event]).is_ok());
    }
}
