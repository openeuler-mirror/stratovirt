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

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use libc::{c_void, read};
use log::warn;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use crate::UtilError;
use anyhow::{anyhow, Context, Result};
use std::fmt;
use std::fmt::Debug;

const READY_EVENT_MAX: usize = 256;
const AIO_PRFETCH_CYCLE_TIME: usize = 100;

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
    /// Park a file descriptor from the event table
    Park = 16,
    /// Resume a file descriptor from the event table
    Resume = 32,
}

#[derive(Debug, PartialEq)]
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
    /// Pre-polling handler
    pub handler_poll: Option<Box<NotifierCallback>>,
    /// Event status
    status: EventStatus,
}

impl fmt::Debug for EventNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventNotifier")
            .field("raw_fd", &self.raw_fd)
            .field("op", &self.op)
            .field("parked_fd", &self.parked_fd)
            .field("event", &self.event)
            .field("status", &self.status)
            .field("io_poll", &self.handler_poll.is_some())
            .finish()
    }
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
            handler_poll: None,
            status: EventStatus::Alive,
        }
    }
}

/// `EventNotifier` Factory
///
/// When an object have some `EventNotifier` wants
/// to add to event loop, the object need to implement
/// `InternalNotifiers` trait, so `EventLoop` would be
/// easy to get notifiers, and add to epoll context.
pub trait EventNotifierHelper {
    fn internal_notifiers(_: Arc<Mutex<Self>>) -> Vec<EventNotifier>;
}

/// EventLoop manager, advise continue running or stop running
pub trait EventLoopManager: Send + Sync {
    fn loop_should_exit(&self) -> bool;
    fn loop_cleanup(&self) -> Result<()>;
}

/// Timer structure is used for delay function execution.
struct Timer {
    /// Given the function that will be called.
    func: Box<dyn Fn()>,
    /// Given the real time when the `func` will be called.
    expire_time: Instant,
}

impl Timer {
    /// Construct function
    ///
    /// # Arguments
    ///
    /// * `func` - the function will be called later.
    /// * `nsec` - delay time in nanosecond.
    pub fn new(func: Box<dyn Fn()>, nsec: u64) -> Self {
        Timer {
            func,
            expire_time: Instant::now() + Duration::new(0, nsec as u32),
        }
    }
}

/// Epoll Loop Context
#[allow(clippy::vec_box)]
pub struct EventLoopContext {
    /// Epoll file descriptor.
    epoll: Epoll,
    /// Control epoll loop running.
    manager: Option<Arc<Mutex<dyn EventLoopManager>>>,
    /// Fds registered to the `EventLoop`.
    events: Arc<RwLock<BTreeMap<RawFd, Box<EventNotifier>>>>,
    /// Events abandoned are stored in garbage collector.
    gc: Arc<RwLock<Vec<Box<EventNotifier>>>>,
    /// Temp events vector, store wait returned events.
    ready_events: Vec<EpollEvent>,
    /// Timer list
    timers: Vec<Timer>,
}

unsafe impl Sync for EventLoopContext {}
unsafe impl Send for EventLoopContext {}

impl EventLoopContext {
    /// Constructs a new `EventLoopContext`.
    pub fn new() -> Self {
        EventLoopContext {
            epoll: Epoll::new().unwrap(),
            manager: None,
            events: Arc::new(RwLock::new(BTreeMap::new())),
            gc: Arc::new(RwLock::new(Vec::new())),
            ready_events: vec![EpollEvent::default(); READY_EVENT_MAX],
            timers: Vec::new(),
        }
    }

    pub fn set_manager(&mut self, manager: Arc<Mutex<dyn EventLoopManager>>) {
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
                return Err(anyhow!(UtilError::BadNotifierOperation));
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
                return Err(anyhow!(UtilError::NoParkedFd(parked_fd)));
            }
        }

        Ok(())
    }

    fn rm_event(&mut self, event: &EventNotifier) -> Result<()> {
        // If there is one same parked event, return Ok.
        // If there is no event in the map, return Error.
        // If there is one same alive event monitored, put the event in gc and reactivate the parked event.
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                if let EventStatus::Alive = notifier.status {
                    // No need to delete fd if status is Parked, it's done in park_event.
                    if let Err(error) = self.epoll.ctl(
                        ControlOperation::Delete,
                        notifier.raw_fd,
                        EpollEvent::default(),
                    ) {
                        let error_num = error.raw_os_error().unwrap();
                        if error_num != libc::EBADF && error_num != libc::ENOENT {
                            return Err(anyhow!(UtilError::BadSyscall(error)));
                        }
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
                        return Err(anyhow!(UtilError::NoParkedFd(parked_fd)));
                    }
                }

                let event = events_map.remove(&event.raw_fd).unwrap();
                self.gc.write().unwrap().push(event);
            }
            _ => {
                return Err(anyhow!(UtilError::NoRegisterFd(event.raw_fd)));
            }
        }

        Ok(())
    }

    /// change the callback for event
    fn modify_event(&mut self, event: EventNotifier) -> Result<()> {
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                notifier.handlers.clear();
                let mut event = event;
                notifier.handlers.append(&mut event.handlers);
            }
            _ => {
                return Err(anyhow!(UtilError::NoRegisterFd(event.raw_fd)));
            }
        }
        Ok(())
    }

    fn park_event(&mut self, event: &EventNotifier) -> Result<()> {
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                self.epoll
                    .ctl(
                        ControlOperation::Delete,
                        notifier.raw_fd,
                        EpollEvent::default(),
                    )
                    .with_context(|| {
                        format!("Failed to park event, event fd:{}", notifier.raw_fd)
                    })?;
                notifier.status = EventStatus::Parked;
            }
            _ => {
                return Err(anyhow!(UtilError::NoRegisterFd(event.raw_fd)));
            }
        }
        Ok(())
    }

    fn resume_event(&mut self, event: &EventNotifier) -> Result<()> {
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                self.epoll
                    .ctl(
                        ControlOperation::Add,
                        notifier.raw_fd,
                        EpollEvent::new(notifier.event, &**notifier as *const _ as u64),
                    )
                    .with_context(|| {
                        format!("Failed to resume event, event fd: {}", notifier.raw_fd)
                    })?;
                notifier.status = EventStatus::Alive;
            }
            _ => {
                return Err(anyhow!(UtilError::NoRegisterFd(event.raw_fd)));
            }
        }
        Ok(())
    }

    /// update fds registered to `EventLoop` according to the operation type.
    ///
    /// # Arguments
    ///
    /// * `notifiers` - event notifiers wanted to add to or remove from `EventLoop`.
    pub fn update_events(&mut self, notifiers: Vec<EventNotifier>) -> Result<()> {
        for en in notifiers {
            match en.op {
                NotifierOperation::AddExclusion | NotifierOperation::AddShared => {
                    self.add_event(en)?;
                }
                NotifierOperation::Modify => {
                    self.modify_event(en)?;
                }
                NotifierOperation::Delete => {
                    self.rm_event(&en)?;
                }
                NotifierOperation::Park => {
                    self.park_event(&en)?;
                }
                NotifierOperation::Resume => {
                    self.resume_event(&en)?;
                }
            }
        }

        Ok(())
    }

    /// Executes `epoll.wait()` to wait for events, and call the responding callbacks.
    pub fn run(&mut self) -> Result<bool> {
        if let Some(manager) = &self.manager {
            if manager.lock().unwrap().loop_should_exit() {
                manager.lock().unwrap().loop_cleanup()?;
                return Ok(false);
            }
        }

        self.epoll_wait_manager(self.timers_min_timeout())
    }

    pub fn iothread_run(&mut self) -> Result<bool> {
        if let Some(manager) = &self.manager {
            if manager.lock().unwrap().loop_should_exit() {
                manager.lock().unwrap().loop_cleanup()?;
                return Ok(false);
            }
        }

        let timeout = self.timers_min_timeout();
        if timeout == -1 {
            for _i in 0..AIO_PRFETCH_CYCLE_TIME {
                for notifer in self.events.read().unwrap().values() {
                    if notifer.status != EventStatus::Alive || notifer.handler_poll.is_none() {
                        continue;
                    }
                    let handler_poll = notifer.handler_poll.as_ref().unwrap();
                    if handler_poll(EventSet::empty(), notifer.raw_fd).is_some() {
                        break;
                    }
                }
            }
        }

        self.epoll_wait_manager(timeout)
    }

    /// Call the function given by `func` after `nsec` nanoseconds.
    ///
    /// # Arguments
    ///
    /// * `func` - the function will be called later.
    /// * `nsec` - delay time in nanoseconds.
    pub fn delay_call(&mut self, func: Box<dyn Fn()>, nsec: u64) {
        let timer = Timer::new(func, nsec);

        // insert in order of expire_time
        let mut index = self.timers.len();
        for (i, t) in self.timers.iter().enumerate() {
            if timer.expire_time < t.expire_time {
                index = i;
                break;
            }
        }
        self.timers.insert(index, timer);
    }

    /// Get the expire_time of the soonest Timer, and then translate it to timeout.
    fn timers_min_timeout(&self) -> i32 {
        if self.timers.is_empty() {
            return -1;
        }

        let now = Instant::now();
        if self.timers[0].expire_time <= now {
            return 0;
        }

        let timeout = (self.timers[0].expire_time - now).as_millis();
        if timeout >= i32::MAX as u128 {
            i32::MAX - 1
        } else {
            timeout as i32
        }
    }

    /// Call function of the timers which have already expired.
    fn run_timers(&mut self) {
        let now = Instant::now();
        let mut expired_nr = 0;

        for timer in &self.timers {
            if timer.expire_time > now {
                break;
            }

            expired_nr += 1;
        }

        let expired_timers: Vec<Timer> = self.timers.drain(0..expired_nr).collect();
        for timer in expired_timers {
            (timer.func)();
        }
    }

    fn epoll_wait_manager(&mut self, time_out: i32) -> Result<bool> {
        let ev_count = match self.epoll.wait(time_out, &mut self.ready_events[..]) {
            Ok(ev_count) => ev_count,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(e) => return Err(anyhow!(UtilError::EpollWait(e))),
        };

        for i in 0..ev_count {
            // It`s safe because elements in self.events_map never get released in other functions
            let event = unsafe {
                let event_ptr = self.ready_events[i].data() as *const EventNotifier;
                &*event_ptr as &EventNotifier
            };
            if let EventStatus::Alive = event.status {
                let mut notifiers = Vec::new();
                for j in 0..event.handlers.len() {
                    let handle = event.handlers[j].lock().unwrap();
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

        self.run_timers();
        self.clear_gc();
        Ok(true)
    }
}

impl Default for EventLoopContext {
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
        warn!("Failed to read fd");
    }

    value
}

#[cfg(test)]
mod test {
    use super::*;
    use libc::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

    impl EventLoopContext {
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
        let mut mainloop = EventLoopContext::new();
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
        let mut mainloop = EventLoopContext::new();
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
        let mut mainloop = EventLoopContext::new();
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
        let mut mainloop = EventLoopContext::new();
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
        let mut mainloop = EventLoopContext::new();
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
        assert!(mainloop.update_events(vec![event1]).is_ok());
    }

    #[test]
    fn fd_released_test() {
        let mut mainloop = EventLoopContext::new();
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
