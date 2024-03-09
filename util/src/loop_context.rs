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
use std::fmt;
use std::fmt::Debug;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use libc::{c_void, read, EFD_NONBLOCK};
use log::{error, warn};
use nix::errno::Errno;
use nix::{
    poll::{ppoll, PollFd, PollFlags},
    sys::time::TimeSpec,
};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use crate::clock::{get_current_time, ClockState};
use crate::thread_pool::ThreadPool;
use crate::UtilError;

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
    /// Event is removed, thus not monitored.
    Removed = 2,
}

// The NotifierCallback must NOT update notifier status of itself, otherwise causes
// deadlock. Instead it should return notifiers and let caller to do so.
pub type NotifierCallback = dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>;

/// Epoll Event Notifier Entry.
pub struct EventNotifier {
    /// Raw file descriptor
    raw_fd: i32,
    /// Notifier operation
    op: NotifierOperation,
    /// Parked fd, temporarily removed from epoll
    parked_fd: Option<i32>,
    /// The types of events for which we use this fd
    event: EventSet,
    /// Event Handler List, one fd event may have many handlers
    handlers: Vec<Rc<NotifierCallback>>,
    /// Pre-polling handler
    pub handler_poll: Option<Box<NotifierCallback>>,
    /// Event status
    status: Arc<Mutex<EventStatus>>,
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
        handlers: Vec<Rc<NotifierCallback>>,
    ) -> Self {
        EventNotifier {
            raw_fd,
            op,
            parked_fd,
            event,
            handlers,
            handler_poll: None,
            status: Arc::new(Mutex::new(EventStatus::Alive)),
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

pub fn get_notifiers_fds(notifiers: &[EventNotifier]) -> Vec<RawFd> {
    let mut fds = Vec::with_capacity(notifiers.len());
    for notifier in notifiers {
        fds.push(notifier.raw_fd);
    }
    fds
}

pub fn gen_delete_notifiers(fds: &[RawFd]) -> Vec<EventNotifier> {
    let mut notifiers = Vec::with_capacity(fds.len());
    for fd in fds {
        notifiers.push(EventNotifier::new(
            NotifierOperation::Delete,
            *fd,
            None,
            EventSet::IN,
            Vec::new(),
        ));
    }
    notifiers
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
    /// Timer id.
    id: u64,
}

impl Timer {
    /// Construct function
    ///
    /// # Arguments
    ///
    /// * `func` - the function will be called later.
    /// * `delay` - delay time to call the function.
    pub fn new(func: Box<dyn Fn()>, delay: Duration, id: u64) -> Self {
        let expire_time = get_current_time() + delay;
        Timer {
            func,
            expire_time,
            id,
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
    /// Used to wakeup epoll to re-evaluate events or timers.
    kick_event: EventFd,
    /// Used to avoid unnecessary kick operation when the
    /// next re-evaluation is performed before next epoll.
    kick_me: AtomicBool,
    /// Used to identify that a kick operation occurred.
    kicked: AtomicBool,
    /// Fds registered to the `EventLoop`.
    events: Arc<RwLock<BTreeMap<RawFd, Box<EventNotifier>>>>,
    /// Events abandoned are stored in garbage collector.
    gc: Arc<RwLock<Vec<Box<EventNotifier>>>>,
    /// Temp events vector, store wait returned events.
    ready_events: Vec<EpollEvent>,
    /// Timer list
    timers: Arc<Mutex<Vec<Box<Timer>>>>,
    /// The next timer id to be used.
    timer_next_id: AtomicU64,
    /// The context for thread pool.
    pub thread_pool: Arc<ThreadPool>,
    /// Record VM clock state.
    pub clock_state: Arc<Mutex<ClockState>>,
}

impl Drop for EventLoopContext {
    fn drop(&mut self) {
        self.thread_pool
            .cancel()
            .unwrap_or_else(|e| error!("Thread pool cancel error: {:?}", e));
    }
}

// SAFETY: The closure in EventNotifier and Timer doesn't impl Send, they're
// not sent between threads actually.
unsafe impl Send for EventLoopContext {}

impl EventLoopContext {
    /// Constructs a new `EventLoopContext`.
    pub fn new() -> Self {
        let mut ctx = EventLoopContext {
            epoll: Epoll::new().unwrap(),
            manager: None,
            kick_event: EventFd::new(EFD_NONBLOCK).unwrap(),
            kick_me: AtomicBool::new(false),
            kicked: AtomicBool::new(false),
            events: Arc::new(RwLock::new(BTreeMap::new())),
            gc: Arc::new(RwLock::new(Vec::new())),
            ready_events: vec![EpollEvent::default(); READY_EVENT_MAX],
            timers: Arc::new(Mutex::new(Vec::new())),
            timer_next_id: AtomicU64::new(0),
            thread_pool: Arc::new(ThreadPool::default()),
            clock_state: Arc::new(Mutex::new(ClockState::default())),
        };
        ctx.init_kick();
        ctx
    }

    fn init_kick(&mut self) {
        let kick_handler: Rc<NotifierCallback> = Rc::new(|_, fd| {
            read_fd(fd);
            None
        });
        self.add_event(EventNotifier::new(
            NotifierOperation::AddExclusion,
            self.kick_event.as_raw_fd(),
            None,
            EventSet::IN,
            vec![kick_handler],
        ))
        .unwrap();
    }

    // Force epoll.wait to exit to re-evaluate events and timers.
    pub fn kick(&mut self) {
        self.kicked.store(true, Ordering::SeqCst);
        if self.kick_me.load(Ordering::SeqCst) {
            if let Err(e) = self.kick_event.write(1) {
                // Rarely fails when event is full, even if this
                // occurs, no need to add event again, so log is
                // enough for error handling.
                warn!("Failed to kick eventloop, {:?}", e);
            }
        }
    }

    pub fn set_manager(&mut self, manager: Arc<Mutex<dyn EventLoopManager>>) {
        self.manager = Some(manager);
    }

    fn clear_gc(&mut self) {
        let max_cnt = self.gc.write().unwrap().len();
        let mut pop_cnt = 0;

        loop {
            // Loop to avoid hold lock for long time.
            if pop_cnt >= max_cnt {
                break;
            }
            // SAFETY: We will stop removing when reach max_cnt and no other place
            // removes element of gc. This is to avoid infinite popping if other
            // thread continuously adds element to gc.
            self.gc.write().unwrap().remove(0);
            pop_cnt += 1;
        }
    }

    fn add_event(&mut self, mut event: EventNotifier) -> Result<()> {
        // If there is one same alive event monitored, update the handlers and eventset.
        // If there is one same parked event, update the handlers and eventset but warn.
        // If there is no event in the map, insert the event and park the related.
        let mut events_map = self.events.write().unwrap();
        if let Some(notifier) = events_map.get_mut(&event.raw_fd) {
            if let NotifierOperation::AddExclusion = event.op {
                return Err(anyhow!(UtilError::BadNotifierOperation));
            }

            if notifier.event != event.event {
                self.epoll.ctl(
                    ControlOperation::Modify,
                    notifier.raw_fd,
                    EpollEvent::new(notifier.event | event.event, &**notifier as *const _ as u64),
                )?;
                notifier.event |= event.event;
            }
            notifier.handlers.append(&mut event.handlers);
            if *notifier.status.lock().unwrap() == EventStatus::Parked {
                warn!("Parked event updated!");
            }
            return Ok(());
        }

        let event = Box::new(event);
        self.epoll.ctl(
            ControlOperation::Add,
            event.raw_fd,
            EpollEvent::new(event.event, &*event as *const _ as u64),
        )?;
        let parked_fd = event.parked_fd;
        events_map.insert(event.raw_fd, event);

        if let Some(parked_fd) = parked_fd {
            if let Some(parked) = events_map.get_mut(&parked_fd) {
                self.epoll
                    .ctl(ControlOperation::Delete, parked_fd, EpollEvent::default())?;
                *parked.status.lock().unwrap() = EventStatus::Parked;
            } else {
                return Err(anyhow!(UtilError::NoParkedFd(parked_fd)));
            }
        }

        Ok(())
    }

    fn rm_event(&mut self, event: &EventNotifier) -> Result<()> {
        // If there is no event in the map, return Error.
        // Else put the event in gc and reactivate the parked event.
        let mut events_map = self.events.write().unwrap();
        match events_map.get(&event.raw_fd) {
            Some(notifier) => {
                // No need to delete fd if status is Parked, it's done in park_event.
                if *notifier.status.lock().unwrap() == EventStatus::Alive {
                    if let Err(error) = self.epoll.ctl(
                        ControlOperation::Delete,
                        notifier.raw_fd,
                        EpollEvent::default(),
                    ) {
                        let error_num = error.raw_os_error().unwrap();
                        if error_num != libc::EBADF
                            && error_num != libc::ENOENT
                            && error_num != libc::EPERM
                        {
                            return Err(anyhow!(UtilError::BadSyscall(error)));
                        } else {
                            warn!("epoll ctl failed: {}", error);
                        }
                    }
                }
                let parked_fd = notifier.parked_fd;
                let event = events_map.remove(&event.raw_fd).unwrap();
                *event.status.lock().unwrap() = EventStatus::Removed;
                self.gc.write().unwrap().push(event);

                if let Some(parked_fd) = parked_fd {
                    if let Some(parked) = events_map.get_mut(&parked_fd) {
                        self.epoll.ctl(
                            ControlOperation::Add,
                            parked_fd,
                            EpollEvent::new(parked.event, &**parked as *const _ as u64),
                        )?;
                        *parked.status.lock().unwrap() = EventStatus::Alive;
                    } else {
                        return Err(anyhow!(UtilError::NoParkedFd(parked_fd)));
                    }
                }
            }
            _ => {
                return Err(anyhow!(UtilError::NoRegisterFd(event.raw_fd)));
            }
        }

        Ok(())
    }

    fn modify_event(&mut self, mut event: EventNotifier) -> Result<()> {
        let mut events_map = self.events.write().unwrap();
        match events_map.get_mut(&event.raw_fd) {
            Some(notifier) => {
                let events_specified = !event.event.is_empty();
                if events_specified && event.event != notifier.event {
                    self.epoll.ctl(
                        ControlOperation::Modify,
                        notifier.raw_fd,
                        EpollEvent::new(event.event, &**notifier as *const _ as u64),
                    )?;
                    notifier.event = event.event;
                }
                let handlers_specified = !event.handlers.is_empty();
                if handlers_specified {
                    notifier.handlers.clear();
                    notifier.handlers.append(&mut event.handlers);
                }
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
                *notifier.status.lock().unwrap() = EventStatus::Parked;
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
                *notifier.status.lock().unwrap() = EventStatus::Alive;
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
            trace::update_event(&en.raw_fd, &en.op);
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
        self.kick();

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

        self.epoll_wait_manager(self.timers_min_duration())
    }

    pub fn iothread_run(&mut self) -> Result<bool> {
        if let Some(manager) = &self.manager {
            if manager.lock().unwrap().loop_should_exit() {
                manager.lock().unwrap().loop_cleanup()?;
                return Ok(false);
            }
        }

        let min_timeout_ns = self.timers_min_duration();
        if min_timeout_ns.is_none() {
            for _i in 0..AIO_PRFETCH_CYCLE_TIME {
                for notifier in self.events.read().unwrap().values() {
                    let status_locked = notifier.status.lock().unwrap();
                    if *status_locked != EventStatus::Alive || notifier.handler_poll.is_none() {
                        continue;
                    }
                    let handler_poll = notifier.handler_poll.as_ref().unwrap();
                    if handler_poll(EventSet::empty(), notifier.raw_fd).is_some() {
                        break;
                    }
                }
            }
        }
        self.epoll_wait_manager(min_timeout_ns)
    }

    /// Call the function given by `func` after `delay` time.
    ///
    /// # Arguments
    ///
    /// * `func` - the function will be called later.
    /// * `delay` - delay time.
    pub fn timer_add(&mut self, func: Box<dyn Fn()>, delay: Duration) -> u64 {
        // insert in order of expire_time
        let mut timers = self.timers.lock().unwrap();

        let timer_id = self.timer_next_id.fetch_add(1, Ordering::SeqCst);
        let timer = Box::new(Timer::new(func, delay, timer_id));

        let mut index = timers.len();
        for (i, t) in timers.iter().enumerate() {
            if timer.expire_time < t.expire_time {
                index = i;
                break;
            }
        }
        trace::timer_add(&timer.id, &timer.expire_time);
        timers.insert(index, timer);
        drop(timers);
        self.kick();
        timer_id
    }

    /// Remove timer with specific timer id.
    pub fn timer_del(&mut self, timer_id: u64) {
        let mut timers = self.timers.lock().unwrap();
        for (i, t) in timers.iter().enumerate() {
            if timer_id == t.id {
                trace::timer_del(&t.id, &t.expire_time);
                timers.remove(i);
                break;
            }
        }
    }

    /// Get the expire_time of the soonest Timer, and then translate it to duration.
    pub fn timers_min_duration(&self) -> Option<Duration> {
        // The kick event happens before re-evaluate can be ignored.
        self.kicked.store(false, Ordering::SeqCst);
        let timers = self.timers.lock().unwrap();
        if timers.is_empty() {
            return None;
        }

        Some(
            timers[0]
                .expire_time
                .saturating_duration_since(get_current_time()),
        )
    }

    /// Call function of the timers which have already expired.
    pub fn run_timers(&mut self) {
        let now = get_current_time();
        let mut expired_nr = 0;

        let mut timers = self.timers.lock().unwrap();
        for timer in timers.iter() {
            if timer.expire_time > now {
                break;
            }
            expired_nr += 1;
        }

        let expired_timers: Vec<Box<Timer>> = timers.drain(0..expired_nr).collect();
        drop(timers);
        for timer in expired_timers {
            trace::timer_run(&timer.id);
            (timer.func)();
        }
    }

    fn epoll_wait_manager(&mut self, mut time_out: Option<Duration>) -> Result<bool> {
        let need_kick = !(time_out.is_some() && *time_out.as_ref().unwrap() == Duration::ZERO);
        if need_kick {
            self.kick_me.store(true, Ordering::SeqCst);
            if self.kicked.load(Ordering::SeqCst) {
                time_out = Some(Duration::ZERO);
            }
        }

        // When time_out greater then zero, use ppoll as a more precise timer.
        if time_out.is_some() && *time_out.as_ref().unwrap() != Duration::ZERO {
            let time_out_spec = Some(TimeSpec::from_duration(*time_out.as_ref().unwrap()));
            let pollflags = PollFlags::POLLIN | PollFlags::POLLOUT | PollFlags::POLLHUP;
            let mut pollfds: [PollFd; 1] = [PollFd::new(self.epoll.as_raw_fd(), pollflags)];

            match ppoll(&mut pollfds, time_out_spec, None) {
                Ok(_) => time_out = Some(Duration::ZERO),
                Err(e) if e == Errno::EINTR => time_out = Some(Duration::ZERO),
                Err(e) => return Err(anyhow!(UtilError::EpollWait(e.into()))),
            };
        }

        let time_out_ms = match time_out {
            Some(t) => t.as_millis() as i32,
            None => -1,
        };
        let ev_count = match self.epoll.wait(time_out_ms, &mut self.ready_events[..]) {
            Ok(ev_count) => ev_count,
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => 0,
            Err(e) => return Err(anyhow!(UtilError::EpollWait(e))),
        };
        if need_kick {
            self.kick_me.store(false, Ordering::SeqCst);
        }

        for i in 0..ev_count {
            // SAFETY: elements in self.events_map never get released in other functions
            let event = unsafe {
                let event_ptr = self.ready_events[i].data() as *const EventNotifier;
                &*event_ptr as &EventNotifier
            };
            let mut notifiers = Vec::new();
            let status_locked = event.status.lock().unwrap();
            if *status_locked == EventStatus::Alive {
                for j in 0..event.handlers.len() {
                    let handler = &event.handlers[j];
                    match handler(self.ready_events[i].event_set(), event.raw_fd) {
                        None => {}
                        Some(mut notifier) => {
                            notifiers.append(&mut notifier);
                        }
                    }
                }
            }
            drop(status_locked);
            if let Err(e) = self.update_events(notifiers) {
                error!("update event failed: {}", e);
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

    // SAFETY: this is called by notifier handler and notifier handler
    // is executed with fd is is valid. The value is defined above thus
    // valid too.
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
    use std::os::unix::io::{AsRawFd, RawFd};

    use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

    use super::*;

    impl EventLoopContext {
        fn check_existence(&self, fd: RawFd) -> Option<bool> {
            let events_map = self.events.read().unwrap();
            match events_map.get(&fd) {
                None => {
                    return None;
                }
                Some(notifier) => Some(*notifier.status.lock().unwrap() == EventStatus::Alive),
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

    fn generate_handler(related_fd: i32) -> Rc<NotifierCallback> {
        Rc::new(move |_, _| {
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
        handlers.push(handler1);
        let event1 = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            handlers,
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
            vec![handler1],
        );

        let event1_update = EventNotifier::new(
            NotifierOperation::AddShared,
            fd1.as_raw_fd(),
            None,
            EventSet::OUT,
            vec![handler1_update],
        );

        notifiers.push(event1);
        notifiers.push(event1_update);
        mainloop.update_events(notifiers).unwrap();
        mainloop.run().unwrap();

        // Firstly, event1 with handler1 would be added. Then, event1's handlers would append
        // handler1_update, which would register fd1_related_update in mainloop.
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
