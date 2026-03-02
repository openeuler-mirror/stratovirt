// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use super::qmp_schema::{self as schema};
use crate::socket::SocketRWHandler;
use util::loop_context::create_new_eventfd;
use util::time::NANOSECONDS_PER_SECOND;

static QMP_CHANNEL: OnceLock<Arc<QmpChannel>> = OnceLock::new();

/// Macro `event!`: send event to qmp-client.
///
/// # Arguments
///
/// * `$x` - event type
/// * `$y` - event context
///
/// # Example
///
/// ```text
/// #[macro_use]
/// use machine_manager::qmp::*;
///
/// event!(Shutdown; shutdown_msg);
/// event!(Stop);
/// event!(Resume);
/// ```
#[macro_export]
macro_rules! event {
    ( $x:tt ) => {{
        QmpChannel::async_send_event($crate::qmp::qmp_schema::QmpEvent::$x {
            data: Default::default(),
            timestamp: $crate::qmp::qmp_channel::create_timestamp(),
        });
    }};
    ( $x:tt;$y:expr ) => {{
        QmpChannel::async_send_event($crate::qmp::qmp_schema::QmpEvent::$x {
            data: $y,
            timestamp: $crate::qmp::qmp_channel::create_timestamp(),
        });
    }};
}

/// `TimeStamp` structure for `QmpEvent`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeStamp {
    seconds: u64,
    microseconds: u64,
}

/// Constructs a `TimeStamp` struct.
pub fn create_timestamp() -> TimeStamp {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let seconds = u128::from(since_the_epoch.as_secs());
    let microseconds =
        (since_the_epoch.as_nanos() - seconds * u128::from(NANOSECONDS_PER_SECOND)) / (1_000_u128);
    TimeStamp {
        seconds: seconds as u64,
        microseconds: microseconds as u64,
    }
}

/// The struct `QmpChannel` is the only struct can handle Global variable
/// `QMP_CHANNEL`.
/// It is used to send event to qmp client and restore some file descriptor
/// which was sent by client.
pub struct QmpChannel {
    /// The `writer` to send `QmpEvent`.
    event_writer: RwLock<Option<SocketRWHandler>>,
    /// Restore file descriptor received from client.
    fds: Arc<RwLock<BTreeMap<String, RawFd>>>,
    /// The event fd to notify to asynchronously send `QmpEvent`.
    evtfd: EventFd,
    /// Events `QmpEvent` to send.
    events: Mutex<VecDeque<schema::QmpEvent>>,
}

impl QmpChannel {
    /// Constructs a `QmpChannel` in global `QMP_CHANNEL`.
    pub fn object_init() {
        // SAFETY: Global variable QMP_CHANNEL is only used in the main thread,
        // so there are no competition or synchronization.
        QMP_CHANNEL.get_or_init(|| {
            Arc::new(QmpChannel {
                event_writer: RwLock::new(None),
                fds: Arc::new(RwLock::new(BTreeMap::new())),
                evtfd: create_new_eventfd().expect("Failed to create eventfd for qmp channel"),
                events: Mutex::new(VecDeque::new()),
            })
        });
    }

    /// Bind a `SocketRWHandler` to `QMP_CHANNEL`.
    ///
    /// # Arguments
    ///
    /// * `writer` - The `SocketRWHandler` used to communicate with client.
    pub(crate) fn bind_writer(writer: SocketRWHandler) {
        *Self::inner().event_writer.write().unwrap() = Some(writer);
    }

    /// Unbind `SocketRWHandler` from `QMP_CHANNEL`.
    pub(crate) fn unbind() {
        *Self::inner().event_writer.write().unwrap() = None;
    }

    /// Check whether a `SocketRWHandler` bind with `QMP_CHANNEL` or not.
    pub fn is_connected() -> bool {
        Self::inner().event_writer.read().unwrap().is_some()
    }

    /// Restore extern file descriptor in `QMP_CHANNEL`.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of file descriptor.
    /// * `fd` - File descriptor sent by client.
    pub fn set_fd(name: String, fd: RawFd) {
        Self::inner().fds.write().unwrap().insert(name, fd);
    }

    /// Get extern file descriptor restored in `QMP_CHANNEL`.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of file descriptor.
    pub fn get_fd(name: &str) -> Option<RawFd> {
        Self::inner().fds.read().unwrap().get(name).copied()
    }

    /// Get file descriptor of eventfd in `QMP_CHANNEL`.
    pub fn get_event_fd() -> RawFd {
        Self::inner().evtfd.as_raw_fd()
    }

    /// Asynchronously send a `QmpEvent` to client.
    ///
    /// # Arguments
    ///
    /// * `event` - The `QmpEvent` sent to client.
    pub fn async_send_event(event: schema::QmpEvent) {
        const MAX_EVENT_COUNT: usize = 50;

        if !Self::is_connected() {
            return;
        }

        let mut events = Self::inner().events.lock().unwrap();
        while events.len() >= MAX_EVENT_COUNT {
            let dropped = events.pop_front();
            warn!(
                "QmpEvent count exceeds {}. {:?} is dropped",
                MAX_EVENT_COUNT, dropped
            );
        }

        events.push_back(event);
        if let Err(e) = Self::inner().evtfd.write(1) {
            error!(
                "Failed to write event fd to notify qmp event async, {:?}",
                e
            );
        }
    }

    /// Send all events `QmpEvent` to client.
    pub fn send_event() {
        loop {
            let Some(event) = Self::inner().events.lock().unwrap().pop_front() else {
                break;
            };
            Self::do_send_event(&event);
        }
    }

    #[allow(clippy::unused_io_amount)]
    fn do_send_event(event: &schema::QmpEvent) {
        if Self::is_connected() {
            let mut event_str = serde_json::to_string(&event).unwrap();
            let mut writer_locked = Self::inner().event_writer.write().unwrap();
            let writer = writer_locked.as_mut().unwrap();

            info!("EVENT: --> {:?}", event);
            if let Err(e) = writer.flush() {
                error!("flush err, {:?}", e);
                return;
            }
            event_str.push_str("\r\n");
            if let Err(e) = writer.write(event_str.as_bytes()) {
                error!("write err, {:?}", e);
            }
        }
    }

    fn inner() -> &'static Arc<QmpChannel> {
        // SAFETY: Global variable QMP_CHANNEL is only used in the main thread,
        // so there are no competition or synchronization.
        QMP_CHANNEL.get().expect("Qmp channel not initialized")
    }
}

/// Send device deleted message to qmp client.
pub fn send_device_deleted_msg(id: &str) {
    if QmpChannel::is_connected() {
        let deleted_event = schema::DeviceDeleted {
            device: Some(id.to_string()),
            path: format!("/machine/peripheral/{}", id),
        };
        event!(DeviceDeleted; deleted_event);
    } else {
        warn!("Qmp channel is not connected while sending device deleted message");
    }
}
