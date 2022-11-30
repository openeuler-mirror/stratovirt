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

//! This module implements a simple way to realize QMP.
//!
//! # Qmp Introduction
//!
//! [Qmp](https://wiki.qemu.org/Documentation/QMP) is a Json-based protocol
//! which allows applications to control a VM instance.
//! It has three feature:
//! 1. Qmp server is no-async service as well as Qemu's.
//! Command + events can replace asynchronous command.
//! 2. Qmp server can only be connected a client at one time.
//! It's no situation where be communicated with many clients.
//! When it must use, can use other communication way not QMP.
//! 3. Qmp's message structure base is transformed by scripts from Qemu's
//! `qmp-schema.json`. It's can be compatible by Qemu's zoology. Those
//! transformed structures can be found in `machine_manager/src/qmp/qmp_schema.rs`

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod qmp_schema;

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{info, warn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use util::leak_bucket::LeakBucket;
use util::set_termi_canon_mode;
use util::time::NANOSECONDS_PER_SECOND;

use self::qmp_schema::{self as schema, QmpCommand};
use crate::event_loop::EventLoop;
use crate::machine::MachineExternalInterface;
use crate::socket::SocketRWHandler;
use crate::temp_cleaner::TempCleaner;
use anyhow::{Context, Result};

static mut QMP_CHANNEL: Option<Arc<QmpChannel>> = None;

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
        QmpChannel::send_event(&$crate::qmp::qmp_schema::QmpEvent::$x {
            data: Default::default(),
            timestamp: $crate::qmp::create_timestamp(),
        });
    }};
    ( $x:tt;$y:expr ) => {{
        QmpChannel::send_event(&$crate::qmp::qmp_schema::QmpEvent::$x {
            data: $y,
            timestamp: $crate::qmp::create_timestamp(),
        });
    }};
}

/// Macro `create_command_matches!`: Generate a match statement for qmp_command
/// , which is combined with its handle func.
///
/// # Arguments
///
/// `cmd_type_1` - The qmp command with no arguments.
/// `cmd_type_2` - The qmp command with arguments.
macro_rules! create_command_matches {
    ( $command:expr; $executor:expr; $ret:expr;
      $(($cmd_type_1:tt, $func_1:tt)),*;
      $(($cmd_type_2:tt, $func_2:tt, $($arg:tt),*)),*;
      $(($cmd_type_3:tt, $func_3:tt)),*
    ) => {
        match $command {
            $(
                $crate::qmp::qmp_schema::QmpCommand::$cmd_type_1{ id, ..} => {
                    qmp_command_match!($func_1, $executor, $ret);
                    id
                },
            )*
            $(
                $crate::qmp::qmp_schema::QmpCommand::$cmd_type_2{ arguments, id } => {
                    qmp_command_match!($func_2, $executor, arguments, $ret, $($arg),*);
                    id
                },
            )*
            $(
                $crate::qmp::qmp_schema::QmpCommand::$cmd_type_3{ arguments, id } => {
                    qmp_command_match_with_argument!($func_3, $executor, arguments, $ret);
                    id
                },
            )*
            _ => None,
        }
    };
}

/// Macro: to execute handle func with every arguments.
macro_rules! qmp_command_match {
    ( $func:tt, $executor:expr, $ret:expr ) => {
        $ret = $executor.$func().into();
    };
    ( $func:tt, $executor:expr, $cmd:expr, $ret:expr, $($arg:tt),* ) => {
        $ret = $executor.$func(
            $($cmd.$arg),*
        ).into();
    };
}

/// Macro: to execute handle func with all arguments.
macro_rules! qmp_command_match_with_argument {
    ( $func:tt, $executor:expr, $cmd:expr, $ret:expr ) => {
        $ret = $executor.$func($cmd).into();
    };
}

/// Qmp greeting message.
///
/// # Notes
///
/// It contains the version of VM or fake Qemu version to adapt others.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct QmpGreeting {
    #[serde(rename = "QMP")]
    qmp: Greeting,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
struct Greeting {
    version: Version,
    capabilities: Vec<String>,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Version {
    #[serde(rename = "qemu")]
    application: VersionNumber,
    package: String,
}

impl Version {
    pub fn new(micro: u8, minor: u8, major: u8) -> Self {
        let version_number = VersionNumber {
            micro,
            minor,
            major,
        };
        Version {
            application: version_number,
            package: "StratoVirt-".to_string() + env!("CARGO_PKG_VERSION"),
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
struct VersionNumber {
    micro: u8,
    minor: u8,
    major: u8,
}

impl QmpGreeting {
    /// Create qmp greeting message.
    ///
    /// # Arguments
    ///
    /// * `micro` - Micro version number.
    /// * `minor` - Minor version number.
    /// * `major` - Major version number.
    pub fn create_greeting(micro: u8, minor: u8, major: u8) -> Self {
        let version_number = VersionNumber {
            micro,
            minor,
            major,
        };
        let cap: Vec<String> = Default::default();
        let version = Version {
            application: version_number,
            package: "".to_string(),
        };
        let greeting = Greeting {
            version,
            capabilities: cap,
        };
        QmpGreeting { qmp: greeting }
    }
}

/// Qmp response to client
///
/// # Notes
///
/// It contains two kind response: `BadResponse` and `GoodResponse`. This two
/// kind response are fit by executing qmp command by success and failure.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Response {
    #[serde(rename = "return", default, skip_serializing_if = "Option::is_none")]
    return_: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<ErrorMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

impl Response {
    /// Create qmp response with inner `Value` and `id`.
    ///
    /// # Arguments
    ///
    /// * `v` - The `Value` of qmp `return` field.
    /// * `id` - The `id` for qmp `Response`, it must be equal to `Request`'s
    ///          `id`.
    pub fn create_response(v: Value, id: Option<String>) -> Self {
        Response {
            return_: Some(v),
            error: None,
            id,
        }
    }

    /// Create a empty qmp response, `return` field will be empty.
    pub fn create_empty_response() -> Self {
        Response {
            return_: Some(serde_json::to_value(Empty {}).unwrap()),
            error: None,
            id: None,
        }
    }

    /// Create a error qmo response with `err_class` and `id`.
    /// # Arguments
    ///
    /// * `err_class` - The `QmpErrorClass` of qmp `error` field.
    /// * `id` - The `id` for qmp `Response`, it must be equal to `Request`'s
    ///          `id`.
    pub fn create_error_response(err_class: schema::QmpErrorClass, id: Option<String>) -> Self {
        Response {
            return_: None,
            error: Some(ErrorMessage::new(&err_class)),
            id,
        }
    }

    fn change_id(&mut self, id: Option<String>) {
        self.id = id;
    }
}

impl From<bool> for Response {
    fn from(value: bool) -> Self {
        if value {
            Response::create_empty_response()
        } else {
            Response::create_error_response(
                schema::QmpErrorClass::GenericError(String::new()),
                None,
            )
        }
    }
}

/// `ErrorMessage` for Qmp Response.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct ErrorMessage {
    #[serde(rename = "class")]
    errorkind: String,
    desc: String,
}

impl ErrorMessage {
    fn new(e: &schema::QmpErrorClass) -> Self {
        let content = e.to_content();
        let serde_str = serde_json::to_string(&e).unwrap();
        let serde_vec: Vec<&str> = serde_str.split(':').collect();
        let class_name = serde_vec[0];
        let len: usize = class_name.len();
        ErrorMessage {
            errorkind: class_name[2..len - 1].to_string(),
            desc: content,
        }
    }
}

/// Empty message for QMP.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Empty {}

/// Command trait for Deserialize and find back Response.
pub trait Command: Serialize {
    type Res: DeserializeOwned;
    fn back(self) -> Self::Res;
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
        (since_the_epoch.as_nanos() - seconds * (NANOSECONDS_PER_SECOND as u128)) / (1_000_u128);
    TimeStamp {
        seconds: seconds as u64,
        microseconds: microseconds as u64,
    }
}

/// Accept qmp command, analyze and exec it.
///
/// # Arguments
///
/// * `stream_fd` - The input stream file description.
/// * `controller` - The controller which execute actual qmp command.
/// * `leak_bucket` - The LeakBucket flow controller for qmp command.
///
/// # Errors
///
/// This function will fail when json parser failed or socket file description broke.
pub fn handle_qmp(
    stream_fd: RawFd,
    controller: &Arc<Mutex<dyn MachineExternalInterface>>,
    leak_bucket: &mut LeakBucket,
) -> Result<()> {
    let mut qmp_service = crate::socket::SocketHandler::new(stream_fd);

    // If flow over `LEAK_BUCKET_LIMIT` per seconds, discard the request and return
    // a `OperationThrottled` error.
    if leak_bucket.throttled(EventLoop::get_ctx(None).unwrap(), 1_u64) {
        qmp_service.discard()?;
        let err_resp = schema::QmpErrorClass::OperationThrottled(crate::socket::LEAK_BUCKET_LIMIT);
        qmp_service
            .send_str(&serde_json::to_string(&Response::create_error_response(
                err_resp, None,
            ))?)
            .with_context(|| "Failed to send message to qmp client.")?;
        return Ok(());
    }

    match qmp_service.decode_line() {
        (Ok(None), _) => Ok(()),
        (Ok(buffer), if_fd) => {
            info!("QMP: <-- {:?}", buffer);
            let qmp_command: schema::QmpCommand = buffer.unwrap();
            let (return_msg, shutdown_flag) = qmp_command_exec(qmp_command, controller, if_fd);
            info!("QMP: --> {:?}", return_msg);
            qmp_service.send_str(&return_msg)?;

            // handle shutdown command
            if shutdown_flag {
                let shutdown_msg = schema::Shutdown {
                    guest: false,
                    reason: "host-qmp-quit".to_string(),
                };
                event!(Shutdown; shutdown_msg);
                TempCleaner::clean();
                set_termi_canon_mode().expect("Failed to set terminal to canonical mode.");

                std::process::exit(0);
            }

            Ok(())
        }
        (Err(e), _) => {
            let err_resp = schema::QmpErrorClass::GenericError(format!("{}", &e));
            warn!("Qmp json parser made an error:{}", e);
            qmp_service.send_str(&serde_json::to_string(&Response::create_error_response(
                err_resp, None,
            ))?)?;
            Ok(())
        }
    }
}

/// Create a match , where `qmp_command` and its arguments matching by handle
/// function, and exec this qmp command.
fn qmp_command_exec(
    qmp_command: QmpCommand,
    controller: &Arc<Mutex<dyn MachineExternalInterface>>,
    if_fd: Option<RawFd>,
) -> (String, bool) {
    let mut qmp_response = Response::create_empty_response();
    let mut shutdown_flag = false;

    // Use macro create match to cover most Qmp command
    let mut id = create_command_matches!(
        qmp_command.clone(); controller.lock().unwrap(); qmp_response;
        (stop, pause),
        (cont, resume),
        (query_status, query_status),
        (query_version, query_version),
        (query_commands, query_commands),
        (query_target, query_target),
        (query_kvm, query_kvm),
        (query_events, query_events),
        (query_machines, query_machines),
        (query_tpm_models, query_tpm_models),
        (query_tpm_types, query_tpm_types),
        (query_command_line_options, query_command_line_options),
        (query_migrate_capabilities, query_migrate_capabilities),
        (query_qmp_schema, query_qmp_schema),
        (query_sev_capabilities, query_sev_capabilities),
        (query_chardev, query_chardev),
        (qom_list, qom_list),
        (qom_get, qom_get),
        (query_block, query_block),
        (query_named_block_nodes, query_named_block_nodes),
        (query_blockstats, query_blockstats),
        (query_block_jobs, query_block_jobs),
        (query_gic_capabilities, query_gic_capabilities),
        (query_iothreads, query_iothreads),
        (query_migrate, query_migrate),
        (cancel_migrate, cancel_migrate),
        (query_cpus, query_cpus),
        (query_balloon, query_balloon),
        (list_type, list_type),
        (query_hotpluggable_cpus, query_hotpluggable_cpus);
        (device_list_properties, device_list_properties, typename),
        (device_del, device_del, id),
        (blockdev_del, blockdev_del, node_name),
        (netdev_del, netdev_del, id),
        (chardev_remove, chardev_remove, id),
        (balloon, balloon, value),
        (migrate, migrate, uri);
        (device_add, device_add),
        (blockdev_add, blockdev_add),
        (netdev_add, netdev_add),
        (chardev_add, chardev_add)
    );

    // Handle the Qmp command which macro can't cover
    if id.is_none() {
        id = match qmp_command {
            QmpCommand::quit { id, .. } => {
                controller.lock().unwrap().destroy();
                shutdown_flag = true;
                id
            }
            QmpCommand::getfd { arguments, id } => {
                qmp_response = controller.lock().unwrap().getfd(arguments.fd_name, if_fd);
                id
            }
            _ => None,
        }
    }

    // Change response id with input qmp message
    qmp_response.change_id(id);
    (
        serde_json::to_string(&qmp_response).unwrap() + "\r",
        shutdown_flag,
    )
}

/// The struct `QmpChannel` is the only struct can handle Global variable
/// `QMP_CHANNEL`.
/// It is used to send event to qmp client and restore some file descriptor
/// which was sended by client.
pub struct QmpChannel {
    /// The `writer` to send `QmpEvent`.
    event_writer: RwLock<Option<SocketRWHandler>>,
    /// Restore file descriptor received from client.
    fds: Arc<RwLock<BTreeMap<String, RawFd>>>,
}

impl QmpChannel {
    /// Constructs a `QmpChannel` in global `QMP_CHANNEL`.
    pub fn object_init() {
        unsafe {
            if QMP_CHANNEL.is_none() {
                QMP_CHANNEL = Some(Arc::new(QmpChannel {
                    event_writer: RwLock::new(None),
                    fds: Arc::new(RwLock::new(BTreeMap::new())),
                }));
            }
        }
    }

    /// Bind a `SocketRWHandler` to `QMP_CHANNEL`.
    ///
    /// # Arguments
    ///
    /// * `writer` - The `SocketRWHandler` used to communicate with client.
    pub fn bind_writer(writer: SocketRWHandler) {
        *Self::inner().event_writer.write().unwrap() = Some(writer);
    }

    /// Unbind `SocketRWHandler` from `QMP_CHANNEL`.
    pub fn unbind() {
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

    /// Send a `QmpEvent` to client.
    ///
    /// # Arguments
    ///
    /// * `event` - The `QmpEvent` sent to client.
    #[allow(clippy::unused_io_amount)]
    pub fn send_event(event: &schema::QmpEvent) {
        if Self::is_connected() {
            let event_str = serde_json::to_string(&event).unwrap();
            let mut writer_unlocked = Self::inner().event_writer.write().unwrap();
            let writer = writer_unlocked.as_mut().unwrap();
            writer.flush().unwrap();
            writer.write(event_str.as_bytes()).unwrap();
            writer.write(&[b'\r']).unwrap();
            writer.write(&[b'\n']).unwrap();
            info!("EVENT: --> {:?}", event);
        }
    }

    fn inner() -> &'static std::sync::Arc<QmpChannel> {
        unsafe {
            match &QMP_CHANNEL {
                Some(channel) => channel,
                None => {
                    panic!("Qmp channel not initialized");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn test_qmp_greeting_msg() {
        let greeting_msg = QmpGreeting::create_greeting(1, 0, 5);

        let json_msg = r#"
            {
                "QMP":{
                    "version":{
                        "qemu":{
                            "micro": 1,
                            "minor": 0,
                            "major": 5
                        },
                        "package": ""
                    },
                    "capabilities": []
                }
            }
        "#;
        let greeting_from_json: QmpGreeting = serde_json::from_str(json_msg).unwrap();

        assert_eq!(greeting_from_json, greeting_msg);
    }

    #[test]
    fn test_qmp_resp() {
        // 1.Empty response and ID change;
        let mut resp = Response::create_empty_response();
        resp.change_id(Some("0".to_string()));

        let json_msg = r#"{"return":{},"id":"0"}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        resp.change_id(Some("1".to_string()));
        let json_msg = r#"{"return":{},"id":"1"}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        // 2.Normal response
        let resp_value = schema::StatusInfo {
            singlestep: false,
            running: true,
            status: schema::RunState::running,
        };
        let resp = Response::create_response(serde_json::to_value(&resp_value).unwrap(), None);

        let json_msg = r#"{"return":{"running":true,"singlestep":false,"status":"running"}}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);

        // 3.Error response
        let qmp_err =
            schema::QmpErrorClass::GenericError("Invalid Qmp command arguments!".to_string());
        let resp = Response::create_error_response(qmp_err, None);

        let json_msg =
            r#"{"error":{"class":"GenericError","desc":"Invalid Qmp command arguments!"}}"#;
        assert_eq!(serde_json::to_string(&resp).unwrap(), json_msg);
    }

    #[test]
    fn test_qmp_event_msg() {
        let event_json =
            r#"{"event":"STOP","data":{},"timestamp":{"seconds":1575531524,"microseconds":91519}}"#;
        let qmp_event: schema::QmpEvent = serde_json::from_str(&event_json).unwrap();
        match qmp_event {
            schema::QmpEvent::Stop {
                data: _,
                timestamp: _,
            } => {
                assert!(true);
            }
            _ => assert!(false),
        }
    }

    // Environment Preparation for UnixSocket
    fn prepare_unix_socket_environment(socket_id: &str) -> (UnixListener, UnixStream, UnixStream) {
        let socket_name: String = format!("test_{}.sock", socket_id);
        let _ = std::fs::remove_file(&socket_name);

        let listener = UnixListener::bind(&socket_name).unwrap();
        let client = UnixStream::connect(&socket_name).unwrap();
        let (server, _) = listener.accept().unwrap();
        (listener, client, server)
    }

    // Environment Recovery for UnixSocket
    fn recover_unix_socket_environment(socket_id: &str) {
        let socket_name: String = format!("test_{}.sock", socket_id);
        std::fs::remove_file(&socket_name).unwrap();
    }

    #[test]
    fn test_qmp_event_macro() {
        use crate::socket::{Socket, SocketRWHandler};
        use std::io::Read;

        // Pre test. Environment preparation
        QmpChannel::object_init();
        let mut buffer = [0u8; 200];
        let (listener, mut client, server) = prepare_unix_socket_environment("06");

        // Use event! macro to send event msg to client
        let socket = Socket::from_unix_listener(listener, None);
        socket.bind_unix_stream(server);
        QmpChannel::bind_writer(SocketRWHandler::new(socket.get_stream_fd()));

        // 1.send no-content event
        event!(Stop);
        let length = client.read(&mut buffer).unwrap();
        let qmp_event: schema::QmpEvent =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        match qmp_event {
            schema::QmpEvent::Stop {
                data: _,
                timestamp: _,
            } => {
                assert!(true);
            }
            _ => assert!(false),
        }

        // 2.send with-content event
        let shutdown_event = schema::Shutdown {
            guest: true,
            reason: "guest-shutdown".to_string(),
        };
        event!(Shutdown; shutdown_event);
        let length = client.read(&mut buffer).unwrap();
        let qmp_event: schema::QmpEvent =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        match qmp_event {
            schema::QmpEvent::Shutdown { data, timestamp: _ } => {
                assert_eq!(data.guest, true);
                assert_eq!(data.reason, "guest-shutdown".to_string());
            }
            _ => assert!(false),
        }

        // After test. Environment Recover
        recover_unix_socket_environment("06");
    }

    #[test]
    fn test_qmp_send_response() {
        use crate::socket::Socket;
        use std::io::Read;

        // Pre test. Environment preparation
        let mut buffer = [0u8; 300];
        let (listener, mut client, server) = prepare_unix_socket_environment("07");

        // Use event! macro to send event msg to client
        let socket = Socket::from_unix_listener(listener, None);
        socket.bind_unix_stream(server);

        // 1.send greeting response
        socket.send_response(true);
        let length = client.read(&mut buffer).unwrap();
        let qmp_response: QmpGreeting =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        let qmp_greeting = QmpGreeting::create_greeting(1, 0, 5);
        assert_eq!(qmp_greeting, qmp_response);

        // 2.send empty response
        socket.send_response(false);
        let length = client.read(&mut buffer).unwrap();
        let qmp_response: Response =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        let qmp_empty_response = Response::create_empty_response();
        assert_eq!(qmp_empty_response, qmp_response);

        // After test. Environment Recover
        recover_unix_socket_environment("07");
        drop(socket);
    }

    #[test]
    fn test_create_error_response() {
        let strange_msg = "!?/.,、。’】=  -~1！@#￥%……&*（）——+".to_string();

        let err_cls = schema::QmpErrorClass::GenericError(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "GenericError".to_string());
        let qmp_err = schema::QmpErrorClass::GenericError(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = schema::QmpErrorClass::CommandNotFound(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "CommandNotFound".to_string());
        let qmp_err = schema::QmpErrorClass::CommandNotFound(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = schema::QmpErrorClass::DeviceNotFound(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "DeviceNotFound".to_string());
        let qmp_err = schema::QmpErrorClass::DeviceNotFound(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));

        let err_cls = schema::QmpErrorClass::KVMMissingCap(strange_msg.clone());
        let msg = ErrorMessage::new(&err_cls);
        assert_eq!(msg.desc, strange_msg);
        assert_eq!(msg.errorkind, "KVMMissingCap".to_string());
        let qmp_err = schema::QmpErrorClass::KVMMissingCap(strange_msg.clone());
        let resp = Response::create_error_response(qmp_err, None);
        assert_eq!(resp.error, Some(msg));
    }
}
