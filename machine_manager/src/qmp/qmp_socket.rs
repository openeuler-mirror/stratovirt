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

use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use log::{error, info, warn};
use vmm_sys_util::epoll::EventSet;

use super::qmp_schema;
use super::qmp_schema::QmpCommand;
use super::{qmp_channel::QmpChannel, qmp_response::QmpGreeting, qmp_response::Response};
use crate::event;
use crate::event_loop::EventLoop;
use crate::machine::MachineExternalInterface;
use crate::socket::SocketHandler;
use crate::socket::SocketRWHandler;
use crate::temp_cleaner::TempCleaner;
use util::leak_bucket::LeakBucket;
use util::loop_context::{
    gen_delete_notifiers, read_fd, EventNotifier, EventNotifierHelper, NotifierCallback,
    NotifierOperation,
};
use util::set_termi_canon_mode;

const LEAK_BUCKET_LIMIT: u64 = 100;

/// Type for api socket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SocketType {
    Unix = 1,
}

/// Wrapper over UnixSteam.
#[derive(Debug)]
struct SocketStream(UnixStream);

impl SocketStream {
    fn from_unix_stream(stream: UnixStream) -> Self {
        SocketStream(stream)
    }
}

impl AsRawFd for SocketStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

/// The wrapper over Unix socket and socket handler.
///
/// # Example
///
/// ```no_run
/// use std::io::prelude::*;
/// use std::os::unix::io::AsRawFd;
/// use std::os::unix::net::{UnixListener, UnixStream};
///
/// use machine_manager::qmp::qmp_socket::Socket;
///
/// fn main() -> std::io::Result<()> {
///     let listener = UnixListener::bind("/path/to/my/socket")?;
///     let socket = Socket::from_unix_listener(listener, None);
///     assert!(!socket.is_connected());
///
///     let client_stream = UnixStream::connect("/path/to/my/socket")?;
///     let server_stream = socket.accept_unix_stream();
///     socket.bind_unix_stream(server_stream);
///     assert!(socket.is_connected());
///     Ok(())
/// }
/// ```
pub struct Socket {
    /// Type for Socket
    sock_type: SocketType,
    /// Socket listener tuple
    listener: UnixListener,
    /// Socket stream with RwLock
    stream: RwLock<Option<SocketStream>>,
    /// Perform socket command
    performer: Option<Arc<Mutex<dyn MachineExternalInterface>>>,
}

impl Socket {
    /// Allocates a new `Socket` with `UnixListener`.
    ///
    /// # Arguments
    ///
    /// * `listener` - The `UnixListener` bind to `Socket`.
    /// * `performer` - The `VM` to perform socket command.
    pub fn from_unix_listener(
        listener: UnixListener,
        performer: Option<Arc<Mutex<dyn MachineExternalInterface>>>,
    ) -> Self {
        Socket {
            sock_type: SocketType::Unix,
            listener,
            stream: RwLock::new(None),
            performer,
        }
    }

    /// Get listener's fd from `Socket`.
    fn get_listener_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// Accept stream and bind to Socket.
    fn accept(&self) {
        match self.sock_type {
            SocketType::Unix => {
                let stream = self.accept_unix_stream();
                self.bind_unix_stream(stream);
            }
        }
    }

    /// Accept a new incoming connection unix stream from unix listener.
    pub fn accept_unix_stream(&self) -> UnixStream {
        let (stream, _) = self.listener.accept().unwrap();
        stream
    }

    /// Get socket type from `Socket`.
    #[allow(unused)]
    fn get_socket_type(&self) -> SocketType {
        self.sock_type
    }

    /// Bind `Socket` with a `UnixStream`.
    ///
    /// # Arguments
    ///
    /// * `unix_stream` - The `UnixStream` bind to `Socket`.
    pub fn bind_unix_stream(&self, unix_stream: UnixStream) {
        let stream = SocketStream::from_unix_stream(unix_stream);
        *self.stream.write().unwrap() = Some(stream);
    }

    /// Unbind stream from `Socket`, reset the state.
    #[allow(unused)]
    fn drop_stream(&self) {
        *self.stream.write().unwrap() = None;
    }

    /// Confirm whether socket stream bind to `Socket` or not.
    pub fn is_connected(&self) -> bool {
        self.stream.read().unwrap().is_some()
    }

    /// Get socket fd from `Socket`, it a private function.
    fn get_stream_fd(&self) -> RawFd {
        if self.is_connected() {
            self.stream.read().unwrap().as_ref().unwrap().as_raw_fd()
        } else {
            panic!("Failed to get socket fd!");
        }
    }

    /// Get a `SocketHandler` from `Socket`.
    fn get_socket_handler(&self) -> SocketHandler {
        SocketHandler::new(self.get_stream_fd())
    }

    /// In qmp feature, send empty or greeting response to client.
    ///
    /// # Arguments
    ///
    /// * `is_greeting` - Whether sending greeting response or not.
    fn send_response(&self, is_greeting: bool) -> std::io::Result<()> {
        if self.is_connected() {
            let mut handler = self.get_socket_handler();
            let resp = if is_greeting {
                serde_json::to_string(&QmpGreeting::create_greeting(1, 0, 5)).unwrap()
            } else {
                serde_json::to_string(&Response::create_empty_response()).unwrap()
            };
            handler.send_str(&resp)?;
            info!("QMP: --> {:?}", resp);
        }
        Ok(())
    }

    /// Create socket's accepted stream to `event_notifier`.
    fn create_event_notifier(&mut self, shared_socket: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let leak_bucket = LeakBucket::new(LEAK_BUCKET_LIMIT);
        if let Err(e) = leak_bucket {
            error!("Failed to create leak bucket, {:?}", e);
            return notifiers;
        }
        let leak_bucket = Arc::new(Mutex::new(leak_bucket.unwrap()));
        let shared_leak_bucket = leak_bucket.clone();
        let leak_bucket_fd = leak_bucket.lock().unwrap().as_raw_fd();

        self.accept();
        QmpChannel::bind_writer(SocketRWHandler::new(self.get_stream_fd()));
        if let Err(e) = self.send_response(true) {
            error!("{:?}", e);
            QmpChannel::unbind();
            return notifiers;
        }
        let handler: Rc<NotifierCallback> = Rc::new(move |event, _| {
            if event == EventSet::IN {
                let socket_mutexed = shared_socket.lock().unwrap();
                let stream_fd = socket_mutexed.get_stream_fd();

                let performer = &socket_mutexed.performer.as_ref().unwrap();
                if let Err(e) = handle_qmp(
                    stream_fd,
                    performer,
                    &mut shared_leak_bucket.lock().unwrap(),
                ) {
                    error!("{:?}", e);
                }
            }
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                let socket_mutexed = shared_socket.lock().unwrap();
                let stream_fd = socket_mutexed.get_stream_fd();

                QmpChannel::unbind();
                Some(gen_delete_notifiers(&[stream_fd, leak_bucket_fd]))
            } else {
                None
            }
        });
        let qmp_notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            self.get_stream_fd(),
            Some(self.get_listener_fd()),
            EventSet::IN | EventSet::HANG_UP,
            vec![handler],
        );
        notifiers.push(qmp_notifier);

        let leak_bucket_notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            leak_bucket_fd,
            None,
            EventSet::IN,
            vec![Rc::new(move |_, fd| {
                read_fd(fd);
                leak_bucket.lock().unwrap().clear_timer();
                None
            })],
        );
        notifiers.push(leak_bucket_notifier);

        notifiers
    }
}

impl EventNotifierHelper for Socket {
    fn internal_notifiers(shared_socket: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let socket = shared_socket.clone();
        let handler: Rc<NotifierCallback> =
            Rc::new(move |_, _| Some(socket.lock().unwrap().create_event_notifier(socket.clone())));
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            shared_socket.lock().unwrap().get_listener_fd(),
            None,
            EventSet::IN,
            vec![handler],
        );
        notifiers.push(notifier);

        notifiers
    }
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
fn handle_qmp(
    stream_fd: RawFd,
    controller: &Arc<Mutex<dyn MachineExternalInterface>>,
    leak_bucket: &mut LeakBucket,
) -> Result<()> {
    let mut qmp_service = crate::socket::SocketHandler::new(stream_fd);

    // If flow over `LEAK_BUCKET_LIMIT` per seconds, discard the request and return
    // a `OperationThrottled` error.
    if leak_bucket.throttled(EventLoop::get_ctx(None).unwrap(), 1_u64) {
        qmp_service.discard()?;
        let err_resp = qmp_schema::QmpErrorClass::OperationThrottled(LEAK_BUCKET_LIMIT);
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
            let qmp_command: QmpCommand = buffer.unwrap();
            let (return_msg, shutdown_flag) = qmp_command_exec(qmp_command, controller, if_fd);
            info!("QMP: --> {:?}", return_msg);
            qmp_service.send_str(&return_msg)?;

            // handle shutdown command
            if shutdown_flag {
                let shutdown_msg = qmp_schema::Shutdown {
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
            let err_resp = qmp_schema::QmpErrorClass::GenericError(format!("{}", &e));
            warn!("Qmp json parser made an error: {:?}", e);
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
        (system_powerdown, powerdown),
        (system_reset, reset),
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
        (query_mem, query_mem),
        (query_vnc, query_vnc),
        (list_type, list_type),
        (query_hotpluggable_cpus, query_hotpluggable_cpus);
        (input_event, input_event, key, value),
        (device_list_properties, device_list_properties, typename),
        (device_del, device_del, id),
        (blockdev_del, blockdev_del, node_name),
        (netdev_del, netdev_del, id),
        (chardev_remove, chardev_remove, id),
        (cameradev_del, cameradev_del,id),
        (balloon, balloon, value),
        (migrate, migrate, uri);
        (device_add, device_add),
        (blockdev_add, blockdev_add),
        (netdev_add, netdev_add),
        (chardev_add, chardev_add),
        (cameradev_add, cameradev_add),
        (update_region, update_region),
        (human_monitor_command, human_monitor_command),
        (blockdev_snapshot_internal_sync, blockdev_snapshot_internal_sync),
        (blockdev_snapshot_delete_internal_sync, blockdev_snapshot_delete_internal_sync)
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
    (serde_json::to_string(&qmp_response).unwrap(), shutdown_flag)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use super::*;
    use serde_json;

    // Environment Preparation for UnixSocket
    fn prepare_unix_socket_environment(socket_id: &str) -> (UnixListener, UnixStream, UnixStream) {
        let socket_name: String = format!("test_{}.sock", socket_id);
        let _ = std::fs::remove_file(&socket_name);

        let listener = UnixListener::bind(&socket_name).unwrap();
        std::thread::sleep(Duration::from_millis(100));
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
    fn test_socket_lifecycle() {
        // Pre test. Environment Preparation
        let (listener, _, server) = prepare_unix_socket_environment("04");
        let socket = Socket::from_unix_listener(listener, None);

        // life cycle test
        // 1.Unconnected
        assert_eq!(socket.is_connected(), false);

        // 2.Connected
        socket.bind_unix_stream(server);
        assert_eq!(socket.is_connected(), true);
        assert_eq!(socket.get_socket_type(), SocketType::Unix);

        // 3.Unbind SocketStream, reset state
        socket.drop_stream();
        assert_eq!(socket.is_connected(), false);

        // 4.Accept and reconnect a new UnixStream
        let _new_client = UnixStream::connect("test_04.sock");
        let new_server = socket.accept_unix_stream();
        socket.bind_unix_stream(new_server);
        assert_eq!(socket.is_connected(), true);

        // After test. Environment Recover
        recover_unix_socket_environment("04");
    }

    #[test]
    fn test_qmp_event_macro() {
        use std::io::Read;

        use crate::socket::SocketRWHandler;

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
        let qmp_event: qmp_schema::QmpEvent =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        match qmp_event {
            qmp_schema::QmpEvent::Stop {
                data: _,
                timestamp: _,
            } => {
                assert!(true);
            }
            _ => assert!(false),
        }

        // 2.send with-content event
        let shutdown_event = qmp_schema::Shutdown {
            guest: true,
            reason: "guest-shutdown".to_string(),
        };
        event!(Shutdown; shutdown_event);
        let length = client.read(&mut buffer).unwrap();
        let qmp_event: qmp_schema::QmpEvent =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        match qmp_event {
            qmp_schema::QmpEvent::Shutdown { data, timestamp: _ } => {
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
        use std::io::Read;

        // Pre test. Environment preparation
        let mut buffer = [0u8; 300];
        let (listener, mut client, server) = prepare_unix_socket_environment("07");

        // Use event! macro to send event msg to client
        let socket = Socket::from_unix_listener(listener, None);
        socket.bind_unix_stream(server);

        // 1.send greeting response
        let res = socket.send_response(true);
        let length = client.read(&mut buffer).unwrap();
        let qmp_response: QmpGreeting =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        let qmp_greeting = QmpGreeting::create_greeting(1, 0, 5);
        assert_eq!(qmp_greeting, qmp_response);
        assert_eq!(res.is_err(), false);

        // 2.send empty response
        let res = socket.send_response(false);
        let length = client.read(&mut buffer).unwrap();
        let qmp_response: Response =
            serde_json::from_str(&(String::from_utf8_lossy(&buffer[..length]))).unwrap();
        let qmp_empty_response = Response::create_empty_response();
        assert_eq!(qmp_empty_response, qmp_response);
        assert_eq!(res.is_err(), false);

        // After test. Environment Recover
        recover_unix_socket_environment("07");
        drop(socket);
    }
}
