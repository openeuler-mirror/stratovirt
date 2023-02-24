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

use serde::Deserialize;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::rc::Rc;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{bail, Result};
use log::{error, info};
use util::leak_bucket::LeakBucket;
use util::loop_context::{
    gen_delete_notifiers, read_fd, EventNotifier, EventNotifierHelper, NotifierCallback,
    NotifierOperation,
};
use vmm_sys_util::epoll::EventSet;

use crate::machine::MachineExternalInterface;
use crate::qmp::{QmpChannel, QmpGreeting, Response};

const MAX_SOCKET_MSG_LENGTH: usize = 8192;
pub(crate) const LEAK_BUCKET_LIMIT: u64 = 100;

/// The wrapper over Unix socket and socket handler.
///
/// # Example
///
/// ```no_run
/// use std::os::unix::net::{UnixListener, UnixStream};
/// use std::os::unix::io::AsRawFd;
/// use std::io::prelude::*;
///
/// use machine_manager::socket::Socket;
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
    pub fn get_listener_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    /// Accept stream and bind to Socket.
    pub fn accept(&self) {
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
    pub fn get_socket_type(&self) -> SocketType {
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
    pub fn drop_stream(&self) {
        *self.stream.write().unwrap() = None;
    }

    /// Confirm whether socket stream bind to `Socket` or not.
    pub fn is_connected(&self) -> bool {
        self.stream.read().unwrap().is_some()
    }

    /// Get socket fd from `Socket`, it a private function.
    pub fn get_stream_fd(&self) -> RawFd {
        if self.is_connected() {
            self.stream.read().unwrap().as_ref().unwrap().as_raw_fd()
        } else {
            panic!("Failed to get socket fd!");
        }
    }

    /// Get a `SocketHandler` from `Socket`.
    pub fn get_socket_handler(&self) -> SocketHandler {
        SocketHandler::new(self.get_stream_fd())
    }

    /// In qmp feature, send empty or greeting response to client.
    ///
    /// # Arguments
    ///
    /// * `is_greeting` - Whether sending greeting response or not.
    pub fn send_response(&self, is_greeting: bool) -> std::io::Result<()> {
        if self.is_connected() {
            let mut handler = self.get_socket_handler();
            let resp = if is_greeting {
                serde_json::to_string(&QmpGreeting::create_greeting(1, 0, 5)).unwrap() + "\r"
            } else {
                serde_json::to_string(&Response::create_empty_response()).unwrap() + "\r"
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
                if let Err(e) = crate::qmp::handle_qmp(
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

/// Type for api socket.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SocketType {
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

/// Wrapper over socket file description read and write message.
///
/// # Examples
///
/// ```no_run
/// use std::os::unix::net::UnixStream;
/// use std::os::unix::io::AsRawFd;
/// use std::io::prelude::*;
///
/// use machine_manager::socket::SocketRWHandler;
///
/// fn main() -> std::io::Result<()> {
///     let mut stream = UnixStream::connect("/path/to/my/socket")?;
///     let mut handler = SocketRWHandler::new(stream.as_raw_fd());
///     stream.write_all(b"hello world")?;
///     let mut buffer = [0_u8; 20];
///     let count = handler.read(&mut buffer)?;
///     println!("{}", String::from_utf8_lossy(&buffer[..count]));
///     Ok(())
/// }
/// ```
#[allow(clippy::upper_case_acronyms)]
pub struct SocketRWHandler {
    /// Socket fd to read and write message
    socket_fd: RawFd,
    /// Buffer to restore byte read and write with fd
    buf: Vec<u8>,
    /// Pos to buffer when read and write with fd
    pos: usize,
    /// Fds when read from fd's scm right
    scm_fd: Vec<RawFd>,
}

impl SocketRWHandler {
    /// Allocates a new `SocketRWHandler` with a socket fd
    ///
    /// # Arguments
    ///
    /// * `r` - The file descriptor for socket.
    pub fn new(r: RawFd) -> Self {
        SocketRWHandler {
            socket_fd: r,
            buf: Vec::new(),
            pos: 0,
            scm_fd: Vec::new(),
        }
    }

    /// Get inner buf as a `String`.
    pub fn get_buf_string(&mut self) -> Result<String> {
        if self.buf.len() > MAX_SOCKET_MSG_LENGTH {
            bail!("The socket message is too long.");
        }

        Ok(String::from_utf8_lossy(&self.buf).trim().to_string())
    }

    /// Get the last file descriptor read from `scm_fd`.
    pub fn getfd(&mut self) -> Option<RawFd> {
        if self.scm_fd.is_empty() {
            None
        } else {
            Some(self.scm_fd[self.scm_fd.len() - 1])
        }
    }

    /// Receive bytes and scm_fd from socket file descriptor.
    ///
    /// # Notes
    ///
    /// Use [recvmsg(2)](https://linux.die.net/man/2/recvmsg) to receive
    /// messages from `socket_fd`. Some fd can be passed over an `UnixSocket`
    /// in a single Control Message.
    /// This function can read both buffer[u8] and fd.
    ///
    /// # Errors
    /// The socket file descriptor is broken.
    fn read_fd(&mut self) -> std::io::Result<()> {
        use libc::{
            c_uint, c_void, cmsghdr, iovec, msghdr, recvmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_SPACE,
            MSG_DONTWAIT, SCM_RIGHTS, SOL_SOCKET,
        };

        loop {
            let tmp_buf = [0_u8; 1];
            let mut iov = iovec {
                iov_base: tmp_buf.as_ptr() as *mut c_void,
                iov_len: 1,
            };

            let mut cmsg_space = {
                let mut space = 0;
                space +=
                    unsafe { CMSG_SPACE(std::mem::size_of::<[RawFd; 2]>() as c_uint) } as usize;
                Some(Vec::<u8>::with_capacity(space))
            };

            let (msg_control, msg_controllen) = cmsg_space
                .as_mut()
                .map(|v| (v.as_mut_ptr(), v.capacity()))
                .unwrap_or((std::ptr::null_mut(), 0));

            // In `musl` toolchain, msghdr has private member `__pad0` and `__pad1`, it can't be
            // initialized in normal way.
            let mut mhdr: msghdr = unsafe { std::mem::zeroed() };
            mhdr.msg_name = std::ptr::null_mut();
            mhdr.msg_namelen = 0;
            mhdr.msg_iov = &mut iov as *mut iovec;
            mhdr.msg_iovlen = 1;
            mhdr.msg_control = msg_control as *mut c_void;
            mhdr.msg_controllen = msg_controllen as _;
            mhdr.msg_flags = 0;

            // MSG_DONTWAIT: Enables nonblocking operation, if the operation would block the call
            // fails with the error EAGAIN or EWOULDBLOCK. When this error occurs, break loop
            let ret = unsafe { recvmsg(self.socket_fd, &mut mhdr, MSG_DONTWAIT) };

            if ret == -1 {
                let sock_err = Error::last_os_error();
                if sock_err.kind() == ErrorKind::WouldBlock {
                    break;
                } else {
                    return Err(sock_err);
                }
            } else if ret == 0 {
                break;
            }

            let cmsg_hdr: Option<&cmsghdr> = unsafe {
                if mhdr.msg_controllen > 0 {
                    cmsg_space
                        .as_mut()
                        .unwrap()
                        .set_len(mhdr.msg_controllen as usize);
                    CMSG_FIRSTHDR(&mhdr as *const msghdr)
                } else {
                    std::ptr::null()
                }
                .as_ref()
            };

            if let Some(scm) = cmsg_hdr {
                if scm.cmsg_level == SOL_SOCKET && scm.cmsg_type == SCM_RIGHTS {
                    let scm_cmsg_header = unsafe {
                        std::slice::from_raw_parts(
                            CMSG_DATA(scm),
                            std::mem::size_of::<[RawFd; 2]>(),
                        )
                    };
                    for fd in scm_cmsg_header.iter() {
                        if *fd != 0 {
                            self.scm_fd.push(i32::from(*fd));
                        }
                    }
                }
            };

            self.buf.push(tmp_buf[0]);
            if let Some(pos) = self.pos.checked_add(1) {
                self.pos = pos;
            } else {
                return Err(ErrorKind::InvalidInput.into());
            }
        }
        Ok(())
    }

    /// Send bytes message with socket file descriptor.
    ///
    /// # Notes
    /// Use [sendmsg(2)](https://linux.die.net/man/2/sendmsg) to send messages
    /// to `socket_fd`.
    /// Message is `self::buf`: Vec<u8> with `self::pos` and length.
    ///
    /// # Arguments
    ///
    /// * `length` - Length of the buf to write.
    ///
    /// # Errors
    /// The socket file descriptor is broken.
    fn write_fd(&mut self, length: usize) -> std::io::Result<()> {
        use libc::{c_void, iovec, msghdr, sendmsg, MSG_NOSIGNAL};

        let mut iov = iovec {
            iov_base: self.buf.as_slice()[(self.pos - length)..(self.pos - 1)].as_ptr()
                as *mut c_void,
            iov_len: length,
        };

        // In `musl` toolchain, msghdr has private member `__pad0` and `__pad1`, it can't be
        // initialized in normal way.
        let mut mhdr: msghdr = unsafe { std::mem::zeroed() };
        mhdr.msg_name = std::ptr::null_mut();
        mhdr.msg_namelen = 0;
        mhdr.msg_iov = &mut iov as *mut iovec;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = std::ptr::null_mut();
        mhdr.msg_controllen = 0;
        mhdr.msg_flags = 0;

        if unsafe { sendmsg(self.socket_fd, &mhdr, MSG_NOSIGNAL) } == -1 {
            Err(Error::new(
                ErrorKind::BrokenPipe,
                "The socket pipe is broken!",
            ))
        } else {
            Ok(())
        }
    }

    /// Reset `SocketRWHandler` buffer and pos.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.scm_fd.clear();
        self.pos = 0;
    }
}

impl Read for SocketRWHandler {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let start = self.pos;
        self.read_fd()?;

        buf[0..self.pos - start].copy_from_slice(&self.buf[start..self.pos]);
        Ok(self.pos - start)
    }
}

impl Write for SocketRWHandler {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend(buf);
        if let Some(pos) = self.pos.checked_add(buf.len()) {
            self.pos = pos;
        } else {
            return Err(ErrorKind::InvalidInput.into());
        }

        self.write_fd(buf.len())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.clear();
        Ok(())
    }
}

/// The handler to handle socket stream and parse socket stream bytes to
/// json-string.
///
/// # Examples
///
/// ```no_run
/// use std::os::unix::net::UnixStream;
/// use std::os::unix::io::AsRawFd;
/// use std::io::prelude::*;
///
/// use machine_manager::socket::SocketHandler;
///
/// fn main() -> std::io::Result<()> {
///     let mut stream = UnixStream::connect("/path/to/my/socket")?;
///     let mut handler = SocketHandler::new(stream.as_raw_fd());
///     handler.send_str(&String::from("hello world"))?;
///     let mut response = String::new();
///     stream.read_to_string(&mut response)?;
///     println!("{}", response);
///     Ok(())
/// }
/// ```
pub struct SocketHandler {
    /// Handler `Read` and `Write` for socket stream
    stream: SocketRWHandler,
    /// Buffer to leave with read result
    buffer: String,
}

impl SocketHandler {
    /// Allocates a new `SocketRWHandler` with `socket_fd`
    ///
    /// # Arguments
    ///
    /// * `r` - The file descriptor for socket.
    pub fn new(r: RawFd) -> Self {
        SocketHandler {
            stream: SocketRWHandler::new(r),
            buffer: String::new(),
        }
    }

    pub fn get_line(&mut self) -> Result<Option<String>> {
        self.buffer.clear();
        self.stream.clear();
        self.stream.read_fd().unwrap();
        self.stream.get_buf_string().map(|buffer| {
            self.buffer = buffer;
            if self.stream.pos == 0 {
                None
            } else {
                Some(self.buffer.clone())
            }
        })
    }

    /// Parse the bytes received by `SocketHandler`.
    ///
    /// # Notes
    /// If the bytes ended with '\n', this function will remove it. And then
    /// parse to Deserialize object.
    pub fn decode_line<'de, D: Deserialize<'de>>(
        &'de mut self,
    ) -> (Result<Option<D>>, Option<RawFd>) {
        self.buffer.clear();
        self.stream.clear();
        self.stream.read_fd().unwrap();
        match self.stream.get_buf_string() {
            Ok(buffer) => {
                self.buffer = buffer;
                if self.stream.pos == 0 {
                    (Ok(None), None)
                } else {
                    (
                        serde_json::from_str(&self.buffer)
                            .map(Some)
                            .map_err(From::from),
                        self.stream.getfd(),
                    )
                }
            }
            Err(e) => (Err(e), None),
        }
    }

    /// Discard message from `socket_fd`.
    pub fn discard(&mut self) -> Result<()> {
        self.stream.read_fd()?;
        self.stream.clear();
        self.buffer.clear();
        Ok(())
    }

    /// Send String to `socket_fd`.
    ///
    /// # Arguments
    ///
    /// * `s` - The `String` send to `socket_fd`.
    ///
    /// # Errors
    /// The socket file descriptor is broken.
    pub fn send_str(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.flush().unwrap();
        match self.stream.write(s.as_bytes()) {
            Ok(_) => {
                let _ = self.stream.write(&[b'\n'])?;
                Ok(())
            }
            Err(_) => Err(Error::new(
                ErrorKind::BrokenPipe,
                "The socket pipe is broken!",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    use serde::{Deserialize, Serialize};

    use super::{Socket, SocketHandler, SocketRWHandler, SocketType};

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

    fn socket_basic_rw(client_fd: RawFd, server_fd: RawFd) -> bool {
        // Create `write_handler` and `read_handler` from `client_fd` and `server_fd`
        let mut write_handler = SocketRWHandler::new(client_fd);
        let mut read_handler = SocketRWHandler::new(server_fd);

        // Send a `buf` from `write_handler` to `read_handler`
        // 1.First write
        let test_buf1: [u8; 11] = [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];

        assert_eq!(write_handler.write(&test_buf1).unwrap(), 11);
        assert_eq!(write_handler.pos, 11);

        let mut rst_buf = [0u8; 20];
        assert_eq!(read_handler.read(&mut rst_buf).unwrap(), 11);
        assert_eq!(rst_buf[..11], test_buf1);
        assert_eq!(read_handler.buf, write_handler.buf);
        assert_eq!(read_handler.buf[..11], test_buf1);
        assert_eq!(write_handler.pos, 11);

        // 2.Second write
        let test_buf2: [u8; 10] = [104, 101, 108, 108, 111, 32, 114, 117, 115, 116];

        assert_eq!(write_handler.write(&test_buf2).unwrap(), 10);
        assert_eq!(write_handler.pos, 21);

        assert_eq!(read_handler.read(&mut rst_buf).unwrap(), 10);
        assert_eq!(rst_buf[..10], test_buf2);
        assert_eq!(read_handler.buf, write_handler.buf);
        assert_eq!(read_handler.buf[11..], test_buf2);
        assert_eq!(write_handler.pos, 21);

        // 3.Use 'flush' and test third time
        let test_buf3: [u8; 6] = [115, 111, 99, 107, 101, 116];
        write_handler.flush().unwrap();
        read_handler.flush().unwrap();
        assert_eq!(write_handler.pos, 0);
        assert_eq!(read_handler.pos, 0);
        assert!(write_handler.buf.is_empty());
        assert!(read_handler.buf.is_empty());

        assert_eq!(write_handler.write(&test_buf3).unwrap(), 6);
        assert_eq!(write_handler.pos, 6);

        assert_eq!(read_handler.read(&mut rst_buf).unwrap(), 6);
        assert_eq!(rst_buf[..6], test_buf3);
        assert_eq!(read_handler.buf, write_handler.buf);
        assert_eq!(read_handler.buf[..6], test_buf3);
        assert_eq!(write_handler.pos, 6);

        true
    }

    #[test]
    fn test_unix_socket_read_and_write() {
        // Pre test. Environment Preparation
        let (_, client, server) = prepare_unix_socket_environment("01");

        // Test fn: socket basic read and write
        assert!(socket_basic_rw(client.as_raw_fd(), server.as_raw_fd()));

        // After test. Environment Recover
        recover_unix_socket_environment("01");
    }

    #[test]
    fn test_socket_handler_sendstr() {
        // Pre test. Environment Preparation
        let (_, mut client, server) = prepare_unix_socket_environment("02");
        let mut handler = SocketHandler::new(server.as_raw_fd());

        // Send a `String` with fn `sendstr` in SocketHandler
        // 1.send str
        handler.send_str("I am a test str").unwrap();
        let mut response = [0u8; 50];
        let length = client.read(&mut response).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response[..length]),
            "I am a test str\n".to_string()
        );

        // 2.send String
        let message = String::from("I am a test String");
        handler.send_str(&message).unwrap();
        let length = client.read(&mut response).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response[..length]),
            "I am a test String\n".to_string()
        );

        // After test. Environment Recover
        recover_unix_socket_environment("02");
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct JsonTestStruct {
        name: String,
        age: u8,
        phones: Vec<String>,
    }

    #[test]
    fn test_socket_handler_json_parser() {
        // Pre test. Environment Preparation
        let (_, mut client, server) = prepare_unix_socket_environment("03");
        let mut handler = SocketHandler::new(server.as_raw_fd());

        // Use fn `decode_line` in `SocketHandler` to receive and parse msg to json struct
        // 1.msg without '\n' or 'EOF'
        let data = r#"
            {
                "name": "Lucky Dog",
                "age": 18,
                "phones": [
                    "+86 01234567890",
                    "+86 09876543210"
                ]
            }
        "#;
        client.write(data.as_bytes()).unwrap();
        let resp_json: JsonTestStruct = match handler.decode_line() {
            (Ok(buffer), _) => buffer.unwrap(),
            _ => panic!("Failed to decode line!"),
        };
        assert_eq!(
            resp_json,
            JsonTestStruct {
                name: "Lucky Dog".to_string(),
                age: 18u8,
                phones: vec!["+86 01234567890".to_string(), "+86 09876543210".to_string()],
            },
        );

        // 2.msg with '\n'
        client.write(data.as_bytes()).unwrap();
        client.write(b"\n").unwrap();
        let resp_json: JsonTestStruct = match handler.decode_line() {
            (Ok(buffer), _) => buffer.unwrap(),
            _ => panic!("Failed to decode line!"),
        };
        assert_eq!(
            resp_json,
            JsonTestStruct {
                name: "Lucky Dog".to_string(),
                age: 18u8,
                phones: vec!["+86 01234567890".to_string(), "+86 09876543210".to_string()],
            },
        );

        // After test. Environment Recover
        recover_unix_socket_environment("03");
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
}
