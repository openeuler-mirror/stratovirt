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

use std::io::{Error, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::io::RawFd;

use anyhow::{bail, Result};
use libc::{
    c_void, iovec, msghdr, poll, pollfd, recvmsg, sendmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN,
    CMSG_NXTHDR, MSG_DONTWAIT, MSG_NOSIGNAL, POLLERR, POLLHUP, POLLNVAL, POLLOUT, SCM_RIGHTS,
    SOL_SOCKET,
};
use serde::Deserialize;

const MAX_SOCKET_MSG_LENGTH: usize = 8192;
/// The max buffer length received by recvmsg.
const MAX_RECV_BUF_LEN: usize = 4096;
/// The max buffer length used by recvmsg for file descriptors.
const MAX_RECV_FDS_LEN: usize = MAX_RECV_BUF_LEN;

/// Wrapper over socket file description read and write message.
///
/// # Examples
///
/// ```no_run
/// use std::io::prelude::*;
/// use std::os::unix::io::AsRawFd;
/// use std::os::unix::net::UnixStream;
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

    fn parse_fd(&mut self, mhdr: &msghdr) {
        // At least it should has one RawFd.
        // SAFETY: The input parameter is valid.
        let min_cmsg_len = unsafe { u64::from(CMSG_LEN(size_of::<RawFd>() as u32)) };
        if (mhdr.msg_controllen as u64) < min_cmsg_len {
            return;
        }

        // SAFETY: The pointer of mhdr can be guaranteed not null.
        let mut cmsg_hdr = unsafe { CMSG_FIRSTHDR(mhdr as *const msghdr).as_ref() };
        while cmsg_hdr.is_some() {
            let scm = cmsg_hdr.unwrap();
            if scm.cmsg_level == SOL_SOCKET
                && scm.cmsg_type == SCM_RIGHTS
                && scm.cmsg_len as u64 >= min_cmsg_len
            {
                // SAFETY: The pointer of scm can be guaranteed not null.
                let fds = unsafe {
                    let fd_num = (scm.cmsg_len as u64 - u64::from(CMSG_LEN(0))) as usize
                        / size_of::<RawFd>();
                    std::slice::from_raw_parts(CMSG_DATA(scm) as *const RawFd, fd_num)
                };
                self.scm_fd.append(&mut fds.to_vec());
            }
            // SAFETY: The pointer of mhdr can be guaranteed not null.
            cmsg_hdr = unsafe { CMSG_NXTHDR(mhdr as *const msghdr, scm).as_ref() };
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
        let recv_buf = [0_u8; MAX_RECV_BUF_LEN];
        let mut iov = iovec {
            iov_base: recv_buf.as_ptr() as *mut c_void,
            iov_len: MAX_RECV_BUF_LEN,
        };
        let mut cmsg_space = [0_u8; MAX_RECV_FDS_LEN];
        loop {
            // SAFETY: Zero is valid for it's member.
            let mut mhdr: msghdr = unsafe { std::mem::zeroed() };
            mhdr.msg_name = std::ptr::null_mut();
            mhdr.msg_namelen = 0;
            mhdr.msg_iov = &mut iov as *mut iovec;
            mhdr.msg_iovlen = 1;
            mhdr.msg_control = cmsg_space.as_mut_ptr() as *mut c_void;
            mhdr.msg_controllen = cmsg_space.len() as _;
            mhdr.msg_flags = 0;

            // MSG_DONTWAIT: Enables nonblocking operation, if the operation would block the call
            // fails with the error EAGAIN or EWOULDBLOCK. When this error occurs, break loop
            // SAFETY: The pointer of mhdr can been guaranteed not null.
            let ret = unsafe { recvmsg(self.socket_fd, &mut mhdr, MSG_DONTWAIT) };
            // when use tcpsocket client and exit with ctrl+c, ret value will return 0 and get
            // error WouldBlock or BrokenPipe, so we should handle this 0 to break this loop.
            if ret == -1 || ret == 0 {
                let sock_err = Error::last_os_error();
                if sock_err.kind() == ErrorKind::WouldBlock
                    || sock_err.kind() == ErrorKind::BrokenPipe
                {
                    break;
                } else {
                    return Err(sock_err);
                }
            }
            self.parse_fd(&mhdr);
            if ret > 0 {
                self.buf.extend(&recv_buf[..ret as usize]);
                if let Some(pos) = self.pos.checked_add(ret as usize) {
                    self.pos = pos;
                } else {
                    return Err(ErrorKind::InvalidInput.into());
                }
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
    /// If the socket would block, this call waits for `POLLOUT` without a timeout.
    ///
    /// # Arguments
    ///
    /// * `length` - Length of the buf to write.
    ///
    /// # Errors
    /// Returns the underlying I/O error if no data can be sent.
    fn write_fd(&mut self, length: usize) -> std::io::Result<usize> {
        if length == 0 {
            return Ok(0);
        }

        let start = self
            .pos
            .checked_sub(length)
            .ok_or(ErrorKind::InvalidInput)?;
        if self.pos > self.buf.len() {
            return Err(ErrorKind::InvalidInput.into());
        }

        let remaining = &self.buf[start..self.pos];
        let mut iov = iovec {
            iov_base: remaining.as_ptr() as *mut c_void,
            iov_len: remaining.len(),
        };

        loop {
            // In `musl` toolchain, msghdr has private member `__pad0` and `__pad1`, it can't be
            // initialized in normal way.
            // SAFETY: The member variables of mhdr have been initialization later.
            let mut mhdr: msghdr = unsafe { std::mem::zeroed() };
            mhdr.msg_name = std::ptr::null_mut();
            mhdr.msg_namelen = 0;
            mhdr.msg_iov = &mut iov as *mut iovec;
            mhdr.msg_iovlen = 1;
            mhdr.msg_control = std::ptr::null_mut();
            mhdr.msg_controllen = 0;
            mhdr.msg_flags = 0;

            // SAFETY: The buffer address and length recorded in mhdr are both legal.
            let ret = unsafe { sendmsg(self.socket_fd, &mhdr, MSG_NOSIGNAL) };
            if ret > 0 {
                let sent = ret as usize;
                if sent > remaining.len() {
                    return Err(ErrorKind::InvalidData.into());
                }
                return Ok(sent);
            }
            if ret == 0 {
                return Err(ErrorKind::WriteZero.into());
            }

            let error = Error::last_os_error();
            match error.kind() {
                ErrorKind::Interrupted => continue,
                ErrorKind::WouldBlock => {
                    self.wait_until_writable()?;
                }
                _ => return Err(error),
            }
        }
    }

    /// Wait until the socket can accept more data.
    fn wait_until_writable(&self) -> std::io::Result<()> {
        let mut poll_fd = pollfd {
            fd: self.socket_fd,
            events: POLLOUT,
            revents: 0,
        };

        loop {
            poll_fd.revents = 0;
            // SAFETY: poll_fd points to one initialized pollfd for the duration of the call.
            let ret = unsafe { poll(&mut poll_fd, 1, -1) };
            if ret > 0 {
                if poll_fd.revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL) != 0 {
                    // Retry sendmsg so that socket errors are returned with their original errno.
                    return Ok(());
                }
                continue;
            }
            if ret == 0 {
                continue;
            }

            let error = Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
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
        let start = self.pos;
        let end = start
            .checked_add(buf.len())
            .ok_or(ErrorKind::InvalidInput)?;

        self.buf.extend(buf);
        self.pos = end;

        match self.write_fd(buf.len()) {
            Ok(written) => {
                if written < buf.len() {
                    self.pos = start + written;
                    self.buf.truncate(self.pos);
                }
                Ok(written)
            }
            Err(error) => {
                self.pos = start;
                self.buf.truncate(start);
                Err(error)
            }
        }
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
/// use std::io::prelude::*;
/// use std::os::unix::io::AsRawFd;
/// use std::os::unix::net::UnixStream;
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
    /// Returns the underlying I/O error when the response cannot be sent.
    pub fn send_str(&mut self, s: &str) -> std::io::Result<()> {
        self.stream.flush().unwrap();
        let msg = s.to_string() + "\r\n";
        self.stream.write_all(msg.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    use libc::{c_void, poll, pollfd, setsockopt, socklen_t, POLLOUT, SOL_SOCKET, SO_SNDBUF};
    use serde::{Deserialize, Serialize};

    use crate::socket::{SocketHandler, SocketRWHandler};

    fn set_send_buffer_size(stream: &UnixStream, size: libc::c_int) {
        // SAFETY: The value pointer refers to an initialized c_int and its length is correct.
        let ret = unsafe {
            setsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_SNDBUF,
                &size as *const libc::c_int as *const c_void,
                std::mem::size_of_val(&size) as socklen_t,
            )
        };
        assert_eq!(ret, 0, "failed to set send buffer size");
    }

    fn wait_until_send_buffer_is_full(stream: &UnixStream) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut poll_fd = pollfd {
            fd: stream.as_raw_fd(),
            events: POLLOUT,
            revents: 0,
        };

        loop {
            poll_fd.revents = 0;
            // SAFETY: poll_fd points to one initialized pollfd for the duration of the call.
            let ret = unsafe { poll(&mut poll_fd, 1, 10) };
            assert!(ret >= 0, "failed to inspect socket writability");
            if ret == 0 || poll_fd.revents & POLLOUT == 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "socket send buffer did not become full"
            );
            std::thread::yield_now();
        }
    }

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
        std::fs::remove_file(socket_name).unwrap();
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
            "I am a test str\r\n".to_string()
        );

        // 2.send String
        let message = String::from("I am a test String");
        handler.send_str(&message).unwrap();
        let length = client.read(&mut response).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response[..length]),
            "I am a test String\r\n".to_string()
        );

        // After test. Environment Recover
        recover_unix_socket_environment("02");
    }

    #[test]
    fn test_socket_handler_sends_full_response_after_partial_write() {
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        set_send_buffer_size(&sender, 4096);
        let sender_probe = sender.try_clone().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let response = format!(
            r#"{{"return":"{}","id":"large-response"}}"#,
            "x".repeat(1024 * 1024)
        );
        let mut expected = response.as_bytes().to_vec();
        expected.extend_from_slice(b"\r\n");

        let writer = std::thread::spawn(move || {
            let mut handler = SocketHandler::new(sender.as_raw_fd());
            let write_result = handler.send_str(&response);
            let shutdown_result = sender.shutdown(Shutdown::Write);
            (write_result, shutdown_result)
        });

        wait_until_send_buffer_is_full(&sender_probe);
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).unwrap();

        let (write_result, shutdown_result) = writer.join().unwrap();
        write_result.unwrap();
        shutdown_result.unwrap();
        assert_eq!(received.len(), expected.len());
        assert!(received == expected, "response contents differ");
    }

    #[test]
    fn test_socket_handler_preserves_disconnect_error_after_partial_write() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        set_send_buffer_size(&sender, 4096);
        let sender_probe = sender.try_clone().unwrap();

        let closer = std::thread::spawn(move || {
            wait_until_send_buffer_is_full(&sender_probe);
            drop(receiver);
        });

        let mut handler = SocketHandler::new(sender.as_raw_fd());
        let error = handler.send_str(&"x".repeat(1024 * 1024)).unwrap_err();
        closer.join().unwrap();

        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn test_socket_rw_handler_reports_progress_before_disconnect_error() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        set_send_buffer_size(&sender, 4096);
        let sender_probe = sender.try_clone().unwrap();

        let closer = std::thread::spawn(move || {
            wait_until_send_buffer_is_full(&sender_probe);
            drop(receiver);
        });

        let data = vec![0_u8; 1024 * 1024];
        let mut handler = SocketRWHandler::new(sender.as_raw_fd());
        let written = handler.write(&data).unwrap();
        closer.join().unwrap();

        assert!(written > 0 && written < data.len());
        assert_eq!(handler.pos, written);
        assert_eq!(handler.buf, data[..written]);

        let error = handler.write(&data[written..]).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn test_socket_handler_empty_write() {
        let (sender, _receiver) = UnixStream::pair().unwrap();
        let mut handler = SocketRWHandler::new(sender.as_raw_fd());

        assert_eq!(handler.write(&[]).unwrap(), 0);
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
}
