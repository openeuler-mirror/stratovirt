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

use std::fs::File;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::ptr::{copy_nonoverlapping, null_mut, write_unaligned};

use anyhow::{anyhow, bail, Context, Result};
use libc::{
    c_void, cmsghdr, iovec, msghdr, recvmsg, sendmsg, CMSG_LEN, CMSG_SPACE, MSG_NOSIGNAL,
    MSG_WAITALL, SCM_RIGHTS, SOL_SOCKET,
};
use log::error;
use nix::unistd::{sysconf, SysconfVar};

use crate::UtilError;

/// This function used to remove group and others permission using libc::chmod.
pub fn limit_permission(path: &str) -> Result<()> {
    let file_path = path.as_bytes().to_vec();
    let cstr_file_path = std::ffi::CString::new(file_path).unwrap();
    // SAFETY: The file_path can be guaranteed to be legal, and the
    // return value have bee verified later.
    let ret = unsafe { libc::chmod(cstr_file_path.as_ptr(), 0o600) };

    if ret == 0 {
        Ok(())
    } else {
        Err(anyhow!(UtilError::ChmodFailed(ret)))
    }
}

/// Gets the page size of host.
pub fn host_page_size() -> u64 {
    let page_size = match sysconf(SysconfVar::PAGE_SIZE) {
        Ok(Some(size)) => size,
        Ok(None) => 0,
        Err(e) => {
            error!("Get host page size failed: {:?}", e);
            0
        }
    };
    page_size as u64
}

/// Parse unix uri to unix path.
///
/// # Notions
///
/// Unix uri is the string as `unix:/xxx/xxx`.
pub fn parse_unix_uri(uri: &str) -> Result<String> {
    let parse_vec: Vec<&str> = uri.split(':').collect();
    if parse_vec.len() == 2 && parse_vec[0] == "unix" {
        Ok(parse_vec[1].to_string())
    } else {
        bail!("Invalid unix uri: {}", uri)
    }
}

/// Call libc::mmap to allocate memory or map disk file.
///
/// # Arguments
///
/// * `file` - Backend file.
/// * `len` - Length of mapping.
/// * `offset` - Offset in the file (or other object).
/// * `read_only` - Allow to write or not.
/// * `is_share` - Share the mapping or not.
/// * `dump_guest_core` - Exclude from a core dump or not.
///
/// # Errors
///
/// * Failed to do mmap.
pub fn do_mmap(
    file: &Option<&File>,
    len: u64,
    offset: u64,
    read_only: bool,
    is_share: bool,
    dump_guest_core: bool,
) -> Result<u64> {
    let mut flags: i32 = 0;
    let mut fd: i32 = -1;
    if let Some(f) = file {
        fd = f.as_raw_fd();
    } else {
        flags |= libc::MAP_ANONYMOUS;
    }

    if is_share {
        flags |= libc::MAP_SHARED;
    } else {
        flags |= libc::MAP_PRIVATE;
    }

    let mut prot = libc::PROT_READ;
    if !read_only {
        prot |= libc::PROT_WRITE;
    }

    // SAFETY: The return value is checked.
    let hva = unsafe {
        libc::mmap(
            std::ptr::null_mut() as *mut libc::c_void,
            len as libc::size_t,
            prot,
            flags,
            fd as libc::c_int,
            offset as libc::off_t,
        )
    };
    if hva == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).with_context(|| "Mmap failed.");
    }
    if !dump_guest_core {
        set_memory_undumpable(hva, len);
    }

    Ok(hva as u64)
}

fn set_memory_undumpable(host_addr: *mut libc::c_void, size: u64) {
    // SAFETY: host_addr and size are valid and return value is checked.
    let ret = unsafe { libc::madvise(host_addr, size as libc::size_t, libc::MADV_DONTDUMP) };
    if ret < 0 {
        error!(
            "Syscall madvise(with MADV_DONTDUMP) failed, OS error is {:?}",
            std::io::Error::last_os_error()
        );
    }
}

/// Unix socket is a data communication endpoint for exchanging data
/// between processes executing on the same host OS.
pub struct UnixSock {
    // Unix socket path
    path: String,
    // A unix socket listener acts as a synchronizalbe event.
    listener: Option<UnixListener>,
    // Unix socket stream perform like streams of information.
    sock: Option<UnixStream>,
}

impl Clone for UnixSock {
    fn clone(&self) -> Self {
        UnixSock {
            path: self.path.clone(),
            listener: self.listener.as_ref().map(|l| l.try_clone().unwrap()),
            sock: self.sock.as_ref().map(|s| s.try_clone().unwrap()),
        }
    }
}

impl UnixSock {
    pub fn new(path: &str) -> Self {
        UnixSock {
            path: path.to_string(),
            listener: None,
            sock: None,
        }
    }

    /// Bind assigns a unique listener for the socket.
    pub fn bind(&mut self, unlink: bool) -> Result<()> {
        if unlink && Path::new(self.path.as_str()).exists() {
            std::fs::remove_file(self.path.as_str())
                .with_context(|| format!("Failed to remove socket file {}.", self.path.as_str()))?;
        }
        let listener = UnixListener::bind(self.path.as_str())
            .with_context(|| format!("Failed to bind the socket {}", self.path))?;
        self.listener = Some(listener);

        Ok(())
    }

    /// The listener accepts incoming client connections.
    pub fn accept(&mut self) -> Result<()> {
        let (sock, _addr) = self
            .listener
            .as_ref()
            .unwrap()
            .accept()
            .with_context(|| format!("Failed to accept the socket {}", self.path))?;
        self.sock = Some(sock);

        Ok(())
    }

    pub fn is_accepted(&self) -> bool {
        self.sock.is_some()
    }

    pub fn server_connection_refuse(&mut self) -> Result<()> {
        // Refuse connection by finishing life cycle of stream fd from listener fd.
        self.listener.as_ref().unwrap().accept().with_context(|| {
            format!(
                "Failed to accept the socket for refused connection {}",
                self.path
            )
        })?;

        Ok(())
    }

    /// Unix socket stream create a connection for requests.
    pub fn connect(&mut self) -> Result<()> {
        let sock = UnixStream::connect(self.path.as_str())
            .with_context(|| format!("Failed to connect the socket {}", self.path))?;
        self.sock = Some(sock);

        Ok(())
    }

    pub fn listen_set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .as_ref()
            .unwrap()
            .set_nonblocking(nonblocking)
            .with_context(|| "couldn't set nonblocking for unix sock listener")
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.sock
            .as_ref()
            .unwrap()
            .set_nonblocking(nonblocking)
            .with_context(|| "couldn't set nonblocking")
    }

    /// Get Stream's fd from `UnixSock`.
    pub fn get_stream_raw_fd(&self) -> RawFd {
        self.sock.as_ref().unwrap().as_raw_fd()
    }

    /// Get listener's fd from `UnixSock`.
    pub fn get_listener_raw_fd(&self) -> RawFd {
        self.listener.as_ref().unwrap().as_raw_fd()
    }

    fn cmsg_data(&self, cmsg_buffer: *mut cmsghdr) -> *mut RawFd {
        (cmsg_buffer as *mut u8).wrapping_add(
            // SAFETY: Parameter is zero.
            unsafe { CMSG_LEN(0) } as usize,
        ) as *mut RawFd
    }

    fn get_next_cmsg(
        &self,
        msghdr: &msghdr,
        cmsg: &cmsghdr,
        cmsg_ptr: *mut cmsghdr,
    ) -> *mut cmsghdr {
        let next_cmsg = (cmsg_ptr as *mut u8).wrapping_add(
            // SAFETY: Safe to get cmsg_len because the parameter is valid.
            unsafe { CMSG_LEN(cmsg.cmsg_len as _) } as usize,
        ) as *mut cmsghdr;
        // Safe to get msg_control because the parameter is valid.
        let nex_cmsg_pos = (next_cmsg as *mut u8).wrapping_sub(msghdr.msg_control as usize) as u64;

        // SAFETY: Parameter is constant.
        if nex_cmsg_pos.wrapping_add(unsafe { CMSG_LEN(0) } as u64) > msghdr.msg_controllen as u64 {
            null_mut()
        } else {
            next_cmsg
        }
    }

    /// Send message and scm_fds to socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `iovecs` - Data buffer that need to send to socket.
    /// * `out_fds` - EventFds that need to send to socket.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn send_msg(&self, iovecs: &mut [iovec], out_fds: &[RawFd]) -> std::io::Result<usize> {
        // SAFETY: We checked the iovecs lens before.
        let iovecs_len = iovecs.len();
        // SAFETY: We checked the out_fds lens before.
        let cmsg_len = unsafe { CMSG_LEN((std::mem::size_of_val(out_fds)) as u32) };
        // SAFETY: We checked the out_fds lens before.
        let cmsg_capacity = unsafe { CMSG_SPACE((std::mem::size_of_val(out_fds)) as u32) };
        let mut cmsg_buffer = vec![0_u64; cmsg_capacity as usize];

        // In `musl` toolchain, msghdr has private member `__pad0` and `__pad1`, it can't be
        // initialized in normal way.
        // SAFETY: The member variable of msg will be assigned value later.
        let mut msg: msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = iovecs_len as _;
        msg.msg_control = null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        if !out_fds.is_empty() {
            let cmsg = cmsghdr {
                cmsg_len: cmsg_len as _,
                #[cfg(any(target_env = "musl", target_env = "ohos"))]
                __pad1: 0,
                cmsg_level: SOL_SOCKET,
                cmsg_type: SCM_RIGHTS,
            };
            // SAFETY: cmsg_buffer was created in this function and can be guaranteed not be null.
            unsafe {
                write_unaligned(cmsg_buffer.as_mut_ptr() as *mut cmsghdr, cmsg);

                copy_nonoverlapping(
                    out_fds.as_ptr(),
                    self.cmsg_data(cmsg_buffer.as_mut_ptr() as *mut cmsghdr),
                    out_fds.len(),
                );
            }

            msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_capacity as _;
        }

        let write_count =
            // SAFETY: msg parameters are valid.
            unsafe { sendmsg(self.sock.as_ref().unwrap().as_raw_fd(), &msg, MSG_NOSIGNAL) };

        if write_count == -1 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Failed to send msg, err: {}",
                    std::io::Error::last_os_error()
                ),
            ))
        } else {
            Ok(write_count as usize)
        }
    }

    /// Receive message and scm_fds from socket file descriptor.
    ///
    /// # Arguments
    ///
    /// * `iovecs` - Data buffer that need to receive from socket.
    /// * `in_fds` - EventFds that need to receive from socket.
    ///
    /// # Errors
    ///
    /// The socket file descriptor is broken.
    pub fn recv_msg(
        &self,
        iovecs: &mut [iovec],
        in_fds: &mut [RawFd],
    ) -> std::io::Result<(usize, usize)> {
        // SAFETY: We check the iovecs lens before.
        let iovecs_len = iovecs.len();
        // SAFETY: We check the in_fds lens before.
        let cmsg_capacity = unsafe { CMSG_SPACE((std::mem::size_of_val(in_fds)) as u32) };
        let mut cmsg_buffer = vec![0_u64; cmsg_capacity as usize];

        // In `musl` toolchain, msghdr has private member `__pad0` and `__pad1`, it can't be
        // initialized in normal way.
        // SAFETY: The member variable of msg will be assigned value later.
        let mut msg: msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = null_mut();
        msg.msg_namelen = 0;
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = iovecs_len as _;
        msg.msg_control = null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        if !in_fds.is_empty() {
            msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut c_void;
            msg.msg_controllen = cmsg_capacity as _;
        }

        // SAFETY: msg parameters are valid.
        let total_read = unsafe {
            recvmsg(
                self.sock.as_ref().unwrap().as_raw_fd(),
                &mut msg,
                MSG_WAITALL,
            )
        };

        if total_read == -1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Failed to recv msg, err: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        if total_read == 0 && (msg.msg_controllen as u64) < size_of::<cmsghdr>() as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "The length of control message is invalid, {} {}",
                    msg.msg_controllen,
                    size_of::<cmsghdr>()
                ),
            ));
        }

        let mut cmsg_ptr = msg.msg_control as *mut cmsghdr;
        let mut in_fds_count = 0_usize;
        while !cmsg_ptr.is_null() {
            // SAFETY: The pointer of cmsg_ptr was created in this function and
            // can be guaranteed not be null.
            let cmsg = unsafe { (cmsg_ptr as *mut cmsghdr).read_unaligned() };

            if cmsg.cmsg_level == SOL_SOCKET && cmsg.cmsg_type == SCM_RIGHTS {
                // SAFETY: Input parameter is constant.
                let fd_count = (cmsg.cmsg_len as u64 - unsafe { CMSG_LEN(0) } as u64) as usize
                    / size_of::<RawFd>();
                // SAFETY:
                // 1. the pointer of cmsg_ptr was created in this function and can be guaranteed not be null.
                // 2. the parameter of in_fds has been checked before.
                unsafe {
                    copy_nonoverlapping(
                        self.cmsg_data(cmsg_ptr),
                        in_fds[in_fds_count..(in_fds_count + fd_count)].as_mut_ptr(),
                        fd_count,
                    );
                }
                in_fds_count += fd_count;
            }

            cmsg_ptr = self.get_next_cmsg(&msg, &cmsg, cmsg_ptr);
        }
        Ok((total_read as usize, in_fds_count))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use libc::{c_void, iovec};

    use super::{parse_unix_uri, UnixSock};

    #[test]
    fn test_parse_uri() {
        let test_uri_01 = "unix:/tmp/test_file.sock";
        assert!(parse_unix_uri(test_uri_01).is_ok());
        assert_eq!(
            parse_unix_uri(test_uri_01).unwrap(),
            String::from("/tmp/test_file.sock")
        );

        let test_uri_02 = "file:/tmp/test_file:file";
        assert!(parse_unix_uri(test_uri_02).is_err());

        let test_uri_03 = "tcp:127.0.0.1";
        assert!(parse_unix_uri(test_uri_03).is_err());
    }

    #[test]
    fn test_create_unix_socket() {
        let path_name = String::from("test_socket1.sock");
        let sock_path = Path::new("./test_socket1.sock");

        let mut listener = UnixSock::new(&path_name);
        if sock_path.exists() {
            assert!(listener.bind(true).is_ok());
        } else {
            assert!(listener.bind(false).is_ok());
        }
        assert_ne!(listener.get_listener_raw_fd(), 0);

        std::thread::sleep(Duration::from_millis(100));
        let mut stream = UnixSock::new(&path_name);
        assert!(stream.connect().is_ok());
        assert_ne!(stream.get_stream_raw_fd(), 0);

        assert!(listener.accept().is_ok());
        assert_eq!(listener.is_accepted(), true);

        if sock_path.exists() {
            fs::remove_file("./test_socket1.sock").unwrap();
        }
    }

    #[test]
    fn test_send_recv_sock_msg() {
        let path_name = String::from("test_socket2.sock");
        let sock_path = Path::new("./test_socket2.sock");
        let mut listener = UnixSock::new(&path_name);
        if sock_path.exists() {
            assert!(listener.bind(true).is_ok());
        } else {
            assert!(listener.bind(false).is_ok());
        }

        std::thread::sleep(Duration::from_millis(100));
        let mut stream = UnixSock::new(&path_name);
        assert!(stream.connect().is_ok());
        assert!(listener.accept().is_ok());

        let buff = "send message".as_bytes();
        let mut data: Vec<u8> = Vec::new();
        data.extend(buff);
        let mut io_data = vec![iovec {
            iov_base: data.as_slice()[0..buff.len()].as_ptr() as *mut c_void,
            iov_len: buff.len(),
        }];
        let out_fds = [listener.get_stream_raw_fd()];
        let size = listener.send_msg(&mut io_data, &out_fds).unwrap();
        assert_eq!(size, buff.len());

        let mut recv: Vec<iovec> = io_data;
        let mut in_fd = [0; 1];
        let (data_size, fd_size) = stream.recv_msg(&mut recv, &mut in_fd).unwrap();
        assert_eq!(data_size, buff.len());
        assert_eq!(fd_size, in_fd.len());

        if sock_path.exists() {
            fs::remove_file("./test_socket2.sock").unwrap();
        }
    }
}
