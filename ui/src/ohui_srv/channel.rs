// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
//
// Stratovirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::os::raw::c_void;
use std::os::unix::io::RawFd;
use std::sync::RwLock;

use anyhow::Result;
use libc::iovec;
use log::error;

use super::msg::*;
use util::byte_code::ByteCode;
use util::unix::UnixSock;

pub struct OhUiChannel {
    pub sock: RwLock<UnixSock>,
    pub path: String,
}

impl OhUiChannel {
    pub fn new(path: &str) -> Self {
        OhUiChannel {
            sock: RwLock::new(UnixSock::new(path)),
            path: String::from(path),
        }
    }

    pub fn bind(&self) -> Result<()> {
        self.sock.write().unwrap().bind(true)
    }

    pub fn get_listener_raw_fd(&self) -> RawFd {
        self.sock.read().unwrap().get_listener_raw_fd()
    }

    pub fn get_stream_raw_fd(&self) -> RawFd {
        self.sock.read().unwrap().get_stream_raw_fd()
    }

    pub fn set_nonblocking(&self, nb: bool) -> Result<()> {
        self.sock.read().unwrap().set_nonblocking(nb)
    }

    pub fn set_listener_nonblocking(&self, nb: bool) -> Result<()> {
        self.sock.read().unwrap().listen_set_nonblocking(nb)
    }

    pub fn accept(&self) -> Result<()> {
        self.sock.write().unwrap().accept()
    }

    pub fn send(&self, data: *const u8, len: usize) -> Result<usize> {
        let mut iovs = Vec::with_capacity(1);
        iovs.push(iovec {
            iov_base: data as *mut c_void,
            iov_len: len,
        });
        let ret = self.sock.read().unwrap().send_msg(&mut iovs, &[])?;
        Ok(ret)
    }

    pub fn send_by_obj<T: Sized + Default + ByteCode>(&self, obj: &T) -> Result<()> {
        let slice = obj.as_bytes();
        let mut left = slice.len();
        let mut count = 0_usize;

        while left > 0 {
            let buf = &slice[count..];
            match self.send(buf.as_ptr(), left) {
                Ok(n) => {
                    left -= n;
                    count += n;
                }
                Err(e) => {
                    if std::io::Error::last_os_error().raw_os_error().unwrap() == libc::EAGAIN {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub fn send_message<T: Sized + Default + ByteCode>(
        &self,
        t: EventType,
        body: &T,
    ) -> Result<()> {
        let hdr = EventMsgHdr::new(t);
        self.send_by_obj(&hdr)?;
        self.send_by_obj(body)
    }

    pub fn recv_slice(&self, data: &mut [u8]) -> Result<usize> {
        let len = data.len();
        if len == 0 {
            return Ok(0);
        }
        let ret = self.recv(data.as_mut_ptr(), len);
        match ret {
            Ok(n) => Ok(n),
            Err(e) => {
                if std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
                    != libc::EAGAIN
                {
                    error!("recv_slice(): error occurred: {}", e);
                }
                Ok(0)
            }
        }
    }

    pub fn recv(&self, data: *mut u8, len: usize) -> Result<usize> {
        let mut iovs = Vec::with_capacity(1);
        iovs.push(iovec {
            iov_base: data as *mut c_void,
            iov_len: len,
        });

        let ret = self.sock.read().unwrap().recv_msg(&mut iovs, &mut []);
        match ret {
            Ok((n, _)) => Ok(n),
            Err(e) => Err(e.into()),
        }
    }
}
