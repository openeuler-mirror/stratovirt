// Copyright (c) 2021 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::mem::size_of;
use std::os::unix::io::RawFd;

use anyhow::{bail, Result};
use libc::{c_void, iovec};

use super::message::{MAX_ATTACHED_FD_ENTRIES, VHOST_USER_MSG_MAX_SIZE};
use util::unix::UnixSock;

#[derive(Clone)]
pub struct VhostUserSock {
    pub domain: UnixSock,
    pub path: String,
}

impl VhostUserSock {
    pub fn new(path: &str) -> Self {
        VhostUserSock {
            domain: UnixSock::new(path),
            path: path.to_string(),
        }
    }

    /// Send vhost user message to unix domain socket.
    ///
    /// # Arguments
    ///
    /// * `hdr_opt` - Vhost user header buffer.
    /// * `body_opt` - Vhost user body buffer.
    /// * `payload_opt` - Vhost user payload buffer.
    /// * `fds` - EventFds that need to send to socket.
    ///
    /// # Errors
    ///
    /// * Body and payload message len is more than VHOST_USER_MSG_MAX_SIZE.
    /// * Fds len is more than MAX_ATTACHED_FD_ENTRIES.
    /// * Failed to call `sendmsg()`.
    pub fn send_msg<D: Sized, T: Sized, P: Sized>(
        &self,
        hdr_opt: Option<&D>,
        body_opt: Option<&T>,
        payload_opt: Option<&[P]>,
        fds: &[RawFd],
    ) -> Result<()> {
        let mut iovs = Vec::with_capacity(3);
        let mut total_len = size_of::<D>();

        if let Some(hdr) = hdr_opt {
            iovs.push(iovec {
                iov_base: hdr as *const D as *const u8 as *mut c_void,
                iov_len: size_of::<D>(),
            });
        }

        if let Some(body) = body_opt {
            iovs.push(iovec {
                iov_base: body as *const T as *const u8 as *mut c_void,
                iov_len: size_of::<T>(),
            });
            total_len += size_of::<T>();
        }

        if let Some(payload) = payload_opt {
            iovs.push(iovec {
                iov_base: payload.as_ptr() as *const u8 as *mut c_void,
                iov_len: std::mem::size_of_val(payload),
            });
            total_len += std::mem::size_of_val(payload);
        }

        if (total_len - size_of::<D>()) > VHOST_USER_MSG_MAX_SIZE {
            bail!(
                "The total length is invalid {}",
                (total_len - size_of::<D>())
            );
        }

        if fds.len() > MAX_ATTACHED_FD_ENTRIES {
            bail!("The number of fds is invalid {}", fds.len());
        }

        let snd_len = self.domain.send_msg(&mut iovs, fds)?;
        if snd_len != total_len {
            bail!(
                "The actual sending length {} is less than the sending length {}",
                snd_len,
                total_len
            );
        }
        Ok(())
    }

    /// Receive vhost user message from unix domain socket.
    ///
    /// # Arguments
    ///
    /// * `hdr_opt` - Vhost user header buffer.
    /// * `body_opt` - Vhost user body buffer.
    /// * `payload_opt` - Vhost user payload buffer.
    /// * `fds` - EventFds that need to receive from socket.
    ///
    /// # Errors
    ///
    /// * Failed to call `recvmsg()`.
    pub fn recv_msg<D: Sized, T: Sized, P: Sized>(
        &self,
        hdr_opt: Option<&mut D>,
        body_opt: Option<&mut T>,
        payload_opt: Option<&mut [P]>,
        fds: &mut [RawFd],
    ) -> Result<(usize, usize)> {
        let mut iovs = Vec::with_capacity(3);

        if let Some(hdr) = hdr_opt {
            iovs.push(iovec {
                iov_base: hdr as *const D as *const u8 as *mut c_void,
                iov_len: size_of::<D>(),
            });
        }

        if let Some(body) = body_opt {
            iovs.push(iovec {
                iov_base: body as *const T as *const u8 as *mut c_void,
                iov_len: size_of::<T>(),
            });
        }

        if let Some(payload) = payload_opt {
            iovs.push(iovec {
                iov_base: payload.as_ptr() as *const u8 as *mut c_void,
                iov_len: std::mem::size_of_val(payload),
            });
        }

        let (rcv_len, fds_num) = self.domain.recv_msg(&mut iovs, fds)?;

        Ok((rcv_len, fds_num))
    }
}
