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

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;

use anyhow::{bail, Result};
use log::error;

use util::byte_code::ByteCode;
use util::socket::{SocketListener, SocketStream};
use util::unix::limit_permission;

pub struct OhUiChannel {
    pub path: String,
    pub listener: SocketListener,
    pub stream: Option<SocketStream>,
}

impl OhUiChannel {
    pub fn new(path: &str) -> Result<Self> {
        let listener = match SocketListener::bind_by_uds(path) {
            Ok(l) => l,
            Err(e) => bail!("Failed to create listener with path {}, {:?}", path, e),
        };
        limit_permission(path.as_str()).unwrap_or_else(|e| {
            error!(
                "Failed to limit permission for ohui-sock {}, err: {:?}",
                path, e
            );
        });

        Ok(OhUiChannel {
            path: String::from(path),
            listener,
            stream: None,
        })
    }

    pub fn get_listener_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn get_stream_raw_fd(&self) -> Option<RawFd> {
        self.stream.as_ref().and_then(|s| Some(s.as_raw_fd()))
    }

    pub fn accept(&mut self) -> Result<()> {
        self.stream = Some(self.listener.accept()?);
        Ok(())
    }

    pub fn send_by_obj<T: Sized + Default + ByteCode>(&mut self, obj: &T) -> Result<()> {
        let stream = self.get_stream()?;
        let slice = obj.as_bytes();
        let mut left = slice.len();
        let mut count = 0_usize;

        while left > 0 {
            let buf = &slice[count..];
            match stream.write(buf) {
                Ok(n) => {
                    left -= n;
                    count += n;
                }
                Err(e) => {
                    if std::io::Error::last_os_error().raw_os_error().unwrap() == libc::EAGAIN {
                        continue;
                    }
                    bail!(e);
                }
            }
        }
        Ok(())
    }

    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize> {
        let stream = self.get_stream()?;
        let len = data.len();
        if len == 0 {
            return Ok(0);
        }
        let ret = stream.read(data);
        match ret {
            Ok(n) => Ok(n),
            Err(e) => {
                if std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
                    != libc::EAGAIN
                {
                    bail!("recv_slice(): error occurred: {:?}", e);
                }
                Ok(0)
            }
        }
    }

    fn get_stream(&mut self) -> Result<&mut SocketStream> {
        if self.stream.is_some() {
            Ok(self.stream.as_mut().unwrap())
        } else {
            bail!("No connection established")
        }
    }
}
