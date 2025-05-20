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

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;

use anyhow::{bail, Result};
use log::error;

use util::byte_code::ByteCode;
use util::socket::{SocketListener, SocketStream};
use util::unix::limit_permission;

pub struct OhUiChannel {
    listener: SocketListener,
    stream: Option<SocketStream>,
}

impl OhUiChannel {
    pub fn new(path: &str) -> Result<Self> {
        let listener = match SocketListener::bind_by_uds(path) {
            Ok(l) => l,
            Err(e) => bail!("Failed to create listener with path {}, {:?}", path, e),
        };
        limit_permission(path).unwrap_or_else(|e| {
            error!(
                "Failed to limit permission for ohui-sock {}, err: {:?}",
                path, e
            );
        });

        Ok(OhUiChannel {
            listener,
            stream: None,
        })
    }

    pub fn get_listener_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }

    pub fn get_stream_raw_fd(&self) -> Option<RawFd> {
        self.stream.as_ref().map(|s| s.as_raw_fd())
    }

    pub fn accept(&mut self) -> Result<()> {
        self.stream = Some(self.listener.accept()?);
        Ok(())
    }

    pub fn disconnect(&mut self) {
        self.stream = None;
    }
}

pub fn recv_slice(stream: &mut dyn Read, data: &mut [u8]) -> Result<usize> {
    let len = data.len();
    let mut ret = 0_usize;

    while ret < len {
        match stream.read(&mut data[ret..len]) {
            Ok(0) => break,
            Ok(n) => ret += n,
            Err(e) => {
                let ek = e.kind();
                if ek != ErrorKind::WouldBlock && ek != ErrorKind::Interrupted {
                    bail!("recv_slice: error occurred: {:?}", e);
                }
                break;
            }
        }
    }
    Ok(ret)
}

pub fn send_obj<T: Sized + Default + ByteCode>(stream: &mut dyn Write, obj: &T) -> Result<()> {
    let slice = obj.as_bytes();
    let mut left = slice.len();
    let mut count = 0_usize;

    while left > 0 {
        match stream.write(&slice[count..]) {
            Ok(n) => {
                left -= n;
                count += n;
            }
            Err(e) => {
                let ek = e.kind();
                if ek == ErrorKind::WouldBlock || ek == ErrorKind::Interrupted {
                    continue;
                }
                bail!(e);
            }
        }
    }
    Ok(())
}
