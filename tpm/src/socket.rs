// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use thiserror::Error;
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Cannot connect to tpm Socket")]
    ConnectToSocket(#[source] io::Error),
    #[error("Failed to read from socket")]
    ReadFromSocket(#[source] io::Error),
    #[error("Failed to write to socket")]
    WriteToSocket(#[source] io::Error),
    #[error("TPM Socket peer disconnected")]
    Disconnected,
    #[error("TPM Socket was not properly initialized or connected")]
    NotConnected,
    #[error("Invalid socket path")]
    InvalidPath,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
pub struct SocketDev {
    stream: Option<UnixStream>,
}

impl SocketDev {
    pub fn new(sock: UnixStream) -> Self {
        Self { stream: Some(sock) }
    }

    pub fn new_with_path(path: impl AsRef<Path>) -> Result<Self> {
        let mut sock_dev = SocketDev::default();
        sock_dev.init(path).and(Ok(sock_dev))
    }

    fn init(&mut self, path: impl AsRef<Path>) -> Result<()> {
        if !path.as_ref().exists() {
            return Err(Error::InvalidPath);
        }
        self.connect(path)
    }

    fn connect(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let stream = UnixStream::connect(path.as_ref()).map_err(Error::ConnectToSocket)?;
        self.stream = Some(stream);
        Ok(())
    }

    fn handle_disconnect(&mut self) -> Error {
        self.stream = None;
        Error::Disconnected
    }

    pub fn write_with_fd(&mut self, buf: &[u8], fd: RawFd) -> Result<()> {
        let mut written = 0;

        while written < buf.len() {
            match self
                .stream
                .as_ref()
                .ok_or(Error::NotConnected)?
                .send_with_fd(buf, fd)
            {
                Ok(n) => written += n,
                Err(e) => match io::Error::from(e).kind() {
                    ErrorKind::BrokenPipe | ErrorKind::ConnectionReset => {
                        return Err(self.handle_disconnect());
                    }
                    _ => return Err(Error::WriteToSocket(e.into())),
                },
            }
        }

        Ok(())
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        self.stream
            .as_ref()
            .ok_or(Error::NotConnected)?
            .read_exact(buf)
            .map_err(|e| {
                if e.kind() == ErrorKind::UnexpectedEof || e.kind() == ErrorKind::ConnectionReset {
                    self.handle_disconnect()
                } else {
                    Error::ReadFromSocket(e)
                }
            })
    }

    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.stream
            .as_ref()
            .ok_or(Error::NotConnected)?
            .write_all(buf)
            .map_err(|e| {
                if e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::ConnectionReset {
                    self.handle_disconnect()
                } else {
                    Error::WriteToSocket(e)
                }
            })
    }
}
