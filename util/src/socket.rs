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

use std::io::{IoSlice, IoSliceMut, Result as IoResult};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use anyhow::Result;

/// Provide socket abstraction for UnixStream and TcpStream.
#[derive(Debug)]
pub enum SocketStream {
    Tcp {
        link_description: String,
        stream: TcpStream,
    },
    Unix {
        link_description: String,
        stream: UnixStream,
    },
}

impl SocketStream {
    pub fn link_description(&self) -> String {
        match self {
            SocketStream::Tcp {
                link_description, ..
            } => link_description.clone(),
            SocketStream::Unix {
                link_description, ..
            } => link_description.clone(),
        }
    }
}

impl AsRawFd for SocketStream {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            SocketStream::Tcp { stream, .. } => stream.as_raw_fd(),
            SocketStream::Unix { stream, .. } => stream.as_raw_fd(),
        }
    }
}

impl std::io::Read for SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self {
            SocketStream::Tcp { stream, .. } => stream.read(buf),
            SocketStream::Unix { stream, .. } => stream.read(buf),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut]) -> IoResult<usize> {
        match self {
            SocketStream::Tcp { stream, .. } => stream.read_vectored(bufs),
            SocketStream::Unix { stream, .. } => stream.read_vectored(bufs),
        }
    }
}

impl std::io::Write for SocketStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match self {
            SocketStream::Tcp { stream, .. } => stream.write(buf),
            SocketStream::Unix { stream, .. } => stream.write(buf),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice]) -> IoResult<usize> {
        match self {
            SocketStream::Tcp { stream, .. } => stream.write_vectored(bufs),
            SocketStream::Unix { stream, .. } => stream.write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match self {
            SocketStream::Tcp { stream, .. } => stream.flush(),
            SocketStream::Unix { stream, .. } => stream.flush(),
        }
    }
}

/// Provide listener abstraction for UnixListener and TcpListener.
#[derive(Debug)]
pub enum SocketListener {
    Tcp {
        address: String,
        listener: TcpListener,
    },
    Unix {
        address: String,
        listener: UnixListener,
    },
}

impl SocketListener {
    pub fn bind_by_tcp(host: &str, port: u16) -> Result<Self> {
        let address = format!("{}:{}", &host, &port);
        let listener = TcpListener::bind(&address)?;
        listener.set_nonblocking(true)?;
        Ok(SocketListener::Tcp { address, listener })
    }

    pub fn bind_by_uds(path: &str) -> Result<Self> {
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(SocketListener::Unix {
            address: String::from(path),
            listener,
        })
    }

    pub fn address(&self) -> String {
        match self {
            SocketListener::Tcp { address, .. } => address.clone(),
            SocketListener::Unix { address, .. } => address.clone(),
        }
    }

    pub fn accept(&self) -> Result<SocketStream> {
        match self {
            SocketListener::Tcp { listener, address } => {
                let (stream, sock_addr) = listener.accept()?;
                let peer_address = sock_addr.to_string();
                let link_description = format!(
                    "{{ protocol: tcp, address: {}, peer: {} }}",
                    address, peer_address
                );
                Ok(SocketStream::Tcp {
                    link_description,
                    stream,
                })
            }
            SocketListener::Unix { listener, address } => {
                let (stream, _) = listener.accept()?;
                let link_description = format!("{{ protocol: unix, address: {} }}", address);
                Ok(SocketStream::Unix {
                    link_description,
                    stream,
                })
            }
        }
    }
}

impl AsRawFd for SocketListener {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            SocketListener::Tcp { listener, .. } => listener.as_raw_fd(),
            SocketListener::Unix { listener, .. } => listener.as_raw_fd(),
        }
    }
}
