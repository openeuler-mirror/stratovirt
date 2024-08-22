// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{
    fmt::Debug,
    io::{IoSlice, IoSliceMut},
    marker::PhantomData,
    mem,
    os::fd::RawFd,
    slice,
};

use anyhow::{bail, Context, Result};
use nix::{
    sys::{
        socket::{
            recvmsg, sendmsg, setsockopt, socketpair, sockopt, AddressFamily, MsgFlags, SockFlag,
            SockType, UnixAddr,
        },
        time::TimeVal,
    },
    unistd::{self, Pid},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// Wrapper for messages to be sent between parent and child processes.
#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    IdMappingStart,
    IdMappingDone,
    InitReady(i32),
    ContainerCreated,
    ExecFailed(String),
}

pub struct Sender<T> {
    fd: RawFd,
    phantom: PhantomData<T>,
}

impl<T> Sender<T>
where
    T: Serialize,
{
    pub fn close(&self) -> Result<()> {
        Ok(unistd::close(self.fd)?)
    }

    pub fn send(&self, msg: T) -> Result<()> {
        let msg_vec = serde_json::to_vec(&msg).with_context(|| "Failed to load message")?;
        let msg_len = msg_vec.len() as u64;
        let iov = [
            IoSlice::new(unsafe {
                slice::from_raw_parts((&msg_len as *const u64) as *const u8, mem::size_of::<u64>())
            }),
            IoSlice::new(&msg_vec),
        ];

        sendmsg::<UnixAddr>(self.fd, &iov, &[], MsgFlags::empty(), None)?;
        Ok(())
    }
}

pub struct Receiver<T> {
    fd: RawFd,
    phantom: PhantomData<T>,
}

impl<T> Receiver<T>
where
    T: DeserializeOwned,
{
    pub fn close(&self) -> Result<()> {
        Ok(unistd::close(self.fd)?)
    }

    pub fn set_timeout(&self, timeout: i64) -> Result<()> {
        let timeval = TimeVal::new(0, timeout);
        setsockopt(self.fd, sockopt::ReceiveTimeout, &timeval)
            .with_context(|| "Failed to set receiver end timeout")?;
        Ok(())
    }

    fn max_len_iovec(&self) -> Result<u64> {
        let mut len: u64 = 0;
        // SAFETY: len and type "u64" are both valid.
        let mut iov = [IoSliceMut::new(unsafe {
            slice::from_raw_parts_mut((&mut len as *mut u64) as *mut u8, mem::size_of::<u64>())
        })];

        recvmsg::<UnixAddr>(self.fd, &mut iov, None, MsgFlags::MSG_PEEK)?;
        match len {
            0 => bail!("Failed to get maximum length"),
            _ => Ok(len),
        }
    }

    pub fn recv(&self) -> Result<T> {
        let msg_len = self.max_len_iovec()?;
        let mut received_len: u64 = 0;
        let mut buf = vec![0u8; msg_len as usize];
        let bytes = {
            let mut iov = [
                IoSliceMut::new(unsafe {
                    slice::from_raw_parts_mut(
                        (&mut received_len as *mut u64) as *mut u8,
                        mem::size_of::<u64>(),
                    )
                }),
                IoSliceMut::new(&mut buf),
            ];
            let mut cmsg = nix::cmsg_space!(T);
            let msg = recvmsg::<UnixAddr>(
                self.fd,
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )?;
            msg.bytes
        };

        match bytes {
            0 => bail!("Received zero length message"),
            _ => Ok(serde_json::from_slice(&buf[..])
                .with_context(|| "Failed to read received message")?),
        }
    }
}

pub struct Channel<T> {
    pub sender: Sender<T>,
    pub receiver: Receiver<T>,
}

impl Channel<Message> {
    pub fn new() -> Result<Channel<Message>> {
        let (sender_fd, receiver_fd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )?;
        let sender = Sender {
            fd: sender_fd,
            phantom: PhantomData,
        };
        let receiver = Receiver {
            fd: receiver_fd,
            phantom: PhantomData,
        };

        Ok(Channel { sender, receiver })
    }

    pub fn recv_container_created(&self) -> Result<()> {
        let msg = self.receiver.recv()?;
        match msg {
            Message::ContainerCreated => Ok(()),
            _ => bail!("Expect receiving ContainerCreated, but got {:?}", msg),
        }
    }

    pub fn send_container_created(&self) -> Result<()> {
        self.sender
            .send(Message::ContainerCreated)
            .with_context(|| "Failed to send created message to parent process")
    }

    pub fn recv_id_mappings(&self) -> Result<()> {
        let msg = self.receiver.recv()?;
        match msg {
            Message::IdMappingStart => Ok(()),
            _ => bail!("Expect receiving IdMappingStart, but got {:?}", msg),
        }
    }

    pub fn send_id_mappings(&self) -> Result<()> {
        self.sender.send(Message::IdMappingStart)
    }

    pub fn recv_init_pid(&self) -> Result<Pid> {
        let msg = self.receiver.recv()?;
        match msg {
            Message::InitReady(pid) => Ok(Pid::from_raw(pid)),
            _ => bail!("Expect receiving InitReady, but got {:?}", msg),
        }
    }

    pub fn recv_id_mappings_done(&self) -> Result<()> {
        let msg = self.receiver.recv()?;
        match msg {
            Message::IdMappingDone => Ok(()),
            _ => bail!("Expect receiving IdMappingDone, but got {:?}", msg),
        }
    }

    pub fn send_id_mappings_done(&self) -> Result<()> {
        self.sender.send(Message::IdMappingDone)
    }

    pub fn send_init_pid(&self, pid: Pid) -> Result<()> {
        self.sender
            .send(Message::InitReady(pid.as_raw()))
            .with_context(|| "Failed to send container process pid")
    }
}
