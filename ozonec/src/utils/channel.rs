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
    os::unix::io::RawFd,
    slice,
};

use anyhow::{bail, Context, Result};
use log::{error, info};
use nix::{
    sys::socket::{
        recvmsg, sendmsg, socketpair, AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr,
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
            // SAFETY: FFI call with valid arguments.
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

    fn max_len_iovec(&self) -> Result<u64> {
        let mut len: u64 = 0;
        // SAFETY: len and type "u64" are both valid.
        let mut iov = [IoSliceMut::new(unsafe {
            slice::from_raw_parts_mut((&mut len as *mut u64) as *mut u8, mem::size_of::<u64>())
        })];
        info!("Receiver starts to find the maximum length of IO vector.");
        recvmsg::<UnixAddr>(self.fd, &mut iov, None, MsgFlags::MSG_PEEK)
            .inspect_err(|e| error!("Failed to receive messages, error: {:?}", e))?;
        match len {
            0 => bail!("Failed to get maximum length"),
            _ => Ok(len),
        }
    }

    pub fn recv(&self) -> Result<T> {
        let msg_len = self
            .max_len_iovec()
            .with_context(|| "Failed to get maximum length of receiver's IO vector")?;
        let mut received_len: u64 = 0;
        let mut buf = vec![0u8; msg_len as usize];
        let bytes = {
            let mut iov = [
                // SAFETY: FFI call with valid arguments.
                IoSliceMut::new(unsafe {
                    slice::from_raw_parts_mut(
                        (&mut received_len as *mut u64) as *mut u8,
                        mem::size_of::<u64>(),
                    )
                }),
                IoSliceMut::new(&mut buf),
            ];
            let mut cmsg = nix::cmsg_space!(T);
            info!("Receiver starts to receive message");
            let msg = recvmsg::<UnixAddr>(
                self.fd,
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .inspect_err(|e| error!("Failed to receive messages, error: {:?}", e))
            .with_context(|| "Receiver failed to receive messages")?;
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
        let msg = self
            .receiver
            .recv()
            .with_context(|| "Failed to receive ContainerCreated message.")?;
        match msg {
            Message::ContainerCreated => {
                info!("Succeed to receive ContainerCreated message.");
                Ok(())
            }
            _ => bail!("Expect receiving ContainerCreated, but got {:?}", msg),
        }
    }

    pub fn send_container_created(&self) -> Result<()> {
        self.sender
            .send(Message::ContainerCreated)
            .inspect(|_| info!("Succeed to send container_created message."))
            .with_context(|| "Failed to send created message to parent process")
    }

    pub fn recv_id_mappings(&self) -> Result<()> {
        let msg = self
            .receiver
            .recv()
            .with_context(|| "Failed to receive IdMappingStart message.")?;
        match msg {
            Message::IdMappingStart => {
                info!("Succeed to receive IdMappingStart message.");
                Ok(())
            }
            _ => bail!("Expect receiving IdMappingStart, but got {:?}", msg),
        }
    }

    pub fn send_id_mappings(&self) -> Result<()> {
        self.sender
            .send(Message::IdMappingStart)
            .inspect(|_| info!("Succeed to send IdMappingStart message."))
            .with_context(|| "Failed to send IdMappingStart message.")
    }

    pub fn recv_init_pid(&self) -> Result<Pid> {
        let msg = self
            .receiver
            .recv()
            .with_context(|| "Failed to receive InitReady message.")?;
        match msg {
            Message::InitReady(pid) => {
                info!("Succeed to receive InitReady message.");
                Ok(Pid::from_raw(pid))
            }
            _ => bail!("Expect receiving InitReady, but got {:?}", msg),
        }
    }

    pub fn recv_id_mappings_done(&self) -> Result<()> {
        let msg = self
            .receiver
            .recv()
            .with_context(|| "Failed to receive IdMappingDone message.")?;
        match msg {
            Message::IdMappingDone => {
                info!("Succeed to receive IdMappingDone message.");
                Ok(())
            }
            _ => bail!("Expect receiving IdMappingDone, but got {:?}", msg),
        }
    }

    pub fn send_id_mappings_done(&self) -> Result<()> {
        self.sender
            .send(Message::IdMappingDone)
            .inspect(|_| info!("Succeed to send IdMappingDone message."))
            .with_context(|| "Failed to send IdMappingDone message.")
    }

    pub fn send_init_pid(&self, pid: Pid) -> Result<()> {
        self.sender
            .send(Message::InitReady(pid.as_raw()))
            .inspect(|_| info!("Succeed to send InitReady message."))
            .with_context(|| "Failed to send container process pid")
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::wait::{waitpid, WaitStatus};
    use unistd::getpid;

    use crate::linux::clone_process;

    use super::*;

    #[test]
    fn test_channel() {
        let channel = Channel::<Message>::new().unwrap();
        let child = clone_process("test_channel", || {
            channel.receiver.close().unwrap();

            channel.send_container_created().unwrap();
            channel.send_init_pid(getpid()).unwrap();
            channel.send_id_mappings().unwrap();
            channel.send_id_mappings_done().unwrap();

            channel.sender.close().unwrap();
            Ok(0)
        })
        .unwrap();

        channel.sender.close().unwrap();

        channel.recv_container_created().unwrap();
        channel.recv_init_pid().unwrap();
        channel.recv_id_mappings().unwrap();
        channel.recv_id_mappings_done().unwrap();

        channel.receiver.close().unwrap();

        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, s)) => {
                assert_eq!(s, 0);
            }
            Ok(_) => (),
            Err(e) => {
                panic!("Failed to waitpid for child process: {e}");
            }
        }
    }
}
