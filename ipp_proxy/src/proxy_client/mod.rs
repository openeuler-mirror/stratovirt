// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod ipp_printer;
pub mod ipp_processing;
pub mod print_api;
pub mod state_channel;

use std::{
    io,
    io::{prelude::*, ErrorKind},
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    sync::{Arc, RwLock},
    thread,
};

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{error, info, trace};
use strum::EnumCount;
use strum_macros::EnumCount;
use vmm_sys_util::{
    epoll::{ControlOperation, Epoll, EpollEvent, EventSet},
    eventfd::EventFd,
};

use crate::proxy_client::{
    ipp_processing::IppProcessing,
    print_api::{PrintApi, PrintOps},
    state_channel::*,
};

pub type StateThreadHandle = Option<thread::JoinHandle<()>>;

pub const VMGT_UUID_PREFIX: &str = "VMGT31dc";

#[derive(Debug, EnumCount)]
enum ProxyClientEvent {
    Stop = 0,
    Data,
}

impl TryFrom<u64> for ProxyClientEvent {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Stop),
            1 => Ok(Self::Data),
            other => bail!("Unknown proxy client event: {}", other),
        }
    }
}

const VPRINT_DATA_HDR_SIZE: usize = 8;
const VPRINT_MAX_DATA_SIZE: usize = 1024 * 1024; // no more then 1M in one chunk

struct StreamData {
    id: u32,
    size: usize,
    data_ready: usize,
    data: Vec<u8>,
}

pub struct ProxyClient {
    _ipp_process: Arc<RwLock<IppProcessing>>,
    exit_evt: Arc<EventFd>,
    need_reset: bool,
    data_stream: UnixStream,
    state_thread: StateThreadHandle,
    _spool_dir: String, // directory for temp files
    epoll: Epoll,
    // hdr:
    //    stream_id: u32,
    //    data_bytes: u32,
    hdr_bytes: [u8; VPRINT_DATA_HDR_SIZE],
    hdr_bytes_ready: usize,
    curr_stream_id: u32,
    stream: Option<StreamData>,
}

impl ProxyClient {
    pub fn new(
        state_stream: UnixStream,
        data_stream: UnixStream,
        spool_dir: &String,
        exit_evt: Arc<EventFd>,
    ) -> Result<Self> {
        if let Err(e) = PrintApi::init_printers() {
            bail!("Failed to initialize printers: {:?}", e);
        }

        state_stream.set_nonblocking(true)?;
        data_stream.set_nonblocking(true)?;

        let mut ipp_process = IppProcessing::new();
        ipp_process.refresh_printers();
        if ipp_process.get_printers_list().is_empty() {
            info!("No printers are installed in system; Will listen for changes.")
        }
        let ipp_process = Arc::new(RwLock::new(ipp_process));
        let state_thread = start_state_thread(state_stream, ipp_process.clone(), exit_evt.clone())?;

        info!("ProxyClient is initialized");

        Ok(Self {
            _ipp_process: ipp_process,
            exit_evt,
            need_reset: false,
            data_stream,
            state_thread,
            _spool_dir: spool_dir.to_string(),
            epoll: Epoll::new()?,
            hdr_bytes: [0; VPRINT_DATA_HDR_SIZE],
            hdr_bytes_ready: 0,
            curr_stream_id: 0,
            stream: None,
        })
    }

    pub fn read_buf_helper(stream: &mut UnixStream, buf: &mut [u8]) -> io::Result<usize> {
        match stream.read(buf) {
            Ok(n) => {
                if n == 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    ))
                } else {
                    Ok(n)
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Interrupted | ErrorKind::TimedOut => Ok(0),
                ErrorKind::WouldBlock => {
                    Ok(0) // message not ready yet
                }
                _ => {
                    error!("Error at read(): {e}");
                    Err(e)
                }
            },
        }
    }

    // Disable all transmits until guest explicitly doesn't reset error.
    fn set_data_error(&mut self) -> Result<()> {
        let _ = self.epoll.ctl(
            ControlOperation::Delete,
            self.data_stream.as_raw_fd(),
            EpollEvent::default(),
        )?;
        self.need_reset = true;
        Ok(())
    }

    fn check_stream_hdr_ready(&mut self) -> Result<bool> {
        if self.stream.is_some() {
            return Ok(true);
        }
        self.hdr_bytes_ready += match self
            .data_stream
            .read(&mut self.hdr_bytes[self.hdr_bytes_ready..VPRINT_DATA_HDR_SIZE])
        {
            Ok(n) => {
                if n == 0 {
                    bail!("Connection closed");
                } else {
                    n
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Interrupted | ErrorKind::WouldBlock => return Ok(false),
                _ => {
                    return Err(e.into());
                }
            },
        };
        if self.hdr_bytes_ready != VPRINT_DATA_HDR_SIZE {
            return Ok(false);
        };

        let id = LittleEndian::read_u32(&self.hdr_bytes[0..]);
        let size = LittleEndian::read_u32(&self.hdr_bytes[4..]) as usize;
        if size > VPRINT_MAX_DATA_SIZE {
            self.set_data_error()?;
            return Ok(false);
        };
        let mut data = Vec::with_capacity(size);
        // We don't want zero this memory. It will be overwritten anyway.
        unsafe {
            data.set_len(size);
        }
        self.stream = Some(StreamData {
            id,
            size,
            data_ready: 0,
            data,
        });
        Ok(true)
    }

    fn handle_data_event(&mut self) -> Result<()> {
        if !self.check_stream_hdr_ready()? {
            return Ok(());
        }
        let stream = &mut self.stream.as_mut().unwrap();
        stream.data_ready += match Self::read_buf_helper(
            &mut self.data_stream,
            &mut stream.data[stream.data_ready..],
        ) {
            Ok(n) => n,
            Err(e) => {
                return Err(e.into());
            }
        };
        if stream.data_ready != stream.size {
            return Ok(());
        }
        let _data = std::mem::take(&mut stream.data);
        self.curr_stream_id = stream.id;
        self.stream = None;
        self.hdr_bytes_ready = 0;

        // just discard data at the moment
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        self.epoll
            .ctl(
                ControlOperation::Add,
                self.exit_evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, ProxyClientEvent::Stop as u64),
            )
            .unwrap();

        self.epoll
            .ctl(
                ControlOperation::Add,
                self.data_stream.as_raw_fd(),
                EpollEvent::new(EventSet::IN, ProxyClientEvent::Data as u64),
            )
            .unwrap();

        let mut events = [EpollEvent::new(EventSet::empty(), 0); ProxyClientEvent::COUNT];

        'epoll_loop: loop {
            let cnt = match self.epoll.wait(-1, &mut events[..]) {
                Err(e) => {
                    error!("epoll_wait failed: {}", e.kind());
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    bail!("unknown poll error");
                }
                Ok(res) => res,
            };

            for event in events.iter().take(cnt) {
                if EventSet::from_bits(event.events()).is_none() {
                    trace!("epoll: ignoring unknown event set: 0x{:x}", event.events());
                    continue;
                };

                match ProxyClientEvent::try_from(event.data())? {
                    ProxyClientEvent::Stop => {
                        info!("stopping proxy-client thread");
                        break 'epoll_loop;
                    }
                    ProxyClientEvent::Data => self.handle_data_event()?,
                }
            }
        }

        info!("stop_state_thread...");
        stop_state_thread(&mut self.state_thread);
        info!("state_thread() finished.");

        Ok(())
    }
}
