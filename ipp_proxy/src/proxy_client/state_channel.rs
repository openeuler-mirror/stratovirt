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

use std::{
    io,
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    sync::{Arc, RwLock},
};

use anyhow::{bail, Context, Result};
use libc::EFD_NONBLOCK;
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
    StateThreadHandle,
};

#[derive(Debug, EnumCount)]
enum StateChannelEvent {
    Update = 0,
    Stop,
}

impl TryFrom<u64> for StateChannelEvent {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Update),
            1 => Ok(Self::Stop),
            other => bail!("Unknown state channel event: {}", other),
        }
    }
}

pub struct StateChannel {
    ipp_process: Arc<RwLock<IppProcessing>>,
    update_evt: Arc<EventFd>,
    exit_evt: Arc<EventFd>,
    epoll: Epoll,
}

impl StateChannel {
    pub fn new(
        ipp_process: Arc<RwLock<IppProcessing>>,
        _state_stream: UnixStream,
        exit_evt: Arc<EventFd>,
    ) -> Result<Self> {
        let update_evt = Arc::new(EventFd::new(EFD_NONBLOCK)?);
        PrintApi::subscribe_printers_changes(update_evt.try_clone().unwrap())?;

        Ok(Self {
            ipp_process,
            update_evt,
            exit_evt,
            epoll: Epoll::new()?,
        })
    }

    fn handle_update_event(&mut self) -> Result<()> {
        info!("printers update notification");
        // Clear the event.
        let _ = self.update_evt.read();
        let ipp_process = self.ipp_process.clone();
        std::thread::Builder::new()
            .name("ipp proxy printer refresh".to_string())
            .spawn(move || refresh_printers_job(ipp_process))
            .with_context(|| "Failed to create refresh printer thread")?;
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        self.epoll.ctl(
            ControlOperation::Add,
            self.exit_evt.try_clone().unwrap().as_raw_fd(),
            EpollEvent::new(EventSet::IN, StateChannelEvent::Stop as u64),
        )?;

        self.epoll.ctl(
            ControlOperation::Add,
            self.update_evt.as_raw_fd(),
            EpollEvent::new(EventSet::IN, StateChannelEvent::Update as u64),
        )?;

        let mut events = [EpollEvent::new(EventSet::empty(), 0); StateChannelEvent::COUNT];
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
                }

                match StateChannelEvent::try_from(event.data())? {
                    StateChannelEvent::Update => self.handle_update_event()?,
                    StateChannelEvent::Stop => {
                        info!("stopping proxy-client thread");
                        break 'epoll_loop;
                    }
                }
            }
        }

        info!("PrinterListSender is stopped");
        Ok(())
    }
}

pub fn start_state_thread(
    state_stream: UnixStream,
    ipp_process: Arc<RwLock<IppProcessing>>,
    exit_evt: Arc<EventFd>,
) -> Result<StateThreadHandle> {
    let join_handle = std::thread::Builder::new()
        .name("printers-state".to_string())
        .spawn(move || {
            if let Err(e) = StateChannel::new(ipp_process, state_stream, exit_evt)
                .unwrap()
                .run()
            {
                error!("State channel state exited with error: {:?}", e);
            }
        })
        .with_context(|| "Failed to create printers-state thread")?;
    Ok(Some(join_handle))
}

pub fn stop_state_thread(h: &mut StateThreadHandle) {
    if h.is_some() && h.take().unwrap().join().is_err() {
        error!("Error at stop of printer-state thread.");
    }
}

fn refresh_printers_job(ipp_process: Arc<RwLock<IppProcessing>>) {
    ipp_process.write().unwrap().refresh_printers();
}
