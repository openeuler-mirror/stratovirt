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

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    rc::Rc,
    sync::{Arc, Mutex},
};

use log::error;
use thiserror::Error;

use machine_manager::event_loop::EventLoop;
use util::loop_context::{read_fd, EventNotifier, NotifierCallback, NotifierOperation};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

pub enum AsyncMsg {
    Request {
        cmd_buf: Vec<u8>,
        cmd_len: usize,
        locty: u8,
    },
}

#[derive(Error, Debug)]
pub enum AioError {
    #[error("TPM Backend disconnected")]
    Disconnected,
    #[error("Command failed with TPM Error Code: {0}")]
    TpmError(String),
    #[error("IO error: {0}")]
    IoError(#[source] io::Error),
    #[error("error: {0}")]
    UnknownError(#[source] anyhow::Error),
}

impl From<io::Error> for AioError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<anyhow::Error> for AioError {
    fn from(e: anyhow::Error) -> Self {
        Self::UnknownError(e)
    }
}

pub type Result<T> = anyhow::Result<T, AioError>;

/*
 * TPM Backend should implement this trait.
 */
pub trait AsyncMsgHandle {
    fn deliver_request_async(&mut self, cmd_buf: Vec<u8>, cmd_len: usize, locty: u8) -> Result<()>;

    fn handle_async_request(&mut self, request: AsyncMsg) -> (Result<()>, Vec<u8>);

    fn get_request(&mut self) -> Option<AsyncMsg>;

    fn get_evt_fd(&self) -> RawFd;
}

/*
 * TPM device should implement this trait.
 */
pub trait OnComplete {
    type T: AsyncMsgHandle;

    fn on_complete(&mut self, res: Result<()>, buf: Vec<u8>);

    fn get_async_handler(&self) -> Arc<Mutex<Self::T>>;
}

pub fn register_async_ctrl_notifier<T>(
    complete_handler: Arc<Mutex<T>>,
    iothread: Option<String>,
) -> Result<Arc<EventFd>>
where
    T: OnComplete + 'static,
{
    let eventfd = Arc::new(EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)?);
    let del_evt = Mutex::new(None);
    let cloned_iothread = iothread.clone();

    let cb: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
        read_fd(fd);

        let mut notifiers = Vec::new();

        if let Some(fd) = del_evt.lock().unwrap().take() {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                fd,
                None,
                EventSet::IN,
                Vec::new(),
            ));
        }

        let async_handler = complete_handler.lock().unwrap().get_async_handler();
        let evtfd = async_handler.lock().unwrap().get_evt_fd();
        let async_notifier = vec![create_async_request_notifier(
            complete_handler.clone(),
            async_handler.clone(),
            evtfd,
        )];
        if let Err(e) = EventLoop::update_event(async_notifier, cloned_iothread.as_ref()) {
            error!("Failed to update event: {:?}", e);
        }

        *del_evt.lock().unwrap() = Some(evtfd);

        Some(notifiers)
    });

    let notifiers = vec![EventNotifier::new(
        NotifierOperation::AddShared,
        eventfd.as_raw_fd(),
        None,
        EventSet::IN,
        vec![cb],
    )];
    EventLoop::update_event(notifiers, iothread.as_ref())?;

    Ok(eventfd)
}

pub fn unregister_async_ctrl_notifier(fd: RawFd, iothread: Option<&String>) {
    let notifier = vec![EventNotifier::new(
        NotifierOperation::Delete,
        fd,
        None,
        EventSet::IN,
        Vec::new(),
    )];

    if let Err(e) = EventLoop::update_event(notifier, iothread) {
        error!("Failed to unregister async ctrl notifier, {:?}", e);
    }
}

fn create_async_request_notifier<A, T>(
    complete_handler: Arc<Mutex<T>>,
    async_handler: Arc<Mutex<A>>,
    evtfd: RawFd,
) -> EventNotifier
where
    A: AsyncMsgHandle + 'static,
    T: OnComplete + 'static,
{
    let cb: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
        read_fd(fd);

        loop {
            let Some(request) = async_handler.lock().unwrap().get_request() else {
                break;
            };

            let (res, buf) = async_handler.lock().unwrap().handle_async_request(request);
            complete_handler.lock().unwrap().on_complete(res, buf);
        }

        None
    });

    EventNotifier::new(
        NotifierOperation::AddShared,
        evtfd,
        None,
        EventSet::IN,
        vec![cb],
    )
}
