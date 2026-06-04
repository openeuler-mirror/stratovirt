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
    collections::VecDeque,
    io,
    os::fd::{AsRawFd, RawFd},
    rc::Rc,
    sync::{Arc, LazyLock, Mutex},
};

use log::{error, warn};
use thiserror::Error;

use crate::TPM_TIS_BUFFER_MAX;
use machine_manager::event_loop::EventLoop;
use util::loop_context::{
    gen_park_notifiers, read_fd, EventNotifier, NotifierCallback, NotifierOperation,
};
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
    fn handle_async_request(&mut self, request: AsyncMsg) -> (Result<()>, Vec<u8>);

    fn get_evt_fd(&self) -> Arc<EventFd>;

    fn get_data_fd(&self) -> Option<RawFd> {
        None
    }
}

/*
 * TPM device should implement this trait.
 */
pub trait OnComplete {
    type T: AsyncMsgHandle;

    fn on_complete(&mut self, res: Result<()>, buf: Vec<u8>);

    fn get_async_handler(&self) -> Arc<Mutex<Self::T>>;
}

#[derive(Default)]
struct AsyncCtrl {
    requests: VecDeque<AsyncMsg>,
    evt: Option<Arc<EventFd>>,
    data_fd: Option<RawFd>,
}

static ASYNC_CTRL: LazyLock<Mutex<AsyncCtrl>> = LazyLock::new(|| Mutex::new(AsyncCtrl::default()));

pub fn deliver_request(msg: AsyncMsg) {
    let mut async_ctrl = ASYNC_CTRL.lock().unwrap();

    if async_ctrl.evt.is_none() {
        warn!("there's no evet fd to notify async handler of tpm data request");
        return;
    }

    async_ctrl.requests.push_back(msg);
    if let Err(e) = async_ctrl.evt.as_ref().unwrap().write(1) {
        error!("Failed to write event fd, {:?}", e);
    }
}

fn pop_request() -> Option<AsyncMsg> {
    ASYNC_CTRL.lock().unwrap().requests.pop_front()
}

fn async_ctrl_reset() {
    let mut async_ctrl = ASYNC_CTRL.lock().unwrap();
    async_ctrl.requests.clear();
    async_ctrl.evt = None;
    async_ctrl.data_fd = None;
}

fn async_ctrl_init(evt: Arc<EventFd>, data_fd: RawFd) {
    let mut async_ctrl = ASYNC_CTRL.lock().unwrap();
    async_ctrl.requests.clear();
    async_ctrl.evt = Some(evt);
    async_ctrl.data_fd = Some(data_fd);
}

fn async_evt_take() -> Option<Arc<EventFd>> {
    ASYNC_CTRL.lock().unwrap().evt.take()
}

fn async_data_fd_take() -> Option<RawFd> {
    ASYNC_CTRL.lock().unwrap().data_fd.take()
}

pub fn register_async_ctrl_notifier<T>(
    complete_handler: Arc<Mutex<T>>,
    iothread: Option<String>,
) -> Result<Arc<EventFd>>
where
    T: OnComplete + 'static,
{
    let eventfd = Arc::new(EventFd::new(libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)?);
    let cloned_iothread = iothread.clone();

    let cb: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
        read_fd(fd);

        let mut notifiers = Vec::new();

        if let Some(evt) = async_evt_take() {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                evt.as_raw_fd(),
                None,
                EventSet::IN,
                Vec::new(),
            ));
        }

        if let Some(data_fd) = async_data_fd_take() {
            notifiers.push(EventNotifier::new(
                NotifierOperation::Delete,
                data_fd,
                None,
                EventSet::HANG_UP,
                Vec::new(),
            ));
        }

        let async_handler = complete_handler.lock().unwrap().get_async_handler();

        let evt = async_handler.lock().unwrap().get_evt_fd();
        let async_notifier = vec![create_async_request_notifier(
            complete_handler.clone(),
            async_handler.clone(),
            evt.as_raw_fd(),
        )];
        if let Err(e) = EventLoop::update_event(async_notifier, cloned_iothread.as_ref()) {
            error!("Failed to update event: {:?}", e);
            async_ctrl_reset();
            return Some(notifiers);
        }

        let data_fd = async_handler.lock().unwrap().get_data_fd().unwrap();
        let data_fd_notifier = vec![create_data_stream_notifier(
            data_fd,
            complete_handler.clone(),
        )];
        if let Err(e) = EventLoop::update_event(data_fd_notifier, cloned_iothread.as_ref()) {
            error!("Failed to update event: {:?}", e);
            async_ctrl_reset();
            return Some(notifiers);
        }

        async_ctrl_init(evt, data_fd);

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
    async_ctrl_reset();

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
            let Some(request) = pop_request() else {
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

pub fn create_data_stream_notifier<T>(fd: RawFd, complete_handler: Arc<Mutex<T>>) -> EventNotifier
where
    T: OnComplete + 'static,
{
    let cb: Rc<NotifierCallback> = Rc::new(move |event: EventSet, fd: RawFd| {
        if event.contains(EventSet::HANG_UP) {
            error!("TPM data stream disconnect/hang detected on fd {}", fd);
            complete_handler
                .lock()
                .unwrap()
                .on_complete(Err(AioError::Disconnected), vec![0; TPM_TIS_BUFFER_MAX]);
            return Some(gen_park_notifiers(&[fd], EventSet::HANG_UP));
        }
        None
    });

    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::HANG_UP,
        vec![cb],
    )
}
