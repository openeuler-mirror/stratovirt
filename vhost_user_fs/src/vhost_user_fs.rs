// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
    rc::Rc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use log::error;
use vmm_sys_util::epoll::EventSet;

use machine_manager::{event_loop::EventLoop, temp_cleaner::TempCleaner};
use util::loop_context::{
    EventLoopManager, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

use super::cmdline::FsConfig;
use super::fs::set_rlimit_nofile;
use super::vhost_user_server::VhostUserServerHandler;
use super::virtio_fs::VirtioFs;

use anyhow::{Context, Result};

/// The vhost-user filesystem device contains virtio fs device and the vhost-user
/// server which can be connected with the vhost-user client in StratoVirt.
#[derive(Clone)]
pub struct VhostUserFs {
    /// Used to communicate with StratoVirt.
    server_handler: VhostUserServerHandler,
    /// Used to determine whether the process should be terminated.
    should_exit: Arc<AtomicBool>,
}

trait CreateEventNotifier {
    fn create_event_notifier(
        &mut self,
        server_handler: Arc<Mutex<Self>>,
    ) -> Option<Vec<EventNotifier>>;
}

impl CreateEventNotifier for VhostUserServerHandler {
    fn create_event_notifier(
        &mut self,
        server_handler: Arc<Mutex<Self>>,
    ) -> Option<Vec<EventNotifier>> {
        if let Err(e) = self.sock.domain.accept() {
            error!("Failed to accept the socket for vhost user server, {:?}", e);
            return None;
        }

        let mut notifiers = Vec::new();

        let should_exit = self.should_exit.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event, _| {
            if event == EventSet::IN {
                let mut lock_server_handler = server_handler.lock().unwrap();
                if let Err(e) = lock_server_handler.handle_request() {
                    error!("Failed to handle request for vhost user server, {:?}", e);
                }
            }
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                should_exit.store(true, Ordering::Release);
            }
            None
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            self.sock.domain.get_stream_raw_fd(),
            None,
            EventSet::IN | EventSet::HANG_UP,
            vec![handler],
        );
        notifiers.push(notifier);

        Some(notifiers)
    }
}

impl EventNotifierHelper for VhostUserServerHandler {
    fn internal_notifiers(server_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let server_handler_clone = server_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, _| {
            server_handler_clone
                .lock()
                .unwrap()
                .create_event_notifier(server_handler_clone.clone())
        });
        let notifier = EventNotifier::new(
            NotifierOperation::AddShared,
            server_handler
                .lock()
                .unwrap()
                .sock
                .domain
                .get_listener_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        );
        notifiers.push(notifier);

        notifiers
    }
}

impl VhostUserFs {
    /// Create a new vhost-user filesystem device.
    ///
    /// # Arguments
    ///
    /// * `fs_config` - Configuration of the vhost-user filesystem device.
    pub fn new(fs_config: FsConfig) -> Result<Self> {
        let should_exit = Arc::new(AtomicBool::new(false));

        if let Some(limit) = fs_config.rlimit_nofile {
            set_rlimit_nofile(limit)
                .with_context(|| format!("Failed to set rlimit nofile {}", limit))?;
        }

        let sock_path = fs_config.sock_path.clone();
        let virtio_fs = Arc::new(Mutex::new(
            VirtioFs::new(fs_config).with_context(|| "Failed to create virtio fs")?,
        ));

        let server_handler =
            VhostUserServerHandler::new(sock_path.as_str(), virtio_fs, should_exit.clone())
                .with_context(|| "Failed to create vhost user server")?;

        Ok(VhostUserFs {
            server_handler,
            should_exit,
        })
    }

    /// Add events to epoll handler for the vhost-user filesystem device.
    pub fn add_event_notifier(&self) -> Result<()> {
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(
                self.server_handler.clone(),
            ))),
            None,
        )?;

        Ok(())
    }
}

impl EventLoopManager for VhostUserFs {
    fn loop_should_exit(&self) -> bool {
        self.should_exit.load(Ordering::Acquire)
    }

    fn loop_cleanup(&self) -> util::Result<()> {
        TempCleaner::clean();
        Ok(())
    }
}
