// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights r&eserved.
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

use super::errors::{ErrorKind, Result};
use machine_manager::{
    config::{ObjConfig, VncConfig},
    event_loop::EventLoop,
};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    net::TcpListener,
    os::unix::prelude::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};
use util::loop_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation};
use vmm_sys_util::epoll::EventSet;

use crate::{VncClient, VNC_SERVERS};

/// VncServer
#[derive(Clone)]
pub struct VncServer {
    // Tcp connection listened by server.
    listener: Arc<Mutex<TcpListener>>,
    // Clients connected to vnc.
    pub clients: HashMap<String, Arc<Mutex<VncClient>>>,
    // Connection limit.
    conn_limits: usize,
}

impl VncServer {
    /// Create a new VncServer.
    pub fn new(listener: Arc<Mutex<TcpListener>>) -> Self {
        VncServer {
            listener,
            clients: HashMap::new(),
            conn_limits: 1,
        }
    }

    /// Make configuration for VncServer.
    pub fn make_config(
        &mut self,
        vnc_cfg: &VncConfig,
        object: &HashMap<String, ObjConfig>,
    ) -> Result<()> {
        Ok(())
    }

    /// Listen to the port and accpet client's connection.
    pub fn handle_connection(&mut self) -> Result<()> {
        Ok(())
    }
}

/// internal_notifiers for VncServer.
impl EventNotifierHelper for VncServer {
    fn internal_notifiers(server_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let server = server_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, fd: RawFd| {
                read_fd(fd);

                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    info!("Client closed.");
                } else if event == EventSet::IN {
                    let mut locked_handler = server.lock().unwrap();
                    if let Err(e) = locked_handler.handle_connection() {
                        error!("Failed to handle vnc client connection, error is {}", e);
                    }
                    drop(locked_handler);
                }

                None as Option<Vec<EventNotifier>>
            });

        let mut notifiers = Vec::new();
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            server_handler
                .lock()
                .unwrap()
                .listener
                .lock()
                .unwrap()
                .as_raw_fd(),
            None,
            EventSet::IN | EventSet::HANG_UP,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}
