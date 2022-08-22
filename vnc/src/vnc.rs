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
    sync::{Arc, Mutex},
};
use util::loop_context::EventNotifierHelper;
use vmm_sys_util::epoll::EventSet;

use crate::VncServer;

pub fn vnc_init(vnc_cfg: &VncConfig, object: &HashMap<String, ObjConfig>) -> Result<()> {
    let addr = format!("{}:{}", vnc_cfg.ip, vnc_cfg.port);
    let listener: TcpListener;
    match TcpListener::bind(&addr.as_str()) {
        Ok(l) => listener = l,
        Err(e) => {
            let msg = format!("Bind {} failed {}", addr, e);
            error!("{}", e);
            return Err(ErrorKind::TcpBindFailed(msg).into());
        }
    }

    listener
        .set_nonblocking(true)
        .expect("Set noblocking for vnc socket failed");

    let mut server = VncServer::new(Arc::new(Mutex::new(listener)));

    // Parameter configuation for VncServeer.
    if let Err(err) = server.make_config(vnc_cfg, object) {
        return Err(err);
    }

    // Add an VncServer.
    add_vnc_server(server);

    EventLoop::update_event(
        EventNotifierHelper::internal_notifiers(VNC_SERVERS.lock().unwrap()[0].clone()),
        None,
    )?;

    Ok(())
}

/// Add a vnc server during initialization.
fn add_vnc_server(server: VncServer) {
    VNC_SERVERS
        .lock()
        .unwrap()
        .push(Arc::new(Mutex::new(server)));
}

pub static VNC_SERVERS: Lazy<Mutex<Vec<Arc<Mutex<VncServer>>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));
