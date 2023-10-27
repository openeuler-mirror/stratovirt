// Copyright (c) 2021 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod fs;

mod block;
mod client;
mod message;
mod net;
mod sock;

pub use self::block::Block;
pub use self::client::*;
pub use self::fs::*;
pub use self::message::*;
pub use self::net::Net;
pub use self::sock::*;

use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::{
    vhost::{VhostIoHandler, VhostNotify},
    NotifyEventFds, VirtioBase, VirtioInterrupt,
};

use machine_manager::event_loop::register_event_helper;
use util::loop_context::EventNotifierHelper;

pub fn listen_guest_notifier(
    base: &mut VirtioBase,
    client: &mut VhostUserClient,
    ctx_name: Option<&String>,
    evts_num: usize,
    interrupt_cb: Arc<VirtioInterrupt>,
) -> Result<()> {
    let call_evts = NotifyEventFds::new(evts_num);
    let events = &call_evts.events;
    client.set_call_events(events);

    let mut host_notifies = Vec::new();
    for (queue_index, queue_mutex) in base.queues.iter().enumerate() {
        if queue_index >= events.len() {
            break;
        }
        let host_notify = VhostNotify {
            notify_evt: events[queue_index].clone(),
            queue: queue_mutex.clone(),
        };
        host_notifies.push(host_notify);
    }

    let handler = VhostIoHandler {
        interrupt_cb,
        host_notifies,
        device_broken: base.broken.clone(),
    };
    let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
    register_event_helper(notifiers, ctx_name, &mut base.deactivate_evts)?;

    Ok(())
}
