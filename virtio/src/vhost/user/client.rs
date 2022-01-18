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

use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use address_space::{
    AddressSpace, FileBackend, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd,
};
use machine_manager::event_loop::EventLoop;
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierOperation};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::super::super::{
    errors::{ErrorKind, Result, ResultExt},
    QueueConfig,
};
use super::super::VhostOps;
use super::message::{
    RegionMemInfo, VhostUserHdrFlag, VhostUserMemContext, VhostUserMemHdr, VhostUserMsgHdr,
    VhostUserMsgReq, VhostUserVringAddr, VhostUserVringState,
};
use super::sock::VhostUserSock;

struct ClientInternal {
    // Used to send requests to the vhost user backend in userspace.
    sock: VhostUserSock,
    // Maximum number of queues which is supported.
    max_queue_num: u64,
}

#[allow(dead_code)]
impl ClientInternal {
    fn new(sock: VhostUserSock, max_queue_num: u64) -> Self {
        ClientInternal {
            sock,
            max_queue_num,
        }
    }

    fn wait_ack_msg<T: Sized + Default>(&self, request: u32) -> Result<T> {
        let mut hdr = VhostUserMsgHdr::default();
        let mut body: T = Default::default();
        let payload_opt: Option<&mut [u8]> = None;

        let (recv_len, _fds_num) = self
            .sock
            .recv_msg(Some(&mut hdr), Some(&mut body), payload_opt, &mut [])
            .chain_err(|| "Failed to recv ack msg")?;

        if request != hdr.request
            || recv_len != (size_of::<VhostUserMsgHdr>() + size_of::<T>())
            || !hdr.is_reply()
        {
            bail!("The ack msg is invalid, request: {}, header request: {}, reply type: {}, recv len: {}, len: {}",
                request, hdr.request, hdr.is_reply(), recv_len, size_of::<VhostUserMsgHdr>() + size_of::<T>(),
            );
        }

        Ok(body)
    }
}

impl EventNotifierHelper for ClientInternal {
    fn internal_notifiers(client_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let mut handlers = Vec::new();

        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, _| {
                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    panic!("Receive the event of HANG_UP from vhost user backend");
                } else {
                    None
                }
            });
        handlers.push(Arc::new(Mutex::new(handler)));

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            client_handler
                .lock()
                .unwrap()
                .sock
                .domain
                .get_stream_raw_fd(),
            None,
            EventSet::HANG_UP,
            handlers,
        ));
        notifiers
    }
}

/// Struct for communication with the vhost user backend in userspace
#[derive(Clone)]
pub struct VhostUserClient {
    client: Arc<Mutex<ClientInternal>>,
    mem_info: VhostUserMemInfo,
}

#[allow(dead_code)]
impl VhostUserClient {
    pub fn new(mem_space: &Arc<AddressSpace>, path: &str, max_queue_num: u64) -> Result<Self> {
        let mut sock = VhostUserSock::new(path);
        sock.domain.connect().chain_err(|| {
            format!(
                "Failed to connect the socket {} for vhost user client",
                path
            )
        })?;

        let mem_info = VhostUserMemInfo::new();
        mem_space
            .register_listener(Arc::new(Mutex::new(mem_info.clone())))
            .chain_err(|| "Failed to register memory for vhost user client")?;

        let client = Arc::new(Mutex::new(ClientInternal::new(sock, max_queue_num)));
        Ok(VhostUserClient { client, mem_info })
    }

    pub fn add_event_notifier(&self) -> Result<()> {
        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(self.client.clone()),
            None,
        )
        .chain_err(|| "Failed to update event for client sock")?;

        Ok(())
    }
}
