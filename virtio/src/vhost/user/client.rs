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
use std::slice::from_raw_parts;
use std::sync::{Arc, Mutex};

use address_space::{
    AddressSpace, FileBackend, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd,
};
use error_chain::bail;
use log::{error, info, warn};
use machine_manager::event_loop::EventLoop;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::super::super::{
    errors::{ErrorKind, Result, ResultExt},
    Queue, QueueConfig, VIRTIO_NET_F_CTRL_VQ,
};
use super::super::VhostOps;
use super::message::{
    RegionMemInfo, VhostUserHdrFlag, VhostUserMemContext, VhostUserMemHdr, VhostUserMsgHdr,
    VhostUserMsgReq, VhostUserVringAddr, VhostUserVringState,
};
use super::sock::VhostUserSock;
use crate::block::VirtioBlkConfig;
use crate::VhostUser::message::VhostUserConfig;

/// Vhost supports multiple queue
pub const VHOST_USER_PROTOCOL_F_MQ: u8 = 0;
/// Vhost supports `VHOST_USER_GET_CONFIG` and `VHOST_USER_GET_CONFIG` msg.
pub const VHOST_USER_PROTOCOL_F_CONFIG: u8 = 9;

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

fn vhost_user_reconnect(client: &Arc<Mutex<VhostUserClient>>) {
    let cloned_client = client.clone();
    let func = Box::new(move || {
        vhost_user_reconnect(&cloned_client);
    });

    info!("Try to reconnect vhost-user net.");
    let cloned_client = client.clone();
    if let Err(_e) = client
        .lock()
        .unwrap()
        .client
        .lock()
        .unwrap()
        .sock
        .domain
        .connect()
    {
        if let Some(ctx) = EventLoop::get_ctx(None) {
            // Default reconnecting time: 3s.
            ctx.delay_call(func, 3 * 1_000_000_000);
        } else {
            error!("Failed to get ctx to delay vhost-user reconnecting");
        }
        return;
    }

    client.lock().unwrap().reconnecting = false;
    if let Err(e) =
        EventLoop::update_event(EventNotifierHelper::internal_notifiers(cloned_client), None)
    {
        error!("Failed to update event for client sock, {}", e);
    }

    if let Err(e) = client.lock().unwrap().activate_vhost_user() {
        error!("Failed to reactivate vhost-user net, {}", e);
    } else {
        info!("Reconnecting vhost-user net succeed.");
    }
}

impl EventNotifierHelper for VhostUserClient {
    fn internal_notifiers(client_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let mut handlers = Vec::new();

        let cloned_client = client_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, _| {
                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    let mut locked_client = cloned_client.lock().unwrap();
                    if let Err(e) = locked_client.delete_event() {
                        error!("Failed to delete vhost-user client event, {}", e);
                    }
                    if !locked_client.reconnecting {
                        locked_client.reconnecting = true;
                        drop(locked_client);
                        vhost_user_reconnect(&cloned_client);
                    }
                    None
                } else {
                    None
                }
            });
        handlers.push(Arc::new(Mutex::new(handler)));

        let locked_client = client_handler.lock().unwrap();
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            locked_client
                .client
                .lock()
                .unwrap()
                .sock
                .domain
                .get_stream_raw_fd(),
            None,
            EventSet::HANG_UP,
            handlers,
        ));

        // Register event notifier for delete_evt.
        let cloned_client = client_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(cloned_client.lock().unwrap().delete_evt_handler())
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            locked_client.delete_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}

#[derive(Clone)]
struct RegionInfo {
    region: RegionMemInfo,
    file_back: FileBackend,
}

#[derive(Clone)]
struct VhostUserMemInfo {
    regions: Arc<Mutex<Vec<RegionInfo>>>,
}

#[allow(dead_code)]
impl VhostUserMemInfo {
    fn new() -> Self {
        VhostUserMemInfo {
            regions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn addr_to_host(&self, addr: GuestAddress) -> Option<u64> {
        let addr = addr.raw_value();
        for reg_info in self.regions.lock().unwrap().iter() {
            if addr >= reg_info.region.guest_phys_addr
                && addr < reg_info.region.guest_phys_addr + reg_info.region.memory_size
            {
                let offset = addr - reg_info.region.guest_phys_addr;
                return Some(reg_info.region.userspace_addr + offset);
            }
        }
        None
    }

    fn add_mem_range(&self, fr: &FlatRange) -> address_space::errors::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let guest_phys_addr = fr.addr_range.base.raw_value();
        let memory_size = fr.addr_range.size;
        let host_address = match fr.owner.get_host_address() {
            Some(addr) => addr,
            None => bail!("Failed to get host address to add mem range for vhost user device"),
        };
        let file_back = match fr.owner.get_file_backend() {
            Some(file_back_) => file_back_,
            _ => {
                info!("It is not share memory for vhost user device");
                return Ok(());
            }
        };

        let region = RegionMemInfo {
            guest_phys_addr,
            memory_size,
            userspace_addr: host_address + fr.offset_in_region,
            mmap_offset: file_back.offset + fr.offset_in_region,
        };
        let region_info = RegionInfo { region, file_back };
        self.regions.lock().unwrap().push(region_info);

        Ok(())
    }

    fn delete_mem_range(&self, fr: &FlatRange) -> address_space::errors::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let file_back = fr.owner.get_file_backend().unwrap();
        let mut mem_regions = self.regions.lock().unwrap();
        let host_address = match fr.owner.get_host_address() {
            Some(addr) => addr,
            None => bail!("Failed to get host address to del mem range for vhost user device"),
        };
        let target = RegionMemInfo {
            guest_phys_addr: fr.addr_range.base.raw_value(),
            memory_size: fr.addr_range.size,
            userspace_addr: host_address + fr.offset_in_region,
            mmap_offset: file_back.offset + fr.offset_in_region,
        };

        for (index, region_info) in mem_regions.iter().enumerate() {
            let mr = &region_info.region;
            if *mr == target && region_info.file_back.file.as_raw_fd() == file_back.file.as_raw_fd()
            {
                mem_regions.remove(index);
                return Ok(());
            }
        }
        warn!(
            "Vhost user: deleting mem region {:?} failed: not matched",
            target
        );

        Ok(())
    }
}

impl Listener for VhostUserMemInfo {
    fn priority(&self) -> i32 {
        0
    }

    fn handle_request(
        &self,
        range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> std::result::Result<(), address_space::errors::Error> {
        match req_type {
            ListenerReqType::AddRegion => {
                self.add_mem_range(range.unwrap())?;
            }
            ListenerReqType::DeleteRegion => {
                self.delete_mem_range(range.unwrap())?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Struct for communication with the vhost user backend in userspace
pub struct VhostUserClient {
    client: Arc<Mutex<ClientInternal>>,
    mem_info: VhostUserMemInfo,
    delete_evt: EventFd,
    queues: Vec<Arc<Mutex<Queue>>>,
    queue_evts: Vec<EventFd>,
    call_events: Vec<EventFd>,
    pub features: u64,
    reconnecting: bool,
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
        let delete_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        Ok(VhostUserClient {
            client,
            mem_info,
            delete_evt,
            queues: Vec::new(),
            queue_evts: Vec::new(),
            call_events: Vec::new(),
            features: 0,
            reconnecting: false,
        })
    }

    /// Save queue info used for reconnection.
    pub fn set_queues(&mut self, queues: &[Arc<Mutex<Queue>>]) {
        for (queue_index, _) in queues.iter().enumerate() {
            self.queues.push(queues[queue_index].clone());
        }
    }

    /// Save eventfd used for reconnection.
    pub fn set_queue_evts(&mut self, queue_evts: &[EventFd]) {
        for evt in queue_evts.iter() {
            self.queue_evts.push(evt.try_clone().unwrap());
        }
    }

    /// Save irqfd used for reconnection.
    pub fn set_call_events(&mut self, call_events: &[EventFd]) {
        for evt in call_events.iter() {
            self.call_events.push(evt.try_clone().unwrap());
        }
    }

    /// Activate device by vhost-user protocol.
    pub fn activate_vhost_user(&mut self) -> Result<()> {
        self.set_owner()
            .chain_err(|| "Failed to set owner for vhost-user net")?;

        self.set_features(self.features)
            .chain_err(|| "Failed to set features for vhost-user net")?;

        self.set_mem_table()
            .chain_err(|| "Failed to set mem table for vhost-user net")?;

        let mut queue_num = self.queues.len();
        if ((self.features & (1 << VIRTIO_NET_F_CTRL_VQ)) != 0) && (queue_num % 2 != 0) {
            queue_num -= 1;
        }
        // Set all vring num to notify ovs/dpdk how many queues it needs to poll
        // before setting vring info.
        for (queue_index, queue_mutex) in self.queues.iter().enumerate().take(queue_num) {
            let queue = queue_mutex.lock().unwrap();
            let actual_size = queue.vring.actual_size();
            self.set_vring_num(queue_index, actual_size).chain_err(|| {
                format!(
                    "Failed to set vring num for vhost-user net, index: {}, size: {}",
                    queue_index, actual_size,
                )
            })?;
        }

        for (queue_index, queue_mutex) in self.queues.iter().enumerate().take(queue_num) {
            let queue = queue_mutex.lock().unwrap();
            let queue_config = queue.vring.get_queue_config();

            self.set_vring_addr(&queue_config, queue_index, 0)
                .chain_err(|| {
                    format!(
                        "Failed to set vring addr for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_base(queue_index, 0).chain_err(|| {
                format!(
                    "Failed to set vring base for vhost-user net, index: {}",
                    queue_index,
                )
            })?;
            self.set_vring_kick(queue_index, &self.queue_evts[queue_index])
                .chain_err(|| {
                    format!(
                        "Failed to set vring kick for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_call(queue_index, &self.call_events[queue_index])
                .chain_err(|| {
                    format!(
                        "Failed to set vring call for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
        }

        for (queue_index, _) in self.queues.iter().enumerate().take(queue_num) {
            self.set_vring_enable(queue_index, true).chain_err(|| {
                format!(
                    "Failed to set vring enable for vhost-user net, index: {}",
                    queue_index,
                )
            })?;
        }

        Ok(())
    }

    /// Delete the socket event in ClientInternal.
    pub fn delete_event(&self) -> Result<()> {
        self.delete_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)?;
        Ok(())
    }

    fn delete_evt_handler(&mut self) -> Vec<EventNotifier> {
        vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.client.lock().unwrap().sock.domain.get_stream_raw_fd(),
                None,
                EventSet::HANG_UP,
                vec![],
            ),
            EventNotifier::new(
                NotifierOperation::Delete,
                self.delete_evt.as_raw_fd(),
                None,
                EventSet::IN,
                vec![],
            ),
        ]
    }

    /// Send get protocol features request to vhost.
    pub fn get_protocol_features(&self) -> Result<u64> {
        let client = self.client.lock().unwrap();
        let request = VhostUserMsgReq::GetProtocolFeatures as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .chain_err(|| "Failed to send msg for getting features")?;
        let features = client
            .wait_ack_msg::<u64>(request)
            .chain_err(|| "Failed to wait ack msg for getting protocols features")?;

        Ok(features)
    }

    /// Send set protocol features request to vhost.
    pub fn set_protocol_features(&self, features: u64) -> Result<()> {
        let client = self.client.lock().unwrap();
        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetProtocolFeatures as u32,
            0,
            size_of::<u64>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), Some(&features), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting protocols features")?;

        Ok(())
    }

    /// Get virtio blk config from vhost.
    pub fn get_virtio_blk_config(&self) -> Result<VirtioBlkConfig> {
        let client = self.client.lock().unwrap();
        let request = VhostUserMsgReq::GetConfig as u32;
        let config_len = size_of::<VhostUserConfig<VirtioBlkConfig>>();
        let hdr = VhostUserMsgHdr::new(
            request,
            VhostUserHdrFlag::NeedReply as u32,
            config_len as u32,
        );
        let cnf = VhostUserConfig::new(0, 0, VirtioBlkConfig::default())?;
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = Some(unsafe {
            from_raw_parts(
                (&cnf as *const VhostUserConfig<VirtioBlkConfig>) as *const u8,
                config_len,
            )
        });
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .chain_err(|| "Failed to send msg for getting config")?;
        let res = client
            .wait_ack_msg::<VhostUserConfig<VirtioBlkConfig>>(request)
            .chain_err(|| "Failed to wait ack msg for getting virtio blk config")?;
        Ok(res.config)
    }

    /// Set virtio blk config to vhost.
    pub fn set_virtio_blk_config(&self, cnf: VirtioBlkConfig) -> Result<()> {
        let client = self.client.lock().unwrap();
        let request = VhostUserMsgReq::SetConfig as u32;
        let config_len = size_of::<VhostUserConfig<VirtioBlkConfig>>();
        let hdr = VhostUserMsgHdr::new(request, 0, config_len as u32);
        let payload_opt: Option<&[u8]> = None;
        let config = VhostUserConfig::new(0, 0, cnf)?;
        client
            .sock
            .send_msg(Some(&hdr), Some(&config), payload_opt, &[])
            .chain_err(|| "Failed to send msg for getting virtio blk config")?;
        Ok(())
    }

    /// Get max queues number that vhost supports.
    pub fn get_max_queue_num(&self) -> Result<u64> {
        let client = self.client.lock().unwrap();
        let request = VhostUserMsgReq::GetQueueNum as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .chain_err(|| "Failed to send msg for getting queue num")?;
        let queue_num = client
            .wait_ack_msg::<u64>(request)
            .chain_err(|| "Failed to wait ack msg for getting queue num")?;
        Ok(queue_num)
    }
}

impl VhostOps for VhostUserClient {
    fn set_owner(&self) -> Result<()> {
        let client = self.client.lock().unwrap();
        let hdr = VhostUserMsgHdr::new(VhostUserMsgReq::SetOwner as u32, 0, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting owner")?;

        Ok(())
    }

    fn get_features(&self) -> Result<u64> {
        let client = self.client.lock().unwrap();
        let request = VhostUserMsgReq::GetFeatures as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .chain_err(|| "Failed to send msg for getting features")?;
        let features = client
            .wait_ack_msg::<u64>(request)
            .chain_err(|| "Failed to wait ack msg for getting features")?;

        Ok(features)
    }

    fn set_features(&self, features: u64) -> Result<()> {
        let client = self.client.lock().unwrap();
        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetFeatures as u32,
            0,
            size_of::<u64>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), Some(&features), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting features")?;

        Ok(())
    }

    fn set_mem_table(&self) -> Result<()> {
        let mem_regions = self.mem_info.regions.lock().unwrap();
        if mem_regions.is_empty() {
            bail!("Failed to initial vhost user memory map, consider using command mem-share=on");
        }

        let num_region = mem_regions.len();
        let mut fds = Vec::with_capacity(num_region);
        let mut memcontext = VhostUserMemContext::default();
        for region_info in mem_regions.iter() {
            memcontext.region_add(region_info.region);
            fds.push(region_info.file_back.file.as_raw_fd());
        }

        let client = self.client.lock().unwrap();
        let len = size_of::<VhostUserMemHdr>() + num_region * size_of::<RegionMemInfo>();
        let hdr = VhostUserMsgHdr::new(VhostUserMsgReq::SetMemTable as u32, 0, len as u32);
        let memhdr = VhostUserMemHdr::new(num_region as u32, 0);
        client
            .sock
            .send_msg(
                Some(&hdr),
                Some(&memhdr),
                Some(memcontext.regions.as_slice()),
                &fds,
            )
            .chain_err(|| "Failed to send msg for setting mem table")?;

        Ok(())
    }

    fn set_vring_num(&self, queue_idx: usize, num: u16) -> Result<()> {
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invaild {} for setting vring num",
                queue_idx,
                client.max_queue_num
            );
        }

        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringNum as u32,
            0,
            size_of::<VhostUserVringState>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        let vring_state = VhostUserVringState::new(queue_idx as u32, num as u32);
        client
            .sock
            .send_msg(Some(&hdr), Some(&vring_state), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting vring num")?;

        Ok(())
    }

    fn set_vring_addr(&self, queue: &QueueConfig, index: usize, flags: u32) -> Result<()> {
        let client = self.client.lock().unwrap();
        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringAddr as u32,
            0,
            size_of::<VhostUserVringAddr>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        let desc_user_addr = self
            .mem_info
            .addr_to_host(queue.desc_table)
            .ok_or_else(|| {
                ErrorKind::Msg(format!(
                    "Failed to transform desc-table address {}",
                    queue.desc_table.0
                ))
            })?;

        let used_user_addr = self.mem_info.addr_to_host(queue.used_ring).ok_or_else(|| {
            ErrorKind::Msg(format!(
                "Failed to transform used ring address {}",
                queue.used_ring.0
            ))
        })?;

        let avail_user_addr = self
            .mem_info
            .addr_to_host(queue.avail_ring)
            .ok_or_else(|| {
                ErrorKind::Msg(format!(
                    "Failed to transform avail ring address {}",
                    queue.avail_ring.0
                ))
            })?;
        let vring_addr = VhostUserVringAddr {
            index: index as u32,
            flags,
            desc_user_addr,
            used_user_addr,
            avail_user_addr,
            log_guest_addr: 0_u64,
        };
        client
            .sock
            .send_msg(Some(&hdr), Some(&vring_addr), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting vring addr")?;

        Ok(())
    }

    fn set_vring_base(&self, queue_idx: usize, last_avail_idx: u16) -> Result<()> {
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invalid {} for setting vring base",
                queue_idx,
                client.max_queue_num
            );
        }

        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringBase as u32,
            0,
            size_of::<VhostUserVringState>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        let vring_state = VhostUserVringState::new(queue_idx as u32, last_avail_idx as u32);
        client
            .sock
            .send_msg(Some(&hdr), Some(&vring_state), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting vring base")?;

        Ok(())
    }

    fn set_vring_call(&self, queue_idx: usize, fd: &EventFd) -> Result<()> {
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invalid {} for setting vring call",
                queue_idx,
                client.max_queue_num
            );
        }

        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringCall as u32,
            0,
            size_of::<usize>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), Some(&queue_idx), payload_opt, &[fd.as_raw_fd()])
            .chain_err(|| "Failed to send msg for setting vring call")?;

        Ok(())
    }

    fn set_vring_kick(&self, queue_idx: usize, fd: &EventFd) -> Result<()> {
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invaild {} for setting vring kick",
                queue_idx,
                client.max_queue_num
            );
        }

        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringKick as u32,
            0,
            size_of::<usize>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        client
            .sock
            .send_msg(Some(&hdr), Some(&queue_idx), payload_opt, &[fd.as_raw_fd()])
            .chain_err(|| "Failed to send msg for setting vring kick")?;

        Ok(())
    }

    fn set_vring_enable(&self, queue_idx: usize, status: bool) -> Result<()> {
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invaild {} for setting vring enable",
                queue_idx,
                client.max_queue_num
            );
        }

        let hdr = VhostUserMsgHdr::new(
            VhostUserMsgReq::SetVringEnable as u32,
            0,
            size_of::<VhostUserVringState>() as u32,
        );
        let payload_opt: Option<&[u8]> = None;
        let vring_state = VhostUserVringState::new(queue_idx as u32, status as u32);
        client
            .sock
            .send_msg(Some(&hdr), Some(&vring_state), payload_opt, &[])
            .chain_err(|| "Failed to send msg for setting vring enable")?;

        Ok(())
    }

    fn reset_owner(&self) -> Result<()> {
        bail!("Does not support for resetting owner")
    }

    fn get_vring_base(&self, _queue_idx: usize) -> Result<u16> {
        bail!("Does not support for getting vring base")
    }
}
