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
use std::rc::Rc;
use std::slice::from_raw_parts;
use std::sync::{Arc, Mutex};

use address_space::{
    AddressSpace, FileBackend, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd,
};
use log::{error, info, warn};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper, EventLoop};
use util::loop_context::{
    gen_delete_notifiers, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::time::NANOSECONDS_PER_SECOND;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::super::super::{Queue, QueueConfig, VIRTIO_NET_F_CTRL_VQ};
use super::super::VhostOps;
use super::message::{
    RegionMemInfo, VhostUserHdrFlag, VhostUserMemContext, VhostUserMemHdr, VhostUserMsgHdr,
    VhostUserMsgReq, VhostUserVringAddr, VhostUserVringState,
};
use super::sock::VhostUserSock;
use crate::block::VirtioBlkConfig;
use crate::VhostUser::message::VhostUserConfig;
use anyhow::{anyhow, bail, Context, Result};

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
            .with_context(|| "Failed to recv ack msg")?;

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
            ctx.delay_call(func, 3 * NANOSECONDS_PER_SECOND);
        } else {
            error!("Failed to get ctx to delay vhost-user reconnecting");
        }
        return;
    }

    client.lock().unwrap().reconnecting = false;
    if let Err(e) = VhostUserClient::add_event(client) {
        error!("Failed to update event for client sock, {:?}", e);
    }

    if let Err(e) = client.lock().unwrap().activate_vhost_user() {
        error!("Failed to reactivate vhost-user net, {:?}", e);
    } else {
        info!("Reconnecting vhost-user net succeed.");
    }
}

impl EventNotifierHelper for VhostUserClient {
    fn internal_notifiers(client_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let cloned_client = client_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event, fd| {
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                let mut locked_client = cloned_client.lock().unwrap();
                if !locked_client.reconnecting {
                    locked_client.reconnecting = true;
                    drop(locked_client);
                    vhost_user_reconnect(&cloned_client);
                }
                Some(gen_delete_notifiers(&[fd]))
            } else {
                None
            }
        });
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
            vec![handler],
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
    enabled: bool,
}

impl VhostUserMemInfo {
    fn new() -> Self {
        VhostUserMemInfo {
            regions: Arc::new(Mutex::new(Vec::new())),
            enabled: false,
        }
    }

    fn addr_to_host(&self, addr: GuestAddress) -> Option<u64> {
        let addr = addr.raw_value();
        for reg_info in self.regions.lock().unwrap().iter() {
            let gpa_end = reg_info
                .region
                .guest_phys_addr
                .checked_add(reg_info.region.memory_size)
                .ok_or_else(|| {
                    anyhow!(
                        "Overflow when adding gpa with memory_size in region {:x?}",
                        reg_info.region
                    )
                })
                .ok()?;
            if addr >= reg_info.region.guest_phys_addr && addr < gpa_end {
                let offset = addr - reg_info.region.guest_phys_addr;
                return Some(reg_info.region.userspace_addr + offset);
            }
        }
        None
    }

    fn add_mem_range(&self, fr: &FlatRange) -> address_space::Result<()> {
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

    fn delete_mem_range(&self, fr: &FlatRange) -> address_space::Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let file_back = fr
            .owner
            .get_file_backend()
            .ok_or_else(|| anyhow!("Failed to get file backend"))?;
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

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }

    fn handle_request(
        &self,
        range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> std::result::Result<(), anyhow::Error> {
        match req_type {
            ListenerReqType::AddRegion => {
                self.add_mem_range(
                    range.ok_or_else(|| anyhow!("Flat range is None when adding region"))?,
                )?;
            }
            ListenerReqType::DeleteRegion => {
                self.delete_mem_range(
                    range.ok_or_else(|| anyhow!("Flat range is None when deleting region"))?,
                )?;
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
    delete_evts: Vec<RawFd>,
    queues: Vec<Arc<Mutex<Queue>>>,
    queue_evts: Vec<Arc<EventFd>>,
    call_events: Vec<Arc<EventFd>>,
    pub features: u64,
    reconnecting: bool,
}

impl VhostUserClient {
    pub fn new(mem_space: &Arc<AddressSpace>, path: &str, max_queue_num: u64) -> Result<Self> {
        let mut sock = VhostUserSock::new(path);
        sock.domain.connect().with_context(|| {
            format!(
                "Failed to connect the socket {} for vhost user client",
                path
            )
        })?;

        let mem_info = VhostUserMemInfo::new();
        mem_space
            .register_listener(Arc::new(Mutex::new(mem_info.clone())))
            .with_context(|| "Failed to register memory for vhost user client")?;

        let client = Arc::new(Mutex::new(ClientInternal::new(sock, max_queue_num)));
        Ok(VhostUserClient {
            client,
            mem_info,
            delete_evts: Vec::new(),
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
    pub fn set_queue_evts(&mut self, queue_evts: &[Arc<EventFd>]) {
        for evt in queue_evts.iter() {
            self.queue_evts.push(evt.clone());
        }
    }

    /// Save irqfd used for reconnection.
    pub fn set_call_events(&mut self, call_events: &[Arc<EventFd>]) {
        for evt in call_events.iter() {
            self.call_events.push(evt.clone());
        }
    }

    /// Activate device by vhost-user protocol.
    pub fn activate_vhost_user(&mut self) -> Result<()> {
        self.set_owner()
            .with_context(|| "Failed to set owner for vhost-user net")?;

        self.set_features(self.features)
            .with_context(|| "Failed to set features for vhost-user net")?;

        self.set_mem_table()
            .with_context(|| "Failed to set mem table for vhost-user net")?;

        let mut queue_num = self.queues.len();
        if ((self.features & (1 << VIRTIO_NET_F_CTRL_VQ)) != 0) && (queue_num % 2 != 0) {
            queue_num -= 1;
        }
        // Set all vring num to notify ovs/dpdk how many queues it needs to poll
        // before setting vring info.
        for (queue_index, queue_mutex) in self.queues.iter().enumerate().take(queue_num) {
            let actual_size = queue_mutex.lock().unwrap().vring.actual_size();
            self.set_vring_num(queue_index, actual_size)
                .with_context(|| {
                    format!(
                        "Failed to set vring num for vhost-user net, index: {}, size: {}",
                        queue_index, actual_size,
                    )
                })?;
        }

        for (queue_index, queue_mutex) in self.queues.iter().enumerate().take(queue_num) {
            let queue_config = queue_mutex.lock().unwrap().vring.get_queue_config();
            self.set_vring_addr(&queue_config, queue_index, 0)
                .with_context(|| {
                    format!(
                        "Failed to set vring addr for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_base(queue_index, 0).with_context(|| {
                format!(
                    "Failed to set vring base for vhost-user net, index: {}",
                    queue_index,
                )
            })?;
            self.set_vring_kick(queue_index, self.queue_evts[queue_index].clone())
                .with_context(|| {
                    format!(
                        "Failed to set vring kick for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_call(queue_index, self.call_events[queue_index].clone())
                .with_context(|| {
                    format!(
                        "Failed to set vring call for vhost-user net, index: {}",
                        queue_index,
                    )
                })?;
        }

        for (queue_index, _) in self.queues.iter().enumerate().take(queue_num) {
            self.set_vring_enable(queue_index, true).with_context(|| {
                format!(
                    "Failed to set vring enable for vhost-user net, index: {}",
                    queue_index,
                )
            })?;
        }

        Ok(())
    }

    pub fn reset_vhost_user(&mut self) -> Result<()> {
        let mut queue_num = self.queues.len();
        if ((self.features & (1 << VIRTIO_NET_F_CTRL_VQ)) != 0) && (queue_num % 2 != 0) {
            queue_num -= 1;
        }

        for (queue_index, _) in self.queues.iter().enumerate().take(queue_num) {
            self.set_vring_enable(queue_index, false)
                .with_context(|| format!("Failed to set vring disable, index: {}", queue_index))?;
            self.get_vring_base(queue_index)
                .with_context(|| format!("Failed to get vring base, index: {}", queue_index))?;
        }

        self.queue_evts.clear();
        self.call_events.clear();
        self.queues.clear();

        Ok(())
    }

    pub fn add_event(client: &Arc<Mutex<Self>>) -> Result<()> {
        let notifiers = EventNotifierHelper::internal_notifiers(client.clone());
        register_event_helper(notifiers, None, &mut client.lock().unwrap().delete_evts)
            .with_context(|| "Failed to update event for client sock")
    }

    /// Delete the socket event in ClientInternal.
    pub fn delete_event(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.delete_evts)
    }

    /// Send get protocol features request to vhost.
    pub fn get_protocol_features(&self) -> Result<u64> {
        let request = VhostUserMsgReq::GetProtocolFeatures as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for getting features")?;
        let features = client
            .wait_ack_msg::<u64>(request)
            .with_context(|| "Failed to wait ack msg for getting protocols features")?;

        Ok(features)
    }

    /// Send u64 value to vhost.
    fn set_value(&self, request: VhostUserMsgReq, value: u64) -> Result<()> {
        let hdr = VhostUserMsgHdr::new(request as u32, 0, size_of::<u64>() as u32);
        let payload_opt: Option<&[u8]> = None;
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(Some(&hdr), Some(&value), payload_opt, &[])
            .with_context(|| "Failed to send msg for setting value")?;

        Ok(())
    }

    /// Set protocol features to vhost.
    pub fn set_protocol_features(&self, features: u64) -> Result<()> {
        self.set_value(VhostUserMsgReq::SetProtocolFeatures, features)
    }

    /// Get virtio blk config from vhost.
    pub fn get_virtio_blk_config(&self) -> Result<VirtioBlkConfig> {
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
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for getting config")?;
        let res = client
            .wait_ack_msg::<VhostUserConfig<VirtioBlkConfig>>(request)
            .with_context(|| "Failed to wait ack msg for getting virtio blk config")?;
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
            .with_context(|| "Failed to send msg for getting virtio blk config")?;
        Ok(())
    }

    /// Get max queues number that vhost supports.
    pub fn get_max_queue_num(&self) -> Result<u64> {
        let request = VhostUserMsgReq::GetQueueNum as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for getting queue num")?;
        let queue_num = client
            .wait_ack_msg::<u64>(request)
            .with_context(|| "Failed to wait ack msg for getting queue num")?;
        Ok(queue_num)
    }
}

impl VhostOps for VhostUserClient {
    fn set_owner(&self) -> Result<()> {
        let hdr = VhostUserMsgHdr::new(VhostUserMsgReq::SetOwner as u32, 0, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for setting owner")?;

        Ok(())
    }

    fn get_features(&self) -> Result<u64> {
        let request = VhostUserMsgReq::GetFeatures as u32;
        let hdr = VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, 0);
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = None;
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for getting features")?;
        let features = client
            .wait_ack_msg::<u64>(request)
            .with_context(|| "Failed to wait ack msg for getting features")?;

        Ok(features)
    }

    fn set_features(&self, features: u64) -> Result<()> {
        self.set_value(VhostUserMsgReq::SetFeatures, features)
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
        drop(mem_regions);

        let len = size_of::<VhostUserMemHdr>() + num_region * size_of::<RegionMemInfo>();
        let hdr = VhostUserMsgHdr::new(VhostUserMsgReq::SetMemTable as u32, 0, len as u32);
        let memhdr = VhostUserMemHdr::new(num_region as u32, 0);
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(
                Some(&hdr),
                Some(&memhdr),
                Some(memcontext.regions.as_slice()),
                &fds,
            )
            .with_context(|| "Failed to send msg for setting mem table")?;

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
            .with_context(|| "Failed to send msg for setting vring num")?;

        Ok(())
    }

    fn set_vring_addr(&self, queue: &QueueConfig, index: usize, flags: u32) -> Result<()> {
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
                anyhow!(format!(
                    "Failed to transform desc-table address {}",
                    queue.desc_table.0
                ))
            })?;
        let used_user_addr = self.mem_info.addr_to_host(queue.used_ring).ok_or_else(|| {
            anyhow!(format!(
                "Failed to transform used ring address {}",
                queue.used_ring.0
            ))
        })?;
        let avail_user_addr = self
            .mem_info
            .addr_to_host(queue.avail_ring)
            .ok_or_else(|| {
                anyhow!(format!(
                    "Failed to transform avail ring address {}",
                    queue.avail_ring.0
                ))
            })?;
        let _vring_addr = VhostUserVringAddr {
            index: index as u32,
            flags,
            desc_user_addr,
            used_user_addr,
            avail_user_addr,
            log_guest_addr: 0_u64,
        };
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(Some(&hdr), Some(&_vring_addr), payload_opt, &[])
            .with_context(|| "Failed to send msg for setting vring addr")?;

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
            .with_context(|| "Failed to send msg for setting vring base")?;

        Ok(())
    }

    fn set_vring_call(&self, queue_idx: usize, fd: Arc<EventFd>) -> Result<()> {
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
            .with_context(|| "Failed to send msg for setting vring call")?;

        Ok(())
    }

    fn set_vring_kick(&self, queue_idx: usize, fd: Arc<EventFd>) -> Result<()> {
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
            .with_context(|| "Failed to send msg for setting vring kick")?;

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
            .with_context(|| "Failed to send msg for setting vring enable")?;

        Ok(())
    }

    fn reset_owner(&self) -> Result<()> {
        bail!("Does not support for resetting owner")
    }

    fn get_vring_base(&self, queue_idx: usize) -> Result<u16> {
        let request = VhostUserMsgReq::GetVringBase as u32;
        let hdr = VhostUserMsgHdr::new(
            request,
            VhostUserHdrFlag::NeedReply as u32,
            size_of::<VhostUserVringState>() as u32,
        );

        let vring_state = VhostUserVringState::new(queue_idx as u32, 0_u32);
        let payload_opt: Option<&[u8]> = None;
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), Some(&vring_state), payload_opt, &[])
            .with_context(|| "Failed to send msg for getting vring base")?;
        let res = client
            .wait_ack_msg::<VhostUserVringState>(request)
            .with_context(|| "Failed to wait ack msg for getting vring base")?;

        Ok(res.value as u16)
    }
}
