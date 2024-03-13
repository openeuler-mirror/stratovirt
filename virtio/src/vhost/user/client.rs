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

use std::cmp::Ordering;
use std::fs::File;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::rc::Rc;
use std::slice::from_raw_parts;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use log::{error, info, warn};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use super::super::VhostOps;
use super::message::{
    RegionMemInfo, VhostUserHdrFlag, VhostUserMemContext, VhostUserMemHdr, VhostUserMsgHdr,
    VhostUserMsgReq, VhostUserVringAddr, VhostUserVringState,
};
use super::sock::VhostUserSock;
use crate::device::block::VirtioBlkConfig;
use crate::VhostUser::message::VhostUserConfig;
use crate::{virtio_has_feature, Queue, QueueConfig};
use address_space::{
    AddressSpace, FileBackend, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd,
};
use machine_manager::event_loop::{register_event_helper, unregister_event_helper, EventLoop};
use util::loop_context::{
    gen_delete_notifiers, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
use util::unix::do_mmap;

/// Vhost supports multiple queue
pub const VHOST_USER_PROTOCOL_F_MQ: u8 = 0;
/// Vhost supports `VHOST_USER_SET_CONFIG` and `VHOST_USER_GET_CONFIG` msg.
pub const VHOST_USER_PROTOCOL_F_CONFIG: u8 = 9;
/// Vhost supports `VHOST_USER_SET_INFLIGHT_FD` and `VHOST_USER_GET_INFLIGHT_FD` msg.
pub const VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD: u8 = 12;

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
        self.wait_ack_msg_and_data::<T>(request, None, &mut [])
    }

    fn wait_ack_msg_and_data<T: Sized + Default>(
        &self,
        request: u32,
        payload_opt: Option<&mut [u8]>,
        fds: &mut [RawFd],
    ) -> Result<T> {
        let mut hdr = VhostUserMsgHdr::default();
        let mut body: T = Default::default();
        let (recv_len, fds_num) = self
            .sock
            .recv_msg(Some(&mut hdr), Some(&mut body), payload_opt, fds)
            .with_context(|| "Failed to recv ack msg")?;
        if fds_num != fds.len() {
            bail!("Unexpected fds num: {}, expected: {}", fds_num, fds.len());
        }
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
    if !client.lock().unwrap().reconnecting {
        return;
    }
    let cloned_client = client.clone();
    let func = Box::new(move || {
        vhost_user_reconnect(&cloned_client);
    });

    let dev_type = client.lock().unwrap().backend_type.to_string();
    info!("Try to reconnect vhost-user {}.", dev_type);
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
        // Default reconnecting time: 3s.
        EventLoop::get_ctx(None)
            .unwrap()
            .timer_add(func, Duration::from_secs(3));
        return;
    }

    client.lock().unwrap().reconnecting = false;
    if let Err(e) = VhostUserClient::add_event(client) {
        error!("Failed to update event for client sock, {:?}", e);
        return;
    }

    let mut locked_client = client.lock().unwrap();
    let protocol_features = locked_client.protocol_features;
    if protocol_features != 0 {
        if let Err(e) = locked_client.set_protocol_features(protocol_features) {
            error!(
                "Failed to set protocol features for vhost-user {}, {:?}",
                dev_type, e
            );
            return;
        }
    }

    if let Err(e) = locked_client.activate_vhost_user() {
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
                .with_context(|| {
                    format!(
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

    fn add_mem_range(&self, fr: &FlatRange) -> Result<()> {
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
        let mut locked_regions = self.regions.lock().unwrap();
        match locked_regions.binary_search_by(|r| {
            if (r.region.guest_phys_addr + r.region.memory_size - 1) < guest_phys_addr {
                Ordering::Less
            } else if r.region.guest_phys_addr > (guest_phys_addr + memory_size - 1) {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }) {
            Ok(p) => bail!(
                "New region {:?} is overlapped with region {:?}",
                region_info.region,
                locked_regions[p].region
            ),
            Err(p) => locked_regions.insert(p, region_info),
        }

        Ok(())
    }

    fn delete_mem_range(&self, fr: &FlatRange) -> Result<()> {
        if fr.owner.region_type() != address_space::RegionType::Ram {
            return Ok(());
        }

        let file_back = match fr.owner.get_file_backend() {
            None => {
                info!("fr {:?} backend is not file, ignored", fr);
                return Ok(());
            }
            Some(fb) => fb,
        };
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
                    range.with_context(|| "Flat range is None when adding region")?,
                )?;
            }
            ListenerReqType::DeleteRegion => {
                self.delete_mem_range(
                    range.with_context(|| "Flat range is None when deleting region")?,
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Struct for set and get inflight fd request, field is defined by dpdk.
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct VhostUserInflight {
    // The size of memory area to track inflight I/O.
    pub mmap_size: u64,
    // The offset from the start of the supplied file descriptor.
    pub mmap_offset: u64,
    // The number of virtqueues.
    pub queue_num: u16,
    // The size of virtqueues.
    pub queue_size: u16,
}

/// Struct for saving inflight info, create this struct to save inflight info when
/// vhost client start, use this struct to set inflight fd when vhost client reconnect.
#[derive(Debug)]
struct VhostInflight {
    // The inflight file.
    file: Arc<File>,
    // Fd mmap addr, used for migration.
    _addr: u64,
    inner: VhostUserInflight,
}

#[derive(PartialEq, Eq)]
pub enum VhostBackendType {
    TypeNet,
    TypeBlock,
    TypeFs,
}

impl ToString for VhostBackendType {
    fn to_string(&self) -> String {
        match self {
            VhostBackendType::TypeNet => String::from("net"),
            VhostBackendType::TypeBlock => String::from("block"),
            VhostBackendType::TypeFs => String::from("fs"),
        }
    }
}

/// Struct for communication with the vhost user backend in userspace
pub struct VhostUserClient {
    client: Arc<Mutex<ClientInternal>>,
    mem_info: VhostUserMemInfo,
    delete_evts: Vec<RawFd>,
    mem_space: Arc<AddressSpace>,
    queues: Vec<Arc<Mutex<Queue>>>,
    queue_evts: Vec<Arc<EventFd>>,
    call_events: Vec<Arc<EventFd>>,
    pub features: u64,
    reconnecting: bool,
    inflight: Option<VhostInflight>,
    backend_type: VhostBackendType,
    pub protocol_features: u64,
}

impl VhostUserClient {
    pub fn new(
        mem_space: &Arc<AddressSpace>,
        path: &str,
        max_queue_num: u64,
        backend_type: VhostBackendType,
    ) -> Result<Self> {
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
            mem_space: mem_space.clone(),
            queues: Vec::new(),
            queue_evts: Vec::new(),
            call_events: Vec::new(),
            features: 0,
            reconnecting: false,
            inflight: None,
            backend_type,
            protocol_features: 0_u64,
        })
    }

    /// Save queue info used for reconnection.
    pub fn set_queues(&mut self, queues: &[Arc<Mutex<Queue>>]) {
        for queue in queues.iter() {
            self.queues.push(queue.clone());
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

    /// Set inflight fd, include get inflight fd from vhost and set inflight to vhost.
    pub fn set_inflight(&mut self, queue_num: u16, queue_size: u16) -> Result<()> {
        if self.backend_type != VhostBackendType::TypeBlock {
            // Only vhost-user-blk supports inflight fd now.
            return Ok(());
        }
        let protocol_feature = self
            .get_protocol_features()
            .with_context(|| "Failed to get protocol features for vhost-user blk")?;
        if virtio_has_feature(
            protocol_feature,
            VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD as u32,
        ) {
            if self.inflight.is_none() {
                // Expect 1 fd.
                let mut fds = [RawFd::default()];
                let vhost_user_inflight = self.get_inflight_fd(queue_num, queue_size, &mut fds)?;
                let file = Arc::new(
                    // SAFETY: fds[0] create in function of get_inflight_fd.
                    unsafe { File::from_raw_fd(fds[0]) },
                );
                let hva = do_mmap(
                    &Some(file.as_ref()),
                    vhost_user_inflight.mmap_size,
                    vhost_user_inflight.mmap_offset,
                    true,
                    true,
                    false,
                )?;
                let inflight = VhostInflight {
                    file,
                    _addr: hva,
                    inner: vhost_user_inflight,
                };
                self.inflight = Some(inflight);
            }
            let inflight = self.inflight.as_ref().unwrap();
            self.set_inflight_fd(inflight.inner.clone(), inflight.file.as_raw_fd())?;
        } else {
            bail!(
                "Failed to get inflight fd, spdk doesn't support, spdk protocol feature: {:#b}",
                protocol_feature
            );
        }
        Ok(())
    }

    /// Activate device by vhost-user protocol.
    pub fn activate_vhost_user(&mut self) -> Result<()> {
        self.set_owner()
            .with_context(|| "Failed to set owner for vhost-user")?;

        self.set_features(self.features)
            .with_context(|| "Failed to set features for vhost-user")?;

        self.set_mem_table()
            .with_context(|| "Failed to set mem table for vhost-user")?;

        let queue_size = self
            .queues
            .first()
            .unwrap()
            .lock()
            .unwrap()
            .vring
            .actual_size();
        self.set_inflight(self.queues.len() as u16, queue_size)?;
        // Set all vring num to notify ovs/dpdk how many queues it needs to poll
        // before setting vring info.
        for (queue_index, queue_mutex) in self.queues.iter().enumerate() {
            let actual_size = queue_mutex.lock().unwrap().vring.actual_size();
            self.set_vring_num(queue_index, actual_size)
                .with_context(|| {
                    format!(
                        "Failed to set vring num for vhost-user, index: {}, size: {}",
                        queue_index, actual_size,
                    )
                })?;
        }

        for (queue_index, queue_mutex) in self.queues.iter().enumerate() {
            let queue = queue_mutex.lock().unwrap();
            if !queue.vring.is_enabled() {
                warn!("Queue {} is not enabled, skip it", queue_index);
                continue;
            }

            let queue_config = queue.vring.get_queue_config();
            self.set_vring_addr(&queue_config, queue_index, 0)
                .with_context(|| {
                    format!(
                        "Failed to set vring addr for vhost-user, index: {}",
                        queue_index,
                    )
                })?;
            // When spdk/ovs has been killed, stratovirt can not get the last avail
            // index in spdk/ovs, it can only use used index as last avail index.
            let last_avail_idx = queue.vring.get_used_idx(&self.mem_space)?;
            self.set_vring_base(queue_index, last_avail_idx)
                .with_context(|| {
                    format!(
                        "Failed to set vring base for vhost-user, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_kick(queue_index, self.queue_evts[queue_index].clone())
                .with_context(|| {
                    format!(
                        "Failed to set vring kick for vhost-user, index: {}",
                        queue_index,
                    )
                })?;
            self.set_vring_call(queue_index, self.call_events[queue_index].clone())
                .with_context(|| {
                    format!(
                        "Failed to set vring call for vhost-user, index: {}",
                        queue_index,
                    )
                })?;
        }

        if self.backend_type == VhostBackendType::TypeBlock {
            // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated, it should call
            // set_vring_enable to enable vring. Otherwise, the ring is enabled by default.
            // Currently, only vhost-user-blk device support negotiate VHOST_USER_F_PROTOCOL_FEATURES.
            for (queue_index, queue_mutex) in self.queues.iter().enumerate() {
                if !queue_mutex.lock().unwrap().is_enabled() {
                    continue;
                }
                self.set_vring_enable(queue_index, true).with_context(|| {
                    format!(
                        "Failed to set vring enable for vhost-user, index: {}",
                        queue_index,
                    )
                })?;
            }
        }

        Ok(())
    }

    pub fn reset_vhost_user(&mut self) -> Result<()> {
        for (queue_index, queue_mutex) in self.queues.iter().enumerate() {
            if !queue_mutex.lock().unwrap().vring.is_enabled() {
                continue;
            }
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
        if self.reconnecting {
            self.reconnecting = false;
            // The socket event has been deleted before try to reconnect so let's just return.
            return Ok(());
        }
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
        // SAFETY: the memory is allocated by us and it has been already aligned.
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

    /// Get inflight file info and inflight fd from vhost.
    pub fn get_inflight_fd(
        &self,
        queue_num: u16,
        queue_size: u16,
        fds: &mut [RawFd],
    ) -> Result<VhostUserInflight> {
        let request = VhostUserMsgReq::GetInflightFd as u32;
        let data_len = size_of::<VhostUserInflight>();
        let hdr =
            VhostUserMsgHdr::new(request, VhostUserHdrFlag::NeedReply as u32, data_len as u32);
        let inflight = VhostUserInflight {
            mmap_size: 0,
            mmap_offset: 0,
            queue_num,
            queue_size,
        };
        let body_opt: Option<&u32> = None;
        let payload_opt: Option<&[u8]> = Some(
            // SAFETY:
            // 1. inflight can be guaranteed not null.
            // 2. data_len is constant.
            unsafe {
                from_raw_parts(
                    (&inflight as *const VhostUserInflight) as *const u8,
                    data_len,
                )
            },
        );
        let client = self.client.lock().unwrap();
        client
            .sock
            .send_msg(Some(&hdr), body_opt, payload_opt, &[])
            .with_context(|| "Failed to send msg for getting inflight fd")?;
        let res = client
            .wait_ack_msg_and_data::<VhostUserInflight>(request, None, fds)
            .with_context(|| "Failed to wait ack msg for getting inflight fd")?;
        Ok(res)
    }

    /// Set inflight file info and send inflight fd to vhost.
    pub fn set_inflight_fd(&self, inflight: VhostUserInflight, fd: RawFd) -> Result<()> {
        let request = VhostUserMsgReq::SetInflightFd as u32;
        let len = size_of::<VhostUserInflight>();
        let hdr = VhostUserMsgHdr::new(request, 0, len as u32);
        let payload_opt: Option<&[u8]> = None;
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(Some(&hdr), Some(&inflight), payload_opt, &[fd])
            .with_context(|| "Failed to send msg for setting inflight fd")?;
        Ok(())
    }
}

impl VhostOps for VhostUserClient {
    fn set_owner(&self) -> Result<()> {
        trace::vhost_set_owner();
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

        trace::vhost_get_features(features);
        Ok(features)
    }

    fn set_features(&self, features: u64) -> Result<()> {
        trace::vhost_set_features(features);
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

        trace::vhost_set_mem_table(&memcontext.regions);
        Ok(())
    }

    fn set_vring_num(&self, queue_idx: usize, num: u16) -> Result<()> {
        trace::vhost_set_vring_num(queue_idx, num);
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invalid {} for setting vring num",
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
            .with_context(|| {
                format!(
                    "Failed to transform desc-table address {}",
                    queue.desc_table.0
                )
            })?;
        let used_user_addr = self
            .mem_info
            .addr_to_host(queue.used_ring)
            .with_context(|| {
                format!(
                    "Failed to transform used ring address {}",
                    queue.used_ring.0
                )
            })?;
        let avail_user_addr = self
            .mem_info
            .addr_to_host(queue.avail_ring)
            .with_context(|| {
                format!(
                    "Failed to transform avail ring address {}",
                    queue.avail_ring.0
                )
            })?;
        let vring_addr = VhostUserVringAddr {
            index: index as u32,
            flags,
            desc_user_addr,
            used_user_addr,
            avail_user_addr,
            log_guest_addr: 0_u64,
        };
        trace::vhost_set_vring_addr(&vring_addr);
        self.client
            .lock()
            .unwrap()
            .sock
            .send_msg(Some(&hdr), Some(&vring_addr), payload_opt, &[])
            .with_context(|| "Failed to send msg for setting vring addr")?;

        Ok(())
    }

    fn set_vring_base(&self, queue_idx: usize, last_avail_idx: u16) -> Result<()> {
        trace::vhost_set_vring_base(queue_idx, last_avail_idx);
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
        trace::vhost_set_vring_call(queue_idx, &fd);
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
        trace::vhost_set_vring_kick(queue_idx, &fd);
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invalid {} for setting vring kick",
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
        trace::vhost_set_vring_enable(queue_idx, status);
        let client = self.client.lock().unwrap();
        if queue_idx as u64 > client.max_queue_num {
            bail!(
                "The queue index {} is invalid {} for setting vring enable",
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

        trace::vhost_get_vring_base(queue_idx, res.value as u16);
        Ok(res.value as u16)
    }
}
