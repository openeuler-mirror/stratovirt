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
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};
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
    // EventFd for client reset.
    delete_evt: EventFd,
}

#[allow(dead_code)]
impl ClientInternal {
    fn new(sock: VhostUserSock, max_queue_num: u64) -> Self {
        ClientInternal {
            sock,
            max_queue_num,
            delete_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
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

    fn delete_evt_handler(&mut self) -> Vec<EventNotifier> {
        vec![
            EventNotifier::new(
                NotifierOperation::Delete,
                self.sock.domain.get_stream_raw_fd(),
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

        // Register event notifier for delete_evt.
        let cloned_client = client_handler.clone();
        let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
            read_fd(fd);
            Some(cloned_client.lock().unwrap().delete_evt_handler())
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            client_handler.lock().unwrap().delete_evt.as_raw_fd(),
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

    pub fn delete_event(&self) -> Result<()> {
        self.client
            .lock()
            .unwrap()
            .delete_evt
            .write(1)
            .chain_err(|| ErrorKind::EventFdWrite)?;
        Ok(())
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
