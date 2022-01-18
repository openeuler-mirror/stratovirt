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
}

impl VhostOps for VhostUserClient {
    fn set_owner(&self) -> Result<()> {
        Ok(())
    }

    fn get_features(&self) -> Result<u64> {
        Ok(0)
    }

    fn set_features(&self, features: u64) -> Result<()> {
        Ok(())
    }

    fn set_mem_table(&self) -> Result<()> {
        Ok(())
    }

    fn set_vring_num(&self, queue_idx: usize, num: u16) -> Result<()> {
        Ok(())
    }

    fn set_vring_addr(&self, queue: &QueueConfig, index: usize, flags: u32) -> Result<()> {
        Ok(())
    }

    fn set_vring_base(&self, queue_idx: usize, last_avail_idx: u16) -> Result<()> {
        Ok(())
    }

    fn set_vring_call(&self, queue_idx: usize, fd: &EventFd) -> Result<()> {
        Ok(())
    }

    fn set_vring_kick(&self, queue_idx: usize, fd: &EventFd) -> Result<()> {
        Ok(())
    }

    fn set_vring_enable(&self, queue_idx: usize, status: bool) -> Result<()> {
        Ok(())
    }

    fn reset_owner(&self) -> Result<()> {
        bail!("Does not support for resetting owner")
    }

    fn get_vring_base(&self, _queue_idx: usize) -> Result<u16> {
        bail!("Does not support for getting vring base")
    }
}
