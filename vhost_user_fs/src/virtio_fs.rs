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

/// The num of high priority queue.
const VIRIOT_FS_HIGH_PRIO_QUEUE_NUM: u64 = 1;
/// The num of request queue.
const VIRTIO_FS_REQ_QUEUES_NUM: u64 = 1;
/// The next queue size.
const VIRTIO_FS_MAX_QUEUE_SIZE: u16 = 1024;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex};

use error_chain::ChainedError;
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

use address_space::{AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};
use machine_manager::event_loop::EventLoop;
use util::loop_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation};

use super::fs::FileSystem;
use super::fuse_req::FuseReq;
use super::vhost_user_server::VhostUserReqHandler;

use crate::errors::{Result, ResultExt};
use virtio::vhost::user::RegionMemInfo;
use virtio::{
    Queue, QueueConfig, QUEUE_TYPE_SPLIT_VRING, VIRTIO_F_RING_EVENT_IDX,
    VIRTIO_F_RING_INDIRECT_DESC, VIRTIO_F_VERSION_1,
};

struct FsIoHandler {
    queue: Queue,
    kick_evt: EventFd,
    call_evt: EventFd,
    mem_space: Arc<AddressSpace>,
    driver_features: u64,
    fs: Arc<Mutex<FileSystem>>,
}

impl FsIoHandler {
    fn new(
        queue_config: QueueConfig,
        kick_evt: &EventFd,
        call_evt: &EventFd,
        mem_space: &Arc<AddressSpace>,
        driver_features: u64,
        fs: Arc<Mutex<FileSystem>>,
    ) -> Result<Self> {
        let queue = Queue::new(queue_config, QUEUE_TYPE_SPLIT_VRING)
            .chain_err(|| "Failed to create virtual queue")?;
        if !queue.is_valid(mem_space) {
            bail!("Invalid queue for fs handler");
        }

        Ok(FsIoHandler {
            queue,
            kick_evt: kick_evt.try_clone().unwrap(),
            call_evt: call_evt.try_clone().unwrap(),
            mem_space: mem_space.clone(),
            driver_features,
            fs,
        })
    }

    fn process_queue(&mut self) -> Result<()> {
        while let Ok(elem) = self
            .queue
            .vring
            .pop_avail(&self.mem_space, self.driver_features)
        {
            let mut req = FuseReq::new(&elem);
            let (index, len) = req.execute(&self.mem_space, self.fs.clone());
            self.queue.vring.add_used(&self.mem_space, index, len)?;
        }

        if self
            .queue
            .vring
            .should_notify(&self.mem_space, self.driver_features)
        {
            self.call_evt
                .write(1)
                .chain_err(|| "Failed to write call fd")?;
        }

        Ok(())
    }

    fn delete_notifiers(&self) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        notifiers.push(EventNotifier::new(
            NotifierOperation::Delete,
            self.kick_evt.as_raw_fd(),
            None,
            EventSet::IN,
            Vec::new(),
        ));

        notifiers
    }
}

impl EventNotifierHelper for FsIoHandler {
    fn internal_notifiers(fs_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();

        let fs_handler_clone = fs_handler.clone();
        let handler = Box::new(move |_, fd: RawFd| {
            read_fd(fd);

            if let Err(e) = fs_handler_clone.lock().unwrap().process_queue() {
                error!("Failed to process fuse msg, {}", e.display_chain());
            }

            None
        });

        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            fs_handler.lock().unwrap().kick_evt.as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));

        notifiers
    }
}

struct QueueInfo {
    config: QueueConfig,
    kick_evt: Option<EventFd>,
    call_evt: Option<EventFd>,
}

impl QueueInfo {
    fn new(queue_size: u16) -> Self {
        QueueInfo {
            config: QueueConfig::new(queue_size),
            kick_evt: None,
            call_evt: None,
        }
    }
}

struct VirtioFsConfig {
    device_features: u64,
    driver_features: u64,
    queues_info: Vec<QueueInfo>,
    mem_regions: Vec<Region>,
}

impl VirtioFsConfig {
    fn new() -> Self {
        let device_features = 1_u64 << VIRTIO_F_VERSION_1
            | 1_u64 << VIRTIO_F_RING_INDIRECT_DESC
            | 1_u64 << VIRTIO_F_RING_EVENT_IDX;

        let mut queues_info = Vec::new();
        for _i in 0..(VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM) {
            queues_info.push(QueueInfo::new(VIRTIO_FS_MAX_QUEUE_SIZE));
        }

        VirtioFsConfig {
            device_features,
            driver_features: 0_u64,
            queues_info,
            mem_regions: Vec::new(),
        }
    }

    fn get_mut_queue_config(&mut self, queue_index: usize) -> Result<&mut QueueInfo> {
        self.queues_info
            .get_mut(queue_index)
            .ok_or_else(|| format!("The select index of queue {} overflows", queue_index).into())
    }
}

/// The virtio fs device contains the configuration of virtio fs, the management of
/// userspace filesystem and the handler used to process requests in virtio queue
/// from the guest.
pub struct VirtioFs {
    /// The config of virtio-fs.
    config: VirtioFsConfig,
    /// Fs handlers of I/O request.
    fs_handlers: Vec<Option<Arc<Mutex<FsIoHandler>>>>,
    /// Address space mapped witch StratoVirt.
    sys_mem: Arc<AddressSpace>,
    /// File system used to store inode and file information.
    fs: Arc<Mutex<FileSystem>>,
    /// The quest memory region information.
    mem_info: Vec<RegionMemInfo>,
}

impl VirtioFs {
    /// Construct a virtio fs device by the path of source directory shared in host.
    ///
    /// # Arguments
    ///
    /// * `source_dir` - The path of source directory shared in host.
    pub fn new(source_dir: &str) -> Result<Self> {
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value()))
            .chain_err(|| "Failed to create address space")?;

        let mut fs_handlers = Vec::new();
        for _i in 0..(VIRIOT_FS_HIGH_PRIO_QUEUE_NUM + VIRTIO_FS_REQ_QUEUES_NUM) {
            fs_handlers.push(None);
        }

        let fs = Arc::new(Mutex::new(FileSystem::new(source_dir).chain_err(|| {
            format!("Failed to create file system, source dir: {}", source_dir)
        })?));

        Ok(VirtioFs {
            config: VirtioFsConfig::new(),
            fs_handlers,
            sys_mem,
            fs,
            mem_info: Vec::new(),
        })
    }

    fn get_guest_address(&self, addr: u64) -> Result<u64> {
        for (_, info) in self.mem_info.iter().enumerate() {
            if addr >= info.userspace_addr
                && addr < info.userspace_addr + info.memory_size {
                return Ok(info.guest_phys_addr + addr - info.userspace_addr);
            }
        }

        bail!("Failed to find the guest address for addr: 0x{:X}", addr);
    }
}

impl VhostUserReqHandler for VirtioFs {
    fn set_owner(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_features(&self) -> Result<u64> {
        Ok(self.config.device_features)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        self.config.driver_features = features;
        Ok(())
    }

    fn set_mem_table(&mut self, regions: &[RegionMemInfo], fds: &[RawFd]) -> Result<()> {
        if !self.config.mem_regions.is_empty() {
            for region in &self.config.mem_regions {
                if let Err(e) = self.sys_mem.root().delete_subregion(region) {
                    error!(
                        "Failed to delete subregion for setting mem table, {}",
                        e.display_chain()
                    );
                }
            }
            self.config.mem_regions = Vec::new();
        }

        self.mem_info = regions.to_vec().clone();

        for (index, region_config) in regions.iter().enumerate() {
            let file = unsafe { File::from_raw_fd(fds[index]) };
            let fileback = FileBackend {
                file: Arc::new(file),
                offset: region_config.mmap_offset,
                page_size: 0_u64,
            };

            let mmap = Arc::new(
                HostMemMapping::new(
                    GuestAddress(region_config.guest_phys_addr),
                    None,
                    region_config.memory_size,
                    Some(fileback),
                    false,
                    true,
                    false,
                )
                    .chain_err(||
                        format!("Failed to create the mapping of host memory for setting mem table, addr: 0x{:X}, size: {}, offset: {}",
                                region_config.guest_phys_addr, region_config.memory_size, region_config.mmap_offset,
                        )
                    )?
            );

            let region = Region::init_ram_region(mmap.clone());
            self.sys_mem
                .root()
                .add_subregion(region.clone(), mmap.start_address().raw_value())
                .chain_err(|| "Failed to add subregion for setting mem table")?;

            self.config.mem_regions.push(region);
        }

        Ok(())
    }

    fn set_vring_num(&mut self, queue_index: usize, num: u16) -> Result<()> {
        self.config
            .get_mut_queue_config(queue_index)
            .map(|queue_info| {
                queue_info.config.size = num;
            })
            .chain_err(|| {
                format!(
                    "Failed to set vring num, index: {}, num: {}",
                    queue_index, num,
                )
            })?;
        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        queue_index: usize,
        _flags: u32,
        desc_table: u64,
        used_ring: u64,
        avail_ring: u64,
        _log: u64,
    ) -> Result<()> {
        let cloned_mem_space = self.sys_mem.clone();

        let desc_addr = self.get_guest_address(desc_table)?;
        let used_addr = self.get_guest_address(used_ring)?;
        let avail_addr = self.get_guest_address(avail_ring)?;

        self.config
            .get_mut_queue_config(queue_index as usize)
            .map(|queue_info| {
                queue_info.config.desc_table = GuestAddress(desc_addr);
                queue_info.config.addr_cache.desc_table_host = cloned_mem_space
                    .get_host_address(GuestAddress(desc_addr))
                    .unwrap_or(0);

                queue_info.config.avail_ring = GuestAddress(avail_addr);
                queue_info.config.addr_cache.avail_ring_host = cloned_mem_space
                    .get_host_address(GuestAddress(avail_addr))
                    .unwrap_or(0);

                queue_info.config.used_ring = GuestAddress(used_addr);
                queue_info.config.addr_cache.used_ring_host = cloned_mem_space
                    .get_host_address(GuestAddress(used_addr))
                    .unwrap_or(0);
            }).chain_err(||
            format!("Failed to set vring addr, index: {}, desc: 0x{:X}, avail: 0x{:X}, used: 0x{:X}",
                    queue_index, desc_addr, avail_addr, used_addr,
            )
        )?;
        Ok(())
    }

    fn set_vring_base(&mut self, _queue_index: usize, _num: u16) -> Result<()> {
        Ok(())
    }

    fn set_vring_call(&mut self, queue_index: usize, fd: RawFd) -> Result<()> {
        self.config
            .get_mut_queue_config(queue_index)
            .map(|queue_info| {
                let call_evt = unsafe { EventFd::from_raw_fd(fd) };
                queue_info.call_evt = Some(call_evt);
            })
            .chain_err(|| format!("Failed to set vring call, index: {}", queue_index))?;
        Ok(())
    }

    fn set_vring_kick(&mut self, queue_index: usize, fd: RawFd) -> Result<()> {
        self.config
            .get_mut_queue_config(queue_index)
            .map(|queue_info| {
                let kick_evt = unsafe { EventFd::from_raw_fd(fd) };
                queue_info.kick_evt = Some(kick_evt);
            })
            .chain_err(|| format!("Failed to set vring kick, index: {}", queue_index))?;
        Ok(())
    }

    fn set_vring_enable(&mut self, queue_index: usize, status: u32) -> Result<()> {
        let driver_features = self.config.driver_features;

        let mut queue_info = self.config.get_mut_queue_config(queue_index)?;
        queue_info.config.ready = status == 1;

        if status == 1 {
            if queue_info.kick_evt.is_none() || queue_info.call_evt.is_none() {
                bail!(
                    "The event for kicking {} or calling {} is none",
                    queue_info.kick_evt.is_none(),
                    queue_info.call_evt.is_none(),
                );
            }

            let fs_handler = Arc::new(Mutex::new(
                FsIoHandler::new(
                    queue_info.config,
                    queue_info.kick_evt.as_ref().unwrap(),
                    queue_info.call_evt.as_ref().unwrap(),
                    &self.sys_mem,
                    driver_features,
                    self.fs.clone(),
                )
                .chain_err(|| "Failed to create fs handler")?,
            ));

            self.fs_handlers[queue_index] = Some(fs_handler.clone());
            EventLoop::update_event(EventNotifierHelper::internal_notifiers(fs_handler), None)
                .chain_err(|| "Failed to update event for queue status which is ready")?;
        } else if let Some(fs_handler) = self.fs_handlers.get_mut(queue_index).unwrap().take() {
            EventLoop::update_event(fs_handler.lock().unwrap().delete_notifiers(), None)
                .chain_err(|| "Failed to update event for queue status which is not ready")?;
        }
        Ok(())
    }
}
