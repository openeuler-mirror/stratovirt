// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use super::{
    errors::*, Element, Queue, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING,
};

use address_space::{
    AddressSpace, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd, RegionType,
};
use machine_manager::config::BalloonConfig;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{
    cmp,
    sync::{Arc, Mutex},
};
use util::{
    byte_code::ByteCode,
    epoll_context::{
        read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
    },
};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2;
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const BALLOON_PAGE_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;
const BALLOON_INFLATE_EVENT: bool = true;
const BALLOON_DEFLATE_EVENT: bool = false;

static mut BALLOON_DEV: Option<Arc<Mutex<Balloon>>> = None;
type VirtioBalloonInterrupt = Box<dyn Fn(u32) -> Result<()> + Send + Sync>;

/// IO vector, used to find memory segments.
#[derive(Clone, Copy, Default)]
pub struct Iovec {
    /// Base address of memory.
    pub iov_base: GuestAddress,
    /// Length of memory segments.
    pub iov_len: u64,
}

impl ByteCode for Iovec {}

/// Read data segment starting at `iov.iov_base` + `offset` to buffer <T>.
/// Return bufer <T>.
///
/// # Arguments
///
/// * `address_space` - Address space of VM.
/// * `iov` - IOvec includes base address and length.
/// * `offset` - Offset.
fn iov_to_buf<T: ByteCode>(
    address_space: &Arc<AddressSpace>,
    &iov: &Iovec,
    offset: u64,
) -> Option<T> {
    let obj_len = std::mem::size_of::<T>() as u64;
    let mut data: Vec<u8> = vec![0; obj_len as usize];
    if offset >= iov.iov_len || offset + obj_len > iov.iov_len {
        return None;
    }

    if address_space
        .read(&mut data, iov.iov_base, iov.iov_len)
        .is_err()
    {
        error!("Read virtioqueue failed!");
        return None;
    }
    unsafe {
        Some(std::ptr::read_volatile(
            &data[(offset as usize)..] as *const _ as *const T,
        ))
    }
}

struct Request {
    /// The index of descriptor for the request.
    pub desc_index: u16,
    /// Count of elements.
    pub elem_cnt: u32,
    /// The data which is both readable and writable.
    pub iovec: Vec<Iovec>,
}

impl Request {
    /// Parse the request from virtio queue.
    /// Return the request from qirtio queue.
    ///
    /// # Arguments
    ///
    /// * `elem` - Available ring.
    pub fn parse(elem: &Element) -> Result<Request> {
        let mut request = Request {
            desc_index: elem.index,
            elem_cnt: 0u32,
            iovec: Vec::new(),
        };
        if elem.out_iovec.is_empty() {
            return Err(ErrorKind::ElementEmpty.into());
        } else {
            let elem_iov = elem.out_iovec.get(0).unwrap();
            request.iovec.push(Iovec {
                iov_base: elem_iov.addr,
                iov_len: elem_iov.len as u64,
            });
            request.elem_cnt += elem_iov.len;
        }
        Ok(request)
    }

    /// Mark balloon page with `MADV_DONTNEED` or `MADV_WILLNEED`.
    ///
    /// # Arguments
    ///
    /// * `req_type` - A label used to mark balloon pages.
    /// * `mem` - Collection of all Ram regions.
    pub fn mark_balloon_page(
        &self,
        req_type: bool,
        address_space: &Arc<AddressSpace>,
        mem: &BlnMemInfo,
    ) {
        let advice = if req_type {
            libc::MADV_DONTNEED
        } else {
            libc::MADV_WILLNEED
        };
        let mut last_addr: u64 = 0;
        let mut count_iov: u64 = 4;
        let mut free_len: u64 = 0;
        let mut start_addr: u64 = 0;

        for iov in self.iovec.iter() {
            let mut offset = 0;
            if req_type == BALLOON_INFLATE_EVENT {
                while let Some(pfn) = iov_to_buf::<u32>(address_space, iov, offset) {
                    offset += std::mem::size_of::<u32>() as u64;
                    let gpa: GuestAddress = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                    let hva = match mem.get_host_address(gpa) {
                        Some(addr) => addr,
                        None => {
                            error!("failed to mark balloon page");
                            continue;
                        }
                    };
                    if (last_addr == 0) || (hva + BALLOON_PAGE_SIZE == last_addr) {
                        free_len += 1;
                    } else {
                        unsafe {
                            libc::madvise(
                                last_addr as *const libc::c_void as *mut _,
                                (free_len * BALLOON_PAGE_SIZE) as usize,
                                advice,
                            );
                        }
                        free_len = 1;
                    }
                    if count_iov == iov.iov_len {
                        unsafe {
                            libc::madvise(
                                hva as *const libc::c_void as *mut _,
                                (free_len * BALLOON_PAGE_SIZE) as usize,
                                advice,
                            );
                        }
                    }
                    count_iov += std::mem::size_of::<u32>() as u64;
                    last_addr = hva;
                }
            } else {
                while let Some(pfn) = iov_to_buf::<u32>(address_space, iov, offset) {
                    offset += std::mem::size_of::<u32>() as u64;
                    let gpa: GuestAddress = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                    let hva = match mem.get_host_address(gpa) {
                        Some(addr) => addr,
                        None => {
                            error!("failed to mark balloon page");
                            continue;
                        }
                    };
                    if last_addr == 0 {
                        free_len += 1;
                        start_addr = hva;
                    } else if hva == last_addr + BALLOON_PAGE_SIZE {
                        free_len += 1;
                    } else {
                        unsafe {
                            libc::madvise(
                                start_addr as *const libc::c_void as *mut _,
                                (free_len * BALLOON_PAGE_SIZE) as usize,
                                advice,
                            );
                        }
                        free_len = 1;
                        start_addr = hva;
                    }
                    if count_iov == iov.iov_len {
                        unsafe {
                            libc::madvise(
                                start_addr as *const libc::c_void as *mut _,
                                (free_len * BALLOON_PAGE_SIZE) as usize,
                                advice,
                            );
                        }
                    }
                    count_iov += std::mem::size_of::<u32>() as u64;
                    last_addr = hva;
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct BlnMemoryRegion {
    /// GPA.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// HVA.
    pub userspace_addr: u64,
    /// No flags specified for now.
    pub flags_padding: u64,
}

#[derive(Clone)]
struct BlnMemInfo {
    pub regions: Arc<Mutex<Vec<BlnMemoryRegion>>>,
}

impl BlnMemInfo {
    pub fn new() -> BlnMemInfo {
        BlnMemInfo {
            regions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_host_address(&self, addr: GuestAddress) -> Option<u64> {
        let all_regions = self.regions.lock().unwrap();
        for i in 0..all_regions.len() {
            if addr.raw_value() < all_regions[i].guest_phys_addr + all_regions[i].memory_size
                && addr.raw_value() >= all_regions[i].guest_phys_addr
            {
                return Some(
                    all_regions[i].userspace_addr + addr.raw_value()
                        - all_regions[i].guest_phys_addr,
                );
            }
        }
        None
    }

    fn add_mem_range(&self, fr: &FlatRange) {
        let guest_phys_addr = fr.addr_range.base.raw_value();
        let memory_size = fr.addr_range.size;
        if let Some(host_addr) = fr.owner.get_host_address() {
            let userspace_addr = host_addr + fr.offset_in_region;
            self.regions.lock().unwrap().push(BlnMemoryRegion {
                guest_phys_addr,
                memory_size,
                userspace_addr,
                flags_padding: 0_u64,
            });
        } else {
            error!("Failed to get host address!");
        }
    }

    fn delete_mem_range(&self, fr: &FlatRange) {
        let mut mem_regions = self.regions.lock().unwrap();
        if let Some(host_addr) = fr.owner.get_host_address() {
            let target = BlnMemoryRegion {
                guest_phys_addr: fr.addr_range.base.raw_value(),
                memory_size: fr.addr_range.size,
                userspace_addr: host_addr + fr.offset_in_region,
                flags_padding: 0_u64,
            };
            for (index, mr) in mem_regions.iter().enumerate() {
                if mr.guest_phys_addr == target.guest_phys_addr
                    && mr.memory_size == target.memory_size
                    && mr.userspace_addr == target.userspace_addr
                    && mr.flags_padding == target.flags_padding
                {
                    mem_regions.remove(index);
                    return;
                }
            }
        } else {
            error!("Failed to get host address!");
        }
        debug!("Balloon: deleting mem region failed: not matched");
    }
}

impl Listener for BlnMemInfo {
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
                let fr = range.unwrap();
                if fr.owner.region_type() == RegionType::Ram {
                    self.add_mem_range(&fr);
                }
            }
            ListenerReqType::DeleteRegion => {
                let fr = range.unwrap();
                if fr.owner.region_type() == RegionType::Ram {
                    self.delete_mem_range(&fr);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Deal with balloon request.
struct BalloonIoHandler {
    /// The features of driver.
    driver_features: u64,
    /// Address space.
    mem_space: Arc<AddressSpace>,
    /// Inflate queue.
    inf_queue: Arc<Mutex<Queue>>,
    /// Inflate EventFd.
    inf_evt: EventFd,
    /// Deflate queue.
    def_queue: Arc<Mutex<Queue>>,
    /// Deflate EventFd.
    def_evt: EventFd,
    /// The interrupt call back function.
    interrupt_cb: Arc<VirtioBalloonInterrupt>,
    /// Balloon Memory information.
    mem_info: BlnMemInfo,
}

impl BalloonIoHandler {
    /// Process balloon queue.
    ///
    /// # Arguments
    ///
    /// * `req_type` - Type of request.
    ///
    /// if `req_type` is `BALLOON_INFLATE_EVENT`, then inflate the balloon, otherwise, deflate the balloon.
    fn process_balloon_queue(&mut self, req_type: bool) -> Result<()> {
        {
            let queue = if req_type {
                &mut self.inf_queue
            } else {
                &mut self.def_queue
            };
            let mut unlocked_queue = queue.lock().unwrap();
            while let Ok(elem) = unlocked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
            {
                match Request::parse(&elem) {
                    Ok(req) => {
                        req.mark_balloon_page(req_type, &self.mem_space, &self.mem_info);
                        unlocked_queue.vring.add_used(
                            &self.mem_space,
                            req.desc_index,
                            req.elem_cnt as u32,
                        )?;
                    }
                    Err(e) => {
                        error!("fail to parse available descriptor chain: {:?}", e);
                        break;
                    }
                }
            }
        }
        self.signal_used_queue()?;
        Ok(())
    }

    /// Trigger interrupt to notify vm.
    fn signal_used_queue(&self) -> Result<()> {
        (self.interrupt_cb)(VIRTIO_MMIO_INT_VRING)
    }
}

/// Create a new EventNotifier.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor.
/// * `handler` - Handle function.
fn build_event_notifier(fd: RawFd, handler: Box<NotifierCallback>) -> EventNotifier {
    let mut handlers = Vec::new();
    handlers.push(Arc::new(Mutex::new(handler)));
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        handlers,
    )
}

impl EventNotifierHelper for BalloonIoHandler {
    /// Register event notifiers for different queue event.
    fn internal_notifiers(balloon_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        {
            let cloned_balloon_io = balloon_io.clone();
            let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);
                let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
                locked_balloon_io
                    .process_balloon_queue(BALLOON_INFLATE_EVENT)
                    .unwrap_or_else(|_| error!("Failed to inflate balloon."));
                None
            });
            let locked_balloon_io = balloon_io.lock().unwrap();
            notifiers.push(build_event_notifier(
                locked_balloon_io.inf_evt.as_raw_fd(),
                handler,
            ));
        }

        {
            let cloned_balloon_io = balloon_io.clone();
            let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);
                let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
                locked_balloon_io
                    .process_balloon_queue(BALLOON_DEFLATE_EVENT)
                    .unwrap_or_else(|_| error!("Failed to deflate balloon."));
                None
            });
            let locked_balloon_io = balloon_io.lock().unwrap();
            notifiers.push(build_event_notifier(
                locked_balloon_io.def_evt.as_raw_fd(),
                handler,
            ));
        }
        notifiers
    }
}

/// A balloon device with some necessary information.
pub struct Balloon {
    /// Balloon device features.
    device_features: u64,
    /// Driver features.
    driver_features: u64,
    /// Actual memory pages.
    actual: u32,
    /// Target memory pages.
    num_pages: u32,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioBalloonInterrupt>>,
    /// Balloon memory information.
    mem_info: BlnMemInfo,
}

impl Balloon {
    /// Create a balloon device.
    ///
    /// # Arguments
    ///
    /// * `bln_cfg` - Balloon configuration.
    pub fn new(bln_cfg: BalloonConfig) -> Balloon {
        let mut device_features = 1u64 << VIRTIO_F_VERSION_1;
        if bln_cfg.deflate_on_oom {
            device_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        }
        Balloon {
            device_features,
            driver_features: 0u64,
            actual: 0u32,
            num_pages: 0u32,
            interrupt_cb: None,
            mem_info: BlnMemInfo::new(),
        }
    }

    /// Init balloon object for global use.
    pub fn object_init(dev: Arc<Mutex<Balloon>>) {
        unsafe {
            if BALLOON_DEV.is_none() {
                BALLOON_DEV = Some(dev)
            }
        }
    }

    /// Get Ram size of AddressSpace.
    pub fn get_ram_size(&self) -> u64 {
        let mut size = 0_u64;
        let unlockedrgs = self.mem_info.regions.lock().unwrap();
        for rg in unlockedrgs.iter() {
            size += rg.memory_size;
        }
        size
    }

    /// Notify configuration changes to VM.
    fn signal_config_change(&self) -> Result<()> {
        if self.interrupt_cb.is_none() {
            debug!("balloon device not activated");
            return Ok(());
        }
        let interrupt = self.interrupt_cb.as_ref().unwrap();
        (*interrupt)(VIRTIO_MMIO_INT_CONFIG)
    }

    /// Set the target memory size of guest. Note that
    /// the actual size may not be the same as the target size.
    ///
    /// # Argument
    ///
    /// * `size` - Target momery size.
    pub fn set_memory_size(&mut self, size: u64) -> Result<()> {
        let target = (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let current_ram_size = (self.get_ram_size() >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let vm_target = cmp::min(target, current_ram_size);
        self.num_pages = current_ram_size - vm_target;
        self.signal_config_change()?;
        Ok(())
    }

    /// Get the memory size of guest.
    pub fn get_memory_size(&self) -> u64 {
        (self.actual as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }
}
