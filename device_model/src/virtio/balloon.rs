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
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::{
    cmp::{self, Reverse},
    time::Duration,
};

use super::{
    errors::*, Element, Queue, VirtioDevice, VIRTIO_F_VERSION_1, VIRTIO_MMIO_INT_CONFIG,
    VIRTIO_MMIO_INT_VRING, VIRTIO_TYPE_BALLOON,
};
use address_space::{
    host_page_size, AddressSpace, FlatRange, GuestAddress, Listener, ListenerReqType,
    RegionIoEventFd, RegionType,
};
use machine_manager::{
    config::BalloonConfig, event_loop::EventLoop, qmp::qmp_schema::BalloonInfo, qmp::QmpChannel,
};
use util::{
    bitmap::Bitmap,
    byte_code::ByteCode,
    loop_context::{
        read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
    },
    num_ops::{read_u32, round_down, write_u32},
    seccomp::BpfRule,
};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd, timerfd::TimerFd};

const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2;
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const QUEUE_SIZE_BALLOON: u16 = 256;
const QUEUE_NUM_BALLOON: usize = 2;
const BALLOON_PAGE_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;
const BALLOON_INFLATE_EVENT: bool = true;
const BALLOON_DEFLATE_EVENT: bool = false;
const BITS_OF_TYPE_U64: u64 = 64;

static mut BALLOON_DEV: Option<Arc<Mutex<Balloon>>> = None;
type VirtioBalloonInterrupt = Box<dyn Fn(u32) -> Result<()> + Send + Sync>;

/// IO vector, used to find memory segments.
#[derive(Clone, Copy, Default)]
struct Iovec {
    /// Base address of memory.
    iov_base: GuestAddress,
    /// Length of memory segments.
    iov_len: u64,
}

/// Balloon configuration, which would be used to transport data between `Guest` and `Host`.
#[derive(Copy, Clone, Default)]
struct VirtioBalloonConfig {
    /// Number of pages host wants Guest to give up.
    pub num_pages: u32,
    /// Number of pages we've actually got in balloon.
    pub actual: u32,
}

impl ByteCode for Iovec {}
impl ByteCode for VirtioBalloonConfig {}

/// Bitmap for balloon. It is used if the host page size is bigger than 4k.
struct BalloonedPageBitmap {
    /// The start hva address of bitmap.
    base_address: u64,
    /// Bitmap.
    bitmap: Bitmap<u64>,
}

impl BalloonedPageBitmap {
    fn new(len: u64) -> Self {
        BalloonedPageBitmap {
            base_address: 0,
            bitmap: Bitmap::<u64>::new((len / BITS_OF_TYPE_U64) as usize + 1),
        }
    }

    fn set_bit(&mut self, location: u64) -> Result<()> {
        self.bitmap.set(location as usize)?;
        Ok(())
    }

    fn is_full(&self, bits: u64) -> bool {
        match self.bitmap.count_front_bits(bits as usize) {
            Ok(nr) => nr == bits as usize,
            Err(ref e) => {
                error!("Failed to count bits: {}", e);
                false
            }
        }
    }
}

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
    if offset + obj_len > iov.iov_len {
        return None;
    }

    match address_space.read_object::<T>(GuestAddress(iov.iov_base.raw_value() + offset)) {
        Ok(dat) => Some(dat),
        Err(ref e) => {
            error!(
                "Read virtioqueue failed: {}",
                error_chain::ChainedError::display_chain(e)
            );
            None
        }
    }
}

fn memory_advise(addr: *mut libc::c_void, len: libc::size_t, advice: libc::c_int) {
    // Safe, because the memory to be freed is allocated by guest.
    if unsafe { libc::madvise(addr, len, advice) } != 0 {
        let evt_type = if advice == libc::MADV_WILLNEED {
            "WILLNEED".to_string()
        } else {
            "DONTNEED".to_string()
        };
        let e = std::io::Error::last_os_error();
        error!(
            "Mark memory address: {} to {} failed: {}",
            addr as u64, evt_type, e
        );
    }
}
struct Request {
    /// The index of descriptor for the request.
    desc_index: u16,
    /// Count of elements.
    elem_cnt: u32,
    /// The data which is both readable and writable.
    iovec: Vec<Iovec>,
}

impl Request {
    /// Parse the request from virtio queue.
    /// Return the request from qirtio queue.
    ///
    /// # Arguments
    ///
    /// * `elem` - Available ring.
    fn parse(elem: &Element) -> Result<Request> {
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
    fn mark_balloon_page(
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
            let mut hvaset = Vec::new();
            while let Some(pfn) = iov_to_buf::<u32>(address_space, iov, offset) {
                offset += std::mem::size_of::<u32>() as u64;
                let gpa: GuestAddress = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                let hva = match mem.get_host_address(gpa) {
                    Some(addr) => addr,
                    None => {
                        error!("Can not get host address, gpa: {}", gpa.raw_value());
                        continue;
                    }
                };
                hvaset.push(hva);
            }
            hvaset.sort_by_key(|&b| Reverse(b));
            let host_page_size = host_page_size();
            if host_page_size == BALLOON_PAGE_SIZE {
                while let Some(hva) = hvaset.pop() {
                    if last_addr == 0 {
                        free_len += 1;
                        start_addr = hva;
                    } else if hva == last_addr + BALLOON_PAGE_SIZE {
                        free_len += 1;
                    } else {
                        memory_advise(
                            start_addr as *const libc::c_void as *mut _,
                            (free_len * BALLOON_PAGE_SIZE) as usize,
                            advice,
                        );
                        free_len = 1;
                        start_addr = hva;
                    }

                    if count_iov == iov.iov_len {
                        memory_advise(
                            start_addr as *const libc::c_void as *mut _,
                            (free_len * BALLOON_PAGE_SIZE) as usize,
                            advice,
                        );
                    }
                    count_iov += std::mem::size_of::<u32>() as u64;
                    last_addr = hva;
                }
            } else {
                let mut host_page_bitmap =
                    BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
                while let Some(hva) = hvaset.pop() {
                    if host_page_bitmap.base_address == 0 {
                        if let Some(base_addr) = round_down(hva, host_page_size) {
                            host_page_bitmap.base_address = base_addr;
                        } else {
                            error!(
                                "Failed to round_down, hva: {}, align: {}",
                                hva, host_page_size
                            );
                        }
                    } else if host_page_bitmap.base_address + host_page_size < hva {
                        host_page_bitmap =
                            BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
                        continue;
                    }

                    if let Err(ref e) =
                        host_page_bitmap.set_bit((hva % host_page_size) / BALLOON_PAGE_SIZE)
                    {
                        error!(
                            "Failed to set bit with index: {} :{}",
                            (hva % host_page_size) / BALLOON_PAGE_SIZE,
                            e
                        );
                    }
                    if host_page_bitmap.is_full(host_page_size / BALLOON_PAGE_SIZE) {
                        memory_advise(
                            host_page_bitmap.base_address as *const libc::c_void as *mut _,
                            host_page_size as usize,
                            advice,
                        );
                        host_page_bitmap =
                            BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct BlnMemoryRegion {
    /// GPA.
    guest_phys_addr: u64,
    /// Size of the memory region.
    memory_size: u64,
    /// HVA.
    userspace_addr: u64,
    /// No flags specified for now.
    flags_padding: u64,
    /// Region Page size
    reg_page_size: Option<u64>,
}

#[derive(Clone)]
struct BlnMemInfo {
    regions: Arc<Mutex<Vec<BlnMemoryRegion>>>,
}

impl BlnMemInfo {
    fn new() -> BlnMemInfo {
        BlnMemInfo {
            regions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_host_address(&self, addr: GuestAddress) -> Option<u64> {
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

    fn has_huge_page(&self) -> bool {
        let all_regions = self.regions.lock().unwrap();
        for reg in all_regions.iter() {
            if let Some(size) = reg.reg_page_size {
                if size > host_page_size() {
                    return true;
                }
            }
        }
        false
    }

    fn add_mem_range(&self, fr: &FlatRange) {
        let guest_phys_addr = fr.addr_range.base.raw_value();
        let memory_size = fr.addr_range.size;
        if let Some(host_addr) = fr.owner.get_host_address() {
            let userspace_addr = host_addr + fr.offset_in_region;
            let reg_page_size = fr.owner.get_region_page_size();
            self.regions.lock().unwrap().push(BlnMemoryRegion {
                guest_phys_addr,
                memory_size,
                userspace_addr,
                flags_padding: 0_u64,
                reg_page_size,
            });
        } else {
            error!("Failed to get host address!");
        }
    }

    fn delete_mem_range(&self, fr: &FlatRange) {
        let mut mem_regions = self.regions.lock().unwrap();
        if let Some(host_addr) = fr.owner.get_host_address() {
            let reg_page_size = fr.owner.get_region_page_size();
            let target = BlnMemoryRegion {
                guest_phys_addr: fr.addr_range.base.raw_value(),
                memory_size: fr.addr_range.size,
                userspace_addr: host_addr + fr.offset_in_region,
                flags_padding: 0_u64,
                reg_page_size,
            };
            for (index, mr) in mem_regions.iter().enumerate() {
                if mr.guest_phys_addr == target.guest_phys_addr
                    && mr.memory_size == target.memory_size
                    && mr.userspace_addr == target.userspace_addr
                    && mr.flags_padding == target.flags_padding
                    && mr.reg_page_size == target.reg_page_size
                {
                    mem_regions.remove(index);
                    return;
                }
            }
        } else {
            error!("Failed to get host address!");
        }
    }

    /// Get Ram size of AddressSpace.
    fn get_ram_size(&self) -> u64 {
        let mut size = 0_u64;
        let unlockedrgs = self.regions.lock().unwrap();
        for rg in unlockedrgs.iter() {
            size += rg.memory_size;
        }
        size
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
    /// Event timer for BALLOON_CHANGED event.
    event_timer: Arc<Mutex<TimerFd>>,
    /// Actual balloon size
    balloon_actual: Arc<AtomicU32>,
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
                        if !self.mem_info.has_huge_page() {
                            req.mark_balloon_page(req_type, &self.mem_space, &self.mem_info);
                        }
                        unlocked_queue
                            .vring
                            .add_used(&self.mem_space, req.desc_index, req.elem_cnt as u32)
                            .chain_err(|| "Failed to add balloon response into used queue")?;
                    }
                    Err(e) => {
                        error!("Fail to parse available descriptor chain: {:?}", e);
                        break;
                    }
                }
            }
        }
        self.signal_used_queue()
            .chain_err(|| "Failed to notify used queue after processing balloon events")?;
        Ok(())
    }

    /// Trigger interrupt to notify vm.
    fn signal_used_queue(&self) -> Result<()> {
        (self.interrupt_cb)(VIRTIO_MMIO_INT_VRING).chain_err(|| "Failed to write interrupt eventfd")
    }

    /// Send balloon changed event.
    fn send_balloon_changed_event(&self) {
        let ram_size = self.mem_info.get_ram_size();
        let balloon_size = self.get_balloon_memory_size();
        let msg = BalloonInfo {
            actual: ram_size - balloon_size,
        };
        event!(BALLOON_CHANGED; msg);
    }

    /// Get the memory size of balloon.
    fn get_balloon_memory_size(&self) -> u64 {
        (self.balloon_actual.load(Ordering::Acquire) as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }
}

/// Create a new EventNotifier.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor.
/// * `handler` - Handle function.
fn build_event_notifier(fd: RawFd, handler: Box<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![Arc::new(Mutex::new(handler))],
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
                if let Err(ref e) = locked_balloon_io.process_balloon_queue(BALLOON_INFLATE_EVENT) {
                    error!(
                        "Failed to inflate balloon: {}",
                        error_chain::ChainedError::display_chain(e)
                    );
                };
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
                if let Err(ref e) = locked_balloon_io.process_balloon_queue(BALLOON_DEFLATE_EVENT) {
                    error!(
                        "Failed to deflate balloon: {}",
                        error_chain::ChainedError::display_chain(e)
                    );
                };
                None
            });
            let locked_balloon_io = balloon_io.lock().unwrap();
            notifiers.push(build_event_notifier(
                locked_balloon_io.def_evt.as_raw_fd(),
                handler,
            ));
        }
        {
            let cloned_balloon_io = balloon_io.clone();
            let handler: Box<NotifierCallback> = Box::new(move |_, fd: RawFd| {
                read_fd(fd);
                let locked_balloon_io = cloned_balloon_io.lock().unwrap();
                locked_balloon_io.send_balloon_changed_event();
                None
            });
            let locked_balloon_io = balloon_io.lock().unwrap();
            notifiers.push(build_event_notifier(
                locked_balloon_io
                    .event_timer
                    .clone()
                    .lock()
                    .unwrap()
                    .as_raw_fd(),
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
    actual: Arc<AtomicU32>,
    /// Target memory pages.
    num_pages: u32,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioBalloonInterrupt>>,
    /// Balloon memory information.
    mem_info: BlnMemInfo,
    /// Memory space
    mem_space: Arc<AddressSpace>,
    /// Event timer for BALLOON_CHANGED event.
    event_timer: Arc<Mutex<TimerFd>>,
}

impl Balloon {
    /// Create a balloon device.
    ///
    /// # Arguments
    ///
    /// * `bln_cfg` - Balloon configuration.
    pub fn new(bln_cfg: BalloonConfig, mem_space: Arc<AddressSpace>) -> Balloon {
        let mut device_features = 1u64 << VIRTIO_F_VERSION_1;
        if bln_cfg.deflate_on_oom {
            device_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        }

        Balloon {
            device_features,
            driver_features: 0u64,
            actual: Arc::new(AtomicU32::new(0)),
            num_pages: 0u32,
            interrupt_cb: None,
            mem_info: BlnMemInfo::new(),
            mem_space,
            event_timer: Arc::new(Mutex::new(TimerFd::new().unwrap())),
        }
    }

    /// Init balloon object for global use.
    pub fn object_init(dev: Arc<Mutex<Balloon>>) {
        // Safe, because there is no confliction when writing global variable BALLOON_DEV, in other words,
        // this function will not be called simultaneously.
        unsafe {
            if BALLOON_DEV.is_none() {
                BALLOON_DEV = Some(dev)
            }
        }
    }

    /// Notify configuration changes to VM.
    fn signal_config_change(&self) -> Result<()> {
        if self.interrupt_cb.is_none() {
            return Err(ErrorKind::DeviceNotActivated("balloon".to_string()).into());
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
    pub fn set_guest_memory_size(&mut self, size: u64) -> Result<()> {
        let host_page_size = host_page_size();
        if host_page_size > BALLOON_PAGE_SIZE && !self.mem_info.has_huge_page() {
            warn!("Balloon used with backing page size > 4kiB, this may not be reliable");
        }
        let target = (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let current_ram_size = (self.mem_info.get_ram_size() >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let vm_target = cmp::min(target, current_ram_size);
        self.num_pages = current_ram_size - vm_target;
        self.signal_config_change().chain_err(|| {
            "Failed to notify about configuration change after setting balloon memory"
        })?;
        let msg = BalloonInfo {
            actual: self.get_guest_memory_size(),
        };
        event!(BALLOON_CHANGED; msg);
        Ok(())
    }

    /// Get the size of memory that reclaimed by balloon.
    fn get_balloon_memory_size(&self) -> u64 {
        (self.actual.load(Ordering::Acquire) as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }

    /// Get the actual memory size of guest.
    pub fn get_guest_memory_size(&self) -> u64 {
        self.mem_info.get_ram_size() - self.get_balloon_memory_size()
    }
}

impl VirtioDevice for Balloon {
    /// Realize a balloon device.
    fn realize(&mut self) -> Result<()> {
        let bln_mem_info = BlnMemInfo::new();
        self.mem_info = bln_mem_info.clone();
        self.mem_space
            .register_listener(Box::new(bln_mem_info))
            .chain_err(|| "Failed to register memory listener defined by balloon device.")?;
        Ok(())
    }

    /// Get the type of balloon.
    fn device_type(&self) -> u32 {
        VIRTIO_TYPE_BALLOON as u32
    }

    /// Get the number of balloon-device queues.
    fn queue_num(&self) -> usize {
        QUEUE_NUM_BALLOON
    }

    /// Get the zise of balloon queue.
    fn queue_size(&self) -> u16 {
        QUEUE_SIZE_BALLOON
    }

    /// Get the feature of `balloon` device.
    fn get_device_features(&self, features_select: u32) -> u32 {
        read_u32(self.device_features, features_select)
    }

    /// Set feature for device.
    ///
    /// # Arguments
    ///
    /// * `page` - Selector of feature.
    /// * `value` - Value to be set.
    fn set_driver_features(&mut self, page: u32, value: u32) {
        let mut v = write_u32(value, page);
        let unrequested_features = v & !self.device_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            v &= !unrequested_features;
        }
        self.driver_features |= v;
    }

    /// Read configuration.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset from base address.
    /// * `data` - Read data to `data`.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) -> Result<()> {
        let new_config = VirtioBalloonConfig {
            num_pages: self.num_pages,
            actual: self.actual.load(Ordering::Acquire),
        };
        if offset != 0 {
            return Err(ErrorKind::IncorrectOffset(0, offset).into());
        }
        data.write_all(&new_config.as_bytes()[offset as usize..data.len()])
            .chain_err(|| "Failed to write data to 'data' while reading balloon config")?;
        Ok(())
    }

    /// Write configuration.
    ///
    /// # Argument
    ///
    /// * `_offset` - Offset from base address.
    fn write_config(&mut self, _offset: u64, data: &[u8]) -> Result<()> {
        // Guest update actual balloon size
        // Safe, because the results will be checked.
        let old_actual = self.actual.load(Ordering::Acquire);
        let new_actual = match unsafe { data.align_to::<u32>() } {
            (_, [new_config], _) => *new_config,
            _ => {
                return Err(ErrorKind::FailedToWriteConfig.into());
            }
        };
        if old_actual != new_actual {
            let mut timer = self.event_timer.lock().unwrap();
            if let Ok(ret) = timer.is_armed() {
                if !ret {
                    timer
                        .reset(Duration::new(1, 0), None)
                        .chain_err(|| "Failed to reset timer for qmp event during ballooning")?;
                }
            }
        }
        self.actual.store(new_actual, Ordering::Release);

        Ok(())
    }

    /// Active balloon device.
    ///
    /// # Arguments
    ///
    /// * `mem_space` - Address space.
    /// * `interrupt_evt` - Interrupt EventFd.
    /// * `interrupt_stats` - Statistics interrupt.
    /// * `queues` - Different virtio queues.
    /// * `queue_evts` Different EventFd.
    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_evt: EventFd,
        interrupt_stats: Arc<AtomicU32>,
        mut queues: Vec<Arc<Mutex<Queue>>>,
        mut queue_evts: Vec<EventFd>,
    ) -> Result<()> {
        if queues.len() != QUEUE_NUM_BALLOON {
            return Err(ErrorKind::IncorrectQueueNum(QUEUE_NUM_BALLOON, queues.len()).into());
        }

        let inf_queue = queues.remove(0);
        let inf_queue_evt = queue_evts.remove(0);
        let def_queue = queues.remove(0);
        let def_queue_evt = queue_evts.remove(0);
        let interrupt_evt = interrupt_evt
            .try_clone()
            .chain_err(|| "Failed to clone event fd for balloon device")?;
        let interrupt_stats = interrupt_stats;
        let cb = Arc::new(Box::new(move |status: u32| {
            interrupt_stats.fetch_or(status, Ordering::SeqCst);
            interrupt_evt.write(1).chain_err(|| ErrorKind::EventFdWrite)
        }) as VirtioBalloonInterrupt);

        self.interrupt_cb = Some(cb.clone());
        let handler = BalloonIoHandler {
            driver_features: self.driver_features,
            mem_space,
            inf_queue,
            inf_evt: inf_queue_evt,
            def_queue,
            def_evt: def_queue_evt,
            interrupt_cb: cb.clone(),
            mem_info: self.mem_info.clone(),
            event_timer: self.event_timer.clone(),
            balloon_actual: self.actual.clone(),
        };

        EventLoop::update_event(
            EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler))),
            None,
        )
        .chain_err(|| "Failed to register balloon event notifier to MainLoop")?;

        Ok(())
    }

    fn reset(&mut self) -> Option<()> {
        None
    }

    fn update_config(
        &mut self,
        _dev_config: Option<Arc<dyn machine_manager::config::ConfigCheck>>,
    ) -> Result<()> {
        bail!("Unsupported to update configuration")
    }
}

pub fn qmp_balloon(target: u64) -> bool {
    // Safe, because there is no confliction when writing global variable BALLOON_DEV, in other words,
    // this function will not be called simultaneously.
    if let Some(dev) = unsafe { &BALLOON_DEV } {
        match dev.lock().unwrap().set_guest_memory_size(target) {
            Ok(()) => {
                return true;
            }
            Err(ref e) => {
                error!(
                    "Failed to set balloon memory size: {}, :{}",
                    target,
                    error_chain::ChainedError::display_chain(e)
                );
                return false;
            }
        }
    }
    error!("Balloon device not configured");
    false
}

pub fn qmp_query_balloon() -> Option<u64> {
    // Safe, because there is no confliction when writing global variable BALLOON_DEV, in other words,
    // this function will not be called simultaneously.
    if let Some(dev) = unsafe { &BALLOON_DEV } {
        let unlocked_dev = dev.lock().unwrap();
        return Some(unlocked_dev.get_guest_memory_size());
    }
    None
}

/// Create a syscall bpf rule for device `Balloon`.
pub fn balloon_allow_list(syscall_allow_list: &mut Vec<BpfRule>) {
    syscall_allow_list.extend(vec![
        BpfRule::new(libc::SYS_timerfd_create),
        BpfRule::new(libc::SYS_timerfd_settime),
        BpfRule::new(libc::SYS_timerfd_gettime),
    ])
}

#[cfg(test)]
mod tests {
    pub use super::super::*;
    pub use super::*;

    use address_space::{HostMemMapping, Region};

    const MEMORY_SIZE: u64 = (1024 * 1024) as u64;

    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36);
        let sys_space = AddressSpace::new(root).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(GuestAddress(0), MEMORY_SIZE, None, false, false).unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone()),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    #[test]
    fn test_balloon_init() {
        let bln_cfg = BalloonConfig {
            deflate_on_oom: true,
        };

        let mem_space = address_space_init();
        let mut bln = Balloon::new(bln_cfg, mem_space);
        assert_eq!(bln.driver_features, 0);
        assert_eq!(bln.actual.load(Ordering::Acquire), 0);
        assert_eq!(bln.num_pages, 0);
        assert!(bln.interrupt_cb.is_none());
        let feature = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
        assert_eq!(bln.device_features, feature);

        // test realize function.
        bln.realize().unwrap();
        assert_eq!(bln.device_type(), 5);
        assert_eq!(bln.queue_num(), 2);
        assert_eq!(bln.queue_size(), 256);
    }

    #[test]
    fn test_object_init() {
        let bln_cfg = BalloonConfig {
            deflate_on_oom: true,
        };

        let mem_space = address_space_init();
        let balloon = Arc::new(Mutex::new(Balloon::new(bln_cfg, mem_space)));
        Balloon::object_init(balloon);
        let balloon_get = unsafe { &BALLOON_DEV };
        assert!(balloon_get.is_some());
    }

    #[test]
    fn test_read_config() {
        let bln_cfg = BalloonConfig {
            deflate_on_oom: true,
        };

        let mem_space = address_space_init();
        let balloon = Balloon::new(bln_cfg, mem_space);
        let write_data = [0, 0, 0, 0, 1, 0, 0, 0];
        let mut random_data: Vec<u8> = vec![0; 8];
        let addr = 0x00;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.actual.store(1, Ordering::Release);
        balloon.read_config(addr, &mut random_data).unwrap();
        assert_eq!(random_data, write_data);
    }

    #[test]
    fn test_write_config() {
        let bln_cfg = BalloonConfig {
            deflate_on_oom: true,
        };

        let mem_space = address_space_init();
        let mut balloon = Balloon::new(bln_cfg, mem_space);
        let write_data = [1, 0, 0, 0];
        let addr = 0x00;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.write_config(addr, &write_data).unwrap();
        assert_eq!(balloon.actual.load(Ordering::Acquire), 1);
    }
}
