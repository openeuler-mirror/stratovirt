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

use std::mem::size_of;
use std::os::unix::io::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::{
    cmp::{self, Reverse},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Parser};
use log::{error, warn};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd, timerfd::TimerFd};

use crate::{
    error::*, read_config_default, report_virtio_error, virtio_has_feature, Element, Queue,
    VirtioBase, VirtioDevice, VirtioInterrupt, VirtioInterruptType, VIRTIO_F_VERSION_1,
    VIRTIO_TYPE_BALLOON,
};
use address_space::{
    AddressSpace, FlatRange, GuestAddress, Listener, ListenerReqType, RegionIoEventFd, RegionType,
};
use machine_manager::{
    config::{get_pci_df, parse_bool, DEFAULT_VIRTQUEUE_SIZE},
    config::{valid_id, ConfigCheck, ConfigError},
    event,
    event_loop::{register_event_helper, unregister_event_helper},
    qmp::qmp_channel::QmpChannel,
    qmp::qmp_schema::BalloonInfo,
};
use util::{
    bitmap::Bitmap,
    byte_code::ByteCode,
    loop_context::{
        read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
    },
    num_ops::round_down,
    offset_of,
    seccomp::BpfRule,
    unix::host_page_size,
};

const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2;
const VIRTIO_BALLOON_F_REPORTING: u32 = 5;
/// The feature for Auto-balloon
const VIRTIO_BALLOON_F_MESSAGE_VQ: u32 = 16;
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;
const QUEUE_NUM_BALLOON: usize = 2;
const BALLOON_PAGE_SIZE: u64 = 1 << VIRTIO_BALLOON_PFN_SHIFT;
const BALLOON_INFLATE_EVENT: bool = true;
const BALLOON_DEFLATE_EVENT: bool = false;
const IN_IOVEC: bool = true;
const OUT_IOVEC: bool = false;
const BITS_OF_TYPE_U64: u64 = 64;

const MEM_BUFFER_PERCENT_MIN: u32 = 20;
const MEM_BUFFER_PERCENT_MAX: u32 = 80;
const MONITOR_INTERVAL_SECOND_MIN: u32 = 5;
const MONITOR_INTERVAL_SECOND_MAX: u32 = 300;

static mut BALLOON_DEV: Option<Arc<Mutex<Balloon>>> = None;

/// IO vector, used to find memory segments.
#[derive(Clone, Copy, Default)]
struct GuestIovec {
    /// Base address of memory.
    iov_base: GuestAddress,
    /// Length of memory segments.
    iov_len: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(packed(1))]
struct BalloonStat {
    _tag: u16,
    _val: u64,
}

/// Balloon configuration, which would be used to transport data between `Guest` and `Host`.
#[derive(Copy, Clone, Default)]
struct VirtioBalloonConfig {
    /// The target page numbers of balloon device.
    _num_pages: u32,
    /// Number of pages we've actually got in balloon device.
    _actual: u32,
    _reserved: u32,
    _reserved1: u32,
    /// Buffer percent is a percentage of memory actually needed by
    /// the applications and services running inside the virtual machine.
    /// This parameter takes effect only when VIRTIO_BALLOON_F_MESSAGE_VQ is supported.
    /// Recommended value range: [20, 80] and default is 50.
    _membuf_percent: u32,
    /// Monitor interval(second) host wants to adjust VM memory size.
    /// Recommended value range: [5, 300] and default is 10.
    _monitor_interval: u32,
}

impl ByteCode for BalloonStat {}
impl ByteCode for GuestIovec {}
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
                error!("Failed to count bits: {:?}", e);
                false
            }
        }
    }
}

/// Read data segment starting at `iov.iov_base` + `offset` to buffer <T>.
/// Return buffer <T>.
///
/// # Arguments
///
/// * `address_space` - Address space of VM.
/// * `iov` - IOvec includes base address and length.
/// * `offset` - Offset.
fn iov_to_buf<T: ByteCode>(
    address_space: &Arc<AddressSpace>,
    &iov: &GuestIovec,
    offset: u64,
) -> Option<T> {
    let obj_len = std::mem::size_of::<T>() as u64;
    if offset + obj_len > iov.iov_len {
        return None;
    }

    match address_space.read_object::<T>(GuestAddress(iov.iov_base.raw_value() + offset)) {
        Ok(dat) => Some(dat),
        Err(ref e) => {
            error!("Read virtioqueue failed: {:?}", e);
            None
        }
    }
}

fn memory_advise(addr: *mut libc::c_void, len: libc::size_t, advice: libc::c_int) {
    // SAFETY: The memory to be freed is allocated by guest.
    if unsafe { libc::madvise(addr, len, advice) } != 0 {
        let evt_type = match advice {
            libc::MADV_DONTNEED => "DONTNEED".to_string(),
            libc::MADV_REMOVE => "REMOVE".to_string(),
            _ => "WILLNEED".to_string(),
        };
        let e = std::io::Error::last_os_error();
        error!(
            "Mark memory address: {} to {} failed: {:?}",
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
    iovec: Vec<GuestIovec>,
}

impl Request {
    /// Parse the request from virtio queue.
    /// Return the request from virtio queue.
    ///
    /// # Arguments
    ///
    /// * `elem` - Available ring.
    /// * `elem_type` - The type of available ring.
    fn parse(elem: &Element, elem_type: bool) -> Result<Request> {
        let mut request = Request {
            desc_index: elem.index,
            elem_cnt: 0u32,
            iovec: Vec::new(),
        };
        let iovec = if elem_type {
            &elem.in_iovec
        } else {
            &elem.out_iovec
        };
        if iovec.is_empty() {
            return Err(anyhow!(VirtioError::ElementEmpty));
        }
        for elem_iov in iovec {
            request.iovec.push(GuestIovec {
                iov_base: elem_iov.addr,
                iov_len: elem_iov.len as u64,
            });
            request.elem_cnt += elem_iov.len;
        }
        Ok(request)
    }

    fn balloon_deflate_page(&self, hvaset: &mut Vec<(u64, bool)>) {
        let mut free_len: u64 = 0;
        let mut start_addr: u64 = 0;
        let mut last_addr: u64 = 0;

        while let Some((hva, _)) = hvaset.pop() {
            if last_addr == 0 {
                free_len += 1;
                start_addr = hva;
            } else if hva == last_addr + BALLOON_PAGE_SIZE {
                free_len += 1;
            } else {
                memory_advise(
                    start_addr as *const libc::c_void as *mut _,
                    (free_len * BALLOON_PAGE_SIZE) as usize,
                    libc::MADV_WILLNEED,
                );
                free_len = 1;
                start_addr = hva;
            }

            last_addr = hva;
        }

        if free_len != 0 {
            memory_advise(
                start_addr as *const libc::c_void as *mut _,
                (free_len * BALLOON_PAGE_SIZE) as usize,
                libc::MADV_WILLNEED,
            );
        }
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
        mem: &Arc<Mutex<BlnMemInfo>>,
    ) {
        let mut last_addr: u64 = 0;
        let mut last_share = false;
        let mut free_len: u64 = 0;
        let mut start_addr: u64 = 0;
        let mut hvaset = Vec::new();

        for iov in self.iovec.iter() {
            let mut offset = 0;

            while let Some(pfn) = iov_to_buf::<u32>(address_space, iov, offset) {
                offset += std::mem::size_of::<u32>() as u64;
                let gpa: GuestAddress = GuestAddress((pfn as u64) << VIRTIO_BALLOON_PFN_SHIFT);
                let (hva, shared) = match mem.lock().unwrap().get_host_address(gpa) {
                    Some((addr, mem_share)) => (addr, mem_share),
                    None => {
                        // Windows OS will populate the address with PA of 0
                        continue;
                    }
                };
                hvaset.push((hva, shared));
            }
        }
        hvaset.sort_by_key(|&b| Reverse(b.0));

        if req_type == BALLOON_DEFLATE_EVENT {
            self.balloon_deflate_page(&mut hvaset);
            return;
        }

        let host_page_size = host_page_size();
        let mut advice = 0;
        // If host_page_size equals BALLOON_PAGE_SIZE and have the same share properties,
        // we can directly call the madvise function without any problem. And if the advice is
        // MADV_WILLNEED, we just hint the whole host page it lives on, since we can't do
        // anything smaller.
        if host_page_size == BALLOON_PAGE_SIZE {
            while let Some((hva, share)) = hvaset.pop() {
                if last_addr == 0 {
                    free_len += 1;
                    start_addr = hva;
                    last_share = share;
                    if share {
                        advice = libc::MADV_REMOVE;
                    } else {
                        advice = libc::MADV_DONTNEED;
                    }
                } else if hva == last_addr + BALLOON_PAGE_SIZE && last_share == share {
                    free_len += 1;
                } else {
                    memory_advise(
                        start_addr as *const libc::c_void as *mut _,
                        (free_len * BALLOON_PAGE_SIZE) as usize,
                        advice,
                    );
                    free_len = 1;
                    start_addr = hva;
                    last_share = share;
                    if share {
                        advice = libc::MADV_REMOVE;
                    } else {
                        advice = libc::MADV_DONTNEED;
                    }
                }

                last_addr = hva;
            }
            if free_len != 0 {
                memory_advise(
                    start_addr as *const libc::c_void as *mut _,
                    (free_len * BALLOON_PAGE_SIZE) as usize,
                    advice,
                );
            }
        } else {
            let mut host_page_bitmap = BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
            while let Some((hva, share)) = hvaset.pop() {
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
                    host_page_bitmap = BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
                    continue;
                }

                if let Err(ref e) =
                    host_page_bitmap.set_bit((hva % host_page_size) / BALLOON_PAGE_SIZE)
                {
                    error!(
                        "Failed to set bit with index: {} :{:?}",
                        (hva % host_page_size) / BALLOON_PAGE_SIZE,
                        e
                    );
                }
                if host_page_bitmap.is_full(host_page_size / BALLOON_PAGE_SIZE) {
                    if share {
                        advice = libc::MADV_REMOVE;
                    } else {
                        advice = libc::MADV_DONTNEED;
                    }
                    memory_advise(
                        host_page_bitmap.base_address as *const libc::c_void as *mut _,
                        host_page_size as usize,
                        advice,
                    );
                    host_page_bitmap = BalloonedPageBitmap::new(host_page_size / BALLOON_PAGE_SIZE);
                }
            }
        }
    }

    fn release_pages(&self, mem: &Arc<Mutex<BlnMemInfo>>) {
        for iov in self.iovec.iter() {
            let gpa: GuestAddress = iov.iov_base;
            let (hva, shared) = match mem.lock().unwrap().get_host_address(gpa) {
                Some((hva, shared)) => (hva, shared),
                None => {
                    error!("Can not get host address, gpa: {}", gpa.raw_value());
                    continue;
                }
            };
            let advice = if shared {
                libc::MADV_REMOVE
            } else {
                libc::MADV_DONTNEED
            };
            memory_advise(
                hva as *const libc::c_void as *mut _,
                iov.iov_len as usize,
                advice,
            );
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
    /// Region shared or not
    mem_share: bool,
}

struct BlnMemInfo {
    regions: Mutex<Vec<BlnMemoryRegion>>,
    enabled: bool,
}

impl BlnMemInfo {
    fn new() -> BlnMemInfo {
        BlnMemInfo {
            regions: Mutex::new(Vec::new()),
            enabled: false,
        }
    }

    fn get_host_address(&self, addr: GuestAddress) -> Option<(u64, bool)> {
        let all_regions = self.regions.lock().unwrap();
        for i in 0..all_regions.len() {
            if addr.raw_value() < all_regions[i].guest_phys_addr + all_regions[i].memory_size
                && addr.raw_value() >= all_regions[i].guest_phys_addr
            {
                return Some((
                    all_regions[i].userspace_addr + addr.raw_value()
                        - all_regions[i].guest_phys_addr,
                    all_regions[i].mem_share,
                ));
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
                mem_share: fr.owner.get_host_share().unwrap_or(false),
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
                mem_share: false,
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
    ) -> Result<(), anyhow::Error> {
        match req_type {
            ListenerReqType::AddRegion => {
                let fr = range.unwrap();
                if fr.owner.region_type() == RegionType::Ram {
                    self.add_mem_range(fr);
                }
            }
            ListenerReqType::DeleteRegion => {
                let fr = range.unwrap();
                if fr.owner.region_type() == RegionType::Ram {
                    self.delete_mem_range(fr);
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
    inf_evt: Arc<EventFd>,
    /// Deflate queue.
    def_queue: Arc<Mutex<Queue>>,
    /// Deflate EventFd.
    def_evt: Arc<EventFd>,
    /// Reporting queue.
    report_queue: Option<Arc<Mutex<Queue>>>,
    /// Reporting EventFd.
    report_evt: Option<Arc<EventFd>>,
    /// Auto balloon msg queue.
    msg_queue: Option<Arc<Mutex<Queue>>>,
    /// Auto balloon msg EventFd.
    msg_evt: Option<Arc<EventFd>>,
    /// Device is broken or not.
    device_broken: Arc<AtomicBool>,
    /// The interrupt call back function.
    interrupt_cb: Arc<VirtioInterrupt>,
    /// Balloon Memory information.
    mem_info: Arc<Mutex<BlnMemInfo>>,
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
    /// if `req_type` is `BALLOON_INFLATE_EVENT`, then inflate the balloon, otherwise, deflate the
    /// balloon.
    fn process_balloon_queue(&mut self, req_type: bool) -> Result<()> {
        let queue = if req_type {
            trace::virtio_receive_request("Balloon".to_string(), "to inflate".to_string());
            &self.inf_queue
        } else {
            trace::virtio_receive_request("Balloon".to_string(), "to inflate".to_string());
            &self.def_queue
        };
        let mut locked_queue = queue.lock().unwrap();
        loop {
            let elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for process balloon queue")?;

            if elem.desc_num == 0 {
                break;
            }
            let req = Request::parse(&elem, OUT_IOVEC)
                .with_context(|| "Fail to parse available descriptor chain")?;
            if !self.mem_info.lock().unwrap().has_huge_page() {
                req.mark_balloon_page(req_type, &self.mem_space, &self.mem_info);
            }
            locked_queue
                .vring
                .add_used(&self.mem_space, req.desc_index, req.elem_cnt)
                .with_context(|| "Failed to add balloon response into used queue")?;
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("balloon", VirtioInterruptType::Vring)
                })?
        }

        Ok(())
    }

    fn reporting_evt_handler(&mut self) -> Result<()> {
        let queue = self
            .report_queue
            .as_ref()
            .with_context(|| VirtioError::VirtQueueIsNone)?;
        let mut locked_queue = queue.lock().unwrap();

        loop {
            let elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring for reporting free pages")?;

            if elem.desc_num == 0 {
                break;
            }
            let req = Request::parse(&elem, IN_IOVEC)
                .with_context(|| "Fail to parse available descriptor chain")?;
            if !self.mem_info.lock().unwrap().has_huge_page() {
                req.release_pages(&self.mem_info);
            }
            locked_queue
                .vring
                .add_used(&self.mem_space, req.desc_index, req.elem_cnt)
                .with_context(|| "Failed to add balloon response into used queue")?;
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("balloon", VirtioInterruptType::Vring)
                })?;
        }

        Ok(())
    }

    fn auto_msg_evt_handler(&mut self) -> Result<()> {
        let queue = self
            .msg_queue
            .as_ref()
            .with_context(|| VirtioError::VirtQueueIsNone)?;
        let mut locked_queue = queue.lock().unwrap();

        loop {
            let elem = locked_queue
                .vring
                .pop_avail(&self.mem_space, self.driver_features)
                .with_context(|| "Failed to pop avail ring")?;

            if elem.desc_num == 0 {
                break;
            }
            let req = Request::parse(&elem, OUT_IOVEC)
                .with_context(|| "Fail to parse available descriptor chain")?;
            // SAFETY: There is no confliction when writing global variable BALLOON_DEV, in other
            // words, this function will not be called simultaneously.
            if let Some(dev) = unsafe { &BALLOON_DEV } {
                let mut balloon_dev = dev.lock().unwrap();
                for iov in req.iovec.iter() {
                    if let Some(stat) = iov_to_buf::<BalloonStat>(&self.mem_space, iov, 0) {
                        let ram_size = (balloon_dev.mem_info.lock().unwrap().get_ram_size()
                            >> VIRTIO_BALLOON_PFN_SHIFT)
                            as u32;
                        balloon_dev.set_num_pages(cmp::min(stat._val as u32, ram_size));
                    }
                }
                balloon_dev
                    .signal_config_change()
                    .with_context(|| "Failed to notify guest")?;
            }

            locked_queue
                .vring
                .add_used(&self.mem_space, req.desc_index, req.elem_cnt)
                .with_context(|| "Failed to add balloon response into used queue")?;
            (self.interrupt_cb)(&VirtioInterruptType::Vring, Some(&locked_queue), false)
                .with_context(|| {
                    VirtioError::InterruptTrigger("balloon", VirtioInterruptType::Vring)
                })?;
        }

        Ok(())
    }

    /// Send balloon changed event.
    fn send_balloon_changed_event(&self) {
        let ram_size = self.mem_info.lock().unwrap().get_ram_size();
        let balloon_size = self.get_balloon_memory_size();
        let msg = BalloonInfo {
            actual: ram_size - balloon_size,
        };
        event!(BalloonChanged; msg);
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
fn build_event_notifier(fd: RawFd, handler: Rc<NotifierCallback>) -> EventNotifier {
    EventNotifier::new(
        NotifierOperation::AddShared,
        fd,
        None,
        EventSet::IN,
        vec![handler],
    )
}

impl EventNotifierHelper for BalloonIoHandler {
    /// Register event notifiers for different queue event.
    fn internal_notifiers(balloon_io: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let mut notifiers = Vec::new();
        let locked_balloon_io = balloon_io.lock().unwrap();

        // register event notifier for inflate event.
        let cloned_balloon_io = balloon_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
            if locked_balloon_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            if let Err(e) = locked_balloon_io.process_balloon_queue(BALLOON_INFLATE_EVENT) {
                error!("Failed to inflate balloon: {:?}", e);
                report_virtio_error(
                    locked_balloon_io.interrupt_cb.clone(),
                    locked_balloon_io.driver_features,
                    &locked_balloon_io.device_broken,
                );
            };
            None
        });
        notifiers.push(build_event_notifier(
            locked_balloon_io.inf_evt.as_raw_fd(),
            handler,
        ));

        // register event notifier for deflate event.
        let cloned_balloon_io = balloon_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
            if locked_balloon_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            if let Err(e) = locked_balloon_io.process_balloon_queue(BALLOON_DEFLATE_EVENT) {
                error!("Failed to deflate balloon: {:?}", e);
                report_virtio_error(
                    locked_balloon_io.interrupt_cb.clone(),
                    locked_balloon_io.driver_features,
                    &locked_balloon_io.device_broken,
                );
            };
            None
        });
        notifiers.push(build_event_notifier(
            locked_balloon_io.def_evt.as_raw_fd(),
            handler,
        ));

        // register event notifier for free page reporting event.
        if let Some(report_evt) = locked_balloon_io.report_evt.as_ref() {
            let cloned_balloon_io = balloon_io.clone();
            let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
                read_fd(fd);
                let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
                if locked_balloon_io.device_broken.load(Ordering::SeqCst) {
                    return None;
                }
                if let Err(e) = locked_balloon_io.reporting_evt_handler() {
                    error!("Failed to report free pages: {:?}", e);
                    report_virtio_error(
                        locked_balloon_io.interrupt_cb.clone(),
                        locked_balloon_io.driver_features,
                        &locked_balloon_io.device_broken,
                    );
                }
                None
            });
            notifiers.push(build_event_notifier(report_evt.as_raw_fd(), handler));
        }

        if let Some(msg_evt) = locked_balloon_io.msg_evt.as_ref() {
            let cloned_balloon_io = balloon_io.clone();
            let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
                read_fd(fd);
                let mut locked_balloon_io = cloned_balloon_io.lock().unwrap();
                if locked_balloon_io.device_broken.load(Ordering::SeqCst) {
                    return None;
                }
                if let Err(e) = locked_balloon_io.auto_msg_evt_handler() {
                    error!("Failed to msg: {:?}", e);
                    report_virtio_error(
                        locked_balloon_io.interrupt_cb.clone(),
                        locked_balloon_io.driver_features,
                        &locked_balloon_io.device_broken,
                    );
                }
                None
            });
            notifiers.push(build_event_notifier(msg_evt.as_raw_fd(), handler));
        }

        // register event notifier for timer event.
        let cloned_balloon_io = balloon_io.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_, fd: RawFd| {
            read_fd(fd);
            let locked_balloon_io = cloned_balloon_io.lock().unwrap();
            if locked_balloon_io.device_broken.load(Ordering::SeqCst) {
                return None;
            }
            locked_balloon_io.send_balloon_changed_event();
            None
        });
        notifiers.push(build_event_notifier(
            locked_balloon_io
                .event_timer
                .clone()
                .lock()
                .unwrap()
                .as_raw_fd(),
            handler,
        ));

        notifiers
    }
}

#[derive(Parser, Debug, Clone, Default)]
#[command(name = "balloon")]
pub struct BalloonConfig {
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long, default_value = "false", action = ArgAction::Append)]
    deflate_on_oom: bool,
    #[arg(long, default_value = "false", action = ArgAction::Append)]
    free_page_reporting: bool,
    #[arg(long, default_value = "false", action = ArgAction::Append)]
    auto_balloon: bool,
    #[arg(long, default_value = "50")]
    membuf_percent: u32,
    #[arg(long, default_value = "10")]
    monitor_interval: u32,
}

impl ConfigCheck for BalloonConfig {
    fn check(&self) -> Result<()> {
        if !self.auto_balloon {
            return Ok(());
        }
        if self.membuf_percent > MEM_BUFFER_PERCENT_MAX
            || self.membuf_percent < MEM_BUFFER_PERCENT_MIN
        {
            return Err(anyhow!(ConfigError::IllegalValue(
                "balloon membuf-percent".to_string(),
                MEM_BUFFER_PERCENT_MIN as u64,
                false,
                MEM_BUFFER_PERCENT_MAX as u64,
                false,
            )));
        }
        if self.monitor_interval > MONITOR_INTERVAL_SECOND_MAX
            || self.monitor_interval < MONITOR_INTERVAL_SECOND_MIN
        {
            return Err(anyhow!(ConfigError::IllegalValue(
                "balloon monitor-interval".to_string(),
                MONITOR_INTERVAL_SECOND_MIN as u64,
                false,
                MONITOR_INTERVAL_SECOND_MAX as u64,
                false,
            )));
        }
        Ok(())
    }
}

/// A balloon device with some necessary information.
pub struct Balloon {
    /// Virtio device base property.
    base: VirtioBase,
    /// Configuration of the balloon device.
    bln_cfg: BalloonConfig,
    /// Actual memory pages of balloon device.
    actual: Arc<AtomicU32>,
    /// Target memory pages of balloon device.
    num_pages: u32,
    /// Interrupt callback function.
    interrupt_cb: Option<Arc<VirtioInterrupt>>,
    /// Balloon memory information.
    mem_info: Arc<Mutex<BlnMemInfo>>,
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
        let mut queue_num = QUEUE_NUM_BALLOON;
        if bln_cfg.free_page_reporting {
            queue_num += 1;
        }
        if bln_cfg.auto_balloon {
            queue_num += 1;
        }

        Balloon {
            base: VirtioBase::new(VIRTIO_TYPE_BALLOON, queue_num, DEFAULT_VIRTQUEUE_SIZE),
            bln_cfg,
            actual: Arc::new(AtomicU32::new(0)),
            num_pages: 0u32,
            interrupt_cb: None,
            mem_info: Arc::new(Mutex::new(BlnMemInfo::new())),
            mem_space,
            event_timer: Arc::new(Mutex::new(TimerFd::new().unwrap())),
        }
    }

    /// Init balloon object for global use.
    pub fn object_init(dev: Arc<Mutex<Balloon>>) {
        // SAFETY: there is no confliction when writing global variable BALLOON_DEV, in other
        // words, this function will not be called simultaneously.
        unsafe {
            if BALLOON_DEV.is_none() {
                BALLOON_DEV = Some(dev)
            }
        }
    }

    /// Notify configuration changes to VM.
    fn signal_config_change(&self) -> Result<()> {
        if let Some(interrupt_cb) = &self.interrupt_cb {
            interrupt_cb(&VirtioInterruptType::Config, None, false).with_context(|| {
                VirtioError::InterruptTrigger("balloon", VirtioInterruptType::Config)
            })
        } else {
            Err(anyhow!(VirtioError::DeviceNotActivated(
                "balloon".to_string()
            )))
        }
    }

    /// Set the target memory size of guest. Note that
    /// the actual size may not be the same as the target size.
    ///
    /// # Argument
    ///
    /// * `size` - Target memory size.
    fn set_guest_memory_size(&mut self, size: u64) -> Result<()> {
        let host_page_size = host_page_size();
        if host_page_size > BALLOON_PAGE_SIZE && !self.mem_info.lock().unwrap().has_huge_page() {
            warn!("Balloon used with backing page size > 4kiB, this may not be reliable");
        }
        let target = (size >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let address_space_ram_size =
            (self.mem_info.lock().unwrap().get_ram_size() >> VIRTIO_BALLOON_PFN_SHIFT) as u32;
        let vm_target = cmp::min(target, address_space_ram_size);
        self.num_pages = address_space_ram_size - vm_target;
        self.signal_config_change().with_context(|| {
            "Failed to notify about configuration change after setting balloon memory"
        })?;
        let msg = BalloonInfo {
            actual: self.get_guest_memory_size(),
        };
        event!(BalloonChanged; msg);
        Ok(())
    }

    /// Get the size of memory that reclaimed by balloon.
    fn get_balloon_memory_size(&self) -> u64 {
        (self.actual.load(Ordering::Acquire) as u64) << VIRTIO_BALLOON_PFN_SHIFT
    }

    /// Get the actual memory size of guest.
    fn get_guest_memory_size(&self) -> u64 {
        self.mem_info.lock().unwrap().get_ram_size() - self.get_balloon_memory_size()
    }

    fn set_num_pages(&mut self, target: u32) {
        self.num_pages = target;
    }
}

impl VirtioDevice for Balloon {
    fn virtio_base(&self) -> &VirtioBase {
        &self.base
    }

    fn virtio_base_mut(&mut self) -> &mut VirtioBase {
        &mut self.base
    }

    fn realize(&mut self) -> Result<()> {
        self.bln_cfg.check()?;
        self.mem_space
            .register_listener(self.mem_info.clone())
            .with_context(|| "Failed to register memory listener defined by balloon device.")?;
        self.init_config_features()?;
        Ok(())
    }

    fn init_config_features(&mut self) -> Result<()> {
        self.base.device_features = 1u64 << VIRTIO_F_VERSION_1;
        if self.bln_cfg.deflate_on_oom {
            self.base.device_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        }
        if self.bln_cfg.free_page_reporting {
            self.base.device_features |= 1u64 << VIRTIO_BALLOON_F_REPORTING;
        }
        if self.bln_cfg.auto_balloon {
            self.base.device_features |= 1u64 << VIRTIO_BALLOON_F_MESSAGE_VQ;
        }
        Ok(())
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) -> Result<()> {
        let new_config = VirtioBalloonConfig {
            _num_pages: self.num_pages,
            _actual: self.actual.load(Ordering::Acquire),
            _reserved: 0_u32,
            _reserved1: 0_u32,
            _membuf_percent: self.bln_cfg.membuf_percent,
            _monitor_interval: self.bln_cfg.monitor_interval,
        };

        let config_len =
            if virtio_has_feature(self.base.device_features, VIRTIO_BALLOON_F_MESSAGE_VQ) {
                size_of::<VirtioBalloonConfig>()
            } else {
                offset_of!(VirtioBalloonConfig, _reserved)
            };

        let config = &new_config.as_bytes()[..config_len];
        read_config_default(config, offset, data)
    }

    fn write_config(&mut self, _offset: u64, data: &[u8]) -> Result<()> {
        // Guest update actual balloon size
        let old_actual = self.actual.load(Ordering::Acquire);
        // SAFETY: The results will be checked.
        let new_actual = match unsafe { data.align_to::<u32>() } {
            (_, [new_config], _) => *new_config,
            _ => {
                return Err(anyhow!(VirtioError::FailedToWriteConfig));
            }
        };
        if old_actual != new_actual {
            let mut timer = self.event_timer.lock().unwrap();
            if let Ok(ret) = timer.is_armed() {
                if !ret {
                    timer
                        .reset(Duration::new(1, 0), None)
                        .with_context(|| "Failed to reset timer for qmp event during ballooning")?;
                }
            }
        }
        self.actual.store(new_actual, Ordering::Release);

        Ok(())
    }

    fn activate(
        &mut self,
        mem_space: Arc<AddressSpace>,
        interrupt_cb: Arc<VirtioInterrupt>,
        queue_evts: Vec<Arc<EventFd>>,
    ) -> Result<()> {
        let queues = &self.base.queues;
        if queues.len() != self.queue_num() {
            return Err(anyhow!(VirtioError::IncorrectQueueNum(
                self.queue_num(),
                queues.len()
            )));
        }

        let inf_queue = queues[0].clone();
        let inf_evt = queue_evts[0].clone();
        let def_queue = queues[1].clone();
        let def_evt = queue_evts[1].clone();

        // Get report queue and eventfd.
        let mut queue_index = 2;
        let mut report_queue = None;
        let mut report_evt = None;
        if virtio_has_feature(self.base.device_features, VIRTIO_BALLOON_F_REPORTING) {
            report_queue = Some(queues[queue_index].clone());
            report_evt = Some(queue_evts[queue_index].clone());
            queue_index += 1;
        }

        // Get msg queue and eventfd.
        let mut msg_queue = None;
        let mut msg_evt = None;
        if virtio_has_feature(self.base.device_features, VIRTIO_BALLOON_F_MESSAGE_VQ) {
            msg_queue = Some(queues[queue_index].clone());
            msg_evt = Some(queue_evts[queue_index].clone());
        }

        self.interrupt_cb = Some(interrupt_cb.clone());
        let handler = BalloonIoHandler {
            driver_features: self.base.driver_features,
            mem_space,
            inf_queue,
            inf_evt,
            def_queue,
            def_evt,
            report_queue,
            report_evt,
            msg_queue,
            msg_evt,
            device_broken: self.base.broken.clone(),
            interrupt_cb,
            mem_info: self.mem_info.clone(),
            event_timer: self.event_timer.clone(),
            balloon_actual: self.actual.clone(),
        };

        let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(handler)));
        register_event_helper(notifiers, None, &mut self.base.deactivate_evts)
            .with_context(|| "Failed to register balloon event notifier to MainLoop")?;
        self.base.broken.store(false, Ordering::SeqCst);

        Ok(())
    }

    fn deactivate(&mut self) -> Result<()> {
        unregister_event_helper(None, &mut self.base.deactivate_evts)
    }

    fn reset(&mut self) -> Result<()> {
        if virtio_has_feature(self.base.device_features, VIRTIO_BALLOON_F_MESSAGE_VQ) {
            self.num_pages = 0;
        }
        Ok(())
    }
}

pub fn qmp_balloon(target: u64) -> bool {
    // SAFETY: there is no confliction when writing global variable BALLOON_DEV, in other
    // words, this function will not be called simultaneously.
    if let Some(dev) = unsafe { &BALLOON_DEV } {
        match dev.lock().unwrap().set_guest_memory_size(target) {
            Ok(()) => {
                return true;
            }
            Err(ref e) => {
                error!("Failed to set balloon memory size: {}, :{:?}", target, e);
                return false;
            }
        }
    }
    error!("Balloon device not configured");
    false
}

pub fn qmp_query_balloon() -> Option<u64> {
    // SAFETY: There is no confliction when writing global variable BALLOON_DEV, in other
    // words, this function will not be called simultaneously.
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
    pub use super::*;
    pub use crate::*;

    use address_space::{AddressRange, HostMemMapping, Region};

    const MEMORY_SIZE: u64 = 1024 * 1024;
    const QUEUE_SIZE: u16 = 256;

    fn address_space_init() -> Arc<AddressSpace> {
        let root = Region::init_container_region(1 << 36, "space");
        let sys_space = AddressSpace::new(root, "space", None).unwrap();
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                MEMORY_SIZE,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        sys_space
            .root()
            .add_subregion(
                Region::init_ram_region(host_mmap.clone(), "space"),
                host_mmap.start_address().raw_value(),
            )
            .unwrap();
        sys_space
    }

    fn create_flat_range(addr: u64, size: u64, offset_in_region: u64) -> FlatRange {
        let mem_mapping = Arc::new(
            HostMemMapping::new(GuestAddress(addr), None, size, None, false, false, false).unwrap(),
        );
        FlatRange {
            addr_range: AddressRange::new(
                mem_mapping.start_address().unchecked_add(offset_in_region),
                mem_mapping.size() - offset_in_region,
            ),
            owner: Region::init_ram_region(mem_mapping.clone(), "mem"),
            offset_in_region,
            rom_dev_romd: None,
        }
    }

    #[test]
    fn test_balloon_init() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };

        let mem_space = address_space_init();
        let mut bln = Balloon::new(bln_cfg, mem_space);

        // Test realize function.
        bln.realize().unwrap();
        assert_eq!(bln.device_type(), 5);
        assert_eq!(bln.queue_num(), 2);
        assert_eq!(bln.queue_size_max(), QUEUE_SIZE);

        assert_eq!(bln.base.driver_features, 0);
        assert_eq!(bln.actual.load(Ordering::Acquire), 0);
        assert_eq!(bln.num_pages, 0);
        assert!(bln.interrupt_cb.is_none());
        let feature = (1u64 << VIRTIO_F_VERSION_1) | (1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
        assert_eq!(bln.base.device_features, feature);

        let fts = bln.device_features(0);
        assert_eq!(fts, feature as u32);
        let fts = bln.device_features(1);
        assert_eq!(fts, (feature >> 32) as u32);
        bln.base.driver_features = 0;
        bln.base.device_features = 1 | 1 << 32;
        bln.set_driver_features(0, 1);
        assert_eq!(bln.base.driver_features, 1);
        assert_eq!(bln.base.driver_features, bln.driver_features(0) as u64);
        bln.base.driver_features = 1 << 32;
        bln.set_driver_features(1, 1);
        assert_eq!(bln.base.driver_features, 1 << 32);
        assert_eq!(
            bln.base.driver_features,
            (bln.driver_features(1) as u64) << 32
        );

        // Test methods of balloon.
        let ram_size = bln.mem_info.lock().unwrap().get_ram_size();
        assert_eq!(ram_size, MEMORY_SIZE);

        assert!(bln.update_config(None).is_err());
    }

    #[test]
    fn test_read_config() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };

        let mem_space = address_space_init();
        let balloon = Balloon::new(bln_cfg, mem_space);
        let ret_data = [0, 0, 0, 0, 1, 0, 0, 0];
        let mut read_data: Vec<u8> = vec![0; 8];
        let addr = 0x00;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.actual.store(1, Ordering::Release);
        balloon.read_config(addr, &mut read_data).unwrap();
        assert_eq!(read_data, ret_data);
    }

    #[test]
    fn test_read_config_partial() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };

        let mem_space = address_space_init();
        let balloon = Balloon::new(bln_cfg, mem_space);
        let ret_data = [1, 0, 0, 0, 0, 0, 0, 0];
        let mut read_data: Vec<u8> = vec![0; 8];
        let addr = 0x4;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.actual.store(1, Ordering::Release);
        assert!(balloon.read_config(addr, &mut read_data).is_err());
        assert_ne!(read_data, ret_data);
    }

    #[test]
    fn test_read_config_overflow() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };

        let mem_space = address_space_init();
        let balloon = Balloon::new(bln_cfg, mem_space);
        let mut read_data: Vec<u8> = vec![0; 8];
        let addr: u64 = 0xffff_ffff_ffff_ffff;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.actual.store(1, Ordering::Release);
        let ret = balloon.read_config(addr, &mut read_data);
        assert!(ret.is_err());
    }

    #[test]
    fn test_write_config() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };

        let mem_space = address_space_init();
        let mut balloon = Balloon::new(bln_cfg, mem_space);
        let write_data = [1, 0, 0, 0];
        let addr = 0x00;
        assert_eq!(balloon.get_balloon_memory_size(), 0);
        balloon.write_config(addr, &write_data).unwrap();
        assert_eq!(balloon.actual.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_balloon_process() {
        let mem_space = address_space_init();
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };
        let mut bln = Balloon::new(bln_cfg, mem_space.clone());
        bln.realize().unwrap();
        let ram_fr1 = create_flat_range(0, MEMORY_SIZE, 0);
        let blninfo = BlnMemInfo::new();
        assert!(blninfo
            .handle_request(Some(&ram_fr1), None, ListenerReqType::AddRegion)
            .is_ok());
        bln.mem_info = Arc::new(Mutex::new(blninfo));

        let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let interrupt_status = Arc::new(AtomicU32::new(0));
        let cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, _needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| VirtioError::EventFdWrite)
            },
        ) as VirtioInterrupt);

        bln.interrupt_cb = Some(cb.clone());
        assert_eq!(bln.get_guest_memory_size(), MEMORY_SIZE);

        let mut queue_config_inf = QueueConfig::new(QUEUE_SIZE);
        queue_config_inf.desc_table = GuestAddress(0x100);
        queue_config_inf.addr_cache.desc_table_host = mem_space
            .get_host_address(queue_config_inf.desc_table)
            .unwrap();
        queue_config_inf.avail_ring = GuestAddress(0x300);
        queue_config_inf.addr_cache.avail_ring_host = mem_space
            .get_host_address(queue_config_inf.avail_ring)
            .unwrap();
        queue_config_inf.used_ring = GuestAddress(0x600);
        queue_config_inf.addr_cache.used_ring_host = mem_space
            .get_host_address(queue_config_inf.used_ring)
            .unwrap();
        queue_config_inf.ready = true;
        queue_config_inf.size = QUEUE_SIZE;

        let mut queue_config_def = QueueConfig::new(QUEUE_SIZE);
        queue_config_def.desc_table = GuestAddress(0x1100);
        queue_config_def.addr_cache.desc_table_host = mem_space
            .get_host_address(queue_config_def.desc_table)
            .unwrap();
        queue_config_def.avail_ring = GuestAddress(0x1300);
        queue_config_def.addr_cache.avail_ring_host = mem_space
            .get_host_address(queue_config_def.avail_ring)
            .unwrap();
        queue_config_def.used_ring = GuestAddress(0x1600);
        queue_config_def.addr_cache.used_ring_host = mem_space
            .get_host_address(queue_config_def.used_ring)
            .unwrap();
        queue_config_def.ready = true;
        queue_config_def.size = QUEUE_SIZE;

        let queue1 = Arc::new(Mutex::new(Queue::new(queue_config_inf, 1).unwrap()));
        let queue2 = Arc::new(Mutex::new(Queue::new(queue_config_def, 1).unwrap()));

        let event_inf = Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let event_def = Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let mut handler = BalloonIoHandler {
            driver_features: bln.base.driver_features,
            mem_space: mem_space.clone(),
            inf_queue: queue1,
            inf_evt: event_inf.clone(),
            def_queue: queue2,
            def_evt: event_def,
            report_queue: None,
            report_evt: None,
            msg_queue: None,
            msg_evt: None,
            device_broken: bln.base.broken.clone(),
            interrupt_cb: cb.clone(),
            mem_info: bln.mem_info.clone(),
            event_timer: bln.event_timer.clone(),
            balloon_actual: bln.actual.clone(),
        };

        let balloon = Arc::new(Mutex::new(bln));
        Balloon::object_init(balloon);

        // Query balloon.
        assert_eq!(qmp_query_balloon(), Some(MEMORY_SIZE));

        // Create SplitVringDesc and set addr to be 0x2000.
        let desc = SplitVringDesc {
            addr: GuestAddress(0x2000),
            len: 4,
            flags: 0,
            next: 1,
        };

        // Set desc table.
        mem_space
            .write_object::<SplitVringDesc>(&desc, GuestAddress(queue_config_inf.desc_table.0))
            .unwrap();

        let ele = GuestIovec {
            iov_base: GuestAddress(0xff),
            iov_len: std::mem::size_of::<GuestIovec>() as u64,
        };
        mem_space
            .write_object::<GuestIovec>(&ele, GuestAddress(0x2000))
            .unwrap();
        mem_space
            .write_object::<u16>(&0, GuestAddress(queue_config_inf.avail_ring.0 + 4 as u64))
            .unwrap();
        mem_space
            .write_object::<u16>(&1, GuestAddress(queue_config_inf.avail_ring.0 + 2 as u64))
            .unwrap();

        assert!(handler.process_balloon_queue(BALLOON_INFLATE_EVENT).is_ok());
        assert_eq!(handler.get_balloon_memory_size(), 0);
        assert_eq!(qmp_query_balloon(), Some(MEMORY_SIZE));

        // SplitVringDesc for deflate.
        let desc = SplitVringDesc {
            addr: GuestAddress(0x2000),
            len: 4,
            flags: 0,
            next: 1,
        };

        mem_space
            .write_object::<SplitVringDesc>(&desc, GuestAddress(queue_config_def.desc_table.0))
            .unwrap();

        mem_space
            .write_object::<GuestIovec>(&ele, GuestAddress(0x3000))
            .unwrap();
        mem_space
            .write_object::<u16>(&0, GuestAddress(queue_config_def.avail_ring.0 + 4 as u64))
            .unwrap();
        mem_space
            .write_object::<u16>(&1, GuestAddress(queue_config_def.avail_ring.0 + 2 as u64))
            .unwrap();

        assert!(handler.process_balloon_queue(BALLOON_DEFLATE_EVENT).is_ok());
    }

    #[test]
    fn test_balloon_activate() {
        let mem_space = address_space_init();
        let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let interrupt_status = Arc::new(AtomicU32::new(0));
        let interrupt_cb = Arc::new(Box::new(
            move |int_type: &VirtioInterruptType, _queue: Option<&Queue>, _needs_reset: bool| {
                let status = match int_type {
                    VirtioInterruptType::Config => VIRTIO_MMIO_INT_CONFIG,
                    VirtioInterruptType::Vring => VIRTIO_MMIO_INT_VRING,
                };
                interrupt_status.fetch_or(status, Ordering::SeqCst);
                interrupt_evt
                    .write(1)
                    .with_context(|| VirtioError::EventFdWrite)
            },
        ) as VirtioInterrupt);

        let mut queue_config_inf = QueueConfig::new(QUEUE_SIZE);
        queue_config_inf.desc_table = GuestAddress(0);
        queue_config_inf.avail_ring = GuestAddress(4096);
        queue_config_inf.used_ring = GuestAddress(8192);
        queue_config_inf.ready = true;
        queue_config_inf.size = QUEUE_SIZE;

        let mut queues: Vec<Arc<Mutex<Queue>>> = Vec::new();
        let queue1 = Arc::new(Mutex::new(Queue::new(queue_config_inf, 1).unwrap()));
        queues.push(queue1);
        let event_inf = Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let queue_evts: Vec<Arc<EventFd>> = vec![event_inf.clone()];

        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            ..Default::default()
        };
        let mut bln = Balloon::new(bln_cfg, mem_space.clone());
        bln.base.queues = queues;
        assert!(bln.activate(mem_space, interrupt_cb, queue_evts).is_err());
    }

    #[test]
    fn test_balloon_memory_listener() {
        let mut blndef = BlnMemoryRegion::default();
        blndef.flags_padding = 0;
        blndef.guest_phys_addr = 0x400;
        blndef.memory_size = 0x8000;
        blndef.userspace_addr = 0;

        let blninfo = BlnMemInfo::new();
        assert_eq!(blninfo.priority(), 0);

        blninfo.regions.lock().unwrap().push(blndef);
        assert_eq!(blninfo.get_host_address(GuestAddress(0x200)), None);
        assert_eq!(
            blninfo.get_host_address(GuestAddress(0x420)),
            Some((0x20, false))
        );

        let ram_size = 0x800;
        let ram_fr1 = create_flat_range(0, ram_size, 0);
        let blninfo = BlnMemInfo::new();
        assert!(blninfo
            .handle_request(Some(&ram_fr1), None, ListenerReqType::AddRegion)
            .is_ok());
        let host_addr = blninfo.get_host_address(GuestAddress(0));
        assert!(host_addr.is_some());
        let host_addr = blninfo.get_host_address(GuestAddress(0x7ff));
        assert!(host_addr.is_some());
        let host_addr = blninfo.get_host_address(GuestAddress(0x800));
        assert!(host_addr.is_none());
        assert!(blninfo
            .handle_request(Some(&ram_fr1), None, ListenerReqType::DeleteRegion)
            .is_ok());
        let host_addr = blninfo.get_host_address(GuestAddress(0));
        assert_eq!(host_addr, None);
    }

    #[test]
    fn test_balloon_bitmap() {
        let mut btp = BalloonedPageBitmap::new(8);
        assert!(btp.set_bit(0).is_ok());
        assert!(btp.set_bit(1).is_ok());
        assert!(btp.set_bit(2).is_ok());
        assert!(btp.set_bit(3).is_ok());
        assert!(btp.set_bit(4).is_ok());
        assert!(btp.set_bit(5).is_ok());
        assert!(btp.set_bit(6).is_ok());
        assert!(!btp.is_full(8));
        assert!(btp.set_bit(7).is_ok());
        assert!(btp.is_full(8));
        // Out of range.
        assert!(!btp.is_full(65));
    }

    #[test]
    fn test_balloon_init_free_page_reporting() {
        let bln_cfg = BalloonConfig {
            id: "bln".to_string(),
            deflate_on_oom: true,
            free_page_reporting: true,
            ..Default::default()
        };
        let mem_space = address_space_init();
        let mut bln = Balloon::new(bln_cfg, mem_space);

        // Test realize function.
        bln.realize().unwrap();
        assert_eq!(bln.device_type(), 5);
        assert_eq!(bln.queue_num(), 3);
        assert_eq!(bln.queue_size_max(), QUEUE_SIZE);

        assert_eq!(bln.base.driver_features, 0);
        assert_eq!(bln.actual.load(Ordering::Acquire), 0);
        assert_eq!(bln.num_pages, 0);
        assert!(bln.interrupt_cb.is_none());
        let feature = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM | 1u64 << VIRTIO_BALLOON_F_REPORTING);
        assert_eq!(bln.base.device_features, feature);

        let fts = bln.device_features(0);
        assert_eq!(fts, feature as u32);
        let fts = bln.device_features(1);
        assert_eq!(fts, (feature >> 32) as u32);

        // Test methods of balloon.
        let ram_size = bln.mem_info.lock().unwrap().get_ram_size();
        assert_eq!(ram_size, MEMORY_SIZE);

        assert!(bln.update_config(None).is_err());
    }
}
