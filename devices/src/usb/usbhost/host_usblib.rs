// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{
    iter::Iterator,
    os::unix::io::{AsRawFd, RawFd},
    rc::Rc,
    slice,
    sync::{Arc, Mutex},
};

use libc::{c_int, c_short, c_uchar, c_uint, c_void, size_t, EPOLLIN, EPOLLOUT};
#[cfg(all(target_arch = "aarch64", target_env = "ohos"))]
use libusb1_sys::{constants::LIBUSB_SUCCESS, libusb_context, libusb_set_option};
use libusb1_sys::{
    constants::{
        LIBUSB_ERROR_ACCESS, LIBUSB_ERROR_BUSY, LIBUSB_ERROR_INTERRUPTED,
        LIBUSB_ERROR_INVALID_PARAM, LIBUSB_ERROR_IO, LIBUSB_ERROR_NOT_FOUND,
        LIBUSB_ERROR_NOT_SUPPORTED, LIBUSB_ERROR_NO_DEVICE, LIBUSB_ERROR_NO_MEM,
        LIBUSB_ERROR_OVERFLOW, LIBUSB_ERROR_PIPE, LIBUSB_ERROR_TIMEOUT, LIBUSB_TRANSFER_CANCELLED,
        LIBUSB_TRANSFER_COMPLETED, LIBUSB_TRANSFER_ERROR, LIBUSB_TRANSFER_NO_DEVICE,
        LIBUSB_TRANSFER_STALL, LIBUSB_TRANSFER_TIMED_OUT, LIBUSB_TRANSFER_TYPE_ISOCHRONOUS,
    },
    libusb_device_handle, libusb_free_pollfds, libusb_get_pollfds, libusb_iso_packet_descriptor,
    libusb_pollfd, libusb_transfer,
};
use log::error;
use rusb::{Context, DeviceHandle, Error, Result, TransferType, UsbContext};
use vmm_sys_util::epoll::EventSet;

use super::{IsoTransfer, UsbHost, UsbHostRequest};
use crate::usb::{UsbPacket, UsbPacketStatus, USB_TOKEN_IN};
use util::{
    link_list::Node,
    loop_context::{EventNotifier, NotifierCallback, NotifierOperation},
};

const CONTROL_TIMEOUT: u32 = 10000; // 10s
const BULK_TIMEOUT: u32 = 0;
const INTERRUPT_TIMEOUT: u32 = 0;

pub fn from_libusb(err: i32) -> Error {
    match err {
        LIBUSB_ERROR_IO => Error::Io,
        LIBUSB_ERROR_INVALID_PARAM => Error::InvalidParam,
        LIBUSB_ERROR_ACCESS => Error::Access,
        LIBUSB_ERROR_NO_DEVICE => Error::NoDevice,
        LIBUSB_ERROR_NOT_FOUND => Error::NotFound,
        LIBUSB_ERROR_BUSY => Error::Busy,
        LIBUSB_ERROR_TIMEOUT => Error::Timeout,
        LIBUSB_ERROR_OVERFLOW => Error::Overflow,
        LIBUSB_ERROR_PIPE => Error::Pipe,
        LIBUSB_ERROR_INTERRUPTED => Error::Interrupted,
        LIBUSB_ERROR_NO_MEM => Error::NoMem,
        LIBUSB_ERROR_NOT_SUPPORTED => Error::NotSupported,
        _ => Error::Other,
    }
}

macro_rules! try_unsafe {
    ($x:expr) => {
        // SAFETY:
        // - `$x` is a call to a libusb C API function that may involve raw pointers.
        // - All pointers or handles passed to `$x` must be valid for the duration of the call,
        //   and must not be freed or mutated concurrently.
        // - The caller ensures that any thread-safety requirements of the libusb function are met.
        // - This macro checks the return value and converts non-zero errors to Rust `Err`
        match unsafe { $x } {
            0 => (),
            err => return Err(from_libusb(err)),
        }
    };
}

// SAFETY:
// - `transfer` must be a valid, non-null pointer to a `libusb_transfer`
//   allocated and managed by libusb.
// - `(*transfer).user_data` must be a non-null pointer to a `Node<UsbHostRequest>`
//   and has not already been converted.
// - The caller must ensure this function is called **at most once** for a
//   given `transfer.user_data`.
// - After this call, ownership of the underlying `Node<UsbHostRequest>`
//   is transferred back to Rust and will be automatically freed when the
//   returned `Box` is dropped.
pub unsafe fn get_node_from_transfer(transfer: *mut libusb_transfer) -> Box<Node<UsbHostRequest>> {
    Box::from_raw((*transfer).user_data.cast::<Node<UsbHostRequest>>())
}

// SAFETY:
// - `transfer` must be a valid, non-null pointer to a `libusb_transfer`.
// - `(*transfer).user_data` must be a non-null pointer obtained from
//   `Arc::into_raw(Arc<Mutex<IsoTransfer>>)` and must still be alive.
// - This function may be called multiple times, but each call will
//   increment the strong count, so the caller must ensure that all
//   returned `Arc`s are eventually dropped to avoid memory leaks.
pub unsafe fn get_iso_transfer_from_transfer(
    transfer: *mut libusb_transfer,
) -> Arc<Mutex<IsoTransfer>> {
    let ptr = (*transfer).user_data.cast::<Mutex<IsoTransfer>>();
    Arc::increment_strong_count(ptr);
    Arc::from_raw(ptr)
}

// SAFETY:
// - `transfer` must be a valid, non-null pointer to a `libusb_transfer`.
// - `(*transfer).buffer` must be non-null and point to a buffer of at least `len` bytes.
// - The caller must ensure no other aliasing mutable references exist
//   while using the returned slice (including libusb itself).
// - The lifetime of the returned slice is only valid as long as the
//   underlying `libusb_transfer` and its buffer are alive.
pub unsafe fn get_buffer_from_transfer(
    transfer: *mut libusb_transfer,
    len: usize,
) -> &'static mut [u8] {
    std::slice::from_raw_parts_mut((*transfer).buffer, len)
}

// SAFETY:
// - `transfer` must be a valid, non-null pointer to a `libusb_transfer`.
pub unsafe fn get_length_from_transfer(transfer: *mut libusb_transfer) -> i32 {
    (*transfer).actual_length
}

// SAFETY:
// - `transfer` must be a valid, non-null pointer to a `libusb_transfer`.
pub unsafe fn get_status_from_transfer(transfer: *mut libusb_transfer) -> i32 {
    (*transfer).status
}

pub fn map_packet_status(status: i32) -> UsbPacketStatus {
    match status {
        LIBUSB_TRANSFER_COMPLETED => UsbPacketStatus::Success,
        LIBUSB_TRANSFER_ERROR => UsbPacketStatus::IoError,
        LIBUSB_TRANSFER_TIMED_OUT => UsbPacketStatus::IoError,
        LIBUSB_TRANSFER_CANCELLED => UsbPacketStatus::IoError,
        LIBUSB_TRANSFER_STALL => UsbPacketStatus::Stall,
        LIBUSB_TRANSFER_NO_DEVICE => UsbPacketStatus::NoDev,
        _ => UsbPacketStatus::Babble,
    }
}

pub fn set_pollfd_notifiers(
    pollfds: PollFds,
    notifiers: &mut Vec<EventNotifier>,
    handler: Rc<NotifierCallback>,
) {
    for pollfd in pollfds.iter() {
        if i32::from(pollfd.events()) == EPOLLIN {
            notifiers.push(EventNotifier::new(
                NotifierOperation::AddShared,
                pollfd.as_raw_fd(),
                None,
                EventSet::IN,
                vec![handler.clone()],
            ));
        } else if i32::from(pollfd.events()) == EPOLLOUT {
            notifiers.push(EventNotifier::new(
                NotifierOperation::AddShared,
                pollfd.as_raw_fd(),
                None,
                EventSet::OUT,
                vec![handler.clone()],
            ));
        }
    }
}

pub fn get_iso_packet_nums(host_transfer: *mut libusb_transfer) -> u32 {
    // SAFETY: host_transfer is guaranteed to be valid once created.
    unsafe { (*host_transfer).num_iso_packets as u32 }
}

pub fn set_iso_packet_length(
    host_transfer: *mut libusb_transfer,
    packet: u32,
    max_packet_size: u32,
) {
    let iso_packet_desc: *mut libusb_iso_packet_descriptor;
    // SAFETY: host_transfer is guaranteed to be valid once created.
    unsafe { iso_packet_desc = (*host_transfer).iso_packet_desc.as_mut_ptr() }
    // SAFETY: iso_packet_desc is guaranteed to be valid once host_transfer is created
    // and packet is guaranteed to be not out of boundary.
    unsafe { (*iso_packet_desc.offset(packet as isize)).length = max_packet_size as c_uint }
}

pub fn get_iso_packet_acl_length(host_transfer: *mut libusb_transfer, packet: u32) -> u32 {
    let iso_packet_desc: *mut libusb_iso_packet_descriptor;
    // SAFETY: host_transfer is guaranteed to be valid once created.
    unsafe { iso_packet_desc = (*host_transfer).iso_packet_desc.as_mut_ptr() }
    // SAFETY: iso_packet_desc is guaranteed to be valid once host_transfer is created
    // and packet is guaranteed to be not out of boundary.
    unsafe { (*iso_packet_desc.offset(packet as isize)).actual_length }
}

pub fn alloc_host_transfer(iso_packets: c_int) -> *mut libusb_transfer {
    if iso_packets < 0 {
        error!(
            "The number of iso packets cannot be less than 0, it is {}",
            iso_packets
        );
        return std::ptr::null_mut();
    }

    // SAFETY: have checked the validity of iso_packets before call C
    // library of libusb to get the pointer of transfer.
    unsafe { libusb1_sys::libusb_alloc_transfer(iso_packets) }
}

extern "system" fn req_complete(host_transfer: *mut libusb_transfer) {
    // SAFETY:
    // - `transfer` comes from libusb's async callback and is guaranteed valid.
    // - We previously stored a `<Node<UsbHostRequest>` in `transfer.user_data`
    //   , and have not yet taken it back.
    // - This is the only place where we reclaim the Box, so no double free occurs.
    let mut node = unsafe { get_node_from_transfer(host_transfer) };
    let request = &mut node.value;
    let requests = match request.requests.upgrade() {
        Some(requests) => requests,
        None => return,
    };

    // Before operating a node, lock requests to prevent multiple threads from operating
    // the node at the same time.
    let mut locked_requests = requests.lock().unwrap();
    let packet = request.packet.clone();
    let mut locked_packet = packet.lock().unwrap();

    if !locked_packet.is_async {
        request.free();
        locked_requests.unlink(&node);
        return;
    }

    // SAFETY: `host_transfer` is provided by libusb callback and guaranteed valid here.
    let actual_length = unsafe { get_length_from_transfer(host_transfer) } as usize;
    // SAFETY: same as above
    let transfer_status = unsafe { get_status_from_transfer(host_transfer) };
    locked_packet.status = map_packet_status(transfer_status);

    if request.is_control {
        request.ctrl_transfer_packet(&mut locked_packet, actual_length);
    } else if locked_packet.pid as u8 == USB_TOKEN_IN && actual_length != 0 {
        // SAFETY:
        // - `host_transfer` is provided by libusb callback and guaranteed valid here.
        // - `transfer.buffer` is allocated and has at least `len` bytes.
        // - We will only use the slice within the scope of this callback,
        //   ensuring no aliasing with libusb's own buffer access.
        let data = unsafe { get_buffer_from_transfer(host_transfer, actual_length) };
        locked_packet.transfer_packet(data, actual_length);
    }

    trace::usb_host_req_complete(
        request.hostbus,
        request.hostaddr,
        &*locked_packet as *const UsbPacket as u64,
        &locked_packet.status,
        actual_length,
    );

    if let Some(transfer) = locked_packet.xfer_ops.as_ref() {
        if let Some(ops) = transfer.clone().upgrade() {
            drop(locked_packet);
            ops.lock().unwrap().transfer_complete_cb();
        }
    }

    request.free();
    locked_requests.unlink(&node);
}

extern "system" fn req_complete_iso(host_transfer: *mut libusb_transfer) {
    // SAFETY:
    // - `host_transfer` is either NULL or points to a valid `libusb_transfer`.
    // - If not NULL, its `user_data` field is readable.
    // - No other thread mutates or frees `host_transfer` concurrently.
    // - The short-circuit `||` ensures that we never dereference a NULL pointer.
    if host_transfer.is_null() || unsafe { (*host_transfer).user_data.is_null() } {
        free_host_transfer(host_transfer);
        return;
    }

    // SAFETY:
    // - `host_transfer` is a valid libusb_transfer pointer from the libusb callback.
    // - `host_transfer.user_data` was set earlier using `Arc::into_raw` with an
    //   `Arc<Mutex<IsoTransfer>>`, and has not been freed.
    // - We understand that calling this increases the strong count, and
    //   dropping the returned Arc will eventually decrement it.
    let iso_transfer = unsafe { get_iso_transfer_from_transfer(host_transfer) };
    let iso_queue = iso_transfer.lock().unwrap().iso_queue.clone();

    if let Some(iso_queue) = iso_queue.upgrade() {
        let mut locked_iso_queue = iso_queue.lock().unwrap();
        let iso_transfer = locked_iso_queue.inflight.pop_front().unwrap();
        if locked_iso_queue.inflight.is_empty() {
            let queue = &locked_iso_queue;
            trace::usb_host_iso_stop(queue.hostbus, queue.hostaddr, queue.ep.ep_number);
        }
        if locked_iso_queue.ep.in_direction {
            locked_iso_queue.copy.push_back(iso_transfer);
        } else {
            locked_iso_queue.unused.push_back(iso_transfer);
        }
    }
}

pub fn fill_transfer_by_type(
    transfer: *mut libusb_transfer,
    handle: Option<&mut DeviceHandle<Context>>,
    ep_number: u8,
    stream: u32,
    node: *mut Node<UsbHostRequest>,
    transfer_type: TransferType,
) {
    // SAFETY: node only deleted when request completed.
    let packet = unsafe { (*node).value.packet.clone() };
    // SAFETY: the reason is same as above.
    let buffer_ptr = unsafe {
        if let Some(dev_mem) = (*node).value.dev_mem.as_ref() {
            dev_mem.as_mut_ptr()
        } else {
            (*node).value.buffer.as_mut().unwrap().as_mut_ptr()
        }
    };
    let size = packet.lock().unwrap().get_iovecs_size();

    if transfer.is_null() {
        error!("Failed to fill bulk transfer, transfer is none");
        return;
    }

    // SAFETY: have checked the validity of parameters of libusb_fill_*_transfer
    // before call libusb_fill_*_transfer.
    match transfer_type {
        TransferType::Control =>
        // SAFETY: the reason is as shown above.
        unsafe {
            libusb1_sys::libusb_fill_control_transfer(
                transfer,
                handle.unwrap().as_raw(),
                buffer_ptr,
                req_complete,
                node.cast::<libc::c_void>(),
                CONTROL_TIMEOUT,
            );
        },
        TransferType::Bulk =>
        // SAFETY: the reason is  as shown above.
        unsafe {
            libusb1_sys::libusb_fill_bulk_stream_transfer(
                transfer,
                handle.unwrap().as_raw(),
                ep_number,
                stream,
                buffer_ptr,
                size as i32,
                req_complete,
                node.cast::<libc::c_void>(),
                BULK_TIMEOUT,
            );
        },
        TransferType::Interrupt =>
        // SAFETY: the reason is as shown above.
        unsafe {
            libusb1_sys::libusb_fill_interrupt_transfer(
                transfer,
                handle.unwrap().as_raw(),
                ep_number,
                buffer_ptr,
                size as i32,
                req_complete,
                node.cast::<libc::c_void>(),
                INTERRUPT_TIMEOUT,
            );
        },
        _ => error!("Unsupported transfer type: {:?}", transfer_type),
    }
}

pub fn fill_iso_transfer(
    transfer: *mut libusb_transfer,
    handle: &mut DeviceHandle<Context>,
    ep_number: u8,
    user_data: *mut c_void,
    packets: u32,
    length: u32,
    buffer: &mut Vec<u8>,
) {
    // SAFETY: have checked the validity of transfer before call fill_iso_transfer.
    unsafe {
        (*transfer).dev_handle = handle.as_raw();
        (*transfer).transfer_type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
        (*transfer).endpoint = ep_number;
        (*transfer).callback = req_complete_iso;
        (*transfer).user_data = user_data;
        (*transfer).num_iso_packets = packets as c_int;
        (*transfer).length = length as c_int;
        (*transfer).buffer = buffer.as_mut_ptr();
    }
}

pub fn submit_host_transfer(transfer: *mut libusb_transfer) -> Result<()> {
    if transfer.is_null() {
        return Err(Error::NoMem);
    }
    try_unsafe!(libusb1_sys::libusb_submit_transfer(transfer));
    Ok(())
}

pub fn cancel_host_transfer(transfer: *mut libusb_transfer) -> Result<()> {
    if transfer.is_null() {
        return Ok(());
    }
    try_unsafe!(libusb1_sys::libusb_cancel_transfer(transfer));
    Ok(())
}

pub fn free_host_transfer(transfer: *mut libusb_transfer) {
    if transfer.is_null() {
        return;
    }

    // SAFETY: have checked the validity of transfer before call libusb_free_transfer.
    unsafe { libusb1_sys::libusb_free_transfer(transfer) };
}

#[cfg(all(target_arch = "aarch64", target_env = "ohos"))]
pub fn set_option(opt: u32) -> Result<()> {
    // SAFETY: This function will only configure a specific option within libusb, null for ctx is valid.
    let err = unsafe {
        libusb_set_option(
            std::ptr::null_mut::<libusb_context>(),
            opt,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if err != LIBUSB_SUCCESS {
        return Err(from_libusb(err));
    }

    Ok(())
}

// These APIs are not included in libusb1-sys crate.
extern "system" {
    pub fn libusb_dev_mem_alloc(
        dev_handle: *mut libusb_device_handle,
        length: size_t,
    ) -> *mut c_uchar;
    pub fn libusb_dev_mem_free(
        dev_handle: *mut libusb_device_handle,
        buffer: *mut c_uchar,
        length: size_t,
    ) -> c_int;
}

#[derive(Debug)]
pub struct PollFd {
    fd: c_int,
    events: c_short,
}

impl PollFd {
    unsafe fn from_raw(raw: *mut libusb_pollfd) -> Self {
        Self {
            fd: (*raw).fd,
            events: (*raw).events,
        }
    }

    pub fn events(&self) -> c_short {
        self.events
    }
}

impl AsRawFd for PollFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

pub struct PollFds {
    poll_fds: *const *mut libusb_pollfd,
}

impl PollFds {
    pub fn new(usbhost: Arc<Mutex<UsbHost>>) -> Result<Self> {
        // SAFETY:
        // - This calls into the C API `libusb_get_pollfds`, which may return a NULL
        //   or a pointer to an array of `*mut libusb_pollfd` managed by libusb.
        // - We immediately check for NULL and wrap the result in a `Result`,
        //   so the caller of `PollFds::new` never observes an invalid pointer.
        // - The returned pointer will eventually be released with
        //   `libusb_free_pollfds` (handled by `PollFds`'s Drop impl).
        let poll_fds = unsafe { libusb_get_pollfds(usbhost.lock().unwrap().context.as_raw()) };
        if poll_fds.is_null() {
            Err(Error::NotFound)
        } else {
            Ok(Self { poll_fds })
        }
    }

    pub fn iter(&self) -> PollFdIter<'_> {
        let mut len: usize = 0;
        // SAFETY: self.poll_fds is acquired from libusb_get_pollfds which is guaranteed to be valid.
        unsafe {
            while !(*self.poll_fds.add(len)).is_null() {
                len += 1;
            }
            PollFdIter {
                fds: slice::from_raw_parts(self.poll_fds, len),
                index: 0,
            }
        }
    }
}

impl Drop for PollFds {
    fn drop(&mut self) {
        // SAFETY: self.poll_fds is acquired from libusb_get_pollfds which is guaranteed to be valid.
        unsafe {
            libusb_free_pollfds(self.poll_fds);
        }
    }
}

pub struct PollFdIter<'a> {
    fds: &'a [*mut libusb_pollfd],
    index: usize,
}

impl Iterator for PollFdIter<'_> {
    type Item = PollFd;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.fds.len() {
            // SAFETY: self.fds and self.index is guaranteed to be valid.
            let poll_fd = unsafe { PollFd::from_raw(self.fds[self.index]) };
            self.index += 1;
            Some(poll_fd)
        } else {
            None
        }
    }
}
