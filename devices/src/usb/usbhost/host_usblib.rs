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
    rc::Rc,
    sync::{Arc, Mutex},
};

use libc::{c_int, c_uint, c_void, EPOLLIN, EPOLLOUT};
use libusb1_sys::{
    constants::{
        LIBUSB_ERROR_ACCESS, LIBUSB_ERROR_BUSY, LIBUSB_ERROR_INTERRUPTED,
        LIBUSB_ERROR_INVALID_PARAM, LIBUSB_ERROR_IO, LIBUSB_ERROR_NOT_FOUND,
        LIBUSB_ERROR_NOT_SUPPORTED, LIBUSB_ERROR_NO_DEVICE, LIBUSB_ERROR_NO_MEM,
        LIBUSB_ERROR_OVERFLOW, LIBUSB_ERROR_PIPE, LIBUSB_ERROR_TIMEOUT, LIBUSB_TRANSFER_CANCELLED,
        LIBUSB_TRANSFER_COMPLETED, LIBUSB_TRANSFER_ERROR, LIBUSB_TRANSFER_NO_DEVICE,
        LIBUSB_TRANSFER_STALL, LIBUSB_TRANSFER_TIMED_OUT, LIBUSB_TRANSFER_TYPE_ISOCHRONOUS,
    },
    libusb_get_pollfds, libusb_iso_packet_descriptor, libusb_pollfd, libusb_transfer,
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

fn from_libusb(err: i32) -> Error {
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
        // SAFETY: expression is calling C library of libusb.
        match unsafe { $x } {
            0 => (),
            err => return Err(from_libusb(err)),
        }
    };
}

pub fn get_node_from_transfer(transfer: *mut libusb_transfer) -> Box<Node<UsbHostRequest>> {
    // SAFETY: cast the raw pointer of transfer's user_data to the
    // Box<Node<UsbHostRequest>>.
    unsafe { Box::from_raw((*transfer).user_data.cast::<Node<UsbHostRequest>>()) }
}

pub fn get_iso_transfer_from_transfer(transfer: *mut libusb_transfer) -> Arc<Mutex<IsoTransfer>> {
    // SAFETY: cast the raw pointer of transfer's user_data to the
    // Arc<Mutex<UsbHostRequest>>.
    unsafe {
        let ptr = (*transfer).user_data.cast::<Mutex<IsoTransfer>>();
        Arc::increment_strong_count(ptr);
        Arc::from_raw(ptr)
    }
}

pub fn get_buffer_from_transfer(transfer: *mut libusb_transfer, len: usize) -> &'static mut [u8] {
    // SAFETY: cast the raw pointer of transfer's buffer which is transformed
    // from a slice with actual_length to a mutable slice.
    unsafe { std::slice::from_raw_parts_mut((*transfer).buffer, len) }
}

pub fn get_length_from_transfer(transfer: *mut libusb_transfer) -> i32 {
    // SAFETY: cast the raw pointer of transfer's actual_length to a integer.
    unsafe { (*transfer).actual_length }
}

pub fn get_status_from_transfer(transfer: *mut libusb_transfer) -> i32 {
    // SAFETY: cast the raw pointer of transfer's status which is to a integer.
    unsafe { (*transfer).status }
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

pub fn get_libusb_pollfds(usbhost: Arc<Mutex<UsbHost>>) -> *const *mut libusb_pollfd {
    // SAFETY: call C library of libusb to get pointer of poll fd.
    unsafe { libusb_get_pollfds(usbhost.lock().unwrap().context.as_raw()) }
}

pub fn set_pollfd_notifiers(
    poll: *const *mut libusb_pollfd,
    notifiers: &mut Vec<EventNotifier>,
    handler: Rc<NotifierCallback>,
) {
    let mut i = 0;
    // SAFETY: have checked whether the pointer is null before dereference it.
    unsafe {
        loop {
            if (*poll.offset(i)).is_null() {
                break;
            };
            if (*(*poll.offset(i))).events as c_int == EPOLLIN {
                notifiers.push(EventNotifier::new(
                    NotifierOperation::AddShared,
                    (*(*poll.offset(i))).fd,
                    None,
                    EventSet::IN,
                    vec![handler.clone()],
                ));
            } else if (*(*poll.offset(i))).events as c_int == EPOLLOUT {
                notifiers.push(EventNotifier::new(
                    NotifierOperation::AddShared,
                    (*(*poll.offset(i))).fd,
                    None,
                    EventSet::OUT,
                    vec![handler.clone()],
                ));
            }
            i += 1;
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
    // SAFETY: transfer is still valid because libusb just completed it
    // but we haven't told anyone yet. user_data remains valid because
    // it is dropped only when the request is completed and removed here.
    let mut node = get_node_from_transfer(host_transfer);
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

    let actual_length = get_length_from_transfer(host_transfer) as usize;
    let transfer_status = get_status_from_transfer(host_transfer);
    locked_packet.status = map_packet_status(transfer_status);

    if request.is_control {
        request.ctrl_transfer_packet(&mut locked_packet, actual_length);
    } else if locked_packet.pid as u8 == USB_TOKEN_IN && actual_length != 0 {
        let data = get_buffer_from_transfer(host_transfer, actual_length);
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
            ops.lock().unwrap().submit_transfer();
        }
    }

    request.free();
    locked_requests.unlink(&node);
}

extern "system" fn req_complete_iso(host_transfer: *mut libusb_transfer) {
    // SAFETY: the pointer has been verified.
    if host_transfer.is_null() || unsafe { (*host_transfer).user_data.is_null() } {
        free_host_transfer(host_transfer);
        return;
    }

    let iso_transfer = get_iso_transfer_from_transfer(host_transfer);
    let locketd_iso_transfer = iso_transfer.lock().unwrap();

    if let Some(iso_queue) = locketd_iso_transfer.iso_queue.clone().upgrade() {
        drop(locketd_iso_transfer);
        let mut locked_iso_queue = iso_queue.lock().unwrap();
        let iso_transfer = locked_iso_queue.inflight.pop_front().unwrap();
        if locked_iso_queue.inflight.is_empty() {
            let queue = &locked_iso_queue;
            trace::usb_host_iso_stop(queue.hostbus, queue.hostaddr, queue.ep_number);
        }
        locked_iso_queue.copy.push_back(iso_transfer);
    }
}

pub fn fill_transfer_by_type(
    transfer: *mut libusb_transfer,
    handle: Option<&mut DeviceHandle<Context>>,
    ep_number: u8,
    node: *mut Node<UsbHostRequest>,
    transfer_type: TransferType,
) {
    // SAFETY: node only deleted when request completed.
    let packet = unsafe { (*node).value.packet.clone() };
    // SAFETY: the reason is same as above.
    let buffer_ptr = unsafe { (*node).value.buffer.as_mut_ptr() };
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
            libusb1_sys::libusb_fill_bulk_transfer(
                transfer,
                handle.unwrap().as_raw(),
                ep_number,
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
