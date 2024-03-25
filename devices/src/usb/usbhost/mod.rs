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

mod host_usblib;

use std::{
    collections::LinkedList,
    os::unix::io::RawFd,
    rc::Rc,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use libc::c_int;
use libusb1_sys::{
    libusb_get_iso_packet_buffer_simple, libusb_set_iso_packet_lengths, libusb_transfer,
};
use log::{error, info, warn};
use rusb::{
    constants::LIBUSB_CLASS_HUB, Context, Device, DeviceDescriptor, DeviceHandle, Direction, Error,
    TransferType, UsbContext,
};

use crate::usb::{
    config::{
        USB_DEVICE_OUT_REQUEST, USB_DIRECTION_DEVICE_TO_HOST, USB_ENDPOINT_ATTR_BULK,
        USB_ENDPOINT_ATTR_INT, USB_ENDPOINT_ATTR_INVALID, USB_ENDPOINT_ATTR_ISOC,
        USB_ENDPOINT_OUT_REQUEST, USB_INTERFACE_OUT_REQUEST, USB_REQUEST_CLEAR_FEATURE,
        USB_REQUEST_SET_ADDRESS, USB_REQUEST_SET_CONFIGURATION, USB_REQUEST_SET_INTERFACE,
        USB_TOKEN_IN, USB_TOKEN_OUT,
    },
    descriptor::USB_MAX_INTERFACES,
    xhci::xhci_controller::XhciDevice,
    UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
};
use host_usblib::*;
use machine_manager::{
    config::valid_id,
    event_loop::{register_event_helper, unregister_event_helper},
    temp_cleaner::{ExitNotifier, TempCleaner},
};
use util::{
    byte_code::ByteCode,
    link_list::{List, Node},
    loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback},
    num_ops::str_to_num,
};

const NON_ISO_PACKETS_NUMS: c_int = 0;
const HANDLE_TIMEOUT_MS: u64 = 2;
const USB_HOST_BUFFER_LEN: usize = 12 * 1024;
const USBHOST_ADDR_MAX: i64 = 127;

#[derive(Default, Copy, Clone)]
struct InterfaceStatus {
    detached: bool,
    claimed: bool,
}

pub struct UsbHostRequest {
    pub hostbus: u8,
    pub hostaddr: u8,
    pub requests: Weak<Mutex<List<UsbHostRequest>>>,
    pub packet: Arc<Mutex<UsbPacket>>,
    pub host_transfer: *mut libusb_transfer,
    /// Async data buffer.
    pub buffer: Vec<u8>,
    pub is_control: bool,
}

impl UsbHostRequest {
    pub fn new(
        hostbus: u8,
        hostaddr: u8,
        requests: Weak<Mutex<List<UsbHostRequest>>>,
        packet: Arc<Mutex<UsbPacket>>,
        host_transfer: *mut libusb_transfer,
        is_control: bool,
    ) -> Self {
        Self {
            hostbus,
            hostaddr,
            requests,
            packet,
            host_transfer,
            buffer: Vec::new(),
            is_control,
        }
    }

    pub fn setup_data_buffer(&mut self) {
        let mut locked_packet = self.packet.lock().unwrap();
        let size = locked_packet.get_iovecs_size();
        self.buffer = vec![0; size as usize];
        if locked_packet.pid as u8 == USB_TOKEN_OUT {
            locked_packet.transfer_packet(self.buffer.as_mut(), size as usize);
        }
    }

    pub fn setup_ctrl_buffer(&mut self, data_buf: &[u8], device_req: &UsbDeviceRequest) {
        self.buffer = vec![0; (device_req.length + 8) as usize];
        self.buffer[..8].copy_from_slice(device_req.as_bytes());
        if self.packet.lock().unwrap().pid as u8 == USB_TOKEN_OUT {
            self.buffer[8..].copy_from_slice(data_buf);
        }
    }

    pub fn free(&mut self) {
        free_host_transfer(self.host_transfer);
        self.buffer.clear();
        self.host_transfer = std::ptr::null_mut();
    }

    pub fn abort_req(&mut self) {
        let mut locked_packet = self.packet.lock().unwrap();
        if locked_packet.is_async {
            locked_packet.status = UsbPacketStatus::NoDev;
            locked_packet.is_async = false;
            trace::usb_host_req_complete(
                self.hostbus,
                self.hostaddr,
                &*locked_packet as *const UsbPacket as u64,
                &locked_packet.status,
                locked_packet.actual_length as usize,
            );
            cancel_host_transfer(self.host_transfer)
                .unwrap_or_else(|e| warn!("usb-host cancel host transfer is error: {:?}", e));

            if let Some(transfer) = locked_packet.xfer_ops.as_ref() {
                if let Some(ops) = transfer.clone().upgrade() {
                    if self.is_control {
                        self.ctrl_transfer_packet(&mut locked_packet, 0);
                    }
                    drop(locked_packet);
                    ops.lock().unwrap().submit_transfer();
                }
            }
        }
    }

    pub fn ctrl_transfer_packet(&self, packet: &mut UsbPacket, actual_length: usize) {
        let setup_buf = get_buffer_from_transfer(self.host_transfer, 8);
        let mut len = (setup_buf[7] as usize) << 8 | setup_buf[6] as usize;
        if len > actual_length {
            len = actual_length;
        }

        if packet.pid as u8 == USB_TOKEN_IN && actual_length != 0 {
            let data = get_buffer_from_transfer(self.host_transfer, len + 8);
            packet.transfer_packet(&mut data[8..], len);
        }
    }
}

// SAFETY: The UsbHostRequest is created in main thread and then be passed to the
// libUSB thread. Once this data is processed, it is cleaned up. So there will be
// no problem with data sharing or synchronization.
unsafe impl Sync for UsbHostRequest {}
// SAFETY: The reason is same as above.
unsafe impl Send for UsbHostRequest {}

pub struct IsoTransfer {
    host_transfer: *mut libusb_transfer,
    copy_completed: bool,
    packet: u32,
    buffer: Vec<u8>,
    iso_queue: Weak<Mutex<IsoQueue>>,
}

impl IsoTransfer {
    pub fn new(packets: u32, iso_queue: Weak<Mutex<IsoQueue>>) -> Self {
        let host_transfer = alloc_host_transfer(packets as i32);
        Self {
            host_transfer,
            copy_completed: false,
            packet: 0,
            buffer: Vec::new(),
            iso_queue,
        }
    }

    pub fn realize(
        &mut self,
        handle: &mut DeviceHandle<Context>,
        packets: u32,
        pid: u8,
        ep_number: u8,
        ep_max_packet_size: u32,
        user_data: *mut libc::c_void,
    ) {
        let mut ep = ep_number;
        let length = ep_max_packet_size * packets;
        if pid == USB_TOKEN_IN {
            ep |= USB_DIRECTION_DEVICE_TO_HOST;
        }
        self.buffer = vec![0; length as usize];
        fill_iso_transfer(
            self.host_transfer,
            handle,
            ep,
            user_data,
            packets,
            length,
            &mut self.buffer,
        );
    }

    pub fn reset(&mut self, max_packet_size: u32) {
        // SAFETY: host_transfer is guaranteed to be valid once created.
        unsafe { libusb_set_iso_packet_lengths(self.host_transfer, max_packet_size) };
        self.packet = 0;
        self.copy_completed = false;
    }

    pub fn clear(&mut self, inflight: bool) {
        if inflight {
            // SAFETY: host_transfer is guaranteed to be valid once created.
            unsafe {
                (*self.host_transfer).user_data = std::ptr::null_mut();
            }
        } else {
            self.buffer.clear();
            free_host_transfer(self.host_transfer);
        }
    }

    pub fn copy_data(&mut self, packet: Arc<Mutex<UsbPacket>>, ep_max_packet_size: u32) -> bool {
        let mut lockecd_packet = packet.lock().unwrap();
        let mut size: usize;
        if lockecd_packet.pid == USB_TOKEN_OUT as u32 {
            size = lockecd_packet.get_iovecs_size() as usize;
            if size > ep_max_packet_size as usize {
                size = ep_max_packet_size as usize;
            }
            set_iso_packet_length(self.host_transfer, self.packet, size as u32);
        } else {
            size = get_iso_packet_acl_length(self.host_transfer, self.packet) as usize;
            if size > lockecd_packet.get_iovecs_size() as usize {
                size = lockecd_packet.get_iovecs_size() as usize;
            }
        }
        let buffer =
            // SAFETY: host_transfer is guaranteed to be valid once created
            // and packet is guaranteed to be not out of boundary.
            unsafe { libusb_get_iso_packet_buffer_simple(self.host_transfer, self.packet) };

        lockecd_packet.transfer_packet(
            // SAFETY: buffer is already allocated and size will not be exceed
            // the size of buffer.
            unsafe { std::slice::from_raw_parts_mut(buffer, size) },
            size,
        );

        self.packet += 1;
        self.copy_completed = self.packet == get_iso_packet_nums(self.host_transfer);
        self.copy_completed
    }
}

// SAFETY: The operation of libusb_transfer is protected by lock.
unsafe impl Sync for IsoTransfer {}
// SAFETY: The reason is same as above.
unsafe impl Send for IsoTransfer {}

pub struct IsoQueue {
    hostbus: u8,
    hostaddr: u8,
    ep_number: u8,
    unused: LinkedList<Arc<Mutex<IsoTransfer>>>,
    inflight: LinkedList<Arc<Mutex<IsoTransfer>>>,
    copy: LinkedList<Arc<Mutex<IsoTransfer>>>,
}

impl IsoQueue {
    pub fn new(hostbus: u8, hostaddr: u8, ep_number: u8) -> Self {
        Self {
            hostbus,
            hostaddr,
            ep_number,
            unused: LinkedList::new(),
            inflight: LinkedList::new(),
            copy: LinkedList::new(),
        }
    }

    pub fn realize(
        &mut self,
        id: &str,
        handle: &mut DeviceHandle<Context>,
        iso_urb_count: u32,
        iso_urb_frames: u32,
        ep: &UsbEndpoint,
        iso_queue: Arc<Mutex<IsoQueue>>,
    ) -> Result<()> {
        let packets: u32 = iso_urb_frames;
        let pid = if ep.in_direction {
            USB_TOKEN_IN
        } else {
            USB_TOKEN_OUT
        };
        let ep_number = ep.ep_number;
        let max_packet_size = ep.max_packet_size;

        for i in 0..iso_urb_count {
            let iso_xfer = Arc::new(Mutex::new(IsoTransfer::new(
                packets,
                Arc::downgrade(&iso_queue),
            )));

            if iso_xfer.lock().unwrap().host_transfer.is_null() {
                return Err(anyhow!(
                    "Failed to allocate host transfer for {}th iso urb of device {} ep {}",
                    i,
                    id,
                    ep_number
                ));
            }

            let cloned_iso_xfer = iso_xfer.clone();
            iso_xfer.lock().unwrap().realize(
                handle,
                packets,
                pid,
                ep_number,
                max_packet_size,
                (Arc::into_raw(cloned_iso_xfer) as *mut Mutex<IsoTransfer>).cast::<libc::c_void>(),
            );
            self.unused.push_back(iso_xfer);
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        for xfer in self.unused.iter_mut() {
            xfer.lock().unwrap().clear(false);
        }

        for xfer in self.inflight.iter_mut() {
            xfer.lock().unwrap().clear(true);
        }

        for xfer in self.copy.iter_mut() {
            xfer.lock().unwrap().clear(false);
        }
    }
}

#[derive(Parser, Clone, Debug, Default)]
#[command(name = "usb_host")]
pub struct UsbHostConfig {
    #[arg(long, value_parser = valid_id)]
    id: String,
    #[arg(long, default_value = "0")]
    hostbus: u8,
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(u8).range(..=USBHOST_ADDR_MAX))]
    hostaddr: u8,
    #[arg(long)]
    hostport: Option<String>,
    #[arg(long, default_value = "0", value_parser = str_to_num::<u16>)]
    vendorid: u16,
    #[arg(long, default_value = "0", value_parser = str_to_num::<u16>)]
    productid: u16,
    #[arg(long = "isobsize", default_value = "32")]
    iso_urb_frames: u32,
    #[arg(long = "isobufs", default_value = "4")]
    iso_urb_count: u32,
}

/// Abstract object of the host USB device.
pub struct UsbHost {
    base: UsbDeviceBase,
    config: UsbHostConfig,
    /// Libusb context.
    context: Context,
    /// A reference to a USB device.
    libdev: Option<Device<Context>>,
    /// A handle to an open USB device.
    handle: Option<DeviceHandle<Context>>,
    /// Describes a device.
    ddesc: Option<DeviceDescriptor>,
    /// EventFd for libusb.
    libevt: Vec<RawFd>,
    /// Configuration interface number.
    ifs_num: u8,
    ifs: [InterfaceStatus; USB_MAX_INTERFACES as usize],
    /// Callback for release dev to Host after the vm exited.
    exit: Option<Arc<ExitNotifier>>,
    /// All pending asynchronous usb request.
    requests: Arc<Mutex<List<UsbHostRequest>>>,
    /// ISO queues corresponding to all endpoints.
    iso_queues: Arc<Mutex<LinkedList<Arc<Mutex<IsoQueue>>>>>,
    iso_urb_frames: u32,
    iso_urb_count: u32,
}

// SAFETY: Send and Sync is not auto-implemented for util::link_list::List.
// Implementing them is safe because List add Mutex.
unsafe impl Sync for UsbHost {}
// SAFETY: The reason is same as above.
unsafe impl Send for UsbHost {}

impl UsbHost {
    pub fn new(config: UsbHostConfig) -> Result<Self> {
        let mut context = Context::new()?;
        context.set_log_level(rusb::LogLevel::None);
        let iso_urb_frames = config.iso_urb_frames;
        let iso_urb_count = config.iso_urb_count;
        let id = config.id.clone();
        Ok(Self {
            config,
            context,
            libdev: None,
            handle: None,
            ddesc: None,
            libevt: Vec::new(),
            ifs_num: 0,
            ifs: [InterfaceStatus::default(); USB_MAX_INTERFACES as usize],
            base: UsbDeviceBase::new(id, USB_HOST_BUFFER_LEN),
            exit: None,
            requests: Arc::new(Mutex::new(List::new())),
            iso_queues: Arc::new(Mutex::new(LinkedList::new())),
            iso_urb_frames,
            iso_urb_count,
        })
    }

    fn find_libdev(&self) -> Option<Device<Context>> {
        if self.config.vendorid != 0 && self.config.productid != 0 {
            self.find_dev_by_vendor_product()
        } else if self.config.hostport.is_some() {
            self.find_dev_by_bus_port()
        } else if self.config.hostbus != 0 && self.config.hostaddr != 0 {
            self.find_dev_by_bus_addr()
        } else {
            None
        }
    }

    fn find_dev_by_bus_addr(&self) -> Option<Device<Context>> {
        self.context
            .devices()
            .ok()
            .map(|devices| {
                devices.iter().find(|device| {
                    if check_device_valid(device) {
                        return device.bus_number() == self.config.hostbus
                            && device.address() == self.config.hostaddr;
                    }
                    false
                })
            })
            .unwrap_or_else(|| None)
    }

    fn find_dev_by_vendor_product(&self) -> Option<Device<Context>> {
        self.context
            .devices()
            .ok()
            .map(|devices| {
                devices.iter().find(|device| {
                    if check_device_valid(device) {
                        let ddesc = device.device_descriptor().unwrap();
                        return ddesc.vendor_id() == self.config.vendorid
                            && ddesc.product_id() == self.config.productid;
                    }
                    false
                })
            })
            .unwrap_or_else(|| None)
    }

    fn find_dev_by_bus_port(&self) -> Option<Device<Context>> {
        let hostport: Vec<&str> = self.config.hostport.as_ref().unwrap().split('.').collect();
        let mut port: Vec<u8> = Vec::new();
        for elem in hostport {
            let elem = elem.to_string().parse::<u8>();
            if elem.is_err() {
                return None;
            }
            port.push(elem.unwrap());
        }

        if port.is_empty() {
            return None;
        }

        self.context
            .devices()
            .ok()
            .map(|devices| {
                devices.iter().find(|device| {
                    if check_device_valid(device) {
                        return device.bus_number() == self.config.hostbus
                            && port.eq(device.port_numbers().as_ref().unwrap());
                    }
                    false
                })
            })
            .unwrap_or_else(|| None)
    }

    fn detach_kernel(&mut self) -> Result<()> {
        let conf = self.libdev.as_ref().unwrap().active_config_descriptor()?;

        self.ifs_num = conf.num_interfaces();

        for i in 0..self.ifs_num {
            if !match self.handle.as_ref().unwrap().kernel_driver_active(i) {
                Ok(rc) => {
                    if !rc {
                        self.ifs[i as usize].detached = true;
                    }
                    rc
                }
                Err(e) => {
                    error!("Failed to kernel driver active: {:?}", e);
                    false
                }
            } {
                continue;
            }
            trace::usb_host_detach_kernel(self.config.hostbus, self.config.hostaddr, i);
            self.handle
                .as_mut()
                .unwrap()
                .detach_kernel_driver(i)
                .unwrap_or_else(|e| error!("Failed to detach kernel driver: {:?}", e));
            self.ifs[i as usize].detached = true;
        }

        Ok(())
    }

    fn attach_kernel(&mut self) {
        if self
            .libdev
            .as_ref()
            .unwrap()
            .active_config_descriptor()
            .is_err()
        {
            return;
        }
        for i in 0..self.ifs_num {
            if !self.ifs[i as usize].detached {
                continue;
            }
            trace::usb_host_attach_kernel(self.config.hostbus, self.config.hostaddr, i);
            self.handle
                .as_mut()
                .unwrap()
                .attach_kernel_driver(i)
                .unwrap_or_else(|e| error!("Failed to attach kernel driver: {:?}", e));
            self.ifs[i as usize].detached = false;
        }
    }

    fn ep_update(&mut self) {
        self.base.reset_usb_endpoint();
        let conf = match self.libdev.as_ref().unwrap().active_config_descriptor() {
            Ok(conf) => conf,
            Err(_) => return,
        };

        trace::usb_host_parse_config(self.config.hostbus, self.config.hostaddr, conf.number());
        for (i, intf) in conf.interfaces().enumerate() {
            // The usb_deviec.altsetting indexes alternate settings by the interface number.
            // Get the 0th alternate setting first so that we can grap the interface number,
            // and then correct the alternate setting value if necessary.
            let mut intf_desc = intf.descriptors().next();
            if intf_desc.is_none() {
                continue;
            }
            let alt = self.base.altsetting[intf_desc.as_ref().unwrap().interface_number() as usize];
            if alt != 0 {
                if alt >= intf.descriptors().count() as u32 {
                    error!(
                        "Interface index {} exceeds max counts {}",
                        alt,
                        intf.descriptors().count()
                    );
                    return;
                }
                intf_desc = intf.descriptors().nth(alt as usize);
            }

            trace::usb_host_parse_interface(
                self.config.hostbus,
                self.config.hostaddr,
                intf_desc.as_ref().unwrap().interface_number(),
                intf_desc.as_ref().unwrap().setting_number(),
            );
            for ep in intf_desc.as_ref().unwrap().endpoint_descriptors() {
                let pid = match ep.direction() {
                    Direction::In => USB_TOKEN_IN,
                    Direction::Out => USB_TOKEN_OUT,
                };
                let ep_num = ep.number();
                let ep_type = ep.transfer_type() as u8;
                if ep_num == 0 {
                    trace::usb_host_parse_error(
                        self.config.hostbus,
                        self.config.hostaddr,
                        "invalid endpoint address",
                    );
                    return;
                }
                let in_direction = pid == USB_TOKEN_IN;
                if self.base.get_endpoint(in_direction, ep_num).ep_type != USB_ENDPOINT_ATTR_INVALID
                {
                    trace::usb_host_parse_error(
                        self.config.hostbus,
                        self.config.hostaddr,
                        "duplicate endpoint address",
                    );
                }

                trace::usb_host_parse_endpoint(
                    self.config.hostbus,
                    self.config.hostaddr,
                    ep_num,
                    &ep.direction(),
                    &ep.transfer_type(),
                );
                let usb_ep = self.base.get_mut_endpoint(in_direction, ep_num);
                usb_ep.set_max_packet_size(ep.max_packet_size());
                usb_ep.ep_type = ep_type;
                usb_ep.ifnum = i as u8;
                usb_ep.halted = false;
            }
        }
    }

    fn open_and_init(&mut self) -> Result<()> {
        self.handle = Some(self.libdev.as_ref().unwrap().open()?);
        self.config.hostbus = self.libdev.as_ref().unwrap().bus_number();
        self.config.hostaddr = self.libdev.as_ref().unwrap().address();
        trace::usb_host_open_started(self.config.hostbus, self.config.hostaddr);

        self.detach_kernel()?;

        self.ddesc = self.libdev.as_ref().unwrap().device_descriptor().ok();

        self.ep_update();

        self.base.speed = self.libdev.as_ref().unwrap().speed() as u32 - 1;
        trace::usb_host_open_success(self.config.hostbus, self.config.hostaddr);

        Ok(())
    }

    fn register_exit(&mut self) {
        let exit = self as *const Self as u64;
        let exit_notifier = Arc::new(move || {
            let usb_host =
                // SAFETY: This callback is deleted after the device hot-unplug, so it is called only
                // when the vm exits abnormally.
                &mut unsafe { std::slice::from_raw_parts_mut(exit as *mut UsbHost, 1) }[0];
            usb_host.release_dev_to_host();
        }) as Arc<ExitNotifier>;
        self.exit = Some(exit_notifier.clone());
        TempCleaner::add_exit_notifier(self.device_id().to_string(), exit_notifier);
    }

    fn release_interfaces(&mut self) {
        for i in 0..self.ifs_num {
            if !self.ifs[i as usize].claimed {
                continue;
            }
            trace::usb_host_release_interface(self.config.hostbus, self.config.hostaddr, i);
            self.handle
                .as_mut()
                .unwrap()
                .release_interface(i)
                .unwrap_or_else(|e| error!("Failed to release interface: {:?}", e));
            self.ifs[i as usize].claimed = false;
        }
    }

    fn claim_interfaces(&mut self) -> UsbPacketStatus {
        self.base.altsetting = [0; USB_MAX_INTERFACES as usize];
        if self.detach_kernel().is_err() {
            return UsbPacketStatus::Stall;
        }

        let conf = match self.libdev.as_ref().unwrap().active_config_descriptor() {
            Ok(conf) => conf,
            Err(e) => {
                if e == Error::NotFound {
                    // Ignore address state
                    return UsbPacketStatus::Success;
                }
                return UsbPacketStatus::Stall;
            }
        };

        let mut claimed = 0;
        for i in 0..self.ifs_num {
            trace::usb_host_claim_interface(self.config.hostbus, self.config.hostaddr, i);
            if self.handle.as_mut().unwrap().claim_interface(i).is_ok() {
                self.ifs[i as usize].claimed = true;
                claimed += 1;
                if claimed == conf.num_interfaces() {
                    break;
                }
            }
        }

        if claimed != conf.num_interfaces() {
            return UsbPacketStatus::Stall;
        }

        UsbPacketStatus::Success
    }

    fn set_config(&mut self, config: u8, packet: &mut UsbPacket) {
        trace::usb_host_set_config(self.config.hostbus, self.config.hostaddr, config);
        self.release_interfaces();

        if self.ddesc.is_some() && self.ddesc.as_ref().unwrap().num_configurations() != 1 {
            if let Err(e) = self
                .handle
                .as_mut()
                .unwrap()
                .set_active_configuration(config)
            {
                error!("Failed to set active configuration: {:?}", e);
                if e == Error::NoDevice {
                    packet.status = UsbPacketStatus::NoDev
                } else {
                    packet.status = UsbPacketStatus::Stall;
                }
                return;
            }
        }

        packet.status = self.claim_interfaces();
        if packet.status == UsbPacketStatus::Success {
            self.ep_update();
        }
    }

    fn set_interface(&mut self, iface: u16, alt: u16, packet: &mut UsbPacket) {
        trace::usb_host_set_interface(self.config.hostbus, self.config.hostaddr, iface, alt);
        self.clear_iso_queues();

        if iface > USB_MAX_INTERFACES as u16 {
            packet.status = UsbPacketStatus::Stall;
            return;
        }
        match self
            .handle
            .as_mut()
            .unwrap()
            .set_alternate_setting(iface as u8, alt as u8)
        {
            Ok(_) => {
                self.base.altsetting[iface as usize] = alt as u32;
                self.ep_update();
            }
            Err(e) => {
                if e == Error::NoDevice {
                    packet.status = UsbPacketStatus::NoDev
                } else {
                    packet.status = UsbPacketStatus::Stall;
                }
            }
        }
    }

    fn clear_halt(&mut self, pid: u8, index: u8) {
        if self.handle.as_mut().unwrap().clear_halt(index).is_err() {
            warn!("Failed to clear halt");
        }
        self.base
            .get_mut_endpoint(pid == USB_TOKEN_IN, index & 0x0f)
            .halted = false;
    }

    fn release_dev_to_host(&mut self) {
        if self.handle.is_none() {
            return;
        }

        trace::usb_host_close(self.config.hostbus, self.config.hostaddr);

        self.abort_host_transfers()
            .unwrap_or_else(|e| error!("Failed to abort all libusb transfers: {:?}", e));
        self.release_interfaces();
        self.handle.as_mut().unwrap().reset().unwrap_or_else(|e| {
            error!(
                "Failed to reset the handle of UsbHost device {}: {:?}",
                self.device_id(),
                e
            )
        });
        self.attach_kernel();
    }

    fn clear_iso_queues(&mut self) {
        let mut locked_iso_queues = self.iso_queues.lock().unwrap();
        for queue in locked_iso_queues.iter() {
            (*queue).lock().unwrap().clear();
        }
        locked_iso_queues.clear();
        drop(locked_iso_queues);
    }

    pub fn abort_host_transfers(&mut self) -> Result<()> {
        let mut locked_requests = self.requests.lock().unwrap();
        for _i in 0..locked_requests.len {
            let mut node = locked_requests.pop_head().unwrap();
            node.value.abort_req();
            locked_requests.add_tail(node);
        }
        drop(locked_requests);

        // Max counts of uncompleted request to be handled.
        let mut limit = 100;
        loop {
            if self.requests.lock().unwrap().len == 0 {
                return Ok(());
            }
            let timeout = Some(Duration::from_millis(HANDLE_TIMEOUT_MS));
            self.context.handle_events(timeout)?;
            if limit == 0 {
                self.requests = Arc::new(Mutex::new(List::new()));
                return Ok(());
            }
            limit -= 1;
        }
    }

    pub fn find_iso_queue(&self, ep_number: u8) -> Option<Arc<Mutex<IsoQueue>>> {
        for queue in self.iso_queues.lock().unwrap().iter() {
            if (*queue).lock().unwrap().ep_number == ep_number {
                return Some(queue.clone());
            }
        }
        None
    }

    pub fn handle_iso_data_in(&mut self, packet: Arc<Mutex<UsbPacket>>) {
        let cloned_packet = packet.clone();
        let locked_packet = packet.lock().unwrap();
        let in_direction = locked_packet.pid == USB_TOKEN_IN as u32;
        let iso_queue = if self.find_iso_queue(locked_packet.ep_number).is_some() {
            self.find_iso_queue(locked_packet.ep_number).unwrap()
        } else {
            let iso_queue = Arc::new(Mutex::new(IsoQueue::new(
                self.config.hostbus,
                self.config.hostaddr,
                locked_packet.ep_number,
            )));
            let cloned_iso_queue = iso_queue.clone();
            let ep = self
                .base
                .get_endpoint(in_direction, locked_packet.ep_number);
            let id = self.device_id().to_string();
            match iso_queue.lock().unwrap().realize(
                &id,
                self.handle.as_mut().unwrap(),
                self.iso_urb_count,
                self.iso_urb_frames,
                ep,
                cloned_iso_queue,
            ) {
                Ok(()) => {
                    self.iso_queues.lock().unwrap().push_back(iso_queue.clone());
                }
                Err(_e) => {
                    return;
                }
            };
            iso_queue
        };

        let mut locked_iso_queue = iso_queue.lock().unwrap();

        let in_direction = locked_packet.pid == USB_TOKEN_IN as u32;
        let ep = self
            .base
            .get_endpoint(in_direction, locked_packet.ep_number);
        drop(locked_packet);

        let iso_transfer = locked_iso_queue.copy.front_mut();
        if iso_transfer.is_some()
            && iso_transfer
                .unwrap()
                .lock()
                .unwrap()
                .copy_data(cloned_packet, ep.max_packet_size)
        {
            let iso_transfer = locked_iso_queue.copy.pop_front().unwrap();
            locked_iso_queue.unused.push_back(iso_transfer);
        }
        drop(locked_iso_queue);

        loop {
            let mut iso_transfer = iso_queue.lock().unwrap().unused.pop_front();
            if iso_transfer.is_none() {
                break;
            }
            iso_transfer
                .as_mut()
                .unwrap()
                .lock()
                .unwrap()
                .reset(ep.max_packet_size);
            let host_transfer = iso_transfer.as_ref().unwrap().lock().unwrap().host_transfer;
            let mut locked_iso_queue = iso_queue.lock().unwrap();
            match submit_host_transfer(host_transfer) {
                Ok(()) => {
                    if locked_iso_queue.inflight.is_empty() {
                        trace::usb_host_iso_start(
                            self.config.hostbus,
                            self.config.hostaddr,
                            ep.ep_number,
                        );
                    }
                    locked_iso_queue
                        .inflight
                        .push_back(iso_transfer.unwrap().clone());
                }
                Err(e) => {
                    locked_iso_queue.unused.push_back(iso_transfer.unwrap());
                    if e == Error::NoDevice || e == Error::Io {
                        // When the USB device reports the preceding error, XHCI notifies the guest
                        // of the error through packet status. The guest initiallizes the device
                        // again.
                        packet.lock().unwrap().status = UsbPacketStatus::Stall;
                    };
                    break;
                }
            };
        }
    }

    pub fn handle_iso_data_out(&mut self, _packet: Arc<Mutex<UsbPacket>>) {
        // TODO
        error!("USBHost device Unsupported Isochronous Transfer from guest to device.");
    }

    fn submit_host_transfer(
        &mut self,
        host_transfer: *mut libusb_transfer,
        packet: &Arc<Mutex<UsbPacket>>,
    ) {
        let mut locked_packet = packet.lock().unwrap();
        match submit_host_transfer(host_transfer) {
            Ok(()) => {}
            Err(Error::NoDevice) => {
                locked_packet.status = UsbPacketStatus::NoDev;
                trace::usb_host_req_complete(
                    self.config.hostbus,
                    self.config.hostaddr,
                    &*locked_packet as *const UsbPacket as u64,
                    &locked_packet.status,
                    locked_packet.actual_length as usize,
                );
                return;
            }
            _ => {
                locked_packet.status = UsbPacketStatus::Stall;
                self.reset();
                return;
            }
        };

        locked_packet.is_async = true;
    }
}

impl Drop for UsbHost {
    fn drop(&mut self) {
        self.release_dev_to_host();
    }
}

impl EventNotifierHelper for UsbHost {
    fn internal_notifiers(usbhost: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let cloned_usbhost = usbhost.clone();
        let mut notifiers = Vec::new();

        let poll = get_libusb_pollfds(usbhost);
        let timeout = Some(Duration::new(0, 0));
        let handler: Rc<NotifierCallback> = Rc::new(move |_, _fd: RawFd| {
            cloned_usbhost
                .lock()
                .unwrap()
                .context
                .handle_events(timeout)
                .unwrap_or_else(|e| error!("Failed to handle event: {:?}", e));
            None
        });

        set_pollfd_notifiers(poll, &mut notifiers, handler);

        notifiers
    }
}

impl UsbDevice for UsbHost {
    fn usb_device_base(&self) -> &UsbDeviceBase {
        &self.base
    }

    fn usb_device_base_mut(&mut self) -> &mut UsbDeviceBase {
        &mut self.base
    }

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        self.libdev = self.find_libdev();
        if self.libdev.is_none() {
            bail!("Invalid USB host config: {:?}", self.config);
        }

        info!("Open and init usbhost device: {:?}", self.config);
        self.open_and_init()?;

        let usbhost = Arc::new(Mutex::new(self));
        let notifiers = EventNotifierHelper::internal_notifiers(usbhost.clone());
        register_event_helper(notifiers, None, &mut usbhost.lock().unwrap().libevt)?;
        // UsbHost addr is changed after Arc::new, so so the registration must be here.
        usbhost.lock().unwrap().register_exit();

        Ok(usbhost)
    }

    fn unrealize(&mut self) -> Result<()> {
        TempCleaner::remove_exit_notifier(self.device_id());
        unregister_event_helper(None, &mut self.libevt)?;
        info!("Usb Host device {} is unrealized", self.device_id());
        Ok(())
    }

    fn reset(&mut self) {
        info!("Usb Host device {} reset", self.device_id());
        if self.handle.is_none() {
            return;
        }

        self.clear_iso_queues();

        trace::usb_host_reset(self.config.hostbus, self.config.hostaddr);

        self.handle
            .as_mut()
            .unwrap()
            .reset()
            .unwrap_or_else(|e| error!("Failed to reset the usb host device {:?}", e));
    }

    fn set_controller(&mut self, _cntlr: std::sync::Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.base.get_endpoint(true, 1)
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        trace::usb_host_req_control(self.config.hostbus, self.config.hostaddr, device_req);
        let mut locked_packet = packet.lock().unwrap();
        if self.handle.is_none() {
            locked_packet.status = UsbPacketStatus::NoDev;
            trace::usb_host_req_emulated(
                self.config.hostbus,
                self.config.hostaddr,
                &*locked_packet as *const UsbPacket as u64,
                &locked_packet.status,
            );
            return;
        }
        match device_req.request_type {
            USB_DEVICE_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_SET_ADDRESS {
                    self.base.addr = device_req.value as u8;
                    trace::usb_host_set_address(
                        self.config.hostbus,
                        self.config.hostaddr,
                        self.base.addr,
                    );
                    trace::usb_host_req_emulated(
                        self.config.hostbus,
                        self.config.hostaddr,
                        &*locked_packet as *const UsbPacket as u64,
                        &locked_packet.status,
                    );
                    return;
                } else if device_req.request == USB_REQUEST_SET_CONFIGURATION {
                    self.set_config(device_req.value as u8, &mut locked_packet);
                    trace::usb_host_req_emulated(
                        self.config.hostbus,
                        self.config.hostaddr,
                        &*locked_packet as *const UsbPacket as u64,
                        &locked_packet.status,
                    );
                    return;
                }
            }
            USB_INTERFACE_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_SET_INTERFACE {
                    self.set_interface(device_req.index, device_req.value, &mut locked_packet);
                    trace::usb_host_req_emulated(
                        self.config.hostbus,
                        self.config.hostaddr,
                        &*locked_packet as *const UsbPacket as u64,
                        &locked_packet.status,
                    );
                    return;
                }
            }
            USB_ENDPOINT_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_CLEAR_FEATURE && device_req.value == 0 {
                    self.clear_halt(locked_packet.pid as u8, device_req.index as u8);
                    trace::usb_host_req_emulated(
                        self.config.hostbus,
                        self.config.hostaddr,
                        &*locked_packet as *const UsbPacket as u64,
                        &locked_packet.status,
                    );
                    return;
                }
            }
            _ => {}
        }
        drop(locked_packet);

        let host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
        let mut node = Box::new(Node::new(UsbHostRequest::new(
            self.config.hostbus,
            self.config.hostaddr,
            Arc::downgrade(&self.requests),
            packet.clone(),
            host_transfer,
            true,
        )));
        node.value.setup_ctrl_buffer(
            &self.base.data_buf[..device_req.length as usize],
            device_req,
        );

        fill_transfer_by_type(
            host_transfer,
            self.handle.as_mut(),
            0,
            &mut (*node) as *mut Node<UsbHostRequest>,
            TransferType::Control,
        );

        self.requests.lock().unwrap().add_tail(node);

        self.submit_host_transfer(host_transfer, packet);
    }

    fn handle_data(&mut self, packet: &Arc<Mutex<UsbPacket>>) {
        let cloned_packet = packet.clone();
        let mut locked_packet = packet.lock().unwrap();

        trace::usb_host_req_data(
            self.config.hostbus,
            self.config.hostaddr,
            &*locked_packet as *const UsbPacket as u64,
            locked_packet.pid,
            locked_packet.ep_number,
            locked_packet.iovecs.len(),
        );

        if self.handle.is_none() {
            locked_packet.status = UsbPacketStatus::NoDev;
            trace::usb_host_req_emulated(
                self.config.hostbus,
                self.config.hostaddr,
                &*locked_packet as *const UsbPacket as u64,
                &locked_packet.status,
            );
            return;
        }
        let in_direction = locked_packet.pid as u8 == USB_TOKEN_IN;
        if self
            .base
            .get_endpoint(in_direction, locked_packet.ep_number)
            .halted
        {
            locked_packet.status = UsbPacketStatus::Stall;
            trace::usb_host_req_emulated(
                self.config.hostbus,
                self.config.hostaddr,
                &*locked_packet as *const UsbPacket as u64,
                &locked_packet.status,
            );
            return;
        }

        drop(locked_packet);
        let mut ep_number = packet.lock().unwrap().ep_number;
        let host_transfer: *mut libusb_transfer;

        match self.base.get_endpoint(in_direction, ep_number).ep_type {
            USB_ENDPOINT_ATTR_BULK => {
                host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
                let mut node = Box::new(Node::new(UsbHostRequest::new(
                    self.config.hostbus,
                    self.config.hostaddr,
                    Arc::downgrade(&self.requests),
                    cloned_packet,
                    host_transfer,
                    false,
                )));
                node.value.setup_data_buffer();

                if packet.lock().unwrap().pid as u8 != USB_TOKEN_OUT {
                    ep_number |= USB_DIRECTION_DEVICE_TO_HOST;
                }
                fill_transfer_by_type(
                    host_transfer,
                    self.handle.as_mut(),
                    ep_number,
                    &mut (*node) as *mut Node<UsbHostRequest>,
                    TransferType::Bulk,
                );
                self.requests.lock().unwrap().add_tail(node);
            }
            USB_ENDPOINT_ATTR_INT => {
                host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
                let mut node = Box::new(Node::new(UsbHostRequest::new(
                    self.config.hostbus,
                    self.config.hostaddr,
                    Arc::downgrade(&self.requests),
                    cloned_packet,
                    host_transfer,
                    false,
                )));
                node.value.setup_data_buffer();

                if packet.lock().unwrap().pid as u8 != USB_TOKEN_OUT {
                    ep_number |= USB_DIRECTION_DEVICE_TO_HOST;
                }
                fill_transfer_by_type(
                    host_transfer,
                    self.handle.as_mut(),
                    ep_number,
                    &mut (*node) as *mut Node<UsbHostRequest>,
                    TransferType::Interrupt,
                );
                self.requests.lock().unwrap().add_tail(node);
            }
            USB_ENDPOINT_ATTR_ISOC => {
                if packet.lock().unwrap().pid as u8 == USB_TOKEN_IN {
                    self.handle_iso_data_in(packet.clone());
                } else {
                    self.handle_iso_data_out(packet.clone());
                }
                let locked_packet = packet.lock().unwrap();
                trace::usb_host_req_complete(
                    self.config.hostbus,
                    self.config.hostaddr,
                    &*locked_packet as *const UsbPacket as u64,
                    &locked_packet.status,
                    locked_packet.actual_length as usize,
                );
                return;
            }
            _ => {
                packet.lock().unwrap().status = UsbPacketStatus::Stall;
                let locked_packet = packet.lock().unwrap();
                trace::usb_host_req_complete(
                    self.config.hostbus,
                    self.config.hostaddr,
                    &*locked_packet as *const UsbPacket as u64,
                    &locked_packet.status,
                    locked_packet.actual_length as usize,
                );
                return;
            }
        };
        self.submit_host_transfer(host_transfer, packet);
    }
}

fn check_device_valid(device: &Device<Context>) -> bool {
    let ddesc = match device.device_descriptor() {
        Ok(ddesc) => ddesc,
        Err(_) => return false,
    };
    if ddesc.class_code() == LIBUSB_CLASS_HUB {
        return false;
    }
    true
}
