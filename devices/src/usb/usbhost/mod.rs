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
    collections::LinkedList,
    os::unix::io::RawFd,
    rc::Rc,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{bail, Result};
use libc::c_int;
use libusb1_sys::libusb_transfer;
use log::{error, info, warn};
use rusb::{
    constants::LIBUSB_CLASS_HUB, Context, Device, DeviceDescriptor, DeviceHandle, Direction, Error,
    TransferType, UsbContext,
};

use crate::usb::{
    config::{
        USB_DEVICE_OUT_REQUEST, USB_DIRECTION_DEVICE_TO_HOST, USB_ENDPOINT_ATTR_BULK,
        USB_ENDPOINT_ATTR_INT, USB_ENDPOINT_ATTR_INVALID, USB_ENDPOINT_OUT_REQUEST,
        USB_INTERFACE_OUT_REQUEST, USB_REQUEST_CLEAR_FEATURE, USB_REQUEST_SET_ADDRESS,
        USB_REQUEST_SET_CONFIGURATION, USB_REQUEST_SET_INTERFACE, USB_TOKEN_IN, USB_TOKEN_OUT,
    },
    descriptor::USB_MAX_INTERFACES,
    xhci::xhci_controller::XhciDevice,
    UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
};
use host_usblib::*;
use machine_manager::{
    config::UsbHostConfig,
    event_loop::{register_event_helper, unregister_event_helper},
    temp_cleaner::{ExitNotifier, TempCleaner},
};
use util::{
    byte_code::ByteCode,
    loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback},
};

mod host_usblib;

const NON_ISO_PACKETS_NUMS: c_int = 0;
const COMPLETE_LIMIT: u32 = 200;
const HANDLE_TIMEOUT_MS: u64 = 2;
const USB_HOST_BUFFER_LEN: usize = 12 * 1024;

#[derive(Default, Copy, Clone)]
struct InterfaceStatus {
    detached: bool,
    claimed: bool,
}

pub struct UsbHostRequest {
    pub packet: Arc<Mutex<UsbPacket>>,
    pub host_transfer: *mut libusb_transfer,
    /// Async data buffer.
    pub buffer: Vec<u8>,
    pub completed: Arc<Mutex<u32>>,
    pub is_control: bool,
}

impl UsbHostRequest {
    pub fn new(
        packet: Arc<Mutex<UsbPacket>>,
        host_transfer: *mut libusb_transfer,
        completed: Arc<Mutex<u32>>,
        is_control: bool,
    ) -> Self {
        Self {
            packet,
            host_transfer,
            buffer: Vec::new(),
            completed,
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

    pub fn setup_ctrl_buffer(&mut self, data_buf: Vec<u8>, device_req: &UsbDeviceRequest) {
        self.buffer = vec![0; (device_req.length + 8) as usize];
        self.buffer[..8].copy_from_slice(device_req.as_bytes());
        if self.packet.lock().unwrap().pid as u8 == USB_TOKEN_OUT {
            self.buffer[8..].clone_from_slice(&data_buf);
        }
    }

    pub fn complete(&mut self) {
        free_host_transfer(self.host_transfer);
        self.buffer.clear();
        self.host_transfer = std::ptr::null_mut();
        let mut completed = self.completed.lock().unwrap();
        *completed += 1;
    }

    pub fn abort_req(&mut self) -> Result<()> {
        let mut locked_packet = self.packet.lock().unwrap();
        if locked_packet.is_async {
            locked_packet.status = UsbPacketStatus::NoDev;
            locked_packet.is_async = false;
            cancel_host_transfer(self.host_transfer)?;

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

        Ok(())
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

unsafe impl Sync for UsbHostRequest {}
unsafe impl Send for UsbHostRequest {}

/// Abstract object of the host USB device.
pub struct UsbHost {
    id: String,
    config: UsbHostConfig,
    /// Libusb context.
    context: Context,
    /// A reference to a USB device.
    libdev: Option<Device<Context>>,
    /// A handle to an open USB device.
    handle: Option<DeviceHandle<Context>>,
    /// Describes a device.
    ddesc: Option<DeviceDescriptor>,
    /// /// EventFd for libusb.
    libevt: Vec<RawFd>,
    /// Configuration interface number.
    ifs_num: u8,
    ifs: [InterfaceStatus; USB_MAX_INTERFACES as usize],
    usb_device: UsbDevice,
    /// Callback for release dev to Host afer the vm exited.
    exit: Option<Arc<ExitNotifier>>,
    /// All pending asynchronous usb request.
    requests: Arc<Mutex<LinkedList<Arc<Mutex<UsbHostRequest>>>>>,
    completed: Arc<Mutex<u32>>,
}

impl UsbHost {
    pub fn new(config: UsbHostConfig) -> Result<Self> {
        let mut context = Context::new()?;
        context.set_log_level(rusb::LogLevel::Warning);
        Ok(Self {
            id: config.id.clone().unwrap(),
            config,
            context,
            libdev: None,
            handle: None,
            ddesc: None,
            libevt: Vec::new(),
            ifs_num: 0,
            ifs: [InterfaceStatus::default(); USB_MAX_INTERFACES as usize],
            usb_device: UsbDevice::new(USB_HOST_BUFFER_LEN),
            exit: None,
            requests: Arc::new(Mutex::new(LinkedList::new())),
            completed: Arc::new(Mutex::new(0)),
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
            self.handle
                .as_mut()
                .unwrap()
                .attach_kernel_driver(i)
                .unwrap_or_else(|e| error!("Failed to attach kernel driver: {:?}", e));
            self.ifs[i as usize].detached = false;
        }
    }

    fn ep_update(&mut self) {
        self.usb_device.reset_usb_endpoint();
        let conf = match self.libdev.as_ref().unwrap().active_config_descriptor() {
            Ok(conf) => conf,
            Err(_) => return,
        };

        for (i, intf) in conf.interfaces().enumerate() {
            // The usb_deviec.altsetting indexs alternate settings by the interface number.
            // Get the 0th alternate setting first so that we can grap the interface number,
            // and then correct the alternate setting value if necessary.
            let mut intf_desc = intf.descriptors().next();
            if intf_desc.is_none() {
                continue;
            }
            let alt =
                self.usb_device.altsetting[intf_desc.as_ref().unwrap().interface_number() as usize];
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

            for ep in intf_desc.as_ref().unwrap().endpoint_descriptors() {
                let addr = ep.address();
                let pid = match ep.direction() {
                    Direction::In => USB_TOKEN_IN,
                    Direction::Out => USB_TOKEN_OUT,
                };
                let ep_num = ep.number();
                let ep_type = ep.transfer_type() as u8;
                if ep_num == 0 {
                    error!("Invalid endpoint address {}", addr);
                    return;
                }
                let in_direction = pid == USB_TOKEN_IN;
                if self.usb_device.get_endpoint(in_direction, ep_num).ep_type
                    != USB_ENDPOINT_ATTR_INVALID
                {
                    error!("duplicate endpoint address")
                }
                let usb_ep = self.usb_device.get_mut_endpoint(in_direction, ep_num);
                usb_ep.ep_type = ep_type;
                usb_ep.ifnum = i as u8;
                usb_ep.halted = false;
            }
        }
    }

    fn open_and_init(&mut self) -> Result<()> {
        self.handle = Some(self.libdev.as_ref().unwrap().open()?);

        self.detach_kernel()?;

        self.ddesc = self.libdev.as_ref().unwrap().device_descriptor().ok();

        self.ep_update();

        self.usb_device.speed = self.libdev.as_ref().unwrap().speed() as u32 - 1;
        Ok(())
    }

    fn register_exit(&mut self) {
        let exit = self as *const Self as u64;
        let exit_notifier = Arc::new(move || {
            // SAFETY: This callback is deleted after the device hot-unplug, so it is called only
            // when the vm exits abnormally.
            let usb_host =
                &mut unsafe { std::slice::from_raw_parts_mut(exit as *mut UsbHost, 1) }[0];
            usb_host.release_dev_to_host();
        }) as Arc<ExitNotifier>;
        self.exit = Some(exit_notifier.clone());
        TempCleaner::add_exit_notifier(self.id.clone(), exit_notifier);
    }

    fn release_interfaces(&mut self) {
        for i in 0..self.ifs_num {
            if !self.ifs[i as usize].claimed {
                continue;
            }
            self.handle
                .as_mut()
                .unwrap()
                .release_interface(i)
                .unwrap_or_else(|e| error!("Failed to release interface: {:?}", e));
            self.ifs[i as usize].claimed = false;
        }
    }

    fn claim_interfaces(&mut self) -> UsbPacketStatus {
        self.usb_device.altsetting = [0; USB_MAX_INTERFACES as usize];
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
                self.usb_device.altsetting[iface as usize] = alt as u32;
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
        self.usb_device
            .get_mut_endpoint(pid == USB_TOKEN_IN, index & 0x0f)
            .halted = false;
    }

    fn release_dev_to_host(&mut self) {
        if self.handle.is_none() {
            return;
        }

        self.abort_host_transfers()
            .unwrap_or_else(|e| error!("Failed to abort all libusb transfers: {:?}", e));
        self.release_interfaces();
        self.handle.as_mut().unwrap().reset().unwrap_or_else(|e| {
            error!(
                "Failed to reset the handle of UsbHost device {}: {:?}",
                self.id, e
            )
        });
        self.attach_kernel();
    }

    pub fn clear_succ_requests(&mut self) {
        let mut updated_requests: LinkedList<Arc<Mutex<UsbHostRequest>>> = LinkedList::new();
        let mut locked_request = self.requests.lock().unwrap();
        let mut completed = self.completed.lock().unwrap();

        while !locked_request.is_empty() {
            let request = locked_request.front();
            if let Some(request) = request {
                if request.lock().unwrap().host_transfer.is_null() {
                    locked_request.pop_front();
                    *completed -= 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if *completed > COMPLETE_LIMIT {
            loop {
                let request = locked_request.pop_front();
                if let Some(request) = request {
                    if request.lock().unwrap().host_transfer.is_null() {
                        continue;
                    }
                    updated_requests.push_back(request);
                } else {
                    break;
                }
            }
        }
        *locked_request = updated_requests;
        *completed = 0;
    }

    pub fn abort_host_transfers(&mut self) -> Result<()> {
        // Max counts of uncompleted request to be handled.
        let mut limit = 100;
        for request in self.requests.lock().unwrap().iter_mut() {
            request.lock().unwrap().abort_req()?;
        }

        loop {
            if self.requests.lock().unwrap().is_empty() {
                return Ok(());
            }
            let timeout = Some(Duration::from_millis(HANDLE_TIMEOUT_MS));
            self.context.handle_events(timeout)?;
            if limit == 0 {
                self.requests.lock().unwrap().clear();
                return Ok(());
            }
            limit -= 1;
        }
    }

    fn submit_host_transfer(
        &mut self,
        host_transfer: *mut libusb_transfer,
        packet: &Arc<Mutex<UsbPacket>>,
    ) {
        match submit_host_transfer(host_transfer) {
            Ok(()) => {}
            Err(Error::NoDevice) => {
                packet.lock().unwrap().status = UsbPacketStatus::NoDev;
                return;
            }
            _ => {
                packet.lock().unwrap().status = UsbPacketStatus::Stall;
                return;
            }
        };

        packet.lock().unwrap().is_async = true;
        self.clear_succ_requests();
    }
}

impl EventNotifierHelper for UsbHost {
    fn internal_notifiers(usbhost: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let cloned_usbhost = usbhost.clone();
        let mut notifiers = Vec::new();

        let poll = get_libusb_pollfds(usbhost);
        let timeout = Some(Duration::from_micros(500));
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

impl UsbDeviceOps for UsbHost {
    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDeviceOps>>> {
        self.libdev = self.find_libdev();
        if self.libdev.is_none() {
            bail!("Invalid USB host config: {:?}", self.config);
        }

        self.open_and_init()?;

        let usbhost = Arc::new(Mutex::new(self));
        let notifiers = EventNotifierHelper::internal_notifiers(usbhost.clone());
        register_event_helper(notifiers, None, &mut usbhost.lock().unwrap().libevt)?;
        // UsbHost addr is changed after Arc::new, so so the registration must be here.
        usbhost.lock().unwrap().register_exit();

        Ok(usbhost)
    }

    fn unrealize(&mut self) -> Result<()> {
        TempCleaner::remove_exit_notifier(&self.id);
        self.release_dev_to_host();
        unregister_event_helper(None, &mut self.libevt)?;
        info!("Usb Host device {} is unrealized", self.id);
        Ok(())
    }

    fn reset(&mut self) {
        info!("Usb Host device {} reset", self.id);
        if self.handle.is_none() {
            return;
        }
        self.abort_host_transfers()
            .unwrap_or_else(|e| error!("Failed to abort all libusb transfers: {:?}", e));

        self.handle
            .as_mut()
            .unwrap()
            .reset()
            .unwrap_or_else(|e| error!("Failed to reset device handle:{:?}", e));
    }

    fn set_controller(&mut self, _cntlr: std::sync::Weak<Mutex<XhciDevice>>) {}

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        None
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        if self.handle.is_none() {
            locked_packet.status = UsbPacketStatus::NoDev;
            return;
        }
        match device_req.request_type {
            USB_DEVICE_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_SET_ADDRESS {
                    self.usb_device.addr = device_req.value as u8;
                    return;
                } else if device_req.request == USB_REQUEST_SET_CONFIGURATION {
                    self.set_config(device_req.value as u8, &mut locked_packet);
                    return;
                }
            }
            USB_INTERFACE_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_SET_INTERFACE {
                    self.set_interface(device_req.index, device_req.value, &mut locked_packet);
                    return;
                }
            }
            USB_ENDPOINT_OUT_REQUEST => {
                if device_req.request == USB_REQUEST_CLEAR_FEATURE && device_req.value == 0 {
                    self.clear_halt(locked_packet.pid as u8, device_req.index as u8);
                    return;
                }
            }
            _ => {}
        }
        drop(locked_packet);

        let host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
        let request = Arc::new(Mutex::new(UsbHostRequest::new(
            packet.clone(),
            host_transfer,
            self.completed.clone(),
            true,
        )));
        request
            .lock()
            .unwrap()
            .setup_ctrl_buffer(self.usb_device.data_buf.clone(), device_req);
        fill_transfer_by_type(
            host_transfer,
            self.handle.as_mut(),
            0,
            request,
            TransferType::Control,
        );

        self.submit_host_transfer(host_transfer, packet);
    }

    fn handle_data(&mut self, packet: &Arc<Mutex<UsbPacket>>) {
        let cloned_packet = packet.clone();
        let mut locked_packet = packet.lock().unwrap();

        if self.handle.is_none() {
            locked_packet.status = UsbPacketStatus::NoDev;
            return;
        }
        let in_direction = locked_packet.pid as u8 == USB_TOKEN_IN;
        if self
            .usb_device
            .get_endpoint(in_direction, locked_packet.ep_number)
            .halted
        {
            locked_packet.status = UsbPacketStatus::Stall;
            return;
        }

        drop(locked_packet);
        let mut ep_number = packet.lock().unwrap().ep_number;
        let host_transfer: *mut libusb_transfer;

        match self
            .usb_device
            .get_endpoint(in_direction, ep_number)
            .ep_type
        {
            USB_ENDPOINT_ATTR_BULK => {
                host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
                let request = Arc::new(Mutex::new(UsbHostRequest::new(
                    cloned_packet,
                    host_transfer,
                    self.completed.clone(),
                    false,
                )));
                request.lock().unwrap().setup_data_buffer();
                self.requests.lock().unwrap().push_back(request.clone());
                if packet.lock().unwrap().pid as u8 != USB_TOKEN_OUT {
                    ep_number |= USB_DIRECTION_DEVICE_TO_HOST;
                }
                fill_transfer_by_type(
                    host_transfer,
                    self.handle.as_mut(),
                    ep_number,
                    request,
                    TransferType::Bulk,
                );
            }
            USB_ENDPOINT_ATTR_INT => {
                host_transfer = alloc_host_transfer(NON_ISO_PACKETS_NUMS);
                let request = Arc::new(Mutex::new(UsbHostRequest::new(
                    cloned_packet,
                    host_transfer,
                    self.completed.clone(),
                    false,
                )));
                request.lock().unwrap().setup_data_buffer();
                self.requests.lock().unwrap().push_back(request.clone());
                if packet.lock().unwrap().pid as u8 != USB_TOKEN_OUT {
                    ep_number |= USB_DIRECTION_DEVICE_TO_HOST;
                }
                fill_transfer_by_type(
                    host_transfer,
                    self.handle.as_mut(),
                    ep_number,
                    request,
                    TransferType::Interrupt,
                );
            }
            _ => {
                error!("Isochronous transmission is not supported by host USB passthrough.");
                packet.lock().unwrap().status = UsbPacketStatus::Stall;
                return;
            }
        };
        self.submit_host_transfer(host_transfer, packet);
    }

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn get_usb_device(&self) -> &UsbDevice {
        &self.usb_device
    }

    fn get_mut_usb_device(&mut self) -> &mut UsbDevice {
        &mut self.usb_device
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
