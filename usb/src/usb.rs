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

use std::{
    collections::LinkedList,
    sync::{Arc, Mutex, Weak},
};

use super::errors::Result;
use crate::config::*;
use crate::descriptor::{
    UsbConfigDescriptor, UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor,
    UsbInterfaceDescriptor,
};
use crate::xhci::xhci_controller::XhciDevice;

const USB_MAX_ENDPOINTS: u32 = 15;
const USB_MAX_INTERFACES: u32 = 16;

/// USB packet return status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbPacketStatus {
    Success,
    NoDev,
    Nak,
    Stall,
    Babble,
    IoError,
    Async,
}

/// USB packet setup state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SetupState {
    Idle,
    Setup,
    Data,
    Ack,
    Parameter,
}

/// USB device state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbDeviceState {
    Removed,
    Attached,
    Powered,
    Default,
    Address,
    Configured,
    Suspended,
}

/// USB request used to transfer to USB device.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UsbDeviceRequest {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

/// The data transmission channel.
#[derive(Default)]
pub struct UsbEndpoint {
    pub nr: u8,
    pub pid: u8,
    pub usb_type: u8,
    pub ifnum: u8,
    pub max_packet_size: u32,
    pub pipeline: bool,
    pub halted: bool,
    pub dev: Option<Weak<Mutex<dyn UsbDeviceOps>>>,
    pub queue: LinkedList<UsbPacket>,
}

impl UsbEndpoint {
    pub fn new(nr: u8, pid: u8, usb_type: u8, ifnum: u8, max_packet_size: u32) -> Self {
        Self {
            nr,
            pid,
            usb_type,
            ifnum,
            max_packet_size,
            pipeline: false,
            halted: false,
            dev: None,
            queue: LinkedList::new(),
        }
    }
}

/// USB port which can attached device.
pub struct UsbPort {
    pub dev: Option<Arc<Mutex<dyn UsbDeviceOps>>>,
    pub speed_mask: u32,
    pub path: String,
    pub index: u32,
}

impl UsbPort {
    pub fn new(index: u32) -> Self {
        Self {
            dev: None,
            speed_mask: 0,
            path: String::new(),
            index,
        }
    }

    /// If the USB port attached USB device.
    pub fn is_attached(&self) -> bool {
        if let Some(dev) = &self.dev {
            let locked_dev = dev.lock().unwrap();
            locked_dev.attached()
        } else {
            false
        }
    }
}

/// USB descriptor strings.
pub struct UsbDescString {
    pub index: u32,
    pub str: String,
}

/// USB packet state.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum UsbPacketState {
    Undefined = 0,
    Setup,
    Queued,
    Async,
    Complete,
    Canceled,
}

// USB descriptor
pub struct UsbDesc {
    pub full_dev: Option<Arc<UsbDescDevice>>,
    pub high_dev: Option<Arc<UsbDescDevice>>,
    pub super_dev: Option<Arc<UsbDescDevice>>,
    pub strings: Vec<String>,
}

// USB device descriptor
pub struct UsbDescDevice {
    pub device_desc: UsbDeviceDescriptor,
    pub confs: Vec<Arc<UsbDescConfig>>,
}

// USB config descriptor
pub struct UsbDescConfig {
    pub config_desc: UsbConfigDescriptor,
    pub if_groups: Vec<Arc<UsbDescIfaceAssoc>>,
    pub ifs: Vec<Arc<UsbDescIface>>,
}

// USB interface descriptor
pub struct UsbDescIface {
    pub interface_desc: UsbInterfaceDescriptor,
    pub other_desc: Vec<Arc<UsbDescOther>>,
    pub eps: Vec<Arc<UsbDescEndpoint>>,
}

/* conceptually an Interface Association Descriptor, and related interfaces */
#[allow(non_snake_case)]
#[repr(C)]
pub struct UsbDescIfaceAssoc {
    pub bFirstInterface: u8,
    pub bInterfaceCount: u8,
    pub bFunctionClass: u8,
    pub bFunctionSubClass: u8,
    pub bFunctionProtocol: u8,
    pub iFunction: u8,
    pub ifs: Vec<Arc<UsbDescIface>>,
}

// USB other descriptor
pub struct UsbDescOther {
    pub length: u8,
    pub data: Vec<u8>,
}

// USB endpoint descriptor
pub struct UsbDescEndpoint {
    pub endpoint_desc: UsbEndpointDescriptor,
    pub extra: Option<Arc<u8>>,
}

/// USB device common structure.
pub struct UsbDevice {
    pub port: Option<Weak<Mutex<UsbPort>>>,
    pub speed: u32,
    pub speed_mask: u32,
    pub addr: u8,
    pub product_desc: String,
    pub auto_attach: bool,
    pub attached: bool,
    pub state: UsbDeviceState,
    pub setup_buf: Vec<u8>,
    pub data_buf: Vec<u8>,
    pub remote_wakeup: u32,
    pub setup_state: SetupState,
    pub setup_len: u32,
    pub setup_index: u32,
    pub ep_ctl: Arc<Mutex<UsbEndpoint>>,
    pub ep_in: Vec<Arc<Mutex<UsbEndpoint>>>,
    pub ep_out: Vec<Arc<Mutex<UsbEndpoint>>>,
    /// USB descriptor
    pub strings: Vec<UsbDescString>,
    pub usb_desc: Option<Arc<UsbDesc>>,
    pub device_desc: Option<Arc<UsbDescDevice>>,
    pub configuration: u32,
    pub ninterfaces: u32,
    pub altsetting: Vec<u32>,
    pub config: Option<Arc<UsbDescConfig>>,
    pub ifaces: Vec<Option<Arc<UsbDescIface>>>,
}

impl UsbDevice {
    pub fn new() -> Self {
        let mut dev = UsbDevice {
            port: None,
            attached: false,
            speed: 0,
            speed_mask: 0,
            addr: 0,
            ep_ctl: Arc::new(Mutex::new(UsbEndpoint::new(
                0,
                0,
                USB_ENDPOINT_ATTR_CONTROL,
                0,
                64,
            ))),
            ep_in: Vec::new(),
            ep_out: Vec::new(),
            product_desc: String::new(),
            auto_attach: false,
            strings: Vec::new(),
            usb_desc: None,
            device_desc: None,
            configuration: 0,
            ninterfaces: 0,
            config: None,
            altsetting: vec![0; USB_MAX_INTERFACES as usize],
            state: UsbDeviceState::Removed,
            setup_buf: vec![0_u8; 8],
            data_buf: vec![0_u8; 4096],
            ifaces: vec![None; USB_MAX_INTERFACES as usize],
            remote_wakeup: 0,
            setup_index: 0,
            setup_len: 0,
            setup_state: SetupState::Idle,
        };

        for i in 0..USB_MAX_ENDPOINTS as u8 {
            dev.ep_in.push(Arc::new(Mutex::new(UsbEndpoint::new(
                i + 1,
                USB_TOKEN_IN,
                USB_ENDPOINT_ATTR_INVALID,
                USB_INTERFACE_INVALID,
                0,
            ))));
            dev.ep_out.push(Arc::new(Mutex::new(UsbEndpoint::new(
                i + 1,
                USB_TOKEN_OUT,
                USB_ENDPOINT_ATTR_INVALID,
                USB_INTERFACE_INVALID,
                0,
            ))));
        }
        dev
    }

    pub fn get_endpoint(&self, pid: u32, ep: u32) -> Arc<Mutex<UsbEndpoint>> {
        if ep == 0 {
            return self.ep_ctl.clone();
        }
        if pid as u8 == USB_TOKEN_IN {
            self.ep_in[(ep - 1) as usize].clone()
        } else {
            self.ep_out[(ep - 1) as usize].clone()
        }
    }

    pub fn init_usb_endpoint(&mut self) {
        self.reset_usb_endpoint();
        let mut ep_ctl = self.ep_ctl.lock().unwrap();
        ep_ctl.queue = LinkedList::new();
        for i in 0..USB_MAX_ENDPOINTS {
            let mut ep_in = self.ep_in[i as usize].lock().unwrap();
            let mut ep_out = self.ep_out[i as usize].lock().unwrap();
            ep_in.queue = LinkedList::new();
            ep_out.queue = LinkedList::new();
        }
    }

    pub fn reset_usb_endpoint(&mut self) {
        let mut ep_ctl = self.ep_ctl.lock().unwrap();
        ep_ctl.nr = 0;
        ep_ctl.usb_type = USB_ENDPOINT_ATTR_CONTROL;
        ep_ctl.ifnum = 0;
        ep_ctl.max_packet_size = 64;
        ep_ctl.pipeline = false;
        for i in 0..USB_MAX_ENDPOINTS {
            let mut ep_in = self.ep_in[i as usize].lock().unwrap();
            let mut ep_out = self.ep_out[i as usize].lock().unwrap();
            ep_in.nr = (i + 1) as u8;
            ep_out.nr = (i + 1) as u8;
            ep_in.pid = USB_TOKEN_IN;
            ep_out.pid = USB_TOKEN_OUT;
            ep_in.usb_type = USB_ENDPOINT_ATTR_INVALID;
            ep_out.usb_type = USB_ENDPOINT_ATTR_INVALID;
            ep_in.ifnum = USB_INTERFACE_INVALID;
            ep_out.ifnum = USB_INTERFACE_INVALID;
            ep_in.max_packet_size = 0;
            ep_out.max_packet_size = 0;
            ep_in.pipeline = false;
            ep_out.pipeline = false;
        }
    }

    pub fn handle_control_for_descriptor(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) -> Result<()> {
        let value = device_req.value as u32;
        let index = device_req.index as u32;
        let length = device_req.length as u32;
        match device_req.request_type {
            USB_DEVICE_IN_REQUEST => match device_req.request {
                USB_REQUEST_GET_DESCRIPTOR => {
                    let res = self.get_descriptor(value)?;
                    let len = std::cmp::min(res.len() as u32, length);
                    data[..(len as usize)].clone_from_slice(&res[..(len as usize)]);
                    packet.actual_length = len;
                }
                USB_REQUEST_GET_CONFIGURATION => {
                    data[0] = if let Some(conf) = &self.config {
                        conf.config_desc.bConfigurationValue
                    } else {
                        0
                    };
                    packet.actual_length = 1;
                }
                USB_REQUEST_GET_STATUS => {
                    let conf = if let Some(conf) = &self.config {
                        conf.clone()
                    } else {
                        let x = &self.device_desc.as_ref().unwrap().confs[0];
                        x.clone()
                    };
                    data[0] = 0;
                    if conf.config_desc.bmAttributes & USB_CONFIGURATION_ATTR_SELF_POWER
                        == USB_CONFIGURATION_ATTR_SELF_POWER
                    {
                        data[0] |= 1 << USB_DEVICE_SELF_POWERED;
                    }

                    if self.remote_wakeup & USB_DEVICE_REMOTE_WAKEUP == USB_DEVICE_REMOTE_WAKEUP {
                        data[0] |= 1 << USB_DEVICE_REMOTE_WAKEUP;
                    }
                    data[1] = 0x00;
                    packet.actual_length = 2;
                }
                _ => {
                    bail!(
                        "Unhandled request: type {} request {}",
                        device_req.request_type,
                        device_req.request
                    );
                }
            },
            USB_DEVICE_OUT_REQUEST => match device_req.request {
                USB_REQUEST_SET_ADDRESS => {
                    self.addr = value as u8;
                }
                USB_REQUEST_SET_CONFIGURATION => {
                    return self.set_config_descriptor(value as u8);
                }
                USB_REQUEST_CLEAR_FEATURE => {
                    if value == USB_DEVICE_REMOTE_WAKEUP {
                        self.remote_wakeup = 0;
                    }
                }
                USB_REQUEST_SET_FEATURE => {
                    if value == USB_DEVICE_REMOTE_WAKEUP {
                        self.remote_wakeup = 1;
                    }
                }
                _ => {
                    bail!(
                        "Unhandled request: type {} request {}",
                        device_req.request_type,
                        device_req.request
                    );
                }
            },
            USB_INTERFACE_IN_REQUEST => match device_req.request {
                USB_REQUEST_GET_INTERFACE => {
                    if index < self.ninterfaces {
                        data[0] = self.altsetting[index as usize] as u8;
                        packet.actual_length = 1;
                    }
                }
                _ => {
                    bail!(
                        "Unhandled request: type {} request {}",
                        device_req.request_type,
                        device_req.request
                    );
                }
            },
            USB_INTERFACE_OUT_REQUEST => match device_req.request {
                USB_REQUEST_SET_INTERFACE => {
                    return self.set_interface_descriptor(index, value);
                }
                _ => {
                    bail!(
                        "Unhandled request: type {} request {}",
                        device_req.request_type,
                        device_req.request
                    );
                }
            },
            _ => {
                bail!("Unhandled request: type {}", device_req.request_type);
            }
        }
        Ok(())
    }
}

impl Default for UsbDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// UsbDeviceOps is the interface for USB device.
/// Include device handle attach/detach and the transfer between controller and device.
pub trait UsbDeviceOps: Send + Sync {
    /// Handle the attach ops when attach device to controller.
    fn handle_attach(&mut self) -> Result<()>;

    /// Reset the USB device.
    fn reset(&mut self);

    /// Set the controller which the USB device attached.
    /// USB deivce need to kick controller in some cases.
    fn set_controller(&mut self, ctrl: Weak<Mutex<XhciDevice>>);

    /// Set the attached USB port.
    fn set_usb_port(&mut self, port: Option<Weak<Mutex<UsbPort>>>);

    /// Handle usb packet, used for controller to deliever packet to device.
    fn handle_packet(&mut self, packet: &mut UsbPacket);

    /// Handle control pakcet.
    fn handle_control(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    );

    /// Handle data pakcet.
    fn handle_data(&mut self, packet: &mut UsbPacket);

    /// Unique device id.
    fn device_id(&self) -> String;

    /// Get the UsbDevice.
    fn get_usb_device(&self) -> Arc<Mutex<UsbDevice>>;

    /// Get the mut UsbDevice.
    fn get_mut_usb_device(&mut self) -> Arc<Mutex<UsbDevice>>;

    /// Get the device speed.
    fn speed(&self) -> u32;

    /// If USB device is attached.
    fn attached(&self) -> bool;
}

/// Io vector which save the hva.
#[derive(Debug, Copy, Clone)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: usize,
}

impl Iovec {
    pub fn new(base: u64, len: usize) -> Self {
        Iovec {
            iov_base: base,
            iov_len: len,
        }
    }
}

/// Usb packet used for device transfer data.
#[derive(Clone)]
pub struct UsbPacket {
    /// USB packet id.
    pub pid: u32,
    pub id: u64,
    pub ep: Option<Weak<Mutex<UsbEndpoint>>>,
    pub iovecs: Vec<Iovec>,
    /// control transfer
    pub parameter: u64,
    pub short_not_ok: bool,
    pub int_req: bool,
    /// USB packet return status
    pub status: UsbPacketStatus,
    /// Actually transfer length
    pub actual_length: u32,
    pub state: UsbPacketState,
}

impl Default for UsbPacket {
    fn default() -> UsbPacket {
        UsbPacket {
            pid: 0,
            id: 0,
            ep: None,
            iovecs: Vec::new(),
            parameter: 0,
            short_not_ok: false,
            int_req: false,
            status: UsbPacketStatus::NoDev,
            actual_length: 0,
            state: UsbPacketState::Undefined,
        }
    }
}
