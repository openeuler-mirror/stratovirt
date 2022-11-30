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

use crate::config::*;
use crate::descriptor::{
    UsbConfigDescriptor, UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor,
    UsbInterfaceDescriptor,
};
use crate::xhci::xhci_controller::XhciDevice;
use anyhow::{bail, Result};
use log::{debug, error, warn};

const USB_MAX_ENDPOINTS: u32 = 15;
const USB_MAX_INTERFACES: u32 = 16;
/// USB max address.
const USB_MAX_ADDRESS: u8 = 127;

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

    pub fn get_ep_id(&self) -> u8 {
        if self.nr == 0 {
            // Control endpoint
            1
        } else if self.pid == USB_TOKEN_IN {
            self.nr * 2 + 1
        } else {
            self.nr * 2
        }
    }
}

/// Init USB endpoint, similar with init_usb_endpoint, but set dev in endpoint.
pub fn usb_endpoint_init(dev: &Arc<Mutex<dyn UsbDeviceOps>>) {
    let mut locked_dev = dev.lock().unwrap();
    let usb_dev = locked_dev.get_mut_usb_device();
    let mut locked_dev = usb_dev.lock().unwrap();
    locked_dev.reset_usb_endpoint();
    let mut ep_ctl = locked_dev.ep_ctl.lock().unwrap();
    ep_ctl.dev = Some(Arc::downgrade(dev));
    ep_ctl.queue = LinkedList::new();
    for i in 0..USB_MAX_ENDPOINTS {
        let mut ep_in = locked_dev.ep_in[i as usize].lock().unwrap();
        let mut ep_out = locked_dev.ep_out[i as usize].lock().unwrap();
        ep_in.queue = LinkedList::new();
        ep_out.queue = LinkedList::new();
        ep_in.dev = Some(Arc::downgrade(dev));
        ep_out.dev = Some(Arc::downgrade(dev));
    }
}

/// USB port which can attached device.
pub struct UsbPort {
    pub dev: Option<Arc<Mutex<dyn UsbDeviceOps>>>,
    pub speed_mask: u32,
    pub path: String,
    pub index: u8,
}

impl UsbPort {
    pub fn new(index: u8) -> Self {
        Self {
            dev: None,
            speed_mask: 0,
            path: String::new(),
            index,
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
    pub state: UsbDeviceState,
    pub data_buf: Vec<u8>,
    pub remote_wakeup: u32,
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
            strings: Vec::new(),
            usb_desc: None,
            device_desc: None,
            configuration: 0,
            ninterfaces: 0,
            config: None,
            altsetting: vec![0; USB_MAX_INTERFACES as usize],
            state: UsbDeviceState::Removed,
            data_buf: vec![0_u8; 4096],
            ifaces: vec![None; USB_MAX_INTERFACES as usize],
            remote_wakeup: 0,
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

    /// Handle USB control request which is for descriptor.
    ///
    /// # Arguments
    ///
    /// * `packet`     - USB packet.
    /// * `device_req` - USB device request.
    /// * `data`       - USB control transfer data.
    ///
    /// # Returns
    ///
    /// Return true if request is handled, false is unhandled.
    pub fn handle_control_for_descriptor(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) -> Result<bool> {
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
                    return Ok(false);
                }
            },
            USB_DEVICE_OUT_REQUEST => match device_req.request {
                USB_REQUEST_SET_ADDRESS => {
                    if value as u8 > USB_MAX_ADDRESS {
                        packet.status = UsbPacketStatus::Stall;
                        bail!("The address is invalid {}", value);
                    } else {
                        self.addr = value as u8;
                    }
                }
                USB_REQUEST_SET_CONFIGURATION => {
                    self.set_config_descriptor(value as u8)?;
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
                    return Ok(false);
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
                    return Ok(false);
                }
            },
            USB_INTERFACE_OUT_REQUEST => match device_req.request {
                USB_REQUEST_SET_INTERFACE => {
                    self.set_interface_descriptor(index, value)?;
                }
                _ => {
                    return Ok(false);
                }
            },
            _ => {
                return Ok(false);
            }
        }
        Ok(true)
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
    fn handle_attach(&mut self) -> Result<()> {
        let usb_dev = self.get_mut_usb_device();
        let mut locked_dev = usb_dev.lock().unwrap();
        locked_dev.state = UsbDeviceState::Attached;
        drop(locked_dev);
        let usb_dev = self.get_mut_usb_device();
        let mut locked_dev = usb_dev.lock().unwrap();
        locked_dev.set_default_descriptor()?;
        Ok(())
    }

    /// Reset the USB device.
    fn reset(&mut self);

    /// Set the controller which the USB device attached.
    /// USB deivce need to kick controller in some cases.
    fn set_controller(&mut self, ctrl: Weak<Mutex<XhciDevice>>);

    /// Set the controller which the USB device attached.
    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>>;

    /// Get the endpoint to wakeup.
    fn get_wakeup_endpoint(&self) -> Option<Weak<Mutex<UsbEndpoint>>>;

    /// Set the attached USB port.
    fn set_usb_port(&mut self, port: Option<Weak<Mutex<UsbPort>>>) {
        let usb_dev = self.get_mut_usb_device();
        let mut locked_dev = usb_dev.lock().unwrap();
        locked_dev.port = port;
    }

    /// Handle usb packet, used for controller to deliever packet to device.
    fn handle_packet(&mut self, packet: &mut UsbPacket) {
        if packet.state != UsbPacketState::Setup {
            error!("The packet state is not Setup");
            return;
        }
        if let Err(e) = self.process_packet(packet) {
            error!("Failed to process packet: {}", e);
        }
        if packet.status != UsbPacketStatus::Nak {
            packet.state = UsbPacketState::Complete;
        }
    }

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
    fn speed(&self) -> u32 {
        let usb_dev = self.get_usb_device();
        let locked_dev = usb_dev.lock().unwrap();
        locked_dev.speed
    }

    fn process_packet(&mut self, packet: &mut UsbPacket) -> Result<()> {
        packet.status = UsbPacketStatus::Success;
        let ep = if let Some(ep) = &packet.ep {
            ep.upgrade().unwrap()
        } else {
            bail!("Failed to find ep");
        };
        let locked_ep = ep.lock().unwrap();
        let nr = locked_ep.nr;
        drop(locked_ep);
        if nr == 0 {
            if packet.parameter != 0 {
                return self.do_parameter(packet);
            }
            match packet.pid as u8 {
                USB_TOKEN_SETUP => {
                    warn!("process_packet USB_TOKEN_SETUP not implemented");
                }
                USB_TOKEN_IN => {
                    warn!("process_packet USB_TOKEN_IN not implemented");
                }
                USB_TOKEN_OUT => {
                    warn!("process_packet USB_TOKEN_OUT not implemented");
                }
                _ => {
                    warn!("Unknown pid {}", packet.pid);
                    packet.status = UsbPacketStatus::Stall;
                }
            }
        } else {
            self.handle_data(packet);
        }
        Ok(())
    }

    fn do_parameter(&mut self, p: &mut UsbPacket) -> Result<()> {
        let usb_dev = self.get_mut_usb_device();
        let mut locked_dev = usb_dev.lock().unwrap();
        let device_req = UsbDeviceRequest {
            request_type: p.parameter as u8,
            request: (p.parameter >> 8) as u8,
            value: (p.parameter >> 16) as u16,
            index: (p.parameter >> 32) as u16,
            length: (p.parameter >> 48) as u16,
        };
        if device_req.length as usize > locked_dev.data_buf.len() {
            bail!("data buffer small len {}", device_req.length);
        }
        if p.pid as u8 == USB_TOKEN_OUT {
            let len = locked_dev.data_buf.len();
            usb_packet_transfer(p, &mut locked_dev.data_buf, len);
        }
        // Drop locked for handle_control use it
        drop(locked_dev);
        let mut data_buf: [u8; 4096] = [0; 4096];
        self.handle_control(p, &device_req, &mut data_buf);
        let mut locked_dev = usb_dev.lock().unwrap();
        locked_dev.data_buf = data_buf.to_vec();
        if p.status == UsbPacketStatus::Async {
            return Ok(());
        }
        if p.pid as u8 == USB_TOKEN_IN {
            p.actual_length = 0;
            let len = locked_dev.data_buf.len();
            usb_packet_transfer(p, &mut locked_dev.data_buf, len);
        }
        Ok(())
    }
}

/// Notify controller to process data request.
pub fn notify_controller(dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()> {
    let locked_dev = dev.lock().unwrap();
    let xhci = if let Some(ctrl) = &locked_dev.get_controller() {
        ctrl.upgrade().unwrap()
    } else {
        bail!("USB controller not found");
    };
    drop(locked_dev);
    // Lock controller before device to avoid dead lock.
    let mut locked_xhci = xhci.lock().unwrap();
    let locked_dev = dev.lock().unwrap();
    let usb_dev = locked_dev.get_usb_device();
    drop(locked_dev);
    let locked_usb_dev = usb_dev.lock().unwrap();
    let usb_port = if let Some(port) = &locked_usb_dev.port {
        port.upgrade().unwrap()
    } else {
        bail!("No usb port found");
    };
    let slot_id = locked_usb_dev.addr;
    let wakeup =
        locked_usb_dev.remote_wakeup & USB_DEVICE_REMOTE_WAKEUP == USB_DEVICE_REMOTE_WAKEUP;
    drop(locked_usb_dev);
    let xhci_port = if let Some(xhci_port) = locked_xhci.lookup_xhci_port(&usb_port) {
        xhci_port
    } else {
        bail!("No xhci port found");
    };
    if wakeup {
        let mut locked_port = xhci_port.lock().unwrap();
        let port_status = locked_port.get_port_link_state();
        if port_status == PLS_U3 {
            locked_port.set_port_link_state(PLS_RESUME);
            debug!(
                "Update portsc when notify controller, port {} status {}",
                locked_port.portsc, port_status
            );
            drop(locked_port);
            locked_xhci.port_notify(&xhci_port, PORTSC_PLC)?;
        }
    }
    let locked_dev = dev.lock().unwrap();
    let intr = if let Some(intr) = locked_dev.get_wakeup_endpoint() {
        intr
    } else {
        bail!("No interrupter found");
    };
    drop(locked_dev);
    let ep = intr.upgrade().unwrap();
    if let Err(e) = locked_xhci.wakeup_endpoint(slot_id as u32, &ep) {
        error!("Failed to wakeup endpoint {}", e);
    }
    Ok(())
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
    pub ep: Option<Weak<Mutex<UsbEndpoint>>>,
    pub iovecs: Vec<Iovec>,
    /// control transfer parameter.
    pub parameter: u64,
    /// USB packet return status.
    pub status: UsbPacketStatus,
    /// Actually transfer length.
    pub actual_length: u32,
    pub state: UsbPacketState,
}

impl std::fmt::Display for UsbPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "pid {} param {} status {:?} actual_length {}, state {:?}",
            self.pid, self.parameter, self.status, self.actual_length, self.state
        )
    }
}

impl UsbPacket {
    pub fn init(&mut self, pid: u32, ep: Weak<Mutex<UsbEndpoint>>) {
        self.pid = pid;
        self.ep = Some(ep);
        self.status = UsbPacketStatus::Success;
        self.actual_length = 0;
        self.parameter = 0;
        self.state = UsbPacketState::Setup;
    }
}

impl Default for UsbPacket {
    fn default() -> UsbPacket {
        UsbPacket {
            pid: 0,
            ep: None,
            iovecs: Vec::new(),
            parameter: 0,
            status: UsbPacketStatus::NoDev,
            actual_length: 0,
            state: UsbPacketState::Undefined,
        }
    }
}

fn read_mem(hva: u64, buf: &mut [u8]) {
    let slice = unsafe { std::slice::from_raw_parts(hva as *const u8, buf.len()) };
    buf.clone_from_slice(&slice[..buf.len()]);
}

fn write_mem(hva: u64, buf: &[u8]) {
    use std::io::Write;
    let mut slice = unsafe { std::slice::from_raw_parts_mut(hva as *mut u8, buf.len()) };
    if let Err(e) = (&mut slice).write(buf) {
        error!("Failed to write mem {:?}", e);
    }
}

/// Transfer packet from host to device or from device to host.
pub fn usb_packet_transfer(packet: &mut UsbPacket, vec: &mut [u8], len: usize) {
    let to_host = packet.pid as u8 & USB_TOKEN_IN == USB_TOKEN_IN;

    if to_host {
        let mut copyed = 0;
        let mut offset = 0;
        for iov in &packet.iovecs {
            let cnt = std::cmp::min(iov.iov_len, len - copyed);
            let tmp = &vec[offset..(offset + cnt)];
            write_mem(iov.iov_base, tmp);
            copyed += cnt;
            offset += cnt;
            if len - copyed == 0 {
                break;
            }
        }
    } else {
        let mut copyed = 0;
        let mut offset = 0;
        for iov in &packet.iovecs {
            let cnt = std::cmp::min(iov.iov_len, len - copyed);
            let tmp = &mut vec[offset..(offset + cnt)];
            read_mem(iov.iov_base, tmp);
            copyed += cnt;
            offset += cnt;
            if len - copyed == 0 {
                break;
            }
        }
    }

    packet.actual_length += len as u32;
}
