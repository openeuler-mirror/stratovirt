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

use std::cmp::min;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Result};
use log::{debug, error};
use util::aio::{mem_from_buf, mem_to_buf};

use crate::config::*;
use crate::descriptor::{UsbDescriptor, UsbDescriptorOps};
use crate::xhci::xhci_controller::{UsbPort, XhciDevice};

const USB_MAX_ENDPOINTS: u32 = 15;
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

/// USB request used to transfer to USB device.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct UsbDeviceRequest {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

/// The data transmission channel.
#[derive(Default, Clone)]
pub struct UsbEndpoint {
    pub ep_number: u8,
    pub in_direction: bool,
    pub ep_type: u8,
}

impl UsbEndpoint {
    pub fn new(ep_number: u8, in_direction: bool, ep_type: u8) -> Self {
        Self {
            ep_number,
            in_direction,
            ep_type,
        }
    }
}

/// USB device common structure.
pub struct UsbDevice {
    pub port: Option<Weak<Mutex<UsbPort>>>,
    pub speed: u32,
    pub addr: u8,
    pub data_buf: Vec<u8>,
    pub remote_wakeup: u32,
    pub ep_ctl: UsbEndpoint,
    pub ep_in: Vec<UsbEndpoint>,
    pub ep_out: Vec<UsbEndpoint>,
    /// USB descriptor
    pub descriptor: UsbDescriptor,
}

impl UsbDevice {
    pub fn new() -> Self {
        let mut dev = UsbDevice {
            port: None,
            speed: 0,
            addr: 0,
            ep_ctl: UsbEndpoint::new(0, false, USB_ENDPOINT_ATTR_CONTROL),
            ep_in: Vec::new(),
            ep_out: Vec::new(),
            data_buf: vec![0_u8; 4096],
            remote_wakeup: 0,
            descriptor: UsbDescriptor::new(),
        };

        for i in 0..USB_MAX_ENDPOINTS as u8 {
            dev.ep_in
                .push(UsbEndpoint::new(i + 1, true, USB_ENDPOINT_ATTR_INVALID));
            dev.ep_out
                .push(UsbEndpoint::new(i + 1, false, USB_ENDPOINT_ATTR_INVALID));
        }
        dev
    }

    pub fn get_endpoint(&self, in_direction: bool, ep: u8) -> &UsbEndpoint {
        if ep == 0 {
            return &self.ep_ctl;
        }
        if in_direction {
            &self.ep_in[(ep - 1) as usize]
        } else {
            &self.ep_out[(ep - 1) as usize]
        }
    }

    pub fn get_mut_endpoint(&mut self, in_direction: bool, ep: u8) -> &mut UsbEndpoint {
        if ep == 0 {
            return &mut self.ep_ctl;
        }
        if in_direction {
            &mut self.ep_in[(ep - 1) as usize]
        } else {
            &mut self.ep_out[(ep - 1) as usize]
        }
    }

    pub fn reset_usb_endpoint(&mut self) {
        self.ep_ctl.ep_number = 0;
        self.ep_ctl.ep_type = USB_ENDPOINT_ATTR_CONTROL;
        for i in 0..USB_MAX_ENDPOINTS {
            self.ep_in[i as usize].ep_number = (i + 1) as u8;
            self.ep_in[i as usize].in_direction = true;
            self.ep_in[i as usize].ep_type = USB_ENDPOINT_ATTR_INVALID;
            self.ep_out[i as usize].ep_number = (i + 1) as u8;
            self.ep_out[i as usize].in_direction = false;
            self.ep_out[i as usize].ep_type = USB_ENDPOINT_ATTR_INVALID;
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
    ) -> Result<bool> {
        let value = device_req.value as u32;
        let index = device_req.index as u32;
        let length = device_req.length as u32;
        match device_req.request_type {
            USB_DEVICE_IN_REQUEST => match device_req.request {
                USB_REQUEST_GET_DESCRIPTOR => {
                    let res = self.get_descriptor(value)?;
                    let len = std::cmp::min(res.len() as u32, length);
                    self.data_buf[..(len as usize)].clone_from_slice(&res[..(len as usize)]);
                    packet.actual_length = len;
                }
                USB_REQUEST_GET_CONFIGURATION => {
                    self.data_buf[0] = if let Some(conf) = &self.descriptor.configuration_selected {
                        conf.config_desc.bConfigurationValue
                    } else {
                        0
                    };
                    packet.actual_length = 1;
                }
                USB_REQUEST_GET_STATUS => {
                    let conf = if let Some(conf) = &self.descriptor.configuration_selected {
                        conf.clone()
                    } else {
                        let desc = if let Some(desc) = self.descriptor.device_desc.as_ref() {
                            desc
                        } else {
                            bail!("Device descriptor not found");
                        };
                        let conf = if let Some(conf) = desc.configs.get(0) {
                            conf
                        } else {
                            bail!("Config descriptor not found");
                        };
                        conf.clone()
                    };
                    self.data_buf[0] = 0;
                    if conf.config_desc.bmAttributes & USB_CONFIGURATION_ATTR_SELF_POWER
                        == USB_CONFIGURATION_ATTR_SELF_POWER
                    {
                        self.data_buf[0] |= 1 << USB_DEVICE_SELF_POWERED;
                    }

                    if self.remote_wakeup & USB_DEVICE_REMOTE_WAKEUP == USB_DEVICE_REMOTE_WAKEUP {
                        self.data_buf[0] |= 1 << USB_DEVICE_REMOTE_WAKEUP;
                    }
                    self.data_buf[1] = 0x00;
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
                    if index < self.descriptor.interface_number {
                        self.data_buf[0] = self.descriptor.altsetting[index as usize] as u8;
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
        usb_dev.set_config_descriptor(0)?;
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
    fn get_wakeup_endpoint(&self) -> &UsbEndpoint;

    /// Set the attached USB port.
    fn set_usb_port(&mut self, port: Option<Weak<Mutex<UsbPort>>>) {
        let usb_dev = self.get_mut_usb_device();
        usb_dev.port = port;
    }

    /// Handle usb packet, used for controller to deliever packet to device.
    fn handle_packet(&mut self, packet: &mut UsbPacket) {
        packet.status = UsbPacketStatus::Success;
        let ep_nr = packet.ep_number;
        debug!("handle packet endpointer number {}", ep_nr);
        if ep_nr == 0 {
            if let Err(e) = self.do_parameter(packet) {
                error!("Failed to handle control packet {}", e);
            }
        } else {
            self.handle_data(packet);
        }
    }

    /// Handle control pakcet.
    fn handle_control(&mut self, packet: &mut UsbPacket, device_req: &UsbDeviceRequest);

    /// Handle data pakcet.
    fn handle_data(&mut self, packet: &mut UsbPacket);

    /// Unique device id.
    fn device_id(&self) -> String;

    /// Get the UsbDevice.
    fn get_usb_device(&self) -> &UsbDevice;

    /// Get the mut UsbDevice.
    fn get_mut_usb_device(&mut self) -> &mut UsbDevice;

    /// Get the device speed.
    fn speed(&self) -> u32 {
        let usb_dev = self.get_usb_device();
        usb_dev.speed
    }

    fn do_parameter(&mut self, p: &mut UsbPacket) -> Result<()> {
        let usb_dev = self.get_mut_usb_device();
        let device_req = UsbDeviceRequest {
            request_type: p.parameter as u8,
            request: (p.parameter >> 8) as u8,
            value: (p.parameter >> 16) as u16,
            index: (p.parameter >> 32) as u16,
            length: (p.parameter >> 48) as u16,
        };
        if device_req.length as usize > usb_dev.data_buf.len() {
            p.status = UsbPacketStatus::Stall;
            bail!("data buffer small len {}", device_req.length);
        }
        if p.pid as u8 == USB_TOKEN_OUT {
            p.transfer_packet(&mut usb_dev.data_buf, device_req.length as usize);
        }
        self.handle_control(p, &device_req);
        let usb_dev = self.get_mut_usb_device();
        if p.status == UsbPacketStatus::Async {
            return Ok(());
        }
        let mut len = device_req.length;
        if len > p.actual_length as u16 {
            len = p.actual_length as u16;
        }
        if p.pid as u8 == USB_TOKEN_IN {
            p.actual_length = 0;
            p.transfer_packet(&mut usb_dev.data_buf, len as usize);
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
    let usb_dev = locked_dev.get_usb_device();
    let usb_port = if let Some(port) = &usb_dev.port {
        port.upgrade().unwrap()
    } else {
        bail!("No usb port found");
    };
    let slot_id = usb_dev.addr;
    let wakeup = usb_dev.remote_wakeup & USB_DEVICE_REMOTE_WAKEUP == USB_DEVICE_REMOTE_WAKEUP;
    let ep = locked_dev.get_wakeup_endpoint().clone();
    // Drop the small lock.
    drop(locked_dev);
    let mut locked_xhci = xhci.lock().unwrap();
    if wakeup {
        let mut locked_port = usb_port.lock().unwrap();
        let port_status = locked_port.get_port_link_state();
        if port_status == PLS_U3 {
            locked_port.set_port_link_state(PLS_RESUME);
            debug!(
                "Update portsc when notify controller, port {} status {}",
                locked_port.portsc, port_status
            );
            drop(locked_port);
            locked_xhci.port_notify(&usb_port, PORTSC_PLC)?;
        }
    }
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
    pub iovecs: Vec<Iovec>,
    /// control transfer parameter.
    pub parameter: u64,
    /// USB packet return status.
    pub status: UsbPacketStatus,
    /// Actually transfer length.
    pub actual_length: u32,
    /// Endpoint number.
    pub ep_number: u8,
}

impl std::fmt::Display for UsbPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "pid {} param {} status {:?} actual_length {}",
            self.pid, self.parameter, self.status, self.actual_length
        )
    }
}

impl UsbPacket {
    pub fn init(&mut self, pid: u32, ep_number: u8) {
        self.pid = pid;
        self.status = UsbPacketStatus::Success;
        self.actual_length = 0;
        self.parameter = 0;
        self.ep_number = ep_number;
    }

    /// Transfer USB packet from host to device or from device to host.
    ///
    /// # Arguments
    ///
    /// * `vec`     - Data buffer.
    /// * `len`     - Transfer length.
    pub fn transfer_packet(&mut self, vec: &mut [u8], len: usize) {
        let len = min(vec.len(), len);
        let to_host = self.pid as u8 & USB_TOKEN_IN == USB_TOKEN_IN;
        let mut copyed = 0;
        if to_host {
            for iov in &self.iovecs {
                let cnt = min(iov.iov_len, len - copyed);
                let tmp = &vec[copyed..(copyed + cnt)];
                if let Err(e) = mem_from_buf(tmp, iov.iov_base) {
                    error!("Failed to write mem: {}", e);
                }
                copyed += cnt;
                if len == copyed {
                    break;
                }
            }
        } else {
            for iov in &self.iovecs {
                let cnt = min(iov.iov_len, len - copyed);
                let tmp = &mut vec[copyed..(copyed + cnt)];
                if let Err(e) = mem_to_buf(tmp, iov.iov_base) {
                    error!("Failed to read mem {}", e);
                }
                copyed += cnt;
                if len == copyed {
                    break;
                }
            }
        }
        self.actual_length = copyed as u32;
    }
}

impl Default for UsbPacket {
    fn default() -> UsbPacket {
        UsbPacket {
            pid: 0,
            iovecs: Vec::new(),
            parameter: 0,
            status: UsbPacketStatus::NoDev,
            actual_length: 0,
            ep_number: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usb_packet_transfer_in() {
        let buf = [0_u8; 10];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_IN as u32;
        packet.iovecs.push(Iovec::new(hva, 4));
        packet.iovecs.push(Iovec::new(hva + 4, 2));
        let mut data: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        packet.transfer_packet(&mut data, 6);
        assert_eq!(packet.actual_length, 6);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_in_over() {
        let buf = [0_u8; 10];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_IN as u32;
        packet.iovecs.push(Iovec::new(hva, 4));

        let mut data: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        packet.transfer_packet(&mut data, 6);
        assert_eq!(packet.actual_length, 4);
        assert_eq!(buf, [1, 2, 3, 4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_in_under() {
        let buf = [0_u8; 10];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_IN as u32;
        packet.iovecs.push(Iovec::new(hva, 4));

        let mut data: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        packet.transfer_packet(&mut data, 2);
        assert_eq!(packet.actual_length, 2);
        assert_eq!(buf, [1, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_in_over_buffer() {
        let buf = [0_u8; 10];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_IN as u32;
        packet.iovecs.push(Iovec::new(hva, 10));

        let mut data: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
        packet.transfer_packet(&mut data, 10);
        assert_eq!(packet.actual_length, 6);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_out() {
        let buf: [u8; 10] = [1, 2, 3, 4, 5, 6, 0, 0, 0, 0];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_OUT as u32;
        packet.iovecs.push(Iovec::new(hva, 4));
        packet.iovecs.push(Iovec::new(hva + 4, 2));

        let mut data = [0_u8; 10];
        packet.transfer_packet(&mut data, 6);
        assert_eq!(packet.actual_length, 6);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_out_over() {
        let buf: [u8; 10] = [1, 2, 3, 4, 5, 6, 0, 0, 0, 0];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_OUT as u32;
        packet.iovecs.push(Iovec::new(hva, 4));
        packet.iovecs.push(Iovec::new(hva + 4, 2));

        let mut data = [0_u8; 10];
        packet.transfer_packet(&mut data, 10);
        assert_eq!(packet.actual_length, 6);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_out_under() {
        let buf: [u8; 10] = [1, 2, 3, 4, 5, 6, 0, 0, 0, 0];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_OUT as u32;
        packet.iovecs.push(Iovec::new(hva, 4));

        let mut data = [0_u8; 10];
        packet.transfer_packet(&mut data, 2);
        assert_eq!(packet.actual_length, 2);
        assert_eq!(data, [1, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_usb_packet_transfer_out_over_buffer() {
        let buf: [u8; 10] = [1, 2, 3, 4, 5, 6, 0, 0, 0, 0];
        let hva = buf.as_ptr() as u64;
        let mut packet = UsbPacket::default();
        packet.pid = USB_TOKEN_OUT as u32;
        packet.iovecs.push(Iovec::new(hva, 6));

        let mut data = [0_u8; 2];
        packet.transfer_packet(&mut data, 6);
        assert_eq!(packet.actual_length, 2);
        assert_eq!(data, [1, 2]);
    }
}
