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
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use anyhow::{bail, Result};
use log::{error, info, warn};
use rusb::{
    constants::LIBUSB_CLASS_HUB, Context, Device, DeviceDescriptor, DeviceHandle, Direction, Error,
    UsbContext,
};

use crate::usb::{
    config::{
        USB_DEVICE_OUT_REQUEST, USB_ENDPOINT_ATTR_INVALID, USB_ENDPOINT_OUT_REQUEST,
        USB_INTERFACE_OUT_REQUEST, USB_REQUEST_CLEAR_FEATURE, USB_REQUEST_SET_ADDRESS,
        USB_REQUEST_SET_CONFIGURATION, USB_REQUEST_SET_INTERFACE, USB_TOKEN_IN, USB_TOKEN_OUT,
    },
    descriptor::USB_MAX_INTERFACES,
    xhci::xhci_controller::XhciDevice,
    UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus,
};
use machine_manager::config::UsbHostConfig;

#[derive(Default, Copy, Clone)]
struct InterfaceStatus {
    detached: bool,
    claimed: bool,
}

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
    /// Configuration interface number.
    ifs_num: u8,
    ifs: [InterfaceStatus; USB_MAX_INTERFACES as usize],
    usb_device: UsbDevice,
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
            ifs_num: 0,
            ifs: [InterfaceStatus::default(); USB_MAX_INTERFACES as usize],
            usb_device: UsbDevice::new(),
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
            if !match self.handle.as_ref().unwrap().kernel_driver_active(i as u8) {
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
                .detach_kernel_driver(i as u8)
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
                .attach_kernel_driver(i as u8)
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

        for (i, intf) in conf.interfaces().into_iter().enumerate() {
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

    fn release_interfaces(&mut self) {
        for i in 0..self.ifs_num {
            if !self.ifs[i as usize].claimed {
                continue;
            }
            self.handle
                .as_mut()
                .unwrap()
                .release_interface(i as u8)
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
            if self
                .handle
                .as_mut()
                .unwrap()
                .claim_interface(i as u8)
                .is_ok()
            {
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
        if self
            .handle
            .as_mut()
            .unwrap()
            .clear_halt(index as u8)
            .is_err()
        {
            warn!("Failed to clear halt");
        }
        self.usb_device
            .get_mut_endpoint(pid == USB_TOKEN_IN, index & 0x0f)
            .halted = false;
    }

    fn control_transfer_pass_through(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
    ) {
        if packet.pid as u8 == USB_TOKEN_OUT {
            if let Err(e) = self.handle.as_ref().unwrap().write_control(
                device_req.request_type,
                device_req.request,
                device_req.value,
                device_req.index,
                &self.usb_device.data_buf[..device_req.length as usize],
                Duration::from_millis(10),
            ) {
                error!("Failed to write control by usb host: {:?}", e);
                packet.status = UsbPacketStatus::Stall;
                return;
            }
        } else {
            packet.actual_length = match self.handle.as_ref().unwrap().read_control(
                device_req.request_type,
                device_req.request,
                device_req.value,
                device_req.index,
                &mut self.usb_device.data_buf[..device_req.length as usize],
                Duration::from_millis(10),
            ) {
                Ok(n) => n as u32,
                Err(e) => {
                    error!("Failed to read control by usb host: {:?}", e);
                    0
                }
            };
        };
        packet.status = UsbPacketStatus::Success;
    }

    fn release_dev_to_host(&mut self) {
        if self.handle.is_none() {
            return;
        }

        self.release_interfaces();
        self.handle.as_mut().unwrap().reset().unwrap_or_else(|e| {
            error!(
                "Failed to reset the handle of UsbHost device {}: {:?}",
                self.id, e
            )
        });
        self.attach_kernel();
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
        Ok(usbhost)
    }

    fn unrealize(&mut self) -> Result<()> {
        self.release_dev_to_host();
        Ok(())
    }

    fn reset(&mut self) {
        info!("Usb Host device {} reset", self.id);
        if self.handle.is_none() {
            return;
        }

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
        self.control_transfer_pass_through(&mut locked_packet, device_req);
    }

    fn handle_data(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {}

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
