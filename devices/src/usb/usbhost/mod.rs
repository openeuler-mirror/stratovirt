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

use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Result};
use log::{error, info};
use rusb::{
    constants::LIBUSB_CLASS_HUB, Context, Device, DeviceDescriptor, DeviceHandle, Direction,
    UsbContext,
};

use crate::usb::{
    config::{USB_ENDPOINT_ATTR_INVALID, USB_TOKEN_IN, USB_TOKEN_OUT},
    descriptor::USB_MAX_INTERFACES,
    xhci::xhci_controller::XhciDevice,
    UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket,
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

    fn handle_control(&mut self, _packet: &Arc<Mutex<UsbPacket>>, _device_req: &UsbDeviceRequest) {}

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
