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

use std::sync::Arc;

use anyhow::{bail, Result};
use log::error;
use util::byte_code::ByteCode;

use crate::config::*;
use crate::usb::{UsbDescConfig, UsbDescEndpoint, UsbDescIface, UsbDevice};

/// USB device descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UsbDeviceDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bcdUSB: u16,
    pub bDeviceClass: u8,
    pub bDeviceSubClass: u8,
    pub bDeviceProtocol: u8,
    pub bMaxPacketSize0: u8,
    pub idVendor: u16,
    pub idProduct: u16,
    pub bcdDevice: u16,
    pub iManufacturer: u8,
    pub iProduct: u8,
    pub iSerialNumber: u8,
    pub bNumConfigurations: u8,
}

impl ByteCode for UsbDeviceDescriptor {}

/// USB config descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UsbConfigDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub wTotalLength: u16,
    pub bNumInterfaces: u8,
    pub bConfigurationValue: u8,
    pub iConfiguration: u8,
    pub bmAttributes: u8,
    pub bMaxPower: u8,
}

impl ByteCode for UsbConfigDescriptor {}

/// USB interface descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UsbInterfaceDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bInterfaceNumber: u8,
    pub bAlternateSetting: u8,
    pub bNumEndpoints: u8,
    pub bInterfaceClass: u8,
    pub bInterfaceSubClass: u8,
    pub bInterfaceProtocol: u8,
    pub iInterface: u8,
}

impl ByteCode for UsbInterfaceDescriptor {}

/// USB endpoint descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UsbEndpointDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bEndpointAddress: u8,
    pub bmAttributes: u8,
    pub wMaxPacketSize: u16,
    pub bInterval: u8,
}

impl ByteCode for UsbEndpointDescriptor {}

/// USB qualifier descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct UsbQualifierDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub bcdUSB: u16,
    pub bDeviceClass: u8,
    pub bDeviceSubClass: u8,
    pub bDeviceProtocol: u8,
    pub bMaxPacketSize0: u8,
    pub bNumConfigurations: u8,
    pub bRESERVED: u8,
}

impl ByteCode for UsbQualifierDescriptor {}

/// USB string descriptor for transfer
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
struct UsbStringDescriptor {
    pub bLength: u8,
    pub bDescriptorType: u8,
    pub wData: [u16; 1],
}

impl ByteCode for UsbStringDescriptor {}

/// USB descriptor ops including get/set descriptor.
pub trait UsbDescriptorOps {
    fn get_descriptor(&self, value: u32) -> Result<Vec<u8>>;

    fn get_device_descriptor(&self) -> Result<Vec<u8>>;

    fn get_config_descriptor(&self, conf: &UsbDescConfig) -> Result<Vec<u8>>;

    fn get_interface_descriptor(&self, iface: &UsbDescIface) -> Result<Vec<u8>>;

    fn get_endpoint_descriptor(&self, ep: &UsbDescEndpoint) -> Result<Vec<u8>>;

    fn get_string_descriptor(&self, index: u32) -> Result<Vec<u8>>;

    fn set_config_descriptor(&mut self, v: u8) -> Result<()>;

    fn set_interface_descriptor(&mut self, index: u32, v: u32) -> Result<()>;

    fn find_interface(&self, nif: u32, alt: u32) -> Option<Arc<UsbDescIface>>;

    fn init_endpoint(&mut self) -> Result<()>;

    fn set_default_descriptor(&mut self) -> Result<()>;

    fn init_descriptor(&mut self) -> Result<()>;
}

impl UsbDescriptorOps for UsbDevice {
    fn get_descriptor(&self, value: u32) -> Result<Vec<u8>> {
        let desc_type = value >> 8;
        let index = value & 0xff;

        let device_desc = if let Some(desc) = self.device_desc.as_ref() {
            desc
        } else {
            bail!("Device descriptor not found");
        };

        let conf = &device_desc.as_ref().confs;
        let vec = match desc_type as u8 {
            USB_DT_DEVICE => self.get_device_descriptor()?,
            USB_DT_CONFIGURATION => self.get_config_descriptor(conf[index as usize].as_ref())?,
            USB_DT_STRING => self.get_string_descriptor(index)?,
            _ => {
                bail!("Unknown descriptor type {}", desc_type);
            }
        };
        Ok(vec)
    }

    fn get_device_descriptor(&self) -> Result<Vec<u8>> {
        if let Some(desc) = self.device_desc.as_ref() {
            Ok(desc.device_desc.as_bytes().to_vec())
        } else {
            bail!("Device descriptor not found");
        }
    }

    fn get_config_descriptor(&self, conf: &UsbDescConfig) -> Result<Vec<u8>> {
        let mut config_desc = conf.config_desc;
        let mut total = config_desc.bLength as u16;
        let mut ifs = Vec::new();
        for i in 0..conf.ifs.len() {
            let mut iface = self.get_interface_descriptor(conf.ifs[i].as_ref())?;
            total += iface.len() as u16;
            ifs.append(&mut iface);
        }
        config_desc.wTotalLength = total;
        let mut buf = config_desc.as_bytes().to_vec();
        buf.append(&mut ifs);
        Ok(buf)
    }

    fn get_interface_descriptor(&self, iface: &UsbDescIface) -> Result<Vec<u8>> {
        let desc = iface.interface_desc;
        let mut buf = desc.as_bytes().to_vec();
        for i in 0..iface.other_desc.len() {
            let desc = iface.other_desc[i].as_ref();
            for x in &desc.data {
                buf.push(*x);
            }
        }
        for i in 0..desc.bNumEndpoints as usize {
            let mut ep = self.get_endpoint_descriptor(iface.eps[i].as_ref())?;
            buf.append(&mut ep);
        }
        Ok(buf)
    }

    fn get_endpoint_descriptor(&self, ep: &UsbDescEndpoint) -> Result<Vec<u8>> {
        let desc = ep.endpoint_desc;
        Ok(desc.as_bytes().to_vec())
    }

    fn get_string_descriptor(&self, index: u32) -> Result<Vec<u8>> {
        if index == 0 {
            // Language ID
            let str: [u8; 4] = [4, 3, 9, 4];
            return Ok(str.to_vec());
        }
        let mut found_str = String::new();
        for str in &self.strings {
            if str.index == index {
                found_str = str.str.clone();
                break;
            }
        }
        if found_str.is_empty() {
            found_str = if let Some(desc) = self.usb_desc.as_ref() {
                desc.strings[index as usize].clone()
            } else {
                bail!("No usb desc found.");
            }
        }
        let len = found_str.len() as u8 * 2 + 2;
        let mut vec = vec![0_u8; len as usize];
        vec[0] = len;
        vec[1] = USB_DT_STRING;

        let mut pos = 2;
        for i in 0..found_str.len() {
            vec[pos] = found_str.as_bytes()[i];
            vec[pos + 1] = 0;
            pos += 2;
        }
        Ok(vec)
    }

    fn set_config_descriptor(&mut self, v: u8) -> Result<()> {
        if v == 0 {
            self.configuration = 0;
            self.ninterfaces = 0;
            self.config = None;
        } else {
            let desc = if let Some(desc) = &self.device_desc {
                desc
            } else {
                bail!("Device Desc is None.");
            };
            let num = desc.device_desc.bNumConfigurations;
            let desc = desc.as_ref();
            for i in 0..num as usize {
                if desc.confs[i].config_desc.bConfigurationValue == v {
                    self.configuration = v as u32;
                    self.ninterfaces = desc.confs[i].config_desc.bNumInterfaces as u32;
                    self.config = Some(desc.confs[i].clone());
                }
            }
        }
        for i in 0..self.ninterfaces {
            self.set_interface_descriptor(i, 0)?;
        }
        for i in self.altsetting.iter_mut() {
            *i = 0;
        }
        Ok(())
    }

    fn set_interface_descriptor(&mut self, index: u32, v: u32) -> Result<()> {
        let iface = if let Some(face) = self.find_interface(index, v) {
            face
        } else {
            bail!("Interface not found.");
        };
        self.altsetting[index as usize] = v;
        self.ifaces[index as usize] = Some(iface);
        self.init_endpoint()?;
        Ok(())
    }

    fn find_interface(&self, nif: u32, alt: u32) -> Option<Arc<UsbDescIface>> {
        self.config.as_ref()?;
        let conf = if let Some(conf) = self.config.as_ref() {
            conf
        } else {
            error!("No config descriptor found");
            return None;
        };
        for group in conf.if_groups.iter() {
            for iface in group.ifs.iter() {
                if iface.interface_desc.bInterfaceNumber == nif as u8
                    && iface.interface_desc.bAlternateSetting == alt as u8
                {
                    return Some(iface.clone());
                }
            }
        }
        for i in 0..conf.ifs.len() {
            let iface = conf.ifs[i].clone();
            if iface.interface_desc.bInterfaceNumber == nif as u8
                && iface.interface_desc.bAlternateSetting == alt as u8
            {
                return Some(iface);
            }
        }
        None
    }

    fn init_endpoint(&mut self) -> Result<()> {
        self.init_usb_endpoint();
        for i in 0..self.ninterfaces {
            let iface = self.ifaces[i as usize].as_ref();
            if iface.is_none() {
                continue;
            }
            let iface = if let Some(iface) = iface {
                iface
            } else {
                bail!("No interface descriptor found.");
            };
            for e in 0..iface.interface_desc.bNumEndpoints {
                let pid = if iface.eps[e as usize].endpoint_desc.bEndpointAddress
                    & USB_DIRECTION_DEVICE_TO_HOST
                    == USB_DIRECTION_DEVICE_TO_HOST
                {
                    USB_TOKEN_IN
                } else {
                    USB_TOKEN_OUT
                };

                let ep = iface.eps[e as usize].endpoint_desc.bEndpointAddress & 0x0f;
                let usb_ep = self.get_endpoint(pid as u32, ep as u32);
                let mut locked_usb_ep = usb_ep.lock().unwrap();
                let usb_type = iface.eps[e as usize].endpoint_desc.bmAttributes & 0x03;
                locked_usb_ep.usb_type = usb_type;
                locked_usb_ep.ifnum = iface.interface_desc.bInterfaceNumber;
                let raw = iface.eps[e as usize].endpoint_desc.wMaxPacketSize;
                let size = raw & 0x7ff;
                let v = (size >> 11) & 3;
                let microframes = if v == 1 {
                    2
                } else if v == 2 {
                    3
                } else {
                    1
                };
                locked_usb_ep.max_packet_size = size as u32 * microframes;
            }
        }
        Ok(())
    }

    fn set_default_descriptor(&mut self) -> Result<()> {
        if let Some(desc) = &self.usb_desc {
            match self.speed {
                USB_SPEED_LOW | USB_SPEED_FULL => {
                    self.device_desc = desc.full_dev.clone();
                }
                USB_SPEED_HIGH => {
                    self.device_desc = desc.high_dev.clone();
                }
                USB_SPEED_MASK_SUPER => {
                    self.device_desc = desc.super_dev.clone();
                }
                _ => {
                    bail!("Unknown device speed.");
                }
            }
        }
        self.set_config_descriptor(0)?;
        Ok(())
    }

    fn init_descriptor(&mut self) -> Result<()> {
        let desc = if let Some(desc) = &self.usb_desc {
            desc.clone()
        } else {
            bail!("Usb descriptor is None");
        };

        self.speed = USB_SPEED_FULL;
        self.speed_mask = 0;

        if desc.full_dev.is_some() {
            self.speed_mask |= USB_SPEED_MASK_FULL;
        }
        if desc.high_dev.is_some() {
            self.speed_mask |= USB_SPEED_MASK_HIGH;
        }
        if desc.super_dev.is_some() {
            self.speed_mask |= USB_SPEED_MASK_SUPER;
        }
        self.set_default_descriptor()?;
        Ok(())
    }
}
