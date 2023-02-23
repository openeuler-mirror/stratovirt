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
use util::byte_code::ByteCode;

use crate::config::*;
use crate::usb::UsbDevice;

const USB_MAX_INTERFACES: u32 = 16;
const USB_DESCRIPTOR_TYPE_SHIFT: u32 = 8;
const USB_DESCRIPTOR_INDEX_MASK: u32 = 0xff;

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

/// USB device descriptor.
pub struct UsbDescDevice {
    pub device_desc: UsbDeviceDescriptor,
    pub configs: Vec<Arc<UsbDescConfig>>,
}

/// USB config descriptor.
pub struct UsbDescConfig {
    pub config_desc: UsbConfigDescriptor,
    pub interfaces: Vec<Arc<UsbDescIface>>,
}

/// USB interface descriptor.
pub struct UsbDescIface {
    pub interface_desc: UsbInterfaceDescriptor,
    pub other_desc: Vec<Arc<UsbDescOther>>,
    pub endpoints: Vec<Arc<UsbDescEndpoint>>,
}

/// USB other descriptor.
pub struct UsbDescOther {
    pub data: Vec<u8>,
}

/// USB endpoint descriptor.
pub struct UsbDescEndpoint {
    pub endpoint_desc: UsbEndpointDescriptor,
    pub extra: Option<Arc<u8>>,
}

/// USB Descriptor.
pub struct UsbDescriptor {
    pub device_desc: Option<Arc<UsbDescDevice>>,
    pub configuration_selected: Option<Arc<UsbDescConfig>>,
    pub interfaces: Vec<Option<Arc<UsbDescIface>>>,
    pub altsetting: Vec<u32>,
    pub interface_number: u32,
    pub strings: Vec<String>,
}

impl UsbDescriptor {
    pub fn new() -> Self {
        Self {
            device_desc: None,
            configuration_selected: None,
            interfaces: vec![None; USB_MAX_INTERFACES as usize],
            altsetting: vec![0; USB_MAX_INTERFACES as usize],
            interface_number: 0,
            strings: Vec::new(),
        }
    }

    fn get_device_descriptor(&self) -> Result<Vec<u8>> {
        if let Some(desc) = self.device_desc.as_ref() {
            Ok(desc.device_desc.as_bytes().to_vec())
        } else {
            bail!("Device descriptor not found");
        }
    }

    fn get_config_descriptor(&self, index: u32) -> Result<Vec<u8>> {
        let confs = if let Some(desc) = self.device_desc.as_ref() {
            &desc.configs
        } else {
            bail!("Device descriptor not found");
        };
        let conf = if let Some(conf) = confs.get(index as usize) {
            conf
        } else {
            bail!("Config descriptor index {} is invalid", index);
        };
        let mut config_desc = conf.config_desc;
        let mut total = config_desc.bLength as u16;
        let mut ifs = Vec::new();
        for i in 0..conf.interfaces.len() {
            let mut iface = self.get_interface_descriptor(conf.interfaces[i].as_ref())?;
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
            let mut ep = self.get_endpoint_descriptor(iface.endpoints[i].as_ref())?;
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
        let found_str = if let Some(str) = self.strings.get(index as usize) {
            str
        } else {
            bail!("String descriptor index {} is invalid", index);
        };
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

    fn find_interface(&self, nif: u32, alt: u32) -> Option<Arc<UsbDescIface>> {
        let conf = self.configuration_selected.as_ref()?;
        for i in 0..conf.interfaces.len() {
            let iface = conf.interfaces[i].as_ref();
            if iface.interface_desc.bInterfaceNumber == nif as u8
                && iface.interface_desc.bAlternateSetting == alt as u8
            {
                return Some(conf.interfaces[i].clone());
            }
        }
        None
    }
}

impl Default for UsbDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// USB descriptor ops including get/set descriptor.
pub trait UsbDescriptorOps {
    /// Get device/configuration/string descriptor.
    fn get_descriptor(&self, value: u32) -> Result<Vec<u8>>;

    /// Set configuration descriptor with the Configuration Value.
    fn set_config_descriptor(&mut self, v: u8) -> Result<()>;

    /// Set interface descriptor with the Interface and Alernate Setting.
    fn set_interface_descriptor(&mut self, index: u32, v: u32) -> Result<()>;

    /// Init all endpoint descriptors and reset the USB endpoint.
    fn init_endpoint(&mut self) -> Result<()>;

    /// Init descriptor with the device descriptor and string descriptors.
    fn init_descriptor(&mut self, desc: Arc<UsbDescDevice>, str: Vec<String>) -> Result<()>;
}

impl UsbDescriptorOps for UsbDevice {
    fn get_descriptor(&self, value: u32) -> Result<Vec<u8>> {
        let desc_type = value >> USB_DESCRIPTOR_TYPE_SHIFT;
        let index = value & USB_DESCRIPTOR_INDEX_MASK;
        let vec = match desc_type as u8 {
            USB_DT_DEVICE => self.descriptor.get_device_descriptor()?,
            USB_DT_CONFIGURATION => self.descriptor.get_config_descriptor(index)?,
            USB_DT_STRING => self.descriptor.get_string_descriptor(index)?,
            _ => {
                bail!("Unknown descriptor type {}", desc_type);
            }
        };
        Ok(vec)
    }

    fn set_config_descriptor(&mut self, v: u8) -> Result<()> {
        if v == 0 {
            self.descriptor.interface_number = 0;
            self.descriptor.configuration_selected = None;
        } else {
            let desc = if let Some(desc) = self.descriptor.device_desc.as_ref() {
                desc
            } else {
                bail!("Device Descriptor not found");
            };
            let num = desc.device_desc.bNumConfigurations;
            let mut found = false;
            for i in 0..num as usize {
                if desc.configs[i].config_desc.bConfigurationValue == v {
                    self.descriptor.interface_number =
                        desc.configs[i].config_desc.bNumInterfaces as u32;
                    self.descriptor.configuration_selected = Some(desc.configs[i].clone());
                    found = true;
                }
            }
            if !found {
                bail!("Invalid bConfigurationValue {}", v);
            }
        }
        for i in 0..self.descriptor.interface_number {
            self.set_interface_descriptor(i, 0)?;
        }
        for i in self.descriptor.altsetting.iter_mut() {
            *i = 0;
        }
        for it in self.descriptor.interfaces.iter_mut() {
            *it = None;
        }
        Ok(())
    }

    fn set_interface_descriptor(&mut self, index: u32, v: u32) -> Result<()> {
        let iface = if let Some(face) = self.descriptor.find_interface(index, v) {
            face
        } else {
            bail!(
                "Interface descriptor not found. index {} value {}",
                index,
                v
            );
        };
        self.descriptor.altsetting[index as usize] = v;
        self.descriptor.interfaces[index as usize] = Some(iface);
        self.init_endpoint()?;
        Ok(())
    }

    fn init_endpoint(&mut self) -> Result<()> {
        self.reset_usb_endpoint();
        for i in 0..self.descriptor.interface_number {
            let iface = if let Some(iface) = self.descriptor.interfaces[i as usize].as_ref() {
                iface
            } else {
                continue;
            };
            let iface = iface.clone();
            for e in 0..iface.interface_desc.bNumEndpoints {
                let in_direction = iface.endpoints[e as usize].endpoint_desc.bEndpointAddress
                    & USB_DIRECTION_DEVICE_TO_HOST
                    == USB_DIRECTION_DEVICE_TO_HOST;
                let ep = iface.endpoints[e as usize].endpoint_desc.bEndpointAddress
                    & USB_ENDPOINT_ADDRESS_NUMBER_MASK;
                let mut usb_ep = self.get_mut_endpoint(in_direction, ep);
                usb_ep.ep_type = iface.endpoints[e as usize].endpoint_desc.bmAttributes
                    & USB_ENDPOINT_ATTR_TRANSFER_TYPE_MASK;
            }
        }
        Ok(())
    }

    fn init_descriptor(&mut self, device_desc: Arc<UsbDescDevice>, str: Vec<String>) -> Result<()> {
        self.descriptor.device_desc = Some(device_desc);
        self.descriptor.strings = str;
        self.set_config_descriptor(0)?;
        Ok(())
    }
}
