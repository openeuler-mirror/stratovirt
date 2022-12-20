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

use std::sync::{Arc, Mutex, Weak};

use log::{debug, error, info};
use once_cell::sync::Lazy;

use crate::config::*;
use crate::descriptor::{
    UsbConfigDescriptor, UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor,
    UsbInterfaceDescriptor,
};
use crate::hid::{
    Hid, HidType, DESC_STRINGS, QUEUE_LENGTH, QUEUE_MASK, STR_CONFIG_KEYBOARD, STR_MANUFACTURER,
    STR_PRODUCT_KEYBOARD, STR_SERIAL_KEYBOARD,
};
use crate::usb::{
    notify_controller, usb_endpoint_init, UsbDesc, UsbDescConfig, UsbDescDevice, UsbDescEndpoint,
    UsbDescIface, UsbDescOther, UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket,
    UsbPacketStatus,
};
use crate::xhci::xhci_controller::XhciDevice;
use anyhow::Result;

/// USB Keyboard Descriptor
static DESC_KEYBOARD: Lazy<Arc<UsbDesc>> = Lazy::new(|| {
    let s = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
    Arc::new(UsbDesc {
        full_dev: Some(DESC_DEVICE_KEYBOARD.clone()),
        high_dev: None,
        super_dev: None,
        strings: s,
    })
});
/// Keyboard device descriptor
static DESC_DEVICE_KEYBOARD: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: 0x0627,
            idProduct: 0x0001,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER,
            iProduct: STR_PRODUCT_KEYBOARD,
            iSerialNumber: STR_SERIAL_KEYBOARD,
            bcdUSB: 0x0100,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 8,
            bNumConfigurations: 1,
        },
        confs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: STR_CONFIG_KEYBOARD,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_REMOTE_WAKEUP,
                bMaxPower: 50,
            },
            if_groups: Vec::new(),
            ifs: vec![DESC_IFACE_KEYBOARD.clone()],
        })],
    })
});
/// Keyboard interface descriptor
static DESC_IFACE_KEYBOARD: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_HID,
            bInterfaceSubClass: 1,
            bInterfaceProtocol: 1,
            iInterface: 0,
        },
        other_desc: vec![Arc::new(UsbDescOther {
            length: 0,
            /// HID descriptor
            data: vec![0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0],
        })],
        eps: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST as u8 | 0x1,
                bmAttributes: USB_ENDPOINT_ATTR_INT,
                wMaxPacketSize: 8,
                bInterval: 0xa,
            },
            extra: None,
        })],
    })
});

/// USB keyboard device.
pub struct UsbKeyboard {
    id: String,
    usb_device: UsbDevice,
    hid: Hid,
    /// USB controller used to notify controller to transfer data.
    ctrl: Option<Weak<Mutex<XhciDevice>>>,
}

impl UsbKeyboard {
    pub fn new(id: String) -> Self {
        Self {
            id,
            usb_device: UsbDevice::new(),
            hid: Hid::new(HidType::Keyboard),
            ctrl: None,
        }
    }

    pub fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        self.usb_device.product_desc = String::from("StratoVirt USB keyboard");
        self.usb_device.strings = Vec::new();
        let kbd = Arc::new(Mutex::new(self));
        let cloned_kbd = kbd.clone();
        usb_endpoint_init(&(kbd as Arc<Mutex<dyn UsbDeviceOps>>));
        let mut locked_kbd = cloned_kbd.lock().unwrap();
        locked_kbd.usb_device.usb_desc = Some(DESC_KEYBOARD.clone());
        locked_kbd.usb_device.init_descriptor()?;
        drop(locked_kbd);
        Ok(cloned_kbd)
    }
}

// Used for VNC to send keyboard event.
pub fn keyboard_event(kbd: &Arc<Mutex<UsbKeyboard>>, scan_codes: &[u32]) -> Result<()> {
    let mut locked_kbd = kbd.lock().unwrap();
    if scan_codes.len() as u32 + locked_kbd.hid.num > QUEUE_LENGTH {
        debug!("Keyboard queue is full!");
        // Return ok to ignore the request.
        return Ok(());
    }
    for code in scan_codes {
        let index = ((locked_kbd.hid.head + locked_kbd.hid.num) & QUEUE_MASK) as usize;
        locked_kbd.hid.num += 1;
        locked_kbd.hid.keyboard.keycodes[index] = *code;
    }
    drop(locked_kbd);
    let clone_kbd = kbd.clone();
    notify_controller(&(clone_kbd as Arc<Mutex<dyn UsbDeviceOps>>))
}

impl UsbDeviceOps for UsbKeyboard {
    fn reset(&mut self) {
        info!("Keyboard device reset");
        self.usb_device.remote_wakeup &= !USB_DEVICE_REMOTE_WAKEUP;
        self.usb_device.addr = 0;
        self.hid.reset();
    }

    fn handle_control(&mut self, packet: &mut UsbPacket, device_req: &UsbDeviceRequest) {
        debug!("handle_control request {:?}", device_req);
        match self
            .usb_device
            .handle_control_for_descriptor(packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!("Keyboard control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                error!("Keyboard descriptor error {}", e);
                packet.status = UsbPacketStatus::Stall;
                return;
            }
        }
        self.hid
            .handle_control_packet(packet, device_req, &mut self.usb_device.data_buf);
    }

    fn handle_data(&mut self, p: &mut UsbPacket) {
        self.hid.handle_data_packet(p);
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

    fn set_controller(&mut self, ctrl: Weak<Mutex<XhciDevice>>) {
        self.ctrl = Some(ctrl);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.ctrl.clone()
    }

    fn get_wakeup_endpoint(&self) -> Option<Weak<Mutex<UsbEndpoint>>> {
        let ep = self.usb_device.get_endpoint(true, 1);
        Some(Arc::downgrade(&ep))
    }
}
