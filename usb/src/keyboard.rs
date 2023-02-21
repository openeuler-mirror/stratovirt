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

use anyhow::Result;
use log::{debug, error, info};
use once_cell::sync::Lazy;

use crate::config::*;
use crate::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface, UsbDescOther,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use crate::hid::{Hid, HidType, QUEUE_LENGTH, QUEUE_MASK};
use crate::usb::{
    notify_controller, UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket,
    UsbPacketStatus,
};
use crate::xhci::xhci_controller::XhciDevice;
use vnc::input::{register_keyboard, KeyboardOpts};

/// Keyboard device descriptor
static DESC_DEVICE_KEYBOARD: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: 0x0627,
            idProduct: 0x0001,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER_INDEX,
            iProduct: STR_PRODUCT_KEYBOARD_INDEX,
            iSerialNumber: STR_SERIAL_KEYBOARD_INDEX,
            bcdUSB: 0x0100,
            bDeviceClass: 0,
            bDeviceSubClass: 0,
            bDeviceProtocol: 0,
            bMaxPacketSize0: 8,
            bNumConfigurations: 1,
        },
        configs: vec![Arc::new(UsbDescConfig {
            config_desc: UsbConfigDescriptor {
                bLength: USB_DT_CONFIG_SIZE,
                bDescriptorType: USB_DT_CONFIGURATION,
                wTotalLength: 0,
                bNumInterfaces: 1,
                bConfigurationValue: 1,
                iConfiguration: STR_CONFIG_KEYBOARD_INDEX,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_REMOTE_WAKEUP,
                bMaxPower: 50,
            },
            interfaces: vec![DESC_IFACE_KEYBOARD.clone()],
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
            /// HID descriptor
            data: vec![0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0],
        })],
        endpoints: vec![Arc::new(UsbDescEndpoint {
            endpoint_desc: UsbEndpointDescriptor {
                bLength: USB_DT_ENDPOINT_SIZE,
                bDescriptorType: USB_DT_ENDPOINT,
                bEndpointAddress: USB_DIRECTION_DEVICE_TO_HOST | 0x1,
                bmAttributes: USB_ENDPOINT_ATTR_INT,
                wMaxPacketSize: 8,
                bInterval: 0xa,
            },
            extra: None,
        })],
    })
});

/// String descriptor index
const STR_MANUFACTURER_INDEX: u8 = 1;
const STR_PRODUCT_KEYBOARD_INDEX: u8 = 2;
const STR_CONFIG_KEYBOARD_INDEX: u8 = 3;
const STR_SERIAL_KEYBOARD_INDEX: u8 = 4;

// Up flag.
const SCANCODE_UP: u16 = 0x80;
// Grey keys.
const SCANCODE_GREY: u16 = 0x80;
// Used to expand Grey keys.
const SCANCODE_EMUL0: u16 = 0xe0;

/// String descriptor
const DESC_STRINGS: [&str; 5] = [
    "",
    "StratoVirt",
    "StratoVirt USB Keyboard",
    "HID Keyboard",
    "1",
];

/// USB keyboard device.
pub struct UsbKeyboard {
    id: String,
    usb_device: UsbDevice,
    hid: Hid,
    /// USB controller used to notify controller to transfer data.
    ctrl: Option<Weak<Mutex<XhciDevice>>>,
}

pub struct UsbKeyboardAdapter {
    usb_kbd: Arc<Mutex<UsbKeyboard>>,
}

impl KeyboardOpts for UsbKeyboardAdapter {
    fn do_key_event(&mut self, keycode: u16, down: bool) -> Result<()> {
        let mut scan_codes = Vec::new();
        let mut keycode = keycode;
        if keycode & SCANCODE_GREY != 0 {
            scan_codes.push(SCANCODE_EMUL0 as u32);
            keycode &= !SCANCODE_GREY;
        }

        if !down {
            keycode |= SCANCODE_UP;
        }
        scan_codes.push(keycode as u32);

        let mut locked_kbd = self.usb_kbd.lock().unwrap();
        if scan_codes.len() as u32 + locked_kbd.hid.num > QUEUE_LENGTH {
            debug!("Keyboard queue is full!");
            // Return ok to ignore the request.
            return Ok(());
        }
        for code in scan_codes {
            let index = ((locked_kbd.hid.head + locked_kbd.hid.num) & QUEUE_MASK) as usize;
            locked_kbd.hid.num += 1;
            locked_kbd.hid.keyboard.keycodes[index] = code;
        }
        drop(locked_kbd);
        let clone_kbd = self.usb_kbd.clone();
        notify_controller(&(clone_kbd as Arc<Mutex<dyn UsbDeviceOps>>))
    }
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
        self.usb_device.reset_usb_endpoint();
        self.usb_device.speed = USB_SPEED_FULL;
        let s = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        self.usb_device
            .init_descriptor(DESC_DEVICE_KEYBOARD.clone(), s)?;
        let kbd = Arc::new(Mutex::new(self));
        let kbd_adapter = Arc::new(Mutex::new(UsbKeyboardAdapter {
            usb_kbd: kbd.clone(),
        }));
        register_keyboard("UsbKeyboard", kbd_adapter);

        Ok(kbd)
    }
}

impl UsbDeviceOps for UsbKeyboard {
    fn reset(&mut self) {
        info!("Keyboard device reset");
        self.usb_device.remote_wakeup = 0;
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

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.usb_device.get_endpoint(true, 1)
    }
}
