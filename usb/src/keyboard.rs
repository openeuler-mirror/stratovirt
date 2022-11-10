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

use once_cell::sync::Lazy;

use crate::config::*;
use crate::descriptor::{
    UsbConfigDescriptor, UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor,
    UsbInterfaceDescriptor,
};
use crate::hid::{
    Hid, HidType, DESC_STRINGS, QUEUE_MASK, STR_CONFIG_KEYBOARD, STR_MANUFACTURER,
    STR_PRODUCT_KEYBOARD, STR_SERIAL_KEYBOARD,
};
use crate::usb::{
    notify_controller, usb_endpoint_init, UsbDesc, UsbDescConfig, UsbDescDevice, UsbDescEndpoint,
    UsbDescIface, UsbDescOther, UsbDevice, UsbDeviceOps, UsbDeviceRequest, UsbDeviceState,
    UsbEndpoint, UsbPacket,
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
    device: Arc<Mutex<UsbDevice>>,
    hid: Arc<Mutex<Hid>>,
    /// USB controller used to notify controller to transfer data.
    ctrl: Option<Weak<Mutex<XhciDevice>>>,
    endpoint: Option<Weak<Mutex<UsbEndpoint>>>,
}

impl UsbKeyboard {
    pub fn new(id: String) -> Self {
        Self {
            id,
            device: Arc::new(Mutex::new(UsbDevice::new())),
            hid: Arc::new(Mutex::new(Hid::new())),
            ctrl: None,
            endpoint: None,
        }
    }

    pub fn realize(self) -> Result<Arc<Mutex<Self>>> {
        let mut locked_usb = self.device.lock().unwrap();
        locked_usb.product_desc = String::from("StratoVirt USB keyboard");
        locked_usb.auto_attach = true;
        locked_usb.strings = Vec::new();
        drop(locked_usb);
        let kbd = Arc::new(Mutex::new(self));
        let cloned_kbd = kbd.clone();
        usb_endpoint_init(&(kbd as Arc<Mutex<dyn UsbDeviceOps>>));
        let mut locked_kbd = cloned_kbd.lock().unwrap();
        locked_kbd.init_hid()?;
        drop(locked_kbd);
        Ok(cloned_kbd)
    }

    fn init_hid(&mut self) -> Result<()> {
        let mut locked_usb = self.device.lock().unwrap();
        locked_usb.usb_desc = Some(DESC_KEYBOARD.clone());
        let mut locked_hid = self.hid.lock().unwrap();
        locked_hid.kind = HidType::Keyboard;
        drop(locked_hid);
        let ep = locked_usb.get_endpoint(USB_TOKEN_IN as u32, 1);
        self.endpoint = Some(Arc::downgrade(&ep));
        locked_usb.init_descriptor()?;
        Ok(())
    }
}

// Used for VNC to send keyboard event.
pub fn keyboard_event(kbd: &Arc<Mutex<UsbKeyboard>>, scan_codes: &[u32]) -> Result<()> {
    let locked_kbd = kbd.lock().unwrap();
    let mut locked_hid = locked_kbd.hid.lock().unwrap();
    for code in scan_codes {
        let index = ((locked_hid.head + locked_hid.num) & QUEUE_MASK) as usize;
        locked_hid.num += 1;
        locked_hid.keyboard.keycodes[index] = *code;
    }
    drop(locked_hid);
    drop(locked_kbd);
    let clone_kbd = kbd.clone();
    notify_controller(&(clone_kbd as Arc<Mutex<dyn UsbDeviceOps>>))
}

impl UsbDeviceOps for UsbKeyboard {
    fn reset(&mut self) {
        info!("Keyboard device reset");
        let mut locked_usb = self.device.lock().unwrap();
        locked_usb.remote_wakeup &= !USB_DEVICE_REMOTE_WAKEUP;
        locked_usb.addr = 0;
        locked_usb.state = UsbDeviceState::Default;
        let mut locked_hid = self.hid.lock().unwrap();
        locked_hid.reset();
    }

    fn handle_control(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) {
        debug!("handle_control request {:?}", device_req);
        let mut locked_dev = self.device.lock().unwrap();
        match locked_dev.handle_control_for_descriptor(packet, device_req, data) {
            Ok(handled) => {
                if handled {
                    debug!("Keyboard control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                error!("Keyboard descriptor error {}", e);
                return;
            }
        }
        let mut locked_hid = self.hid.lock().unwrap();
        locked_hid.handle_control_packet(packet, device_req, data);
    }

    fn handle_data(&mut self, p: &mut UsbPacket) {
        let mut locked_hid = self.hid.lock().unwrap();
        locked_hid.handle_data_packet(p);
    }

    fn device_id(&self) -> String {
        self.id.clone()
    }

    fn get_usb_device(&self) -> Arc<Mutex<UsbDevice>> {
        self.device.clone()
    }

    fn get_mut_usb_device(&mut self) -> Arc<Mutex<UsbDevice>> {
        self.device.clone()
    }

    fn set_controller(&mut self, ctrl: Weak<Mutex<XhciDevice>>) {
        self.ctrl = Some(ctrl);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.ctrl.clone()
    }

    fn get_endpoint(&self) -> Option<Weak<Mutex<UsbEndpoint>>> {
        self.endpoint.clone()
    }
}
