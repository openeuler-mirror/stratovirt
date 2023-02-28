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
use vnc::input::{register_pointer, PointerOpts};

const INPUT_BUTTON_WHEEL_UP: u32 = 0x08;
const INPUT_BUTTON_WHEEL_DOWN: u32 = 0x10;
const INPUT_BUTTON_MASK: u32 = 0x7;
const INPUT_COORDINATES_MAX: u32 = 0x7fff;

/// Tablet device descriptor
static DESC_DEVICE_TABLET: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: 0x0627,
            idProduct: 0x0001,
            bcdDevice: 0,
            iManufacturer: STR_MANUFACTURER_INDEX,
            iProduct: STR_PRODUCT_TABLET_INDEX,
            iSerialNumber: STR_SERIAL_TABLET_INDEX,
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
                iConfiguration: STR_CONFIG_TABLET_INDEX,
                bmAttributes: USB_CONFIGURATION_ATTR_ONE | USB_CONFIGURATION_ATTR_REMOTE_WAKEUP,
                bMaxPower: 50,
            },
            interfaces: vec![DESC_IFACE_TABLET.clone()],
        })],
    })
});
/// Tablet interface descriptor
static DESC_IFACE_TABLET: Lazy<Arc<UsbDescIface>> = Lazy::new(|| {
    Arc::new(UsbDescIface {
        interface_desc: UsbInterfaceDescriptor {
            bLength: USB_DT_INTERFACE_SIZE,
            bDescriptorType: USB_DT_INTERFACE,
            bInterfaceNumber: 0,
            bAlternateSetting: 0,
            bNumEndpoints: 1,
            bInterfaceClass: USB_CLASS_HID,
            bInterfaceSubClass: 0,
            bInterfaceProtocol: 0,
            iInterface: 0,
        },
        other_desc: vec![Arc::new(UsbDescOther {
            /// HID descriptor
            data: vec![0x09, 0x21, 0x01, 0x0, 0x0, 0x01, 0x22, 74, 0x0],
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
const STR_PRODUCT_TABLET_INDEX: u8 = 2;
const STR_CONFIG_TABLET_INDEX: u8 = 3;
const STR_SERIAL_TABLET_INDEX: u8 = 4;

/// String descriptor
const DESC_STRINGS: [&str; 5] = ["", "StratoVirt", "StratoVirt USB Tablet", "HID Tablet", "2"];
/// USB tablet device.
pub struct UsbTablet {
    id: String,
    usb_device: UsbDevice,
    hid: Hid,
    /// USB controller used to notify controller to transfer data.
    ctrl: Option<Weak<Mutex<XhciDevice>>>,
}

impl UsbTablet {
    pub fn new(id: String) -> Self {
        Self {
            id,
            usb_device: UsbDevice::new(),
            hid: Hid::new(HidType::Tablet),
            ctrl: None,
        }
    }

    pub fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        self.usb_device.reset_usb_endpoint();
        self.usb_device.speed = USB_SPEED_FULL;
        let s = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        self.usb_device
            .init_descriptor(DESC_DEVICE_TABLET.clone(), s)?;
        let tablet = Arc::new(Mutex::new(self));
        let tablet_adapter = Arc::new(Mutex::new(UsbTabletAdapter {
            tablet: tablet.clone(),
        }));
        register_pointer("UsbTablet", tablet_adapter);
        Ok(tablet)
    }
}

pub struct UsbTabletAdapter {
    tablet: Arc<Mutex<UsbTablet>>,
}

impl PointerOpts for UsbTabletAdapter {
    fn do_point_event(&mut self, button: u32, x: u32, y: u32) -> Result<()> {
        let mut locked_tablet = self.tablet.lock().unwrap();
        if locked_tablet.hid.num >= QUEUE_LENGTH {
            debug!("Pointer queue is full!");
            // Return ok to ignore the request.
            return Ok(());
        }
        let index = ((locked_tablet.hid.head + locked_tablet.hid.num) & QUEUE_MASK) as usize;
        let mut evt = &mut locked_tablet.hid.pointer.queue[index];
        if button == INPUT_BUTTON_WHEEL_UP {
            evt.pos_z = 1;
        } else if button == INPUT_BUTTON_WHEEL_DOWN {
            evt.pos_z = -1;
        } else {
            evt.pos_z = 0;
        }
        evt.button_state = button & INPUT_BUTTON_MASK;
        evt.pos_x = min(x, INPUT_COORDINATES_MAX);
        evt.pos_y = min(y, INPUT_COORDINATES_MAX);
        locked_tablet.hid.num += 1;
        drop(locked_tablet);
        let clone_tablet = self.tablet.clone();
        notify_controller(&(clone_tablet as Arc<Mutex<dyn UsbDeviceOps>>))
    }
}

impl UsbDeviceOps for UsbTablet {
    fn reset(&mut self) {
        info!("Tablet device reset");
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
                    debug!("Tablet control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                error!("Tablet descriptor error {}", e);
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
