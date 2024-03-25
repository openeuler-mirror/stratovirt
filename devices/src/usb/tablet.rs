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
use clap::Parser;
use log::{debug, info, warn};
use once_cell::sync::Lazy;

use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface, UsbDescOther,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use super::hid::{Hid, HidType, QUEUE_LENGTH, QUEUE_MASK};
use super::xhci::xhci_controller::XhciDevice;
use super::{
    config::*, notify_controller, UsbDevice, UsbDeviceBase, UsbDeviceRequest, UsbEndpoint,
    UsbPacket, UsbPacketStatus, USB_DEVICE_BUFFER_DEFAULT_LEN,
};
use machine_manager::config::valid_id;
use ui::input::{
    register_pointer, unregister_pointer, Axis, InputEvent, InputType, PointerOpts,
    INPUT_BUTTON_WHEEL_DOWN, INPUT_BUTTON_WHEEL_LEFT, INPUT_BUTTON_WHEEL_RIGHT,
    INPUT_BUTTON_WHEEL_UP,
};

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
            iad_desc: vec![],
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
            // HID descriptor
            data: vec![0x09, 0x21, 0x01, 0x0, 0x0, 0x01, 0x22, 89, 0x0],
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
            extra: Vec::new(),
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

#[derive(Parser, Clone, Debug, Default)]
#[command(name = "usb_tablet")]
pub struct UsbTabletConfig {
    #[arg(long, value_parser = valid_id)]
    id: String,
    #[arg(long)]
    bus: Option<String>,
    #[arg(long)]
    port: Option<String>,
}

/// USB tablet device.
pub struct UsbTablet {
    base: UsbDeviceBase,
    hid: Hid,
    /// USB controller used to notify controller to transfer data.
    cntlr: Option<Weak<Mutex<XhciDevice>>>,
}

impl UsbTablet {
    pub fn new(config: UsbTabletConfig) -> Self {
        Self {
            base: UsbDeviceBase::new(config.id, USB_DEVICE_BUFFER_DEFAULT_LEN),
            hid: Hid::new(HidType::Tablet),
            cntlr: None,
        }
    }
}

pub struct UsbTabletAdapter {
    tablet: Arc<Mutex<UsbTablet>>,
}

impl PointerOpts for UsbTabletAdapter {
    fn update_point_state(&mut self, input_event: InputEvent) -> Result<()> {
        trace::usb_tablet_update_point_state(&input_event.input_type);

        let mut locked_tablet = self.tablet.lock().unwrap();
        if locked_tablet.hid.num >= QUEUE_LENGTH {
            trace::usb_tablet_queue_full();

            // Return ok to ignore the request.
            return Ok(());
        }
        let index = ((locked_tablet.hid.head + locked_tablet.hid.num) & QUEUE_MASK) as usize;
        let evt = &mut locked_tablet.hid.pointer.queue[index];

        match input_event.input_type {
            InputType::ButtonEvent => {
                let button_event = &input_event.button_event;
                if button_event.down {
                    if button_event.button & INPUT_BUTTON_WHEEL_LEFT != 0 {
                        evt.h_wheel = -1;
                    } else if button_event.button & INPUT_BUTTON_WHEEL_RIGHT != 0 {
                        evt.h_wheel = 1;
                    } else {
                        evt.h_wheel = 0;
                    }

                    if button_event.button & INPUT_BUTTON_WHEEL_UP != 0 {
                        evt.v_wheel = 1;
                    } else if button_event.button & INPUT_BUTTON_WHEEL_DOWN != 0 {
                        evt.v_wheel = -1;
                    } else {
                        evt.v_wheel = 0;
                    }

                    evt.button_state |= button_event.button & INPUT_BUTTON_MASK;
                } else {
                    evt.button_state &= !(button_event.button & INPUT_BUTTON_MASK);
                }
            }
            InputType::MoveEvent => {
                let move_event = &input_event.move_event;
                match move_event.axis {
                    Axis::X => evt.pos_x = min(move_event.data, INPUT_COORDINATES_MAX),
                    Axis::Y => evt.pos_y = min(move_event.data, INPUT_COORDINATES_MAX),
                }
            }
            _ => bail!(
                "Input type: {:?} is unsupported by usb tablet!",
                input_event.input_type
            ),
        };

        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        trace::usb_tablet_point_sync();
        let mut locked_tablet = self.tablet.lock().unwrap();

        // The last evt is used to save the latest button state,
        // so the max number of events can be cached at one time is QUEUE_LENGTH - 1.
        if locked_tablet.hid.num == QUEUE_LENGTH - 1 {
            trace::usb_tablet_queue_full();
            return Ok(());
        }
        let curr_index = ((locked_tablet.hid.head + locked_tablet.hid.num) & QUEUE_MASK) as usize;
        let next_index = (curr_index + 1) & QUEUE_MASK as usize;
        let curr_evt = locked_tablet.hid.pointer.queue[curr_index];
        let next_evt = &mut locked_tablet.hid.pointer.queue[next_index];

        // Update the status of the next event in advance.
        next_evt.v_wheel = 0;
        next_evt.h_wheel = 0;
        next_evt.button_state = curr_evt.button_state;
        next_evt.pos_x = curr_evt.pos_x;
        next_evt.pos_y = curr_evt.pos_y;

        locked_tablet.hid.num += 1;
        drop(locked_tablet);
        let clone_tablet = self.tablet.clone();
        notify_controller(&(clone_tablet as Arc<Mutex<dyn UsbDevice>>))
    }
}

impl UsbDevice for UsbTablet {
    fn usb_device_base(&self) -> &UsbDeviceBase {
        &self.base
    }

    fn usb_device_base_mut(&mut self) -> &mut UsbDeviceBase {
        &mut self.base
    }

    fn realize(mut self) -> Result<Arc<Mutex<dyn UsbDevice>>> {
        self.base.reset_usb_endpoint();
        self.base.speed = USB_SPEED_FULL;
        let mut s: Vec<String> = DESC_STRINGS.iter().map(|&s| s.to_string()).collect();
        let prefix = &s[STR_SERIAL_TABLET_INDEX as usize];
        s[STR_SERIAL_TABLET_INDEX as usize] = self.base.generate_serial_number(prefix);
        self.base.init_descriptor(DESC_DEVICE_TABLET.clone(), s)?;
        let id = self.device_id().to_string();
        let tablet = Arc::new(Mutex::new(self));
        let tablet_adapter = Arc::new(Mutex::new(UsbTabletAdapter {
            tablet: tablet.clone(),
        }));
        register_pointer(&id, tablet_adapter);
        Ok(tablet)
    }

    fn unrealize(&mut self) -> Result<()> {
        unregister_pointer(self.device_id());
        Ok(())
    }

    fn reset(&mut self) {
        info!("Tablet device reset");
        self.base.remote_wakeup = 0;
        self.base.addr = 0;
        self.hid.reset();
    }

    fn handle_control(&mut self, packet: &Arc<Mutex<UsbPacket>>, device_req: &UsbDeviceRequest) {
        let mut locked_packet = packet.lock().unwrap();
        match self
            .base
            .handle_control_for_descriptor(&mut locked_packet, device_req)
        {
            Ok(handled) => {
                if handled {
                    debug!("Tablet control handled by descriptor, return directly.");
                    return;
                }
            }
            Err(e) => {
                warn!("Tablet descriptor error {:?}", e);
                locked_packet.status = UsbPacketStatus::Stall;
                return;
            }
        }
        self.hid
            .handle_control_packet(&mut locked_packet, device_req, &mut self.base.data_buf);
    }

    fn handle_data(&mut self, p: &Arc<Mutex<UsbPacket>>) {
        let mut locked_p = p.lock().unwrap();
        self.hid.handle_data_packet(&mut locked_p);
    }

    fn set_controller(&mut self, cntlr: Weak<Mutex<XhciDevice>>) {
        self.cntlr = Some(cntlr);
    }

    fn get_controller(&self) -> Option<Weak<Mutex<XhciDevice>>> {
        self.cntlr.clone()
    }

    fn get_wakeup_endpoint(&self) -> &UsbEndpoint {
        self.base.get_endpoint(true, 1)
    }
}
