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

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{debug, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use super::descriptor::{
    UsbConfigDescriptor, UsbDescConfig, UsbDescDevice, UsbDescEndpoint, UsbDescIface, UsbDescOther,
    UsbDescriptorOps, UsbDeviceDescriptor, UsbEndpointDescriptor, UsbInterfaceDescriptor,
};
use super::hid::{Hid, HidDevState, HidType, QUEUE_LENGTH, QUEUE_MASK};
use super::xhci::xhci_controller::{endpoint_number_to_id, XhciDevice};
use super::{
    config::*, notify_controller, UsbDevState, UsbDevice, UsbDeviceBase, UsbDeviceRequest,
    UsbPacket, UsbPacketStatus, USB_DEVICE_BUFFER_DEFAULT_LEN,
};
use machine_manager::config::valid_id;
use migration::{DeviceStateDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use ui::input::{
    register_pointer, unregister_pointer, Axis, InputEvent, InputType, PointerOpts,
    INPUT_BUTTON_MASK, INPUT_BUTTON_WHEEL_DOWN, INPUT_BUTTON_WHEEL_LEFT, INPUT_BUTTON_WHEEL_RIGHT,
    INPUT_BUTTON_WHEEL_UP,
};
use util::gen_base_func;

const INPUT_COORDINATES_MAX: u32 = 0x7fff;

/// Tablet device descriptor
static DESC_DEVICE_TABLET: Lazy<Arc<UsbDescDevice>> = Lazy::new(|| {
    Arc::new(UsbDescDevice {
        device_desc: UsbDeviceDescriptor {
            bLength: USB_DT_DEVICE_SIZE,
            bDescriptorType: USB_DT_DEVICE,
            idVendor: 0x0627,
            idProduct: USB_PRODUCT_ID_TABLET,
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
#[command(no_binary_name(true))]
pub struct UsbTabletConfig {
    #[arg(long)]
    pub classtype: String,
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

#[derive(DescSerde, Deserialize, Serialize)]
#[desc_version(current_version = "0.1.0")]
struct UsbTabletDevState {
    usb_state: UsbDevState,
    hid_state: HidDevState,
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
        // Wakeup endpoint.
        let ep_id = endpoint_number_to_id(true, 1);
        notify_controller(&(clone_tablet as Arc<Mutex<dyn UsbDevice>>), ep_id)
    }
}

impl UsbDevice for UsbTablet {
    gen_base_func!(usb_device_base, usb_device_base_mut, UsbDeviceBase, base);

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

        MigrationManager::register_device_instance(
            UsbTabletDevState::descriptor(),
            tablet.clone(),
            &id,
        );

        Ok(tablet)
    }

    fn unrealize(&mut self) -> Result<()> {
        unregister_pointer(self.device_id());

        MigrationManager::unregister_device_instance(
            UsbTabletDevState::descriptor(),
            self.device_id(),
        );

        Ok(())
    }

    fn cancel_packet(&mut self, _packet: &Arc<Mutex<UsbPacket>>) {}

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
                warn!("Received incorrect USB Tablet descriptor message: {:?}", e);
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
}

impl StateTransfer for UsbTablet {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = UsbTabletDevState {
            usb_state: self.base.get_usb_state(),
            hid_state: self.hid.get_state()?,
        };

        Ok(serde_json::to_vec(&state)?)
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let usb_tablet_state: UsbTabletDevState =
            serde_json::from_slice(state).with_context(|| "Failed to get usb tablet state")?;

        self.base.set_usb_state(&usb_tablet_state.usb_state);
        self.hid.set_state(&usb_tablet_state.hid_state)?;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&UsbTabletDevState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for UsbTablet {}

#[cfg(test)]
mod tests {
    use super::*;
    use ui::input::{ButtonEvent, KeyEvent, MoveEvent};

    #[test]
    fn test_tablet_interface() {
        let interface_descriptor = &DESC_IFACE_TABLET.clone().interface_desc;
        // bInterfaceClass: 3(HID)
        assert_eq!(interface_descriptor.bInterfaceClass, 3);
        // bInterfaceSubClass: 0(No Subclass) 1(Boot Interface Subclass) 2-255(Reserved)
        assert_eq!(interface_descriptor.bInterfaceSubClass, 0);
        // bInterfaceProtocol: 0(None) 1(Keyboard) 2(Mouse) 3-255(Reserved)
        assert_eq!(interface_descriptor.bInterfaceProtocol, 0);
    }

    #[test]
    fn test_usb_device_method() {
        let mut tablet = UsbTablet::new(UsbTabletConfig {
            classtype: "usb-tablet".to_string(),
            id: "tablet".to_string(),
            bus: None,
            port: None,
        });

        let _ = &tablet.reset();
        let _ = &tablet.unrealize();
        let _ = &tablet.get_controller();
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_ADDRESS,
            value: 0,
            index: 0,
            length: 0,
        };
        let target_dev =
            Arc::downgrade(&Arc::new(Mutex::new(tablet))) as Weak<Mutex<dyn UsbDevice>>;
        let packet = Arc::new(Mutex::new(UsbPacket::new(
            1,
            u32::from(USB_TOKEN_OUT),
            0,
            0,
            Vec::new(),
            None,
            Some(target_dev),
        )));
        let mut tablet = UsbTablet::new(UsbTabletConfig {
            classtype: "usb-tablet".to_string(),
            id: "tablet".to_string(),
            bus: None,
            port: None,
        });
        let _ = &tablet.handle_control(&packet, &device_req);
        let _ = &tablet.handle_data(&packet);
        let _ = &tablet.cancel_packet(&packet);
        let _ = &tablet.realize();
    }

    #[test]
    fn test_tablet_event() {
        let mut usb_adapter = UsbTabletAdapter {
            tablet: Arc::new(Mutex::new(UsbTablet::new(UsbTabletConfig {
                classtype: "usb-tablet".to_string(),
                id: "tablet".to_string(),
                bus: None,
                port: None,
            }))),
        };

        // test button event
        let press_button_event = InputEvent {
            input_type: InputType::ButtonEvent,
            move_event: MoveEvent::default(),
            button_event: ButtonEvent {
                button: INPUT_BUTTON_WHEEL_UP,
                down: true,
            },
            key_event: KeyEvent::default(),
        };
        let _ = usb_adapter.update_point_state(press_button_event);

        let release_button_event = InputEvent {
            input_type: InputType::ButtonEvent,
            move_event: MoveEvent::default(),
            button_event: ButtonEvent {
                button: INPUT_BUTTON_WHEEL_UP,
                down: false,
            },
            key_event: KeyEvent::default(),
        };
        let _ = usb_adapter.update_point_state(release_button_event);

        // test move event
        let move_event = InputEvent {
            input_type: InputType::MoveEvent,
            move_event: MoveEvent::default(),
            button_event: ButtonEvent::default(),
            key_event: KeyEvent::default(),
        };
        let _ = usb_adapter.update_point_state(move_event);

        match usb_adapter.sync() {
            Ok(_) => true,
            Err(_) => false,
        };
    }
}
