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

use std::fmt::{Display, Formatter, Result as FmtResult};

use log::{debug, error, warn};

use crate::config::*;
use crate::usb::{UsbDeviceRequest, UsbPacket, UsbPacketStatus};

/// HID keycode
const HID_KEYBOARD_LEFT_CONTROL: u8 = 0xe0;
#[allow(unused)]
const HID_KEYBOARD_LEFT_SHIFT: u8 = 0xe1;
#[allow(unused)]
const HID_KEYBOARD_LEFT_ALT: u8 = 0xe2;
#[allow(unused)]
const HID_KEYBOARD_LEFT_GUI: u8 = 0xe3;
#[allow(unused)]
const HID_KEYBOARD_RIGHT_CONTROL: u8 = 0xe4;
#[allow(unused)]
const HID_KEYBOARD_RIGHT_SHIFT: u8 = 0xe5;
#[allow(unused)]
const HID_KEYBOARD_RIGHT_ALT: u8 = 0xe6;
const HID_KEYBOARD_RIGHT_GUI: u8 = 0xe7;

/// See the spec section 7.2 Class-Specific Requests
pub const HID_GET_REPORT: u8 = 0x01;
pub const HID_GET_IDLE: u8 = 0x02;
pub const HID_GET_PROTOCOL: u8 = 0x03;
pub const HID_SET_REPORT: u8 = 0x09;
pub const HID_SET_IDLE: u8 = 0x0a;
pub const HID_SET_PROTOCOL: u8 = 0x0b;

/// See the spec section 7.2.5 Get Protocol Request
#[allow(unused)]
const HID_PROTOCTL_BOOT: u8 = 0;
const HID_PROTOCOL_REPORT: u8 = 1;
const KEYCODE_UP: u32 = 0x80;
pub const QUEUE_LENGTH: u32 = 16;
pub const QUEUE_MASK: u32 = QUEUE_LENGTH - 1;
const HID_USAGE_ERROR_ROLLOVER: u8 = 0x1;

/// QKeyCode to HID code table
const HID_CODE: [u8; 0x100] = [
    0x00, 0x29, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2d, 0x2e, 0x2a, 0x2b,
    0x14, 0x1a, 0x08, 0x15, 0x17, 0x1c, 0x18, 0x0c, 0x12, 0x13, 0x2f, 0x30, 0x28, 0xe0, 0x04, 0x16,
    0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e, 0x0f, 0x33, 0x34, 0x35, 0xe1, 0x31, 0x1d, 0x1b, 0x06, 0x19,
    0x05, 0x11, 0x10, 0x36, 0x37, 0x38, 0xe5, 0x55, 0xe2, 0x2c, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
    0x3f, 0x40, 0x41, 0x42, 0x43, 0x53, 0x47, 0x5f, 0x60, 0x61, 0x56, 0x5c, 0x5d, 0x5e, 0x57, 0x59,
    0x5a, 0x5b, 0x62, 0x63, 0x46, 0x00, 0x64, 0x44, 0x45, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
    0xe8, 0xe9, 0x71, 0x72, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x85, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x00, 0x00, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x8b, 0x00, 0x89, 0xe7, 0x65,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0xe4, 0x00, 0x00,
    0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x46, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x48, 0x4a, 0x52, 0x4b, 0x00, 0x50, 0x00, 0x4f, 0x00, 0x4d,
    0x51, 0x4e, 0x49, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe3, 0xe7, 0x65, 0x66, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
/// Tablet report descriptor
const TABLET_REPORT_DESCRIPTOR: [u8; 74] = [
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x02, // Usage (Mouse)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x01, // Usage (Pointer)
    0xa1, 0x00, // Collection (Physical)
    0x05, 0x09, // Usage Page (Button)
    0x19, 0x01, // Usage Minimum (1)
    0x29, 0x03, // Usage Maximum (3)
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0x01, // Logical Maximum (1)
    0x95, 0x03, // Report Count (3)
    0x75, 0x01, // Report Size (1)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x95, 0x01, // Report Count (1)
    0x75, 0x05, // Report Size (5)
    0x81, 0x01, // Input (Constant)
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x30, // Usage (X)
    0x09, 0x31, // Usage (Y)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x7f, // Logical Maximum (0x7fff)
    0x35, 0x00, // Physical Minimum (0)
    0x46, 0xff, 0x7f, // Physical Maximum (0x7fff)
    0x75, 0x10, // Report Size (16)
    0x95, 0x02, // Report Count (2)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x38, // Usage (Wheel)
    0x15, 0x81, // Logical Minimum (-0x7f)
    0x25, 0x7f, // Logical Maximum (0x7f)
    0x35, 0x00, // Physical Minimum (same as logical)
    0x45, 0x00, // Physical Maximum (same as logical)
    0x75, 0x08, // Report Size (8)
    0x95, 0x01, // Report Count (1)
    0x81, 0x06, // Input (Data, Variable, Relative)
    0xc0, 0xc0, // End Collection
];
/// Keyboard report descriptor
const KEYBOARD_REPORT_DESCRIPTOR: [u8; 63] = [
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xa1, 0x01, // Collection (Application)
    0x75, 0x01, // Report Size (1)
    0x95, 0x08, // Report Count (8)
    0x05, 0x07, // Usage Page (Key Codes)
    0x19, 0xe0, // Usage Minimum (224)
    0x29, 0xe7, // Usage Maximum (231)
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0x01, // Logical Maximum (1)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x95, 0x01, // Report Count (1)
    0x75, 0x08, // Report Size (8)
    0x81, 0x01, // Input (Constant)
    0x95, 0x05, // Report Count (5)
    0x75, 0x01, // Report Size (1)
    0x05, 0x08, // Usage Page (LEDs)
    0x19, 0x01, // Usage Minimum (1)
    0x29, 0x05, // Usage Maximum (5)
    0x91, 0x02, // Output (Data, Variable, Absolute)
    0x95, 0x01, // Report Count (1)
    0x75, 0x03, // Report Size (3)
    0x91, 0x01, // Output (Constant)
    0x95, 0x06, // Report Count (6)
    0x75, 0x08, // Report Size (8)
    0x15, 0x00, // Logical Minimum (0)
    0x25, 0xff, // Logical Maximum (255)
    0x05, 0x07, // Usage Page (Key Codes)
    0x19, 0x00, // Usage Minimum (0)
    0x29, 0xff, // Usage Maximum (255)
    0x81, 0x00, // Input (Data, Array)
    0xc0, // End Collection
];

/// HID type
#[derive(Debug)]
pub enum HidType {
    Mouse,
    Tablet,
    Keyboard,
    UnKnown,
}

/// HID keyboard including keycode and modifier.
pub struct HidKeyboard {
    /// Recive keycode from VNC.
    pub keycodes: [u32; QUEUE_LENGTH as usize],
    pub modifiers: u16,
    /// Send keycode to driver.
    pub key_buf: [u8; QUEUE_LENGTH as usize],
    pub key_num: u32,
}

impl HidKeyboard {
    fn new() -> HidKeyboard {
        HidKeyboard {
            keycodes: [0; QUEUE_LENGTH as usize],
            modifiers: 0,
            key_buf: [0; QUEUE_LENGTH as usize],
            key_num: 0,
        }
    }

    fn reset(&mut self) {
        self.keycodes.iter_mut().for_each(|x| *x = 0);
        self.modifiers = 0;
        self.key_buf.iter_mut().for_each(|x| *x = 0);
        self.key_num = 0;
    }
}

/// HID pointer event including position and button state.
#[derive(Debug, Clone, Copy, Default)]
pub struct HidPointerEvent {
    /// Direction: left to right.
    pub pos_x: u32,
    /// Direction: up to down.
    pub pos_y: u32,
    /// Wheel up or down.
    pub pos_z: i32,
    pub button_state: u32,
}

/// HID pointer which include hid pointer event.
pub struct HidPointer {
    pub queue: [HidPointerEvent; QUEUE_LENGTH as usize],
}

impl HidPointer {
    fn new() -> Self {
        HidPointer {
            queue: [HidPointerEvent::default(); QUEUE_LENGTH as usize],
        }
    }

    fn reset(&mut self) {
        self.queue
            .iter_mut()
            .for_each(|x| *x = HidPointerEvent::default());
    }
}

/// Human Interface Device.
pub struct Hid {
    pub(crate) head: u32,
    pub(crate) num: u32,
    pub(crate) kind: HidType,
    protocol: u8,
    idle: u8,
    pub(crate) keyboard: HidKeyboard,
    pub(crate) pointer: HidPointer,
}

impl Hid {
    pub fn new(kind: HidType) -> Self {
        Hid {
            head: 0,
            num: 0,
            kind,
            protocol: 0,
            idle: 0,
            keyboard: HidKeyboard::new(),
            pointer: HidPointer::new(),
        }
    }

    pub fn reset(&mut self) {
        self.head = 0;
        self.num = 0;
        self.protocol = HID_PROTOCOL_REPORT;
        self.idle = 0;
        self.keyboard.reset();
        self.pointer.reset();
    }

    fn convert_to_hid_code(&mut self) {
        if self.num == 0 {
            return;
        }
        let slot = self.head & QUEUE_MASK;
        self.increase_head();
        self.num -= 1;
        let keycode = self.keyboard.keycodes[slot as usize];
        let key = keycode & 0x7f;
        let index = key | ((self.keyboard.modifiers as u32 & (1 << 8)) >> 1);
        let hid_code = HID_CODE[index as usize];
        self.keyboard.modifiers &= !(1 << 8);
        debug!(
            "convert_to_hid_code hid_code {} index {} key {}",
            hid_code, index, key
        );
        if hid_code == 0x0 {
            return;
        }
        if hid_code == HID_KEYBOARD_LEFT_CONTROL && self.keyboard.modifiers & (1 << 9) == (1 << 9) {
            self.keyboard.modifiers ^= (1 << 8) | (1 << 9);
            return;
        }
        if (HID_KEYBOARD_LEFT_CONTROL..=HID_KEYBOARD_RIGHT_GUI).contains(&hid_code)
            && keycode & KEYCODE_UP == KEYCODE_UP
        {
            self.keyboard.modifiers &= !(1 << (hid_code & 0x0f));
            return;
        }
        if (HID_KEYBOARD_LEFT_CONTROL..=0xe9).contains(&hid_code) {
            self.keyboard.modifiers |= 1 << (hid_code & 0x0f);
            return;
        }
        // Invalid code.
        if (0xea..=0xef).contains(&hid_code) {
            error!("Convert error, invalid code {}", hid_code);
            return;
        }
        if keycode & KEYCODE_UP == KEYCODE_UP {
            let mut i = self.keyboard.key_num as i32 - 1;
            while i >= 0 {
                if self.keyboard.key_buf[i as usize] == hid_code {
                    self.keyboard.key_num -= 1;
                    self.keyboard.key_buf[i as usize] =
                        self.keyboard.key_buf[self.keyboard.key_num as usize];
                    self.keyboard.key_buf[self.keyboard.key_num as usize] = 0x0;
                    break;
                }
                i -= 1;
            }
        } else {
            let mut i = self.keyboard.key_num as i32 - 1;
            while i >= 0 {
                if self.keyboard.key_buf[i as usize] == hid_code {
                    break;
                }
                i -= 1;
            }
            if i < 0 && self.keyboard.key_num < self.keyboard.key_buf.len() as u32 {
                self.keyboard.key_buf[self.keyboard.key_num as usize] = hid_code;
                self.keyboard.key_num += 1;
            }
        }
    }

    fn keyboard_poll(&mut self) -> Vec<u8> {
        let mut data = vec![0; 8];
        self.convert_to_hid_code();
        data[0] = self.keyboard.modifiers as u8;
        data[1] = 0;
        let len = data.len() - 2;
        if self.keyboard.key_num > 6 {
            for i in 0..len {
                data[i + 2] = HID_USAGE_ERROR_ROLLOVER;
            }
        } else {
            data[2..(len + 2)].clone_from_slice(&self.keyboard.key_buf[..len]);
        }
        data
    }

    fn pointer_poll(&mut self) -> Vec<u8> {
        let index = self.head;
        if self.num != 0 {
            self.increase_head();
            self.num -= 1;
        }
        let evt = &mut self.pointer.queue[(index & QUEUE_MASK) as usize];
        vec![
            evt.button_state as u8,
            evt.pos_x as u8,
            (evt.pos_x >> 8) as u8,
            evt.pos_y as u8,
            (evt.pos_y >> 8) as u8,
            evt.pos_z as u8,
        ]
    }

    fn increase_head(&mut self) {
        if self.head + 1 >= QUEUE_LENGTH {
            self.head = 0;
        } else {
            self.head += 1;
        }
    }

    /// USB HID device handle control packet.
    pub fn handle_control_packet(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) {
        match device_req.request_type {
            USB_INTERFACE_IN_REQUEST => {
                self.do_interface_in_request(packet, device_req, data);
            }
            USB_INTERFACE_CLASS_IN_REQUEST => {
                self.do_interface_class_in_request(packet, device_req, data);
            }
            USB_INTERFACE_CLASS_OUT_REQUEST => {
                self.do_interface_class_out_request(packet, device_req);
            }
            _ => {
                error!("Unhandled request {}", device_req.request);
                packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn do_interface_in_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) {
        match device_req.request {
            USB_REQUEST_GET_DESCRIPTOR => match device_req.value >> 8 {
                0x22 => match self.kind {
                    HidType::Tablet => {
                        data[..TABLET_REPORT_DESCRIPTOR.len()]
                            .clone_from_slice(&TABLET_REPORT_DESCRIPTOR[..]);
                        packet.actual_length = TABLET_REPORT_DESCRIPTOR.len() as u32;
                    }
                    HidType::Keyboard => {
                        data[..KEYBOARD_REPORT_DESCRIPTOR.len()]
                            .clone_from_slice(&KEYBOARD_REPORT_DESCRIPTOR[..]);
                        packet.actual_length = KEYBOARD_REPORT_DESCRIPTOR.len() as u32;
                    }
                    _ => {
                        error!("Unknown HID type");
                        packet.status = UsbPacketStatus::Stall;
                    }
                },
                _ => {
                    error!("Invalid value: {:?}", device_req);
                    packet.status = UsbPacketStatus::Stall;
                }
            },
            _ => {
                error!("Unhandled request {}", device_req.request);
                packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn do_interface_class_in_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
        data: &mut [u8],
    ) {
        match device_req.request {
            HID_GET_REPORT => match self.kind {
                HidType::Tablet => {
                    let buf = self.pointer_poll();
                    data[0..buf.len()].copy_from_slice(buf.as_slice());
                    packet.actual_length = buf.len() as u32;
                }
                HidType::Keyboard => {
                    let buf = self.keyboard_poll();
                    data[0..buf.len()].copy_from_slice(buf.as_slice());
                    packet.actual_length = buf.len() as u32;
                }
                _ => {
                    error!("Unsupported HID type for report");
                    packet.status = UsbPacketStatus::Stall;
                }
            },
            HID_GET_PROTOCOL => {
                data[0] = self.protocol;
                packet.actual_length = 1;
            }
            HID_GET_IDLE => {
                data[0] = self.idle;
                packet.actual_length = 1;
            }
            _ => {
                error!("Unhandled request {}", device_req.request);
                packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    fn do_interface_class_out_request(
        &mut self,
        packet: &mut UsbPacket,
        device_req: &UsbDeviceRequest,
    ) {
        match device_req.request {
            HID_SET_REPORT => match self.kind {
                HidType::Keyboard => {
                    warn!("Keyboard set report not implemented");
                }
                _ => {
                    error!("Unsupported to set report");
                    packet.status = UsbPacketStatus::Stall;
                }
            },
            HID_SET_PROTOCOL => {
                self.protocol = device_req.value as u8;
            }
            HID_SET_IDLE => {
                self.idle = (device_req.value >> 8) as u8;
            }
            _ => {
                error!("Unhandled request {}", device_req.request);
                packet.status = UsbPacketStatus::Stall;
            }
        }
    }

    /// USB HID device handle data packet.
    pub fn handle_data_packet(&mut self, p: &mut UsbPacket) {
        match p.pid as u8 {
            USB_TOKEN_IN => {
                self.handle_token_in(p);
            }
            _ => {
                error!("Unhandled packet {}", p.pid);
                p.status = UsbPacketStatus::Stall;
            }
        };
    }

    fn handle_token_in(&mut self, p: &mut UsbPacket) {
        let mut buf = Vec::new();
        if p.ep_number == 1 {
            if self.num == 0 {
                debug!("No data in usb device.");
                p.status = UsbPacketStatus::Nak;
                return;
            }
            match self.kind {
                HidType::Keyboard => {
                    buf = self.keyboard_poll();
                }
                HidType::Tablet => {
                    buf = self.pointer_poll();
                }
                _ => {
                    error!("Unsupported HID device");
                    p.status = UsbPacketStatus::Stall;
                }
            }
            let len = buf.len();
            p.transfer_packet(&mut buf, len);
        } else {
            error!("Unhandled endpoint {}", p.ep_number);
            p.status = UsbPacketStatus::Stall;
        }
    }
}

impl Display for Hid {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "HID head {} num {} kind {:?} protocol {} idle {}",
            self.head, self.num, self.kind, self.protocol, self.idle
        )
    }
}
