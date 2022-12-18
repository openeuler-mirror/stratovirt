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

use crate::{
    client::ClientIoHandler,
    pixman::{get_image_height, get_image_width},
    vnc::BIT_PER_BYTE,
};
use log::error;
use usb::{keyboard::keyboard_event, tablet::pointer_event, INPUT};
use util::bitmap::Bitmap;

// Logical window size for mouse.
const ABS_MAX: u64 = 0x7fff;
// Up flag.
const SCANCODE_UP: u16 = 0x80;
// Grey keys.
const SCANCODE_GREY: u16 = 0x80;
// Used to expand Grey keys.
const SCANCODE_EMUL0: u16 = 0xe0;
// Event type of Point.
const INPUT_POINT_LEFT: u8 = 0x01;
const INPUT_POINT_MIDDLE: u8 = 0x02;
const INPUT_POINT_RIGHT: u8 = 0x04;
// ASCII value.
const ASCII_A: i32 = 65;
const ASCII_Z: i32 = 90;
const UPPERCASE_TO_LOWERCASE: i32 = 32;

// Keyboard Modifier State
pub enum KeyboardModifier {
    KeyModNone = 0,
    KeyModShift = 1,
    KeyModCtrl = 2,
    KeyModAlt = 3,
    KeyModAltgr = 4,
    KeyModNumlock = 5,
    KeyModCapslock = 6,
    KeyModMax = 7,
}

/// Record the keyboard status,
/// Including the press information of keys,
/// and some status information.
pub struct KeyBoardState {
    /// Keyboard state.
    pub keystate: Bitmap<u8>,
    /// Key Modifier states.
    pub keymods: Bitmap<u8>,
}

impl KeyBoardState {
    pub fn new(key_num: usize) -> Self {
        Self {
            keystate: Bitmap::new(key_num / (BIT_PER_BYTE as usize) + 1),
            keymods: Bitmap::new(
                KeyboardModifier::KeyModMax as usize / (BIT_PER_BYTE as usize) + 1,
            ),
        }
    }
}

impl ClientIoHandler {
    /// Keyboard event.
    pub fn key_envent(&mut self) {
        if self.expect == 1 {
            self.expect = 8;
            return;
        }
        let buf = self.read_incoming_msg();
        let down = buf[1] as u8;
        let mut keysym = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        // Uppercase -> Lowercase.
        if (ASCII_A..=ASCII_Z).contains(&keysym) {
            keysym += UPPERCASE_TO_LOWERCASE;
        }

        let keycode: u16 = match self.server.keysym2keycode.get(&(keysym as u16)) {
            Some(k) => *k,
            None => 0,
        };
        self.do_key_event(down, keycode);
        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
    }

    // Mouse event.
    pub fn point_event(&mut self) {
        if self.expect == 1 {
            self.expect = 6;
            return;
        }

        let buf = self.read_incoming_msg();
        let mut x = ((buf[2] as u16) << 8) + buf[3] as u16;
        let mut y = ((buf[4] as u16) << 8) + buf[5] as u16;

        // Window size alignment.
        let locked_surface = self.server.vnc_surface.lock().unwrap();
        let width = get_image_width(locked_surface.server_image);
        let height = get_image_height(locked_surface.server_image);
        drop(locked_surface);
        x = ((x as u64 * ABS_MAX) / width as u64) as u16;
        y = ((y as u64 * ABS_MAX) / height as u64) as u16;

        // ASCII -> HidCode.
        let button_mask: u8 = match buf[1] as u8 {
            INPUT_POINT_LEFT => 0x01,
            INPUT_POINT_MIDDLE => 0x04,
            INPUT_POINT_RIGHT => 0x02,
            _ => buf[1] as u8,
        };

        let locked_input = INPUT.lock().unwrap();
        if let Some(tablet) = &locked_input.tablet {
            if let Err(e) = pointer_event(tablet, button_mask as u32, x as i32, y as i32) {
                error!("Point event error: {}", e);
            }
        }

        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
    }

    /// Do keyboard event.
    ///
    /// # Arguments
    ///
    /// * `down` - press keyboard down or up.
    /// * `keycode` - keycode.
    pub fn do_key_event(&mut self, down: u8, keycode: u16) {
        let mut scancode = Vec::new();
        let mut keycode = keycode;
        if keycode & SCANCODE_GREY != 0 {
            scancode.push(SCANCODE_EMUL0 as u32);
            keycode &= !SCANCODE_GREY;
        }

        if down == 0 {
            keycode |= SCANCODE_UP;
        }
        scancode.push(keycode as u32);
        // Send key event.
        let locked_input = INPUT.lock().unwrap();
        if let Some(keyboard) = &locked_input.keyboard {
            if let Err(e) = keyboard_event(keyboard, scancode.as_slice()) {
                error!("Key event error: {}", e);
            }
        }
    }

    /// Client cut text.
    pub fn client_cut_event(&mut self) {
        let buf = self.read_incoming_msg();
        if self.expect == 1 {
            self.expect = 8;
            return;
        }
        if self.expect == 8 {
            let buf = [buf[4], buf[5], buf[6], buf[7]];
            let len = u32::from_be_bytes(buf);
            if len > 0 {
                self.expect += len as usize;
                return;
            }
        }

        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
    }
}
