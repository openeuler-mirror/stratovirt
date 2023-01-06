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
    console::console_select,
    pixman::{get_image_height, get_image_width},
    vnc::BIT_PER_BYTE,
};
use anyhow::Result;
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

// Keycode.
const KEYCODE_1: u16 = 2;
const KEYCODE_9: u16 = 10;
const KEYCODE_CTRL: u16 = 29;
const KEYCODE_SHIFT: u16 = 42;
const KEYCODE_SHIFT_R: u16 = 54;
const KEYCODE_ALT: u16 = 56;
const KEYCODE_CAPS_LOCK: u16 = 58;
const KEYCODE_NUM_LOCK: u16 = 69;
const KEYCODE_CTRL_R: u16 = 157;
const KEYCODE_ALT_R: u16 = 184;

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

    /// Get the corresponding keyboard modifier.
    fn keyboard_modifier_get(&self, key_mod: KeyboardModifier) -> bool {
        match self.keymods.contain(key_mod as usize) {
            Ok(res) => res,
            Err(_e) => false,
        }
    }

    /// Reset all keyboard modifier state.
    fn keyboard_state_reset(&mut self) {
        self.keymods.clear_all();
    }

    /// Record the press and up state in the keyboard.
    fn keyboard_state_update(&mut self, keycode: u16, down: bool) -> Result<()> {
        // Key is not pressed and the incoming key action is up.
        if !down && !self.keystate.contain(keycode as usize)? {
            return Ok(());
        }

        // Update Keyboard key modifier state.
        if down {
            self.keystate.set(keycode as usize)?;
        } else {
            self.keystate.clear(keycode as usize)?;
        }

        // Update Keyboard modifier state.
        match keycode {
            KEYCODE_SHIFT | KEYCODE_SHIFT_R => {
                self.keyboard_modstate_update(
                    KEYCODE_SHIFT,
                    KEYCODE_SHIFT,
                    KeyboardModifier::KeyModShift,
                )?;
            }
            KEYCODE_CTRL | KEYCODE_CTRL_R => {
                self.keyboard_modstate_update(
                    KEYCODE_CTRL,
                    KEYCODE_CTRL_R,
                    KeyboardModifier::KeyModCtrl,
                )?;
            }
            KEYCODE_ALT => {
                self.keyboard_modstate_update(
                    KEYCODE_ALT,
                    KEYCODE_ALT,
                    KeyboardModifier::KeyModAlt,
                )?;
            }
            KEYCODE_ALT_R => {
                self.keyboard_modstate_update(
                    KEYCODE_ALT_R,
                    KEYCODE_ALT_R,
                    KeyboardModifier::KeyModAltgr,
                )?;
            }
            KEYCODE_CAPS_LOCK => {
                if down {
                    self.keymods
                        .change(KeyboardModifier::KeyModCapslock as usize)?;
                }
            }
            KEYCODE_NUM_LOCK => {
                if down {
                    self.keymods
                        .change(KeyboardModifier::KeyModNumlock as usize)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// If one of the keys keycode_1 and keycode_2 is pressed,
    /// Then the corresponding keyboard modifier state will be set.
    /// Otherwise, it will be clear.
    fn keyboard_modstate_update(
        &mut self,
        keycode_1: u16,
        keycode_2: u16,
        mod_state: KeyboardModifier,
    ) -> Result<()> {
        let mut res = self.keystate.contain(keycode_1 as usize)?;
        res |= self.keystate.contain(keycode_2 as usize)?;

        if res {
            self.keymods.set(mod_state as usize)?;
        } else {
            self.keymods.clear(mod_state as usize)?;
        }
        Ok(())
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
        let down: bool = buf[1] != 0;
        let mut keysym = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let server = self.server.clone();

        // Uppercase -> Lowercase.
        if (ASCII_A..=ASCII_Z).contains(&keysym) {
            keysym += UPPERCASE_TO_LOWERCASE;
        }
        let mut locked_kbd_state = server.keyboard_state.lock().unwrap();
        let dcl_id = self.server.display_listener.lock().unwrap().dcl_id;

        let keycode: u16 = match server.keysym2keycode.get(&(keysym as u16)) {
            Some(k) => *k,
            None => 0,
        };

        // Ctr + Alt + Num(1~9)
        // Switch to the corresponding display device.
        if (KEYCODE_1..KEYCODE_9 + 1).contains(&keycode)
            && down
            && dcl_id.is_some()
            && locked_kbd_state.keyboard_modifier_get(KeyboardModifier::KeyModCtrl)
            && locked_kbd_state.keyboard_modifier_get(KeyboardModifier::KeyModAlt)
        {
            locked_kbd_state.keyboard_state_reset();
            console_select(Some((keycode - KEYCODE_1) as usize));
        }

        if let Err(e) = locked_kbd_state.keyboard_state_update(keycode, down) {
            error!("{:?}", e);
            return;
        }
        drop(locked_kbd_state);
        do_key_event(keycode, down);

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
        let button_mask: u8 = match buf[1] {
            INPUT_POINT_LEFT => 0x01,
            INPUT_POINT_MIDDLE => 0x04,
            INPUT_POINT_RIGHT => 0x02,
            _ => buf[1],
        };

        let locked_input = INPUT.lock().unwrap();
        if let Some(tablet) = &locked_input.tablet {
            if let Err(e) = pointer_event(tablet, button_mask as u32, x as i32, y as i32) {
                error!("Point event error: {}", e);
            }
        }

        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
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

/// Do keyboard event.
///
/// # Arguments
///
/// * `down` - press keyboard down or up.
/// * `keycode` - keycode.
fn do_key_event(keycode: u16, down: bool) {
    let mut scancode = Vec::new();
    let mut keycode = keycode;
    if keycode & SCANCODE_GREY != 0 {
        scancode.push(SCANCODE_EMUL0 as u32);
        keycode &= !SCANCODE_GREY;
    }

    if !down {
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
