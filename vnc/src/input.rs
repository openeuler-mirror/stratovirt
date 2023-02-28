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
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use util::bitmap::Bitmap;

// Logical window size for mouse.
const ABS_MAX: u64 = 0x7fff;
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
        let mut kbd_state = server.keyboard_state.borrow_mut();

        let keycode: u16 = match server.keysym2keycode.get(&(keysym as u16)) {
            Some(k) => *k,
            None => 0,
        };

        // Ctr + Alt + Num(1~9)
        // Switch to the corresponding display device.
        if (KEYCODE_1..KEYCODE_9 + 1).contains(&keycode)
            && down
            && self.server.display_listener.is_some()
            && kbd_state.keyboard_modifier_get(KeyboardModifier::KeyModCtrl)
            && kbd_state.keyboard_modifier_get(KeyboardModifier::KeyModAlt)
        {
            kbd_state.keyboard_state_reset();
            console_select(Some((keycode - KEYCODE_1) as usize))
                .unwrap_or_else(|e| error!("{:?}", e));
        }

        kbd_state
            .keyboard_state_update(keycode, down)
            .unwrap_or_else(|e| error!("Key State update error: {:?}", e));
        key_event(keycode, down).unwrap_or_else(|e| error!("Key event error: {:?}", e));

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

        point_event(button_mask as u32, x as u32, y as u32)
            .unwrap_or_else(|e| error!("Point event error: {:?}", e));

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

static INPUTS: Lazy<Arc<Mutex<Inputs>>> = Lazy::new(|| Arc::new(Mutex::new(Inputs::default())));
#[derive(Default)]
struct Inputs {
    active_kbd: Option<String>,
    active_tablet: Option<String>,
    kbd_lists: HashMap<String, Arc<Mutex<dyn KeyboardOpts>>>,
    tablet_lists: HashMap<String, Arc<Mutex<dyn PointerOpts>>>,
}

impl Inputs {
    fn register_kbd(&mut self, device: &str, kbd: Arc<Mutex<dyn KeyboardOpts>>) {
        if self.active_kbd.is_none() {
            self.active_kbd = Some(device.to_string());
        }

        self.kbd_lists.insert(device.to_string(), kbd);
    }

    fn register_mouse(&mut self, device: &str, tablet: Arc<Mutex<dyn PointerOpts>>) {
        if self.active_tablet.is_none() {
            self.active_tablet = Some(device.to_string());
        }

        self.tablet_lists.insert(device.to_string(), tablet);
    }

    fn get_active_kbd(&mut self) -> Option<Arc<Mutex<dyn KeyboardOpts>>> {
        match &self.active_kbd {
            Some(active_kbd) => {
                let kbd = self.kbd_lists.get(active_kbd)?.clone();
                Some(kbd)
            }
            None => None,
        }
    }

    fn get_active_mouse(&mut self) -> Option<Arc<Mutex<dyn PointerOpts>>> {
        match &self.active_tablet {
            Some(active_mouse) => {
                let mouse = self.tablet_lists.get(active_mouse)?.clone();
                Some(mouse)
            }
            None => None,
        }
    }
}

pub fn register_keyboard(device: &str, kbd: Arc<Mutex<dyn KeyboardOpts>>) {
    INPUTS.lock().unwrap().register_kbd(device, kbd);
}

pub fn register_pointer(device: &str, tablet: Arc<Mutex<dyn PointerOpts>>) {
    INPUTS.lock().unwrap().register_mouse(device, tablet);
}

pub fn key_event(keycode: u16, down: bool) -> Result<()> {
    let kbd = INPUTS.lock().unwrap().get_active_kbd();
    if let Some(k) = kbd {
        k.lock().unwrap().do_key_event(keycode, down)?;
    }
    Ok(())
}

pub fn point_event(button: u32, x: u32, y: u32) -> Result<()> {
    let mouse = INPUTS.lock().unwrap().get_active_mouse();
    if let Some(m) = mouse {
        m.lock().unwrap().do_point_event(button, x, y)?;
    }
    Ok(())
}

pub trait KeyboardOpts: Send {
    fn do_key_event(&mut self, keycode: u16, down: bool) -> Result<()>;
}

pub trait PointerOpts: Send {
    fn do_point_event(&mut self, button: u32, x: u32, y: u32) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    pub struct TestKbd {
        keycode: u16,
        down: bool,
    }

    impl KeyboardOpts for TestKbd {
        fn do_key_event(&mut self, keycode: u16, down: bool) -> Result<()> {
            self.keycode = keycode;
            self.down = down;
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct TestTablet {
        pub button: u32,
        x: u32,
        y: u32,
    }
    impl PointerOpts for TestTablet {
        fn do_point_event(&mut self, button: u32, x: u32, y: u32) -> Result<()> {
            self.button = button;
            self.x = x;
            self.y = y;
            Ok(())
        }
    }

    #[test]
    fn test_input_basic() {
        // Test keyboard event.
        let test_kdb = Arc::new(Mutex::new(TestKbd {
            keycode: 0,
            down: false,
        }));
        register_keyboard("TestKeyboard", test_kdb.clone());
        assert!(key_event(12, true).is_ok());
        assert_eq!(test_kdb.lock().unwrap().keycode, 12);
        assert_eq!(test_kdb.lock().unwrap().down, true);

        // Test point event.
        let test_mouse = Arc::new(Mutex::new(TestTablet::default()));
        assert_eq!(test_mouse.lock().unwrap().button, 0);
        assert_eq!(test_mouse.lock().unwrap().x, 0);
        assert_eq!(test_mouse.lock().unwrap().y, 0);
        register_pointer("TestPointer", test_mouse.clone());
        assert!(point_event(1, 54, 12).is_ok());
        assert_eq!(test_mouse.lock().unwrap().button, 1);
        assert_eq!(test_mouse.lock().unwrap().x, 54);
        assert_eq!(test_mouse.lock().unwrap().y, 12);
    }
}
