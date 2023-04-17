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

use anyhow::Result;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use util::bitmap::Bitmap;

// Logical window size for mouse.
pub const ABS_MAX: u64 = 0x7fff;
// Event type of Point.
pub const INPUT_POINT_LEFT: u8 = 0x01;
pub const INPUT_POINT_MIDDLE: u8 = 0x02;
pub const INPUT_POINT_RIGHT: u8 = 0x04;
// ASCII value.
pub const ASCII_A: i32 = 65;
pub const ASCII_Z: i32 = 90;
pub const UPPERCASE_TO_LOWERCASE: i32 = 32;
const BIT_PER_BYTE: u32 = 8;

// Keycode.
pub const KEYCODE_1: u16 = 2;
pub const KEYCODE_9: u16 = 10;
const KEYCODE_CTRL: u16 = 29;
const KEYCODE_SHIFT: u16 = 42;
const KEYCODE_SHIFT_R: u16 = 54;
const KEYCODE_ALT: u16 = 56;
const KEYCODE_CAPS_LOCK: u16 = 58;
const KEYCODE_NUM_LOCK: u16 = 69;
const KEYCODE_CTRL_R: u16 = 157;
const KEYCODE_ALT_R: u16 = 184;

static INPUTS: Lazy<Arc<Mutex<Inputs>>> = Lazy::new(|| Arc::new(Mutex::new(Inputs::default())));

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
    pub fn keyboard_modifier_get(&self, key_mod: KeyboardModifier) -> bool {
        match self.keymods.contain(key_mod as usize) {
            Ok(res) => res,
            Err(_e) => false,
        }
    }

    /// Reset all keyboard modifier state.
    pub fn keyboard_state_reset(&mut self) {
        self.keymods.clear_all();
    }

    /// Record the press and up state in the keyboard.
    pub fn keyboard_state_update(&mut self, keycode: u16, down: bool) -> Result<()> {
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
#[derive(Default)]
struct Inputs {
    kbd_ids: Vec<String>,
    kbd_lists: HashMap<String, Arc<Mutex<dyn KeyboardOpts>>>,
    tablet_ids: Vec<String>,
    tablet_lists: HashMap<String, Arc<Mutex<dyn PointerOpts>>>,
}

impl Inputs {
    fn register_kbd(&mut self, device: &str, kbd: Arc<Mutex<dyn KeyboardOpts>>) {
        self.kbd_ids.insert(0, device.to_string());
        self.kbd_lists.insert(device.to_string(), kbd);
    }

    fn unregister_kbd(&mut self, device: &str) {
        self.kbd_lists.remove(&device.to_string());
        let len = self.kbd_ids.len();
        for i in 0..len {
            if self.kbd_ids[i] == device {
                self.kbd_ids.remove(i);
                break;
            }
        }
    }

    fn register_mouse(&mut self, device: &str, tablet: Arc<Mutex<dyn PointerOpts>>) {
        self.tablet_ids.insert(0, device.to_string());
        self.tablet_lists.insert(device.to_string(), tablet);
    }

    fn unregister_mouse(&mut self, device: &str) {
        self.tablet_lists.remove(&device.to_string());
        let len = self.tablet_ids.len();
        for i in 0..len {
            if self.tablet_ids[i] == device {
                self.tablet_ids.remove(i);
                break;
            }
        }
    }

    fn get_active_kbd(&mut self) -> Option<Arc<Mutex<dyn KeyboardOpts>>> {
        if !self.kbd_ids.is_empty() {
            let kbd = self.kbd_lists.get(&self.kbd_ids[0])?.clone();
            Some(kbd)
        } else {
            None
        }
    }

    fn get_active_mouse(&mut self) -> Option<Arc<Mutex<dyn PointerOpts>>> {
        if !self.tablet_ids.is_empty() {
            let mouse = self.tablet_lists.get(&self.tablet_ids[0])?.clone();
            Some(mouse)
        } else {
            None
        }
    }
}

pub fn register_keyboard(device: &str, kbd: Arc<Mutex<dyn KeyboardOpts>>) {
    INPUTS.lock().unwrap().register_kbd(device, kbd);
}

pub fn unregister_keyboard(device: &str) {
    INPUTS.lock().unwrap().unregister_kbd(device);
}

pub fn register_pointer(device: &str, tablet: Arc<Mutex<dyn PointerOpts>>) {
    INPUTS.lock().unwrap().register_mouse(device, tablet);
}

pub fn unregister_pointer(device: &str) {
    INPUTS.lock().unwrap().unregister_mouse(device);
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
