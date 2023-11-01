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

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use log::debug;
use once_cell::sync::Lazy;

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
const ASCII_A_LOWERCASE: i32 = 97;
const ASCII_Z_LOWERCASE: i32 = 122;
const BIT_PER_BYTE: u32 = 8;

// Keycode.
pub const KEYCODE_1: u16 = 2;
pub const KEYCODE_9: u16 = 10;
const KEYCODE_CTRL: u16 = 29;
pub const KEYCODE_RET: u16 = 38;
const KEYCODE_SHIFT: u16 = 42;
const KEYCODE_SHIFT_R: u16 = 54;
const KEYCODE_ALT: u16 = 56;
const KEYCODE_CAPS_LOCK: u16 = 58;
const KEYCODE_NUM_LOCK: u16 = 69;
const KEYCODE_CTRL_R: u16 = 157;
const KEYCODE_ALT_R: u16 = 184;
const KEYPAD_1: u16 = 0xffb0;
const KEYPAD_9: u16 = 0xffb9;
const KEYPAD_SEPARATOR: u16 = 0xffac;
const KEYPAD_DECIMAL: u16 = 0xffae;
const KEYCODE_KP_7: u16 = 0x47;
const KEYCODE_KP_DECIMAL: u16 = 0x53;
// Led (HID)
const NUM_LOCK_LED: u8 = 0x1;
const CAPS_LOCK_LED: u8 = 0x2;
pub const SCROLL_LOCK_LED: u8 = 0x4;
/// Input button state.
pub const INPUT_BUTTON_WHEEL_UP: u32 = 0x08;
pub const INPUT_BUTTON_WHEEL_DOWN: u32 = 0x10;
pub const INPUT_BUTTON_WHEEL_LEFT: u32 = 0x20;
pub const INPUT_BUTTON_WHEEL_RIGHT: u32 = 0x40;

static INPUTS: Lazy<Arc<Mutex<Inputs>>> = Lazy::new(|| Arc::new(Mutex::new(Inputs::default())));

static LED_STATE: Lazy<Arc<Mutex<LedState>>> =
    Lazy::new(|| Arc::new(Mutex::new(LedState::default())));

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
    pub keystate: HashSet<u16>,
    /// Key Modifier states.
    pub keymods: Bitmap<u8>,
}

impl Default for KeyBoardState {
    fn default() -> Self {
        Self {
            keystate: HashSet::new(),
            keymods: Bitmap::new(
                KeyboardModifier::KeyModMax as usize / (BIT_PER_BYTE as usize) + 1,
            ),
        }
    }
}

impl KeyBoardState {
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
        if !down && !self.keystate.contains(&keycode) {
            return Ok(());
        }

        // Update Keyboard key modifier state.
        if down {
            self.keystate.insert(keycode);
        } else {
            self.keystate.remove(&keycode);
        }

        // Update Keyboard modifier state.
        match keycode {
            KEYCODE_SHIFT | KEYCODE_SHIFT_R => {
                self.keyboard_modstate_update(
                    KEYCODE_SHIFT,
                    KEYCODE_SHIFT_R,
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
        if self.keystate.contains(&keycode_1) | self.keystate.contains(&keycode_2) {
            self.keymods.set(mod_state as usize)?;
        } else {
            self.keymods.clear(mod_state as usize)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct LedState {
    kbd_led: u8,
}

#[derive(Default)]
struct Inputs {
    kbd_ids: Vec<String>,
    kbd_lists: HashMap<String, Arc<Mutex<dyn KeyboardOpts>>>,
    tablet_ids: Vec<String>,
    tablet_lists: HashMap<String, Arc<Mutex<dyn PointerOpts>>>,
    keyboard_state: KeyBoardState,
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

    fn press_key(&mut self, keycode: u16) -> Result<()> {
        self.keyboard_state.keyboard_state_update(keycode, true)?;
        let kbd = self.get_active_kbd();
        if let Some(k) = kbd.as_ref() {
            k.lock().unwrap().do_key_event(keycode, true)?;
        }
        self.keyboard_state.keyboard_state_update(keycode, false)?;
        if let Some(k) = kbd.as_ref() {
            k.lock().unwrap().do_key_event(keycode, false)?;
        }
        Ok(())
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

/// A complete mouse click event.
pub fn press_mouse(button: u32, x: u32, y: u32) -> Result<()> {
    let mouse = INPUTS.lock().unwrap().get_active_mouse();
    if let Some(m) = mouse {
        let mut locked_mouse = m.lock().unwrap();
        locked_mouse.do_point_event(button, x, y)?;
        locked_mouse.do_point_event(0, x, y)?
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

/// 1. Keep the key state in keyboard_state.
/// 2. Sync the caps lock and num lock state to guest.
pub fn update_key_state(down: bool, keysym: i32, keycode: u16) -> Result<()> {
    let mut locked_input = INPUTS.lock().unwrap();
    let upper = (ASCII_A..=ASCII_Z).contains(&keysym);
    let is_letter = upper || (ASCII_A_LOWERCASE..=ASCII_Z_LOWERCASE).contains(&keysym);
    let in_keypad = (KEYCODE_KP_7..=KEYCODE_KP_DECIMAL).contains(&keycode);

    if down && is_letter {
        let shift = locked_input
            .keyboard_state
            .keyboard_modifier_get(KeyboardModifier::KeyModShift);
        let in_upper = get_kbd_led_state(CAPS_LOCK_LED);
        if (shift && upper == in_upper) || (!shift && upper != in_upper) {
            debug!("Correct caps lock {} inside {}", upper, in_upper);
            locked_input.press_key(KEYCODE_CAPS_LOCK)?;
        }
    } else if down && in_keypad {
        let numlock = keysym_is_num_lock(keysym);
        let in_numlock = get_kbd_led_state(NUM_LOCK_LED);
        if in_numlock != numlock {
            debug!("Correct num lock {} inside {}", numlock, in_numlock);
            locked_input.press_key(KEYCODE_NUM_LOCK)?;
        }
    }

    locked_input
        .keyboard_state
        .keyboard_state_update(keycode, down)
}

/// Release all pressed key.
pub fn release_all_key() -> Result<()> {
    let mut locked_input = INPUTS.lock().unwrap();
    let mut keycode_lists: Vec<u16> = Vec::new();
    for keycode in locked_input.keyboard_state.keystate.iter() {
        keycode_lists.push(*keycode);
    }
    for keycode in keycode_lists.iter() {
        locked_input
            .keyboard_state
            .keyboard_state_update(*keycode, false)?;
        if let Some(k) = locked_input.get_active_kbd().as_ref() {
            k.lock().unwrap().do_key_event(*keycode, false)?;
        }
    }
    Ok(())
}

pub fn get_kbd_led_state(state: u8) -> bool {
    LED_STATE.lock().unwrap().kbd_led & state == state
}

pub fn set_kbd_led_state(state: u8) {
    LED_STATE.lock().unwrap().kbd_led = state;
}

pub fn keyboard_modifier_get(key_mod: KeyboardModifier) -> bool {
    INPUTS
        .lock()
        .unwrap()
        .keyboard_state
        .keyboard_modifier_get(key_mod)
}

pub fn keyboard_state_reset() {
    INPUTS.lock().unwrap().keyboard_state.keyboard_state_reset();
}

fn keysym_is_num_lock(sym: i32) -> bool {
    matches!(
        (sym & 0xffff) as u16,
        KEYPAD_1..=KEYPAD_9 | KEYPAD_SEPARATOR | KEYPAD_DECIMAL
    )
}

pub trait KeyboardOpts: Send {
    fn do_key_event(&mut self, keycode: u16, down: bool) -> Result<()>;
}

pub trait PointerOpts: Send {
    fn do_point_event(&mut self, button: u32, x: u32, y: u32) -> Result<()>;
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "keycode")]
    use crate::keycode::KeyCode;
    static TEST_INPUT: Lazy<Arc<Mutex<TestInput>>> =
        Lazy::new(|| Arc::new(Mutex::new(TestInput::default())));

    use super::*;

    pub struct TestInput {
        kbd: Arc<Mutex<TestKbd>>,
        tablet: Arc<Mutex<TestTablet>>,
    }

    impl Default for TestInput {
        fn default() -> Self {
            Self {
                kbd: Arc::new(Mutex::new(TestKbd {
                    keycode: 0,
                    down: false,
                })),
                tablet: Arc::new(Mutex::new(TestTablet {
                    button: 0,
                    x: 0,
                    y: 0,
                })),
            }
        }
    }

    impl TestInput {
        fn register_input(&self) {
            register_keyboard("TestKeyboard", self.kbd.clone());
            register_pointer("TestPointer", self.tablet.clone());
        }

        fn unregister_input(&self) {
            unregister_keyboard("TestKeyboard");
            unregister_pointer("TestPointer");
            self.kbd.lock().unwrap().keycode = 0;
            self.kbd.lock().unwrap().down = false;
            self.tablet.lock().unwrap().x = 0;
            self.tablet.lock().unwrap().y = 0;
            self.tablet.lock().unwrap().button = 0;
        }
    }

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
        let test_input = TEST_INPUT.lock().unwrap();
        test_input.register_input();
        let test_kdb = test_input.kbd.clone();
        let test_mouse = test_input.tablet.clone();

        assert!(key_event(12, true).is_ok());
        assert_eq!(test_kdb.lock().unwrap().keycode, 12);
        assert_eq!(test_kdb.lock().unwrap().down, true);

        // Test point event.
        assert_eq!(test_mouse.lock().unwrap().button, 0);
        assert_eq!(test_mouse.lock().unwrap().x, 0);
        assert_eq!(test_mouse.lock().unwrap().y, 0);
        register_pointer("TestPointer", test_mouse.clone());
        assert!(point_event(1, 54, 12).is_ok());
        assert_eq!(test_mouse.lock().unwrap().button, 1);
        assert_eq!(test_mouse.lock().unwrap().x, 54);
        assert_eq!(test_mouse.lock().unwrap().y, 12);

        test_input.unregister_input();
    }

    #[cfg(feature = "keycode")]
    #[test]
    fn test_release_all_key() {
        fn do_key_event(press: bool, keysym: i32, keycode: u16) -> Result<()> {
            update_key_state(press, keysym, keycode)?;
            key_event(keycode, press)
        }

        // Test keyboard event.
        let test_input = TEST_INPUT.lock().unwrap();
        test_input.register_input();
        let test_kdb = test_input.kbd.clone();

        let keysym2qkeycode = KeyCode::keysym_to_qkeycode();
        // ["0", "a", "space"]
        let keysym_lists: Vec<u16> = vec![0x0030, 0x0061, 0x0020];
        let keycode_lists: Vec<u16> = keysym_lists
            .iter()
            .map(|x| *keysym2qkeycode.get(&x).unwrap())
            .collect();
        for idx in 0..keysym_lists.len() {
            let keysym = keycode_lists[idx];
            let keycode = keycode_lists[idx];
            assert!(do_key_event(true, keysym as i32, keycode).is_ok());
            assert_eq!(test_kdb.lock().unwrap().keycode, keycode);
            assert_eq!(test_kdb.lock().unwrap().down, true);
        }

        let locked_input = INPUTS.lock().unwrap();
        for keycode in &keycode_lists {
            assert!(locked_input.keyboard_state.keystate.contains(keycode));
            assert!(locked_input.keyboard_state.keystate.contains(keycode));
        }
        drop(locked_input);

        // Release all keys
        assert!(release_all_key().is_ok());

        let locked_input = INPUTS.lock().unwrap();
        for keycode in &keycode_lists {
            assert!(!locked_input.keyboard_state.keystate.contains(keycode));
            assert!(!locked_input.keyboard_state.keystate.contains(keycode));
        }
        drop(locked_input);

        test_input.unregister_input();
    }
}
