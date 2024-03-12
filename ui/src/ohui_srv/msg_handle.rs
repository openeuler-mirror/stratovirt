// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
//
// Stratovirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{anyhow, bail, Result};
use log::{error, warn};
use util::byte_code::ByteCode;

use super::{channel::OhUiChannel, msg::*};
use crate::{
    console::{get_active_console, graphic_hardware_ui_info},
    input::{
        self, get_kbd_led_state, input_button, input_move_abs, input_point_sync, keyboard_update,
        release_all_key, trigger_key, Axis, ABS_MAX, CAPS_LOCK_LED, INPUT_BUTTON_WHEEL_DOWN,
        INPUT_BUTTON_WHEEL_LEFT, INPUT_BUTTON_WHEEL_RIGHT, INPUT_BUTTON_WHEEL_UP,
        KEYCODE_CAPS_LOCK, KEYCODE_NUM_LOCK, KEYCODE_SCR_LOCK, NUM_LOCK_LED, SCROLL_LOCK_LED,
    },
    keycode::{DpyMod, KeyCode},
};

fn trans_mouse_pos(x: f64, y: f64, w: f64, h: f64) -> (u32, u32) {
    if x < 0.0 || y < 0.0 || x > w || y > h {
        error!("incorrect mouse pos info, ({}, {}) of {} * {}", x, y, w, h);
        return (0, 0);
    }
    // TODO: we don't take the situation that image is scaled into consideration
    //
    // The horizontal and vertical directions of the USB tablet are mapped as follows:
    // Horizontal: [0, ABS_MAX] in the tablet is mapped to screan pixels [0, PIXELMAX_W] linearly;
    // Vertical: [0, ABS_MAX] in the tablet is mapped linearly to [0, PIXELMAX_H] on the screen;
    // For example, if the mouse position is (x, y) and the screen size is wh,
    // the data converted to the USB tablet is as follows: ((x/w) ABS_MAX, (y/h) * ABS_MAX).
    (
        (x * (ABS_MAX as f64) / w) as u32,
        (y * (ABS_MAX as f64) / h) as u32,
    )
}

#[derive(Default)]
struct WindowState {
    width: u32,
    height: u32,
    led_state: Option<u8>,
}

impl WindowState {
    fn update_window_info(&mut self, w: u32, h: u32) {
        self.width = w;
        self.height = h;
    }

    fn press_btn(&mut self, btn: u32) -> Result<()> {
        input_button(btn, true)?;
        input_point_sync()
    }

    fn release_btn(&mut self, btn: u32) -> Result<()> {
        input_button(btn, false)?;
        input_point_sync()
    }

    fn do_key_action(&self, keycode: u16, action: u16) -> Result<()> {
        let press = action != 0;
        keyboard_update(press, keycode)?;
        input::key_event(keycode, press).map_err(|e| {
            anyhow!(
                "do key event failed: code: {}, action: {}, {:?}",
                keycode,
                press,
                e
            )
        })
    }

    fn move_pointer(&mut self, x: f64, y: f64) -> Result<()> {
        let (pos_x, pos_y) = trans_mouse_pos(x, y, self.width as f64, self.height as f64);
        input_move_abs(Axis::X, pos_x)?;
        input_move_abs(Axis::Y, pos_y)?;
        input_point_sync()
    }

    fn update_host_ledstate(&mut self, led: u8) {
        self.led_state = Some(led);
    }

    fn sync_kbd_led_state(&mut self) -> Result<()> {
        if self.led_state.is_none() {
            return Ok(());
        }

        let host_stat = self.led_state.unwrap();
        let guest_stat = get_kbd_led_state();
        if host_stat != guest_stat {
            let sync_bits = host_stat ^ guest_stat;
            if (sync_bits & CAPS_LOCK_LED) != 0 {
                trigger_key(KEYCODE_CAPS_LOCK)?;
            }
            if (sync_bits & NUM_LOCK_LED) != 0 {
                trigger_key(KEYCODE_NUM_LOCK)?;
            }
            if (sync_bits & SCROLL_LOCK_LED) != 0 {
                trigger_key(KEYCODE_SCR_LOCK)?;
            }
        }
        self.led_state = None;
        Ok(())
    }
}

pub struct OhUiMsgHandler {
    channel: Arc<OhUiChannel>,
    state: Mutex<WindowState>,
    hmcode2svcode: HashMap<u16, u16>,
    reader: Mutex<MsgReader>,
}

impl OhUiMsgHandler {
    pub fn new(channel: Arc<OhUiChannel>) -> Self {
        OhUiMsgHandler {
            channel,
            state: Mutex::new(WindowState::default()),
            hmcode2svcode: KeyCode::keysym_to_qkeycode(DpyMod::Ohui),
            reader: Mutex::new(MsgReader::default()),
        }
    }

    pub fn handle_msg(&self, token_id: Arc<RwLock<u64>>) -> Result<()> {
        let mut reader = self.reader.lock().unwrap();
        if !reader.recv(&self.channel)? {
            return Ok(());
        }

        let hdr = &reader.header;
        let body_size = hdr.size as usize;
        let event_type = hdr.event_type;
        if body_size != event_msg_data_len(hdr.event_type) {
            warn!(
                "{:?} data len is wrong, we want {}, but receive {}",
                event_type,
                event_msg_data_len(hdr.event_type),
                body_size
            );
            reader.clear();
            return Ok(());
        }

        let body_bytes = reader.body.as_ref().unwrap();
        if let Err(e) = match event_type {
            EventType::MouseButton => {
                let body = MouseButtonEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_mouse_button(body)
            }
            EventType::MouseMotion => {
                let body = MouseMotionEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_mouse_motion(body)
            }
            EventType::Keyboard => {
                let body = KeyboardEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_keyboard(body)
            }
            EventType::WindowInfo => {
                let body = WindowInfoEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_windowinfo(body);
                Ok(())
            }
            EventType::Scroll => {
                let body = ScrollEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_scroll(body)
            }
            EventType::Focus => {
                let body = FocusEvent::from_bytes(&body_bytes[..]).unwrap();
                if body.state == CLIENT_FOCUSOUT_EVENT {
                    reader.clear();
                    release_all_key()?;
                }
                Ok(())
            }
            EventType::Ledstate => {
                let body = LedstateEvent::from_bytes(&body_bytes[..]).unwrap();
                self.handle_ledstate(body);
                Ok(())
            }
            EventType::Greet => {
                let body = GreetEvent::from_bytes(&body_bytes[..]).unwrap();
                *token_id.write().unwrap() = body.token_id;
                Ok(())
            }
            _ => {
                error!(
                    "unsupported type {:?} and body size {}",
                    event_type, body_size
                );
                Ok(())
            }
        } {
            error!("handle_msg: error: {e}");
        }
        reader.clear();
        Ok(())
    }

    fn handle_mouse_button(&self, mb: &MouseButtonEvent) -> Result<()> {
        let (btn, action) = (mb.button, mb.btn_action);
        match action {
            CLIENT_PRESS_BTN => self.state.lock().unwrap().press_btn(btn),
            CLIENT_RELEASE_BTN => self.state.lock().unwrap().release_btn(btn),
            _ => bail!("Invalid mouse event number {}", action),
        }
    }

    pub fn handle_cursor_define(
        &self,
        w: u32,
        h: u32,
        hot_x: u32,
        hot_y: u32,
        size_per_pixel: u32,
    ) {
        let body = HWCursorEvent::new(w, h, hot_x, hot_y, size_per_pixel);
        if let Err(e) = self.channel.send_message(EventType::CursorDefine, &body) {
            error!("handle_cursor_define: failed to send message with error {e}");
        }
    }

    // NOTE: we only support absolute position info now, that means usb-mouse does not work.
    fn handle_mouse_motion(&self, mm: &MouseMotionEvent) -> Result<()> {
        self.state.lock().unwrap().move_pointer(mm.x, mm.y)
    }

    fn handle_keyboard(&self, ke: &KeyboardEvent) -> Result<()> {
        if self.state.lock().unwrap().led_state.is_some() {
            self.state.lock().unwrap().sync_kbd_led_state()?;
        }
        let hmkey = ke.keycode;
        let keycode = match self.hmcode2svcode.get(&hmkey) {
            Some(k) => *k,
            None => {
                bail!("not supported keycode {}", hmkey);
            }
        };
        self.state
            .lock()
            .unwrap()
            .do_key_action(keycode, ke.key_action)
    }

    fn handle_scroll(&self, se: &ScrollEvent) -> Result<()> {
        let org_dir = se.direction;
        let dir = match org_dir {
            CLIENT_WHEEL_UP => INPUT_BUTTON_WHEEL_UP,
            CLIENT_WHEEL_DOWN => INPUT_BUTTON_WHEEL_DOWN,
            CLIENT_WHEEL_LEFT => INPUT_BUTTON_WHEEL_LEFT,
            CLIENT_WHEEL_RIGHT => INPUT_BUTTON_WHEEL_RIGHT,
            _ => bail!("Invalid mouse scroll number {}", org_dir),
        };
        self.state.lock().unwrap().press_btn(dir)?;
        self.state.lock().unwrap().release_btn(dir)?;
        Ok(())
    }

    fn handle_windowinfo(&self, wi: &WindowInfoEvent) {
        let cons = get_active_console();

        for con in cons {
            let c = match con.upgrade() {
                Some(c) => c,
                None => continue,
            };
            if let Err(e) = graphic_hardware_ui_info(c, wi.width, wi.height) {
                error!("handle_windowinfo failed with error {e}");
            }
        }
    }

    fn handle_ledstate(&self, led: &LedstateEvent) {
        self.state
            .lock()
            .unwrap()
            .update_host_ledstate(led.state as u8);
    }

    pub fn send_windowinfo(&self, w: u32, h: u32) {
        self.state.lock().unwrap().update_window_info(w, h);
        let body = WindowInfoEvent::new(w, h);
        self.channel
            .send_message(EventType::WindowInfo, &body)
            .unwrap();
    }

    pub fn handle_dirty_area(&self, x: u32, y: u32, w: u32, h: u32) {
        let body = FrameBufferDirtyEvent::new(x, y, w, h);
        if let Err(e) = self
            .channel
            .send_message(EventType::FrameBufferDirty, &body)
        {
            error!("handle_dirty_area: failed to send message with error {e}");
        }
    }
}

#[derive(Default)]
struct MsgReader {
    /// cache for header
    pub header: EventMsgHdr,
    /// received byte size of header
    pub header_ready: usize,
    /// cache of body
    pub body: Option<Vec<u8>>,
    /// received byte size of body
    pub body_ready: usize,
}

impl MsgReader {
    pub fn recv(&mut self, channel: &Arc<OhUiChannel>) -> Result<bool> {
        if self.recv_header(channel)? {
            return self.recv_body(channel);
        }
        Ok(false)
    }

    pub fn clear(&mut self) {
        self.header_ready = 0;
        self.body_ready = 0;
        self.body = None;
    }

    fn recv_header(&mut self, channel: &Arc<OhUiChannel>) -> Result<bool> {
        if self.header_ready == EVENT_MSG_HDR_SIZE as usize {
            return Ok(true);
        }

        let buf = self.header.as_mut_bytes();
        self.header_ready += channel.recv_slice(&mut buf[self.header_ready..])?;
        Ok(self.header_ready == EVENT_MSG_HDR_SIZE as usize)
    }

    fn recv_body(&mut self, channel: &Arc<OhUiChannel>) -> Result<bool> {
        let body_size = self.header.size as usize;
        if body_size == self.body_ready {
            return Ok(true);
        }

        // The caller make sure that self.clear() is
        // called after a complete message receiving.
        if self.body.is_none() {
            self.body = Some(Vec::with_capacity(body_size));
        }
        let buf = self.body.as_mut().unwrap();
        // SAFETY: 1. we guarantee new message has new body, so
        // buf's capcity is equal to body_size. 2. buf has 'u8'
        // type elements, it will be initialized by zero.
        unsafe {
            buf.set_len(body_size);
        }
        self.body_ready += channel.recv_slice(&mut buf[self.body_ready..])?;

        Ok(self.body_ready == body_size)
    }
}
