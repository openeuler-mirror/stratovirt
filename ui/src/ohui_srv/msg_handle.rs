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
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, LazyLock, Mutex, RwLock};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info, warn};
use util::byte_code::ByteCode;

use super::{
    channel::{recv_slice, send_obj, OhUiChannel},
    msg::*,
    touchpad::*,
};
use crate::{
    console::{get_active_console, graphic_hardware_ui_info, set_dpy_rotation, Rotation},
    input::{
        self, get_kbd_led_state, input_button, input_move_abs, input_point_sync, keyboard_update,
        lift_all_fingers, register_input_notifier, release_all_btn, release_all_key,
        send_mt_screen_event, send_mt_screen_sync, trigger_key, Axis, InputStateChangeReason,
        MultiTouchAbsData, MultiTouchEventKind, MultitouchType, ABS_MAX, CAPS_LOCK_LED,
        CONSUMER_PREFIX, INPUT_BUTTON_WHEEL_DOWN, INPUT_BUTTON_WHEEL_LEFT,
        INPUT_BUTTON_WHEEL_RIGHT, INPUT_BUTTON_WHEEL_UP, INPUT_POINT_BACK, INPUT_POINT_FORWARD,
        INPUT_POINT_LEFT, INPUT_POINT_MIDDLE, INPUT_POINT_RIGHT, KEYCODE_CAPS_LOCK,
        KEYCODE_NUM_LOCK, KEYCODE_SCR_LOCK, NUM_LOCK_LED, SCROLL_LOCK_LED,
    },
    keycode::{DpyMod, KeyCode},
};
use machine_manager::notifier::register_vm_pause_notifier;

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

#[derive(Clone, Default)]
struct CursorState {
    w: u32,
    h: u32,
    hot_x: u32,
    hot_y: u32,
    size_per_pixel: u32,
}

#[derive(Default)]
struct WindowState {
    width: u32,
    height: u32,
    cursor: CursorState,
}

impl WindowState {
    fn update_window_info(&mut self, w: u32, h: u32) {
        self.width = w;
        self.height = h;
    }

    fn press_btn(&mut self, btn: u32) -> Result<()> {
        if let Ok(true) = stop_slide() {
            return Ok(());
        }
        input_button(btn, true)?;
        input_point_sync()
    }

    fn release_btn(&mut self, btn: u32) -> Result<()> {
        input_button(btn, false)?;
        input_point_sync()
    }

    fn do_key_action(&self, keycode: u16, action: u16) -> Result<()> {
        let press = action != 0;
        if keycode & CONSUMER_PREFIX == CONSUMER_PREFIX {
            input::consumer_event(keycode, press).map_err(|e| {
                anyhow!(
                    "do consumer event failed: code: {}, action: {}, {:?}",
                    keycode,
                    press,
                    e
                )
            })
        } else {
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
    }

    fn move_pointer(&mut self, x: f64, y: f64) -> Result<()> {
        let (pos_x, pos_y) = trans_mouse_pos(x, y, f64::from(self.width), f64::from(self.height));
        let _ = stop_slide();
        input_move_abs(Axis::X, pos_x)?;
        input_move_abs(Axis::Y, pos_y)?;
        input_point_sync()
    }

    fn sync_kbd_led_state(&mut self, led: u8) -> Result<()> {
        let guest_stat = get_kbd_led_state();
        if led != guest_stat {
            let sync_bits = led ^ guest_stat;
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
        Ok(())
    }
}

#[derive(Default)]
struct InputDeviceState {
    input_notifier_id: u64,
    has_multitouch_screen: bool,
    has_multitouch_pad: bool,
}

#[derive(Default)]
pub struct OhUiMsgHandler {
    state: Mutex<WindowState>,
    hmcode2svcode: HashMap<u16, u16>,
    reader: Mutex<Option<MsgReader>>,
    writer: Arc<Mutex<Option<MsgWriter>>>,
    vm_pause: Arc<RwLock<bool>>,
    pause_notifier_id: Mutex<u64>,
    input_state: Arc<Mutex<InputDeviceState>>,
    surface_size: RwLock<(u32, u32)>,
}

impl OhUiMsgHandler {
    pub fn new() -> Self {
        let handler = OhUiMsgHandler {
            state: Mutex::new(WindowState::default()),
            hmcode2svcode: KeyCode::keysym_to_qkeycode(DpyMod::Ohui),
            reader: Mutex::new(None),
            writer: Arc::new(Mutex::new(None)),
            vm_pause: Arc::new(RwLock::new(false)),
            pause_notifier_id: Mutex::new(0),
            input_state: Arc::new(Mutex::new(InputDeviceState::default())),
            surface_size: RwLock::new((0, 0)),
        };
        handler.register_pause_notifier(handler.vm_pause.clone());
        handler.register_input_change_notifier();

        handler
    }

    fn register_pause_notifier(&self, vm_pause: Arc<RwLock<bool>>) {
        let pause_notify = Arc::new(move |paused: bool| {
            info!("Message Handler get vm pause state {:?}", paused);
            *vm_pause.write().unwrap() = paused;
        });
        *self.pause_notifier_id.lock().unwrap() = register_vm_pause_notifier(pause_notify);
    }

    fn register_input_change_notifier(&self) {
        let writer = self.writer.clone();
        let input_state = self.input_state.clone();
        let notifier = Arc::new(
            move |touchtype: MultitouchType, reason: InputStateChangeReason| {
                let internal_reason = match touchtype {
                    MultitouchType::Screen => match reason {
                        InputStateChangeReason::MultitouchRegister => {
                            input_state.lock().unwrap().has_multitouch_screen = true;
                            INPUT_MULTITOUCH_SCREEN_ONLINE
                        }
                        InputStateChangeReason::MultitouchUnregister => {
                            input_state.lock().unwrap().has_multitouch_screen = false;
                            INPUT_MULTITOUCH_SCREEN_OFFLINE
                        }
                    },
                    MultitouchType::Pad => match reason {
                        InputStateChangeReason::MultitouchRegister => {
                            input_state.lock().unwrap().has_multitouch_pad = true;
                            if let Err(e) = init_tp_emu() {
                                error!("failed to init touchpad emulator {:?}", e);
                            }
                            INPUT_MULTITOUCH_PAD_ONLINE
                        }
                        InputStateChangeReason::MultitouchUnregister => {
                            input_state.lock().unwrap().has_multitouch_pad = false;
                            uninit_tp_emu();
                            INPUT_MULTITOUCH_PAD_OFFLINE
                        }
                    },
                };
                send_input_device_change_msg(writer.clone(), internal_reason);
            },
        );

        self.input_state.lock().unwrap().input_notifier_id = register_input_notifier(notifier);
    }

    pub fn update_sock(&self, channel: Arc<Mutex<OhUiChannel>>) {
        let fd = channel.lock().unwrap().get_stream_raw_fd().unwrap();
        *self.reader.lock().unwrap() = Some(MsgReader::new(fd));
        *self.writer.lock().unwrap() = Some(MsgWriter::new(fd));
    }

    pub fn handle_msg(&self, token_id: Arc<RwLock<u64>>) -> Result<()> {
        let mut locked_reader = self.reader.lock().unwrap();
        let reader = locked_reader
            .as_mut()
            .with_context(|| "handle_msg: no connection established")?;
        if !reader.recv()? {
            return Ok(());
        }

        let hdr = &reader.header;
        let event_type = hdr.event_type;
        let body_size = hdr.size as usize;

        if event_type >= EventType::Max {
            error!("unsupported event type {:?}", event_type);
            reader.clear();
            return Ok(());
        }

        if self.filter_message(&event_type) {
            reader.clear();
            return Ok(());
        }

        trace::trace_scope_start!(handle_msg, args = (&event_type));

        let body_bytes = reader.body.as_ref().unwrap();

        if event_type == EventType::Greet {
            let body = GreetEvent::from_bytes(&body_bytes[..body_size]).unwrap();
            *token_id.write().unwrap() = body.token_id;
        }

        let handler = &MSG_HANDLER_TABLE[event_type as usize];
        if let Err(e) = handler(self, &body_bytes[..body_size]) {
            error!("handle_msg: error: {e}");
        }
        reader.clear();
        Ok(())
    }

    fn filter_message(&self, et: &EventType) -> bool {
        if !*self.vm_pause.read().unwrap() {
            return false;
        }

        let ret =
            matches!(et, EventType::WindowInfoExtension) || matches!(et, EventType::WindowInfo);
        !ret
    }

    fn handle_mouse_button(&self, mb: &MouseButtonEvent) -> Result<()> {
        let (msg_btn, action) = (mb.button, mb.btn_action);
        trace::oh_event_mouse_button(msg_btn, action);
        let btn = match msg_btn {
            CLIENT_MOUSE_BUTTON_LEFT => INPUT_POINT_LEFT,
            CLIENT_MOUSE_BUTTON_RIGHT => INPUT_POINT_RIGHT,
            CLIENT_MOUSE_BUTTON_MIDDLE => INPUT_POINT_MIDDLE,
            CLIENT_MOUSE_BUTTON_FORWARD => INPUT_POINT_FORWARD,
            CLIENT_MOUSE_BUTTON_BACK => INPUT_POINT_BACK,
            _ => bail!("Invalid mouse button number {}", msg_btn),
        };
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
        self.state.lock().unwrap().cursor = CursorState {
            w,
            h,
            hot_x,
            hot_y,
            size_per_pixel,
        };

        if let Some(writer) = self.writer.lock().unwrap().as_mut() {
            let body = HWCursorEvent::new(w, h, hot_x, hot_y, size_per_pixel);
            if let Err(e) = writer.send_message(EventType::CursorDefine, &body) {
                error!("handle_cursor_define: failed to send message with error {e}");
            }
        }
    }

    // NOTE: we only support absolute position info now, that means usb-mouse does not work.
    fn handle_mouse_motion(&self, mm: &MouseMotionEvent) -> Result<()> {
        trace::oh_event_mouse_motion(mm.x, mm.y);
        self.state.lock().unwrap().move_pointer(mm.x, mm.y)
    }

    fn handle_keyboard(&self, ke: &KeyboardEvent) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .sync_kbd_led_state(ke.led_state)?;
        let hmkey = ke.keycode;
        let keycode = match self.hmcode2svcode.get(&hmkey) {
            Some(k) => *k,
            None => {
                bail!("not supported keycode {}", hmkey);
            }
        };
        trace::oh_event_keyboard(keycode, ke.key_action);
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
        trace::oh_event_scroll(dir);
        Ok(())
    }

    fn handle_windowinfo(&self, wi: &WindowInfoEvent) {
        let cons = get_active_console();

        for con in cons {
            if let Some(c) = con.upgrade() {
                if let Err(e) = graphic_hardware_ui_info(c.clone(), wi.width, wi.height) {
                    error!("handle_windowinfo failed with error {e}");
                }
            }
        }
        trace::oh_event_windowinfo(wi.width, wi.height);
    }

    fn handle_windowinfo_extension(&self, wie: &WindowInfoExtensionEvent) -> Result<()> {
        *self.surface_size.write().unwrap() = (wie.surface_width, wie.surface_height);
        set_dpy_rotation(Rotation::try_from(wie.rotation).map_err(|e| anyhow!("{:?}", e))?);
        Ok(())
    }

    fn handle_focuschange(&self, fe: &FocusEvent) -> Result<()> {
        trace::oh_event_focus(fe.state);
        match fe.state {
            CLIENT_FOCUSIN_EVENT => {
                info!("received focus-in event");
            }
            CLIENT_FOCUSOUT_EVENT => {
                info!("received focus-out event");
                release_all_key()?;
                release_all_btn()?;
                lift_all_fingers()?;
            }
            _ => warn!("focus message type error."),
        }
        Ok(())
    }

    fn handle_multitouch_screen_event(&self, mtt: &MultiTouchScreenEvent) -> Result<()> {
        let mtt_type = mtt.event_type;
        let slot_id = mtt.tracking_id;
        let mut tracking_id = mtt.tracking_id;

        if mtt_type == MULTITOUCH_EVENT_CANCEL {
            return lift_all_fingers();
        }

        let evt_type = match mtt_type {
            MULTITOUCH_EVENT_DOWN => MultiTouchEventKind::BEGIN,
            MULTITOUCH_EVENT_MOVE => MultiTouchEventKind::UPDATE,
            MULTITOUCH_EVENT_UP => {
                tracking_id = -1;
                MultiTouchEventKind::END
            }
            _ => bail!("unsupported multitouch screen event type {}", mtt_type),
        };
        let mut evt = MultiTouchAbsData::new(
            evt_type,
            mtt.x,
            mtt.y,
            mtt.major,
            mtt.minor,
            slot_id,
            tracking_id,
        );
        let (w, h) = *self.surface_size.read().unwrap();

        send_mt_screen_event(&mut evt, w as i32, h as i32)?;
        send_mt_screen_sync()?;
        trace::oh_event_multitouch(
            mtt.x,
            mtt.y,
            mtt.major,
            mtt.minor,
            tracking_id,
            mtt.blob_id,
            mtt.pressure,
        );
        Ok(())
    }

    fn handle_touchpad_scroll(&self, mtt: &TouchPadScrollEvent) -> Result<()> {
        let action = try_into_mt_event(mtt.action)?;
        let evt = TouchPadScrollData::new(action, mtt.horizontal, mtt.vertical);
        send_scroll_event(evt)
    }

    fn handle_touchpad_pinch(&self, mtt: &TouchPadPinchEvent) -> Result<()> {
        let action = try_into_mt_event(mtt.action)?;
        let evt = TouchPadPinchData::new(action, mtt.pinch);
        send_pinch_event(evt)
    }

    pub fn send_windowinfo(&self, w: u32, h: u32) {
        self.state.lock().unwrap().update_window_info(w, h);
        if let Some(writer) = self.writer.lock().unwrap().as_mut() {
            let body = WindowInfoEvent::new(w, h);
            if let Err(e) = writer.send_message(EventType::WindowInfo, &body) {
                error!("send_windowinfo: failed to send message with error {e}");
            }
        }
    }

    pub fn send_input_device_state(&self) {
        match self.input_state.lock().unwrap().has_multitouch_screen {
            true => {
                send_input_device_change_msg(self.writer.clone(), INPUT_MULTITOUCH_SCREEN_ONLINE)
            }
            false => {
                send_input_device_change_msg(self.writer.clone(), INPUT_MULTITOUCH_SCREEN_OFFLINE)
            }
        }
        match self.input_state.lock().unwrap().has_multitouch_pad {
            true => send_input_device_change_msg(self.writer.clone(), INPUT_MULTITOUCH_PAD_ONLINE),
            false => {
                send_input_device_change_msg(self.writer.clone(), INPUT_MULTITOUCH_PAD_OFFLINE)
            }
        }
    }

    pub fn handle_dirty_area(&self, x: u32, y: u32, w: u32, h: u32) {
        if let Some(writer) = self.writer.lock().unwrap().as_mut() {
            let body = FrameBufferDirtyEvent::new(x, y, w, h);
            if let Err(e) = writer.send_message(EventType::FrameBufferDirty, &body) {
                error!("handle_dirty_area: failed to send message with error {e}");
            }
        }
    }

    pub fn reset(&self) {
        *self.reader.lock().unwrap() = None;
        *self.writer.lock().unwrap() = None;
    }
}

type MsgHandleFunc = Box<dyn Fn(&OhUiMsgHandler, &[u8]) -> Result<()> + Send + Sync>;

static MSG_HANDLER_TABLE: LazyLock<Vec<MsgHandleFunc>> = LazyLock::new(|| {
    vec![
        // WindowInfo        0
        Box::new(window_info_handler),
        // MouseButton       1
        Box::new(mouse_button_handler),
        // MouseMotion       2
        Box::new(mouse_motion_handler),
        // Keyboard          3
        Box::new(keyboard_handler),
        // Scroll            4
        Box::new(scroll_handler),
        // Ledstate          5
        Box::new(stub_handler),
        // FrameBufferDirty  6
        Box::new(stub_handler),
        // Greet             7
        Box::new(greet_handler),
        // CursorDefine      8
        Box::new(stub_handler),
        // Focus             9
        Box::new(focus_handler),
        // VmCtrlInfo        10
        Box::new(stub_handler),
        // FlushFrame        11
        Box::new(flush_frame_handler),
        // MultitouchScreen  12
        Box::new(mtt_screen_handler),
        // InputDeviceChange 13
        Box::new(stub_handler),
        // WindowInfoV2      14
        Box::new(windowinfo_extension_handler),
        // VmViewChange      15
        Box::new(vm_view_change_handler),
        // TouchPadScroll    16
        Box::new(tp_scroll_handler),
        // TouchPadPinch     17
        Box::new(tp_pinch_handler),
    ]
});

fn stub_handler(_msg_handler: &OhUiMsgHandler, _body_bytes: &[u8]) -> Result<()> {
    Ok(())
}

fn window_info_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = WindowInfoEvent::from_bytes(body_bytes).unwrap();
    info!("{:?}", body);
    msg_handler.handle_windowinfo(body);
    Ok(())
}

fn mouse_button_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = MouseButtonEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_mouse_button(body)
}

fn mouse_motion_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = MouseMotionEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_mouse_motion(body)
}

fn keyboard_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = KeyboardEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_keyboard(body)
}

fn scroll_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = ScrollEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_scroll(body)
}

fn greet_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = GreetEvent::from_bytes(body_bytes).unwrap();
    trace::oh_event_greet(body.token_id);
    let cursor = msg_handler.state.lock().unwrap().cursor.clone();
    msg_handler.handle_cursor_define(
        cursor.w,
        cursor.h,
        cursor.hot_x,
        cursor.hot_y,
        cursor.size_per_pixel,
    );
    Ok(())
}

fn focus_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = FocusEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_focuschange(body)
}

fn flush_frame_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    stub_handler(msg_handler, body_bytes)
}

fn mtt_screen_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = MultiTouchScreenEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_multitouch_screen_event(body)
}

fn windowinfo_extension_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = WindowInfoExtensionEvent::from_bytes(body_bytes).unwrap();
    info!("{:?}", body);
    msg_handler.handle_windowinfo_extension(body)
}

fn vm_view_change_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    stub_handler(msg_handler, body_bytes)
}

fn tp_scroll_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = TouchPadScrollEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_touchpad_scroll(body)
}

fn tp_pinch_handler(msg_handler: &OhUiMsgHandler, body_bytes: &[u8]) -> Result<()> {
    let body = TouchPadPinchEvent::from_bytes(body_bytes).unwrap();
    msg_handler.handle_touchpad_pinch(body)
}

fn send_input_device_change_msg(writer: Arc<Mutex<Option<MsgWriter>>>, reason: u64) {
    if let Some(writer) = writer.lock().unwrap().as_mut() {
        let body = InputDeviceChange::new(reason);
        if let Err(e) = writer.send_message(EventType::InputDeviceChange, &body) {
            error!("failed to send InputDeviceChange message with error {e}");
        }
    }
}

struct MsgReader {
    /// cache for header
    header: EventMsgHdr,
    /// received byte size of header
    header_ready: usize,
    /// cache of body
    body: Option<Vec<u8>>,
    /// received byte size of body
    body_ready: usize,
    /// UnixStream to read
    sock: UnixStream,
}

impl MsgReader {
    pub fn new(fd: RawFd) -> Self {
        MsgReader {
            header: EventMsgHdr::default(),
            header_ready: 0,
            body: None,
            body_ready: 0,
            // SAFETY: The fd is valid only when the new connection has been established
            // and MsgReader instance would be destroyed when disconnected.
            sock: unsafe { UnixStream::from_raw_fd(fd) },
        }
    }

    pub fn recv(&mut self) -> Result<bool> {
        if self.recv_header()? {
            self.check_header()?;
            return self.recv_body();
        }
        Ok(false)
    }

    fn clear(&mut self) {
        self.header_ready = 0;
        self.body_ready = 0;
        self.body = None;
    }

    fn check_header(&mut self) -> Result<()> {
        let expected_size = event_msg_data_len(self.header.event_type);
        if expected_size != self.header.size as usize {
            self.clear();
            bail!(
                "{:?} data len is wrong, we want {}, but receive {}",
                self.header.event_type as EventType,
                expected_size,
                self.header.size as usize,
            );
        }
        Ok(())
    }

    fn recv_header(&mut self) -> Result<bool> {
        if self.header_ready == EVENT_MSG_HDR_SIZE as usize {
            return Ok(true);
        }

        let buf = self.header.as_mut_bytes();
        self.header_ready += recv_slice(&mut self.sock, &mut buf[self.header_ready..])?;
        Ok(self.header_ready == EVENT_MSG_HDR_SIZE as usize)
    }

    fn recv_body(&mut self) -> Result<bool> {
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
        // buf's capacity is equal to body_size. 2. buf has 'u8'
        // type elements, it will be initialized by zero.
        unsafe {
            buf.set_len(body_size);
        }
        self.body_ready += recv_slice(&mut self.sock, &mut buf[self.body_ready..])?;

        Ok(self.body_ready == body_size)
    }
}

struct MsgWriter {
    sock: UnixStream,
}

impl MsgWriter {
    fn new(fd: RawFd) -> Self {
        Self {
            // SAFETY: The fd is valid only when the new connection has been established
            // and MsgWriter instance would be destroyed when disconnected.
            sock: unsafe { UnixStream::from_raw_fd(fd) },
        }
    }

    fn send_message<T: Sized + Default + ByteCode>(
        &mut self,
        t: EventType,
        body: &T,
    ) -> Result<()> {
        let hdr = EventMsgHdr::new(t);
        send_obj(&mut self.sock, &hdr)?;
        send_obj(&mut self.sock, body)
    }
}
