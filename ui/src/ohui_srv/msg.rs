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

use std::mem::size_of;

use util::byte_code::ByteCode;

pub const CLIENT_FOCUSOUT_EVENT: u32 = 0x1;
pub const CLIENT_PRESS_BTN: u32 = 0x1;
pub const CLIENT_RELEASE_BTN: u32 = 0x0;
pub const CLIENT_WHEEL_UP: u32 = 0x1;
pub const CLIENT_WHEEL_DOWN: u32 = 0x2;
pub const CLIENT_WHEEL_LEFT: u32 = 0x3;
pub const CLIENT_WHEEL_RIGHT: u32 = 0x4;
pub const EVENT_MSG_HDR_SIZE: u32 = size_of::<EventMsgHdr>() as u32;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub enum EventType {
    WindowInfo,
    MouseButton,
    MouseMotion,
    Keyboard,
    Scroll,
    Ledstate,
    FrameBufferDirty,
    Greet,
    CursorDefine,
    Focus,
    VmCtrlInfo,
    #[default]
    Max,
}

impl ByteCode for EventType {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WindowInfoEvent {
    pub width: u32,
    pub height: u32,
}

impl ByteCode for WindowInfoEvent {}

impl WindowInfoEvent {
    pub fn new(width: u32, height: u32) -> Self {
        WindowInfoEvent { width, height }
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct HWCursorEvent {
    pub w: u32,
    pub h: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub size_per_pixel: u32,
}

impl HWCursorEvent {
    pub fn new(w: u32, h: u32, hot_x: u32, hot_y: u32, size_per_pixel: u32) -> Self {
        HWCursorEvent {
            w,
            h,
            hot_x,
            hot_y,
            size_per_pixel,
        }
    }
}

impl ByteCode for HWCursorEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MouseButtonEvent {
    pub button: u32,
    pub btn_action: u32,
}

impl ByteCode for MouseButtonEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MouseMotionEvent {
    pub x: f64,
    pub y: f64,
}

impl ByteCode for MouseMotionEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct KeyboardEvent {
    pub key_action: u16,
    pub keycode: u16,
}

impl ByteCode for KeyboardEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ScrollEvent {
    pub direction: u32,
    pub delta_x: f64,
    pub delta_y: f64,
}

impl ByteCode for ScrollEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LedstateEvent {
    pub state: u32,
}

impl ByteCode for LedstateEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct GreetEvent {
    pad: [u32; 6],
    pub token_id: u64,
}

impl ByteCode for GreetEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FocusEvent {
    pub state: u32,
}

impl ByteCode for FocusEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FrameBufferDirtyEvent {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

impl ByteCode for FrameBufferDirtyEvent {}

impl FrameBufferDirtyEvent {
    pub fn new(x: u32, y: u32, w: u32, h: u32) -> Self {
        FrameBufferDirtyEvent { x, y, w, h }
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct EventMsgHdr {
    pub magic: u32,
    pub size: u32,
    pub event_type: EventType,
}

impl ByteCode for EventMsgHdr {}

impl EventMsgHdr {
    pub fn new(event_type: EventType) -> EventMsgHdr {
        EventMsgHdr {
            magic: 0,
            size: event_msg_data_len(event_type) as u32,
            event_type,
        }
    }
}

pub fn event_msg_data_len(event_type: EventType) -> usize {
    match event_type {
        EventType::WindowInfo => size_of::<WindowInfoEvent>(),
        EventType::MouseButton => size_of::<MouseButtonEvent>(),
        EventType::MouseMotion => size_of::<MouseMotionEvent>(),
        EventType::Keyboard => size_of::<KeyboardEvent>(),
        EventType::Scroll => size_of::<ScrollEvent>(),
        EventType::Focus => size_of::<FocusEvent>(),
        EventType::FrameBufferDirty => size_of::<FrameBufferDirtyEvent>(),
        EventType::CursorDefine => size_of::<HWCursorEvent>(),
        EventType::Ledstate => size_of::<LedstateEvent>(),
        EventType::Greet => size_of::<GreetEvent>(),
        _ => 0,
    }
}
