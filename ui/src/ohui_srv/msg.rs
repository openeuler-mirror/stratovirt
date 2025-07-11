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
use std::sync::LazyLock;

use anyhow::{bail, Result};
use util::byte_code::ByteCode;

use crate::input::MultiTouchEventKind;

pub const CLIENT_FOCUSIN_EVENT: u32 = 0x0;
pub const CLIENT_FOCUSOUT_EVENT: u32 = 0x1;
pub const CLIENT_PRESS_BTN: u32 = 0x1;
pub const CLIENT_RELEASE_BTN: u32 = 0x0;
pub const CLIENT_WHEEL_UP: u32 = 0x1;
pub const CLIENT_WHEEL_DOWN: u32 = 0x2;
pub const CLIENT_WHEEL_LEFT: u32 = 0x3;
pub const CLIENT_WHEEL_RIGHT: u32 = 0x4;
pub const CLIENT_MOUSE_BUTTON_LEFT: u32 = 0x0;
pub const CLIENT_MOUSE_BUTTON_RIGHT: u32 = 0x1;
pub const CLIENT_MOUSE_BUTTON_MIDDLE: u32 = 0x2;
pub const CLIENT_MOUSE_BUTTON_BACK: u32 = 0x3;
pub const CLIENT_MOUSE_BUTTON_FORWARD: u32 = 0x4;
pub const EVENT_MSG_HDR_SIZE: u32 = size_of::<EventMsgHdr>() as u32;

#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialOrd, PartialEq)]
pub enum EventType {
    WindowInfo = 0,
    MouseButton = 1,
    MouseMotion = 2,
    Keyboard = 3,
    Scroll = 4,
    Ledstate = 5,
    FrameBufferDirty = 6,
    Greet = 7,
    CursorDefine = 8,
    Focus = 9,
    VmCtrlInfo = 10,
    FlushFrame = 11,
    MultitouchScreen = 12,
    InputDeviceChange = 13,
    WindowInfoExtension = 14,
    VmViewChange = 15,
    TouchPadScroll = 16,
    TouchPadPinch = 17,
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
    pub led_state: u8,
    pad: [u8; 3],
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

// Currently we only expose 3 fingers at most to the guest.
// The touch with more than 3 fingers is interpreted by Harmony.
pub const MULTITOUCH_SLOT_MAX: usize = 3;
pub const MULTITOUCH_EVENT_DOWN: u32 = 0;
pub const MULTITOUCH_EVENT_MOVE: u32 = 1;
pub const MULTITOUCH_EVENT_UP: u32 = 2;
pub const MULTITOUCH_EVENT_CANCEL: u32 = 3;

pub fn try_into_mt_event(evt: u32) -> Result<MultiTouchEventKind> {
    Ok(match evt {
        MULTITOUCH_EVENT_DOWN => MultiTouchEventKind::BEGIN,
        MULTITOUCH_EVENT_MOVE => MultiTouchEventKind::UPDATE,
        MULTITOUCH_EVENT_UP => MultiTouchEventKind::END,
        _ => bail!("unknown event {}", evt),
    })
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct MultiTouchScreenEvent {
    // 0: start(finger starts to press)
    // 1: update(finger moves)
    // 2: end(finger leaves)
    // 3: cancel(lift all fingers)
    pub event_type: u32,
    pub tracking_id: i32,
    pub x: i32,
    pub y: i32,
    pub major: i32,
    pub minor: i32,
    pub pressure: u32,
    pub blob_id: u32,
}

impl ByteCode for MultiTouchScreenEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FlushFrameEvent {
    pub reserved: u64,
}

impl ByteCode for FlushFrameEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct InputDeviceChange {
    pub reason: u64,
}

impl ByteCode for InputDeviceChange {}

impl InputDeviceChange {
    pub fn new(reason: u64) -> Self {
        Self { reason }
    }
}

pub const INPUT_MULTITOUCH_SCREEN_ONLINE: u64 = 1;
pub const INPUT_MULTITOUCH_SCREEN_OFFLINE: u64 = 2;
pub const INPUT_MULTITOUCH_PAD_ONLINE: u64 = 3;
pub const INPUT_MULTITOUCH_PAD_OFFLINE: u64 = 4;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct WindowInfoExtensionEvent {
    pub surface_width: u32,
    pub surface_height: u32,
    pub rotation: u32,
    pub fold_status: u32,
}

impl ByteCode for WindowInfoExtensionEvent {}

pub const WINDOW_ROTATION_0: u32 = 0;
pub const WINDOW_ROTATION_90: u32 = 1;
pub const WINDOW_ROTATION_180: u32 = 2;
pub const WINDOW_ROTATION_270: u32 = 3;

pub const FOLD_STATUS_UNKNOWN: u32 = 0;
pub const FOLD_STATUS_EXPAND: u32 = 1;
pub const FOLD_STATUS_FOLDED: u32 = 2;
pub const FOLD_STATUS_HALF_FOLDED: u32 = 3;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TouchPadScrollEvent {
    pub action: u32,
    pub horizontal: f64,
    pub vertical: f64,
}

impl ByteCode for TouchPadScrollEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct TouchPadPinchEvent {
    pub action: u32,
    pub pinch: f64,
}

impl ByteCode for TouchPadPinchEvent {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct VmViewChangeEvent {
    pub is_recreate: u32,
}

impl ByteCode for VmViewChangeEvent {}

impl VmViewChangeEvent {
    pub fn new(is_recreate: u32) -> Self {
        VmViewChangeEvent { is_recreate }
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
    static EVENT_LEN: LazyLock<Vec<usize>> = LazyLock::new(|| {
        vec![
            // WindowInfo
            size_of::<WindowInfoEvent>(),
            // MouseButton
            size_of::<MouseButtonEvent>(),
            // MouseMotion
            size_of::<MouseMotionEvent>(),
            // Keyboard
            size_of::<KeyboardEvent>(),
            // Scroll
            size_of::<ScrollEvent>(),
            // LedState
            size_of::<LedstateEvent>(),
            // FrameBufferDirty
            size_of::<FrameBufferDirtyEvent>(),
            // Greet
            size_of::<GreetEvent>(),
            // CursorDefine
            size_of::<HWCursorEvent>(),
            // Focus
            size_of::<FocusEvent>(),
            // VmCtrlInfo
            0,
            // FlushFrame
            size_of::<FlushFrameEvent>(),
            // MultitouchScreen
            size_of::<MultiTouchScreenEvent>(),
            // InputDeviceChange
            size_of::<InputDeviceChange>(),
            // WindowInfoV2
            size_of::<WindowInfoExtensionEvent>(),
            // VmViewChange
            size_of::<VmViewChangeEvent>(),
            // TouchPadScroll
            size_of::<TouchPadScrollEvent>(),
            // TouchPadPinch
            size_of::<TouchPadPinchEvent>(),
        ]
    });

    if event_type >= EventType::Max {
        0
    } else {
        EVENT_LEN[event_type as usize]
    }
}
