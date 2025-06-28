// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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
    sync::{Arc, Condvar, LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use log::{error, info, warn};
use util::evdev::*;

use crate::input::{
    get_mt_pad_feature, send_mt_pad_raw_events, send_mt_pad_sync, MultiTouchEventKind,
};

// Currently we only support maximum 2 fingers.
const SUPPORT_SLOT_MAX: usize = 2;

// If we send all events for 2 fingers, the events are like below:
// ABS_MT_SLOT 0
// ABS_TRACKING_ID 0
// ABS_MT_POSITION_X
// ABS_MT_POSITION_Y
// ABS_MT_SLOT 1
// ABS_TRACKING_ID 1
// ABS_MT_POSITION_X
// ABS_MT_POSITION_Y
// SYN_REPORT
//
// So 20 is enough for current limitation of 2 fingers support.
const MAX_EVENT_SIZE: usize = 20;

// After scroll/pinch begins, we need to send sync event at intervals to
// make Windows be aware of the finger is still down because MultiModal
// scroll/pinch UPDATE events intervals might be longer than 20ms and unstable.
const SEND_SYNC_INTERVAL: u64 = 40;

// We use 1.5s because most slides will end after 1.5 seconds in windows.
const SLIDE_WAIT_TIME: u64 = 1500;
// When the last scroll pixel exceeds 15, We think there will be a slide
const SLIDE_CHECK_PIXELS: i32 = 15;
// The distance between two fingers when scrolling
const DISTANCE_BETWEEN_TWO_FINGERS_SCROLL: i32 = 5;
// two fingers
const TWO_FINGERS: usize = 2;
// Minimum scroll pixels, When the scroll pixels is too small,
// Windows will think it is a two-finger touch.
const MIN_SCROLL_PIXELS: i32 = 180;

#[derive(Clone)]
struct MultiTouchPadAbsData {
    pub x: i32,
    pub x_update: i32,
    pub y: i32,
    pub y_update: i32,
}

impl MultiTouchPadAbsData {
    pub fn new(x: i32, x_update: i32, y: i32, y_update: i32) -> Self {
        Self {
            x,
            x_update,
            y,
            y_update,
        }
    }
}

#[derive(Clone)]
pub struct TouchPadScrollData {
    pub action: MultiTouchEventKind,
    pub horizontal: f64,
    pub vertical: f64,
}

impl TouchPadScrollData {
    pub fn new(action: MultiTouchEventKind, horizontal: f64, vertical: f64) -> Self {
        Self {
            action,
            horizontal,
            vertical,
        }
    }
}

#[derive(Clone)]
pub struct TouchPadPinchData {
    pub action: MultiTouchEventKind,
    pub pinch: f64,
}

impl TouchPadPinchData {
    pub fn new(action: MultiTouchEventKind, pinch: f64) -> Self {
        Self { action, pinch }
    }
}

#[derive(Default)]
enum MultiTouchPadStatus {
    #[default]
    Up,
    Down,
    Stop,
}

#[derive(Clone)]
struct TouchpadEmulator {
    init: bool,
    x_max: i32,
    y_max: i32,
    slots: Vec<MultiTouchPadAbsData>,
    evts: Vec<InputEvent>,
    first_scroll: bool,
    touch_state: Arc<(Mutex<MultiTouchPadStatus>, Condvar)>,
    slide_begin: Instant,
    sliding: bool,
}

impl TouchpadEmulator {
    fn new() -> Self {
        TouchpadEmulator {
            init: false,
            x_max: 0,
            y_max: 0,
            slots: vec![MultiTouchPadAbsData::new(0, 0, 0, 0); SUPPORT_SLOT_MAX],
            evts: Vec::with_capacity(MAX_EVENT_SIZE),
            first_scroll: false,
            touch_state: Arc::new((Mutex::new(MultiTouchPadStatus::default()), Condvar::new())),
            slide_begin: Instant::now(),
            sliding: false,
        }
    }

    fn init(&mut self) -> Result<()> {
        let (x_max, y_max) = get_mt_pad_feature()?;

        self.set_touch_status(MultiTouchPadStatus::Up);
        if let Err(e) = self.start_thread() {
            bail!("failed to create touchpad emulator thread {:?}", e);
        }

        self.x_max = x_max;
        self.y_max = y_max;
        self.init = true;
        Ok(())
    }

    fn uninit(&mut self) {
        self.set_touch_status(MultiTouchPadStatus::Stop);
        self.x_max = 0;
        self.y_max = 0;
        self.init = false;
    }

    fn start_thread(&self) -> Result<()> {
        let cloned_touch_state = Arc::clone(&self.touch_state);

        thread::Builder::new()
            .name("touchpad emulator thread".to_string())
            .spawn(move || {
                info!("touchpad emulator thread is running");
                let (state, cvar) = &*cloned_touch_state;
                loop {
                    let locked_state = state.lock().unwrap();
                    match *locked_state {
                        MultiTouchPadStatus::Up => {
                            let _unused = cvar.wait(locked_state).unwrap();
                        }
                        MultiTouchPadStatus::Down => {
                            let (_unused, timeout) = cvar
                                .wait_timeout(
                                    locked_state,
                                    Duration::from_millis(SEND_SYNC_INTERVAL),
                                )
                                .unwrap();
                            if timeout.timed_out() {
                                if let Err(e) = send_mt_pad_sync() {
                                    error!(
                                        "touchpad emulator thread: failed to send sync event {:?}",
                                        e
                                    );
                                }
                            }
                        }
                        MultiTouchPadStatus::Stop => break,
                    }
                }
                info!("touchpad emulator thread is exiting");
            })?;
        Ok(())
    }

    fn set_touch_status(&self, new_state: MultiTouchPadStatus) {
        let (state, cvar) = &*self.touch_state;
        let mut locked_state = state.lock().unwrap();
        *locked_state = new_state;
        cvar.notify_one();
    }

    fn stop_slide(&mut self) -> Result<bool> {
        if !self.sliding || self.slide_begin.elapsed() >= Duration::from_millis(SLIDE_WAIT_TIME) {
            return Ok(false);
        }

        // Simulate a two-finger touch to stop the slide.
        // The physical distance between the fingers should be large enough(about > 40mm),
        // otherwise it will trigger the right-click gesture of Windows. For general touchpads,
        // distance of x_max/2 is enough.
        let evts = [
            InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, 0),
            InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, 0),
            InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_X, self.x_max / 4),
            InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_Y, self.y_max / 2),
            InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, 1),
            InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, 1),
            InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_X, self.x_max * 3 / 4),
            InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_Y, self.y_max / 2),
            InputEvent::new(EV_SYN, SYN_REPORT, 0),
            InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, 0),
            InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, -1),
            InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, 1),
            InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, -1),
            InputEvent::new(EV_SYN, SYN_REPORT, 0),
        ];
        send_mt_pad_raw_events(&evts)?;
        self.sliding = false;
        Ok(true)
    }

    fn handle_finger_event(&mut self, finger_count: usize) -> Result<()> {
        if finger_count > self.slots.len() {
            bail!("unsupported count of fingers: {}", finger_count);
        }

        self.evts.clear();
        for (i, slot) in self.slots[0..finger_count].iter().enumerate() {
            if slot.x < 0 || slot.x > self.x_max || slot.y < 0 || slot.y > self.y_max {
                warn!("position out of bounds: x {}, y {}", slot.x, slot.y);
                return Ok(());
            }
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, i as i32));
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, i as i32));
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_X, slot.x));
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_POSITION_Y, slot.y));
        }
        self.evts.push(InputEvent::new(EV_SYN, SYN_REPORT, 0));
        send_mt_pad_raw_events(&self.evts)
    }

    fn send_scroll_event(&mut self, evt: TouchPadScrollData) -> Result<()> {
        if !self.init {
            warn!("touchpad emulator is not init, ignore scroll event");
            return Ok(());
        }

        match evt.action {
            MultiTouchEventKind::BEGIN => {
                // In BEGIN event, horizontal and vertical is 0. Let's just
                // reset finger slots to the central of touchpad and set
                // first scroll to true for the first UPDATE event.
                self.handle_scroll(evt.horizontal, evt.vertical, true)?;
                self.set_touch_status(MultiTouchPadStatus::Down);
                self.first_scroll = true;
            }
            MultiTouchEventKind::UPDATE => {
                self.handle_scroll(evt.horizontal, evt.vertical, false)?;
                self.first_scroll = false;
            }
            MultiTouchEventKind::END => {
                self.set_touch_status(MultiTouchPadStatus::Up);
                self.lift_all_fingers()?;
                if self.slots[0].x_update.abs() > SLIDE_CHECK_PIXELS
                    || self.slots[0].y_update.abs() > SLIDE_CHECK_PIXELS
                {
                    self.slide_begin = Instant::now();
                    self.sliding = true;
                }
            }
        }
        Ok(())
    }

    fn handle_scroll(&mut self, horizontal: f64, vertical: f64, begin: bool) -> Result<()> {
        let distance = DISTANCE_BETWEEN_TWO_FINGERS_SCROLL;
        if begin {
            self.slots[0].x = self.x_max / 2 - distance;
            self.slots[0].y = self.y_max / 2 - distance;
            self.slots[1].x = self.x_max / 2 + distance;
            self.slots[1].y = self.y_max / 2 + distance;
            self.handle_finger_event(TWO_FINGERS)?;
            return Ok(());
        }

        // In OHOS, the ratio of horizontal/vertical and touchpad pixels
        // is not constant. Normally, it is like this:
        //   vertical    | pixels change | (pixel/vertical)
        // ------------  |-------------|-----------------
        //   16.3878     | 45          | ≈ 2.746
        //   18.4133     | 55          | ≈ 2.987
        //   58.7383     | 163         | ≈ 2.775
        //   60.3955     | 165         | ≈ 2.732
        //   117.2926    | 329         | ≈ 2.805
        //   122.2643    | 335         | ≈ 2.739
        // The ratio between them is about 2.8
        // But when the horizontal/vertical is small, this ratio will change:
        //   vertical    | pixels change | (pixel/vertical)
        // ------------  |-------------|-----------------
        //   0.70832     | 1           | ≈ 1.412
        //   1.41664     | 2           | ≈ 1.412
        //   1.93317     | 3           | ≈ 1.552
        //   2.42090     | 4           | ≈ 1.652
        //   3.19456     | 6           | ≈ 1.878
        //   3.94942     | 8           | ≈ 2.026
        //   4.57256     | 10          | ≈ 2.187
        //   5.00945     | 12          | ≈ 2.396
        //   5.80351     | 15          | ≈ 2.585
        // and horizontal is similar, so we need to restore them.
        // The following is an approximate ratio.
        let speed = if horizontal.abs() > 6.0 || vertical.abs() > 6.0 {
            2.8
        } else if horizontal.abs() > 4.0 || vertical.abs() > 4.0 {
            2.2
        } else if horizontal.abs() > 2.0 || vertical.abs() > 2.0 {
            1.8
        } else if horizontal.abs() > 0.4 || vertical.abs() > 0.4 {
            1.4
        } else {
            // When horizontal/vertical * speed is too small(about < 0.5),
            // we don't think it's a scroll, just return it.
            return Ok(());
        };
        loop {
            let x_total = self.slots[0].x + self.slots[1].x - (horizontal * speed).round() as i32;
            let y_total = self.slots[0].y + self.slots[1].y - (vertical * speed).round() as i32;

            self.slots[0].x_update = x_total / 2 - self.slots[0].x - distance;
            self.slots[0].x = x_total / 2 - distance;
            self.slots[0].y_update = y_total / 2 - self.slots[0].y - distance;
            self.slots[0].y = y_total / 2 - distance;
            self.slots[1].x_update = x_total - x_total / 2 - self.slots[1].x + distance;
            self.slots[1].x = x_total - x_total / 2 + distance;
            self.slots[1].y_update = y_total - y_total / 2 - self.slots[1].y + distance;
            self.slots[1].y = y_total - y_total / 2 + distance;
            self.handle_finger_event(TWO_FINGERS)?;

            if !self.first_scroll
                || (x_total - self.x_max).abs() > MIN_SCROLL_PIXELS
                || (y_total - self.y_max).abs() > MIN_SCROLL_PIXELS
            {
                break;
            }
        }
        Ok(())
    }

    fn send_pinch_event(&mut self, evt: TouchPadPinchData) -> Result<()> {
        if !self.init {
            warn!("touchpad emulator is not init, ignore pinch event");
            return Ok(());
        }

        match evt.action {
            MultiTouchEventKind::BEGIN => {
                self.handle_pinch(evt.pinch)?;
                self.set_touch_status(MultiTouchPadStatus::Down);
            }
            MultiTouchEventKind::UPDATE => {
                self.handle_pinch(evt.pinch)?;
            }
            MultiTouchEventKind::END => {
                self.set_touch_status(MultiTouchPadStatus::Up);
                self.lift_all_fingers()?;
            }
        }
        Ok(())
    }

    fn handle_pinch(&mut self, value: f64) -> Result<()> {
        // The initial distance between x and y is 1/5, so the maximum zoom
        // in pinch simulation is 5. When value < 4, we zoom in normally.
        // When the value > 4, we calculate the return value let it never
        // greater than 5.
        let change_value = if value > 4.0 {
            (4.0 - 1.0 / (1.0 + (value - 4.0))) / 10.0
        } else {
            (value - 1.0) / 10.0
        };
        self.slots[0].x = self.x_max * 2 / 5 - (change_value * self.x_max as f64).round() as i32;
        self.slots[0].y = self.y_max * 2 / 5 - (change_value * self.y_max as f64).round() as i32;
        self.slots[1].x = self.x_max * 3 / 5 + (change_value * self.x_max as f64).round() as i32;
        self.slots[1].y = self.y_max * 3 / 5 + (change_value * self.y_max as f64).round() as i32;
        self.handle_finger_event(TWO_FINGERS)
    }

    fn lift_all_fingers(&mut self) -> Result<()> {
        let len = self.slots.len();
        self.evts.clear();

        for i in 0..len {
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_SLOT, i as i32));
            self.evts
                .push(InputEvent::new_u8(EV_ABS, ABS_MT_TRACKING_ID, -1));
        }
        self.evts.push(InputEvent::new(EV_SYN, SYN_REPORT, 0));

        send_mt_pad_raw_events(&self.evts)
    }
}

static TP_EMU: LazyLock<Mutex<TouchpadEmulator>> =
    LazyLock::new(|| Mutex::new(TouchpadEmulator::new()));

pub fn send_pinch_event(evt: TouchPadPinchData) -> Result<()> {
    TP_EMU.lock().unwrap().send_pinch_event(evt)
}

pub fn send_scroll_event(evt: TouchPadScrollData) -> Result<()> {
    TP_EMU.lock().unwrap().send_scroll_event(evt)
}

pub fn stop_slide() -> Result<bool> {
    TP_EMU.lock().unwrap().stop_slide()
}

pub fn init_tp_emu() -> Result<()> {
    TP_EMU.lock().unwrap().init()
}

pub fn uninit_tp_emu() {
    TP_EMU.lock().unwrap().uninit()
}
