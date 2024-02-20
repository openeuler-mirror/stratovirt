// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::os::raw::c_void;
use std::sync::{
    atomic::{fence, AtomicI32, Ordering},
    Arc, Mutex,
};
use std::{cmp, ptr, thread, time};

use log::{error, warn};

use super::ohaudio_bindings::{OhAudioCapturer, OhAudioRenderer};
use super::ohaudio_rapi::{AudioContext, AudioProcessCb, AudioStreamType};
use crate::misc::scream::{AudioInterface, ScreamDirection, ShmemStreamHeader, StreamData};

trait OhAudioProcess {
    fn init(&mut self, stream: &StreamData) -> bool;
    fn destroy(&mut self);
    fn preprocess(&mut self, _start_addr: u64, _sh_header: &ShmemStreamHeader) {}
    fn process(&mut self, recv_data: &StreamData) -> i32;
}

#[derive(Debug, Clone, Copy)]
struct StreamUnit {
    pub addr: u64,
    pub len: u64,
}

const STREAM_DATA_VEC_CAPACITY: usize = 30;

struct OhAudioRender {
    ctx: Option<AudioContext>,
    stream_data: Arc<Mutex<Vec<StreamUnit>>>,
    prepared_data: u32,
    start: bool,
}

impl Default for OhAudioRender {
    fn default() -> OhAudioRender {
        OhAudioRender {
            ctx: None,
            stream_data: Arc::new(Mutex::new(Vec::with_capacity(STREAM_DATA_VEC_CAPACITY))),
            prepared_data: 0,
            start: false,
        }
    }
}

impl OhAudioRender {
    #[inline(always)]
    fn check_data_ready(&self, recv_data: &StreamData) -> bool {
        let size = recv_data.fmt.size as u32 / 8;
        let channels = recv_data.fmt.channels as u32;
        let rate = recv_data.fmt.get_rate();
        // Wait for data of 500 ms ready.
        // FIXME: the value of rate is wrong.
        self.prepared_data >= (size * channels * rate / 2)
    }

    fn check_fmt_update(&mut self, recv_data: &StreamData) {
        if self.ctx.is_some()
            && !self.ctx.as_ref().unwrap().check_fmt(
                recv_data.fmt.size,
                recv_data.fmt.get_rate(),
                recv_data.fmt.channels,
            )
        {
            self.destroy();
        }
    }
}

impl OhAudioProcess for OhAudioRender {
    fn init(&mut self, stream: &StreamData) -> bool {
        let mut context = AudioContext::new(AudioStreamType::Render);
        match context.init(
            stream.fmt.size,
            stream.fmt.get_rate(),
            stream.fmt.channels,
            AudioProcessCb::RendererCb(Some(on_write_data_cb)),
            ptr::addr_of!(*self) as *mut c_void,
        ) {
            Ok(()) => self.ctx = Some(context),
            Err(e) => {
                error!("failed to create oh audio render context: {}", e);
                return false;
            }
        }
        match self.ctx.as_ref().unwrap().start() {
            Ok(()) => {
                self.start = true;
                true
            }
            Err(e) => {
                error!("failed to start oh audio renderer: {}", e);
                false
            }
        }
    }

    fn destroy(&mut self) {
        if self.ctx.is_some() {
            if self.start {
                self.ctx.as_mut().unwrap().stop();
                self.start = false;
            }
            self.ctx = None;
        }
        self.stream_data.lock().unwrap().clear();
        self.prepared_data = 0;
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        self.check_fmt_update(recv_data);

        fence(Ordering::Acquire);

        let su = StreamUnit {
            addr: recv_data.audio_base,
            len: recv_data.audio_size as u64,
        };
        self.stream_data.lock().unwrap().push(su);

        if !self.start {
            self.prepared_data += recv_data.audio_size;
            if self.check_data_ready(recv_data) && !self.init(recv_data) {
                error!("failed to init oh audio");
                self.destroy();
            }
        }
        0
    }
}

#[derive(Default)]
struct OhAudioCapture {
    ctx: Option<AudioContext>,
    align: u32,
    new_chunks: AtomicI32,
    shm_addr: u64,
    shm_len: u64,
    cur_pos: u64,
    start: bool,
}

impl OhAudioCapture {
    fn check_fmt_update(&mut self, recv_data: &StreamData) {
        if self.ctx.is_none()
            || !self.ctx.as_ref().unwrap().check_fmt(
                recv_data.fmt.size,
                recv_data.fmt.get_rate(),
                recv_data.fmt.channels,
            )
        {
            self.destroy();
        }
    }
}

impl OhAudioProcess for OhAudioCapture {
    fn init(&mut self, stream: &StreamData) -> bool {
        let mut context = AudioContext::new(AudioStreamType::Capturer);
        match context.init(
            stream.fmt.size,
            stream.fmt.get_rate(),
            stream.fmt.channels,
            AudioProcessCb::CapturerCb(Some(on_read_data_cb)),
            ptr::addr_of!(*self) as *mut c_void,
        ) {
            Ok(()) => self.ctx = Some(context),
            Err(e) => {
                error!("failed to create oh audio capturer context: {}", e);
                return false;
            }
        }
        match self.ctx.as_ref().unwrap().start() {
            Ok(()) => {
                self.start = true;
                true
            }
            Err(e) => {
                error!("failed to start oh audio capturer: {}", e);
                false
            }
        }
    }

    fn destroy(&mut self) {
        if self.ctx.is_some() {
            if self.start {
                self.ctx.as_mut().unwrap().stop();
                self.start = false;
            }
            self.ctx = None;
        }
    }

    fn preprocess(&mut self, start_addr: u64, sh_header: &ShmemStreamHeader) {
        self.align = sh_header.chunk_size;
        self.new_chunks.store(0, Ordering::Release);
        self.shm_addr = start_addr;
        self.shm_len = sh_header.max_chunks as u64 * sh_header.chunk_size as u64;
        self.cur_pos = start_addr + sh_header.chunk_idx as u64 * sh_header.chunk_size as u64;
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        self.check_fmt_update(recv_data);
        if !self.start && !self.init(recv_data) {
            self.destroy();
            return 0;
        }
        self.new_chunks.store(0, Ordering::Release);
        while self.new_chunks.load(Ordering::Acquire) == 0 {
            thread::sleep(time::Duration::from_millis(10));
        }

        self.new_chunks.load(Ordering::Acquire)
    }
}

extern "C" fn on_write_data_cb(
    _renderer: *mut OhAudioRenderer,
    user_data: *mut ::std::os::raw::c_void,
    buffer: *mut ::std::os::raw::c_void,
    length: i32,
) -> i32 {
    // SAFETY: we make sure that it is OhAudioRender when register callback.
    let render = unsafe {
        (user_data as *mut OhAudioRender)
            .as_mut()
            .unwrap_unchecked()
    };
    if !render.start {
        return 0;
    }

    // Copy stream data from shared memory to buffer.
    let mut dst_addr = buffer as u64;
    let mut left = length as u64;
    let mut su_list = render.stream_data.lock().unwrap();
    while left > 0 && su_list.len() > 0 {
        let su = &mut su_list[0];
        let len = cmp::min(left, su.len);

        // SAFETY: we checked len.
        unsafe {
            ptr::copy_nonoverlapping(su.addr as *const u8, dst_addr as *mut u8, len as usize)
        };

        dst_addr += len;
        left -= len;
        su.len -= len;
        if su.len == 0 {
            su_list.remove(0);
        } else {
            su.addr += len;
        }
    }
    if left > 0 {
        warn!("data in stream unit list is not enough");
    }
    0
}

extern "C" fn on_read_data_cb(
    _capturer: *mut OhAudioCapturer,
    user_data: *mut ::std::os::raw::c_void,
    buffer: *mut ::std::os::raw::c_void,
    length: i32,
) -> i32 {
    // SAFETY: we make sure that it is OhAudioCapture when register callback.
    let capture = unsafe {
        (user_data as *mut OhAudioCapture)
            .as_mut()
            .unwrap_unchecked()
    };

    loop {
        if !capture.start {
            return 0;
        }
        if capture.new_chunks.load(Ordering::Acquire) == 0 {
            break;
        }
    }
    let old_pos = capture.cur_pos - ((capture.cur_pos - capture.shm_addr) % capture.align as u64);
    let buf_end = capture.shm_addr + capture.shm_len;
    let mut src_addr = buffer as u64;
    let mut left = length as u64;
    while left > 0 {
        let len = cmp::min(left, buf_end - capture.cur_pos);
        // SAFETY: we checked len.
        unsafe {
            ptr::copy_nonoverlapping(
                src_addr as *const u8,
                capture.cur_pos as *mut u8,
                len as usize,
            )
        };
        left -= len;
        src_addr += len;
        capture.cur_pos += len;
        if capture.cur_pos == buf_end {
            capture.cur_pos = capture.shm_addr;
        }
    }

    let new_chunks = match capture.cur_pos <= old_pos {
        true => (capture.shm_len - (old_pos - capture.cur_pos)) / capture.align as u64,
        false => (capture.cur_pos - old_pos) / capture.align as u64,
    };
    capture
        .new_chunks
        .store(new_chunks as i32, Ordering::Release);
    0
}

pub struct OhAudio {
    processor: Box<dyn OhAudioProcess>,
}

// SAFETY: OhAudio's 'send' trait is guaranteed by Mutex lock.
unsafe impl Send for OhAudio {}

impl OhAudio {
    pub fn init(dir: ScreamDirection) -> Self {
        match dir {
            ScreamDirection::Playback => Self {
                processor: Box::<OhAudioRender>::default(),
            },
            ScreamDirection::Record => Self {
                processor: Box::<OhAudioCapture>::default(),
            },
        }
    }
}

impl AudioInterface for OhAudio {
    fn send(&mut self, recv_data: &StreamData) {
        self.processor.process(recv_data);
    }

    fn pre_receive(&mut self, start_addr: u64, sh_header: &ShmemStreamHeader) {
        self.processor.preprocess(start_addr, sh_header);
    }

    fn receive(&mut self, recv_data: &StreamData) -> i32 {
        self.processor.process(recv_data)
    }

    fn destroy(&mut self) {
        self.processor.destroy();
    }
}
