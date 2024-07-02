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
    atomic::{fence, AtomicBool, AtomicI32, Ordering},
    Arc, Mutex, RwLock,
};
use std::{
    cmp, ptr, thread,
    time::{Duration, Instant},
};

use log::{error, warn};

use crate::misc::scream::{AudioInterface, ScreamDirection, ShmemStreamHeader, StreamData};
use machine_manager::notifier::register_vm_pause_notifier;
use util::ohos_binding::audio::*;

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

const STREAM_DATA_VEC_CAPACITY: usize = 15;
const FLUSH_DELAY_THRESHOLD_MS: u64 = 100;
const FLUSH_DELAY_MS: u64 = 5;
const FLUSH_DELAY_CNT: u64 = 200;

#[derive(Copy, Clone, Default, PartialEq, PartialOrd)]
enum OhAudioStatus {
    // Processor is ready and waiting for play/capture.
    #[default]
    READY,
    // Processor is started and doing job.
    STARTED,
    // Processor is paused.
    PAUSED,
    // OH audio framework error occurred.
    ERROR,
}

struct OhAudioRender {
    ctx: Option<AudioContext>,
    stream_data: Arc<Mutex<Vec<StreamUnit>>>,
    data_size: AtomicI32,
    flushing: AtomicBool,
    status: Arc<RwLock<OhAudioStatus>>,
    last_called_time: Option<Instant>,
    pause_notifier_id: u64,
}

impl Default for OhAudioRender {
    fn default() -> OhAudioRender {
        OhAudioRender {
            ctx: None,
            stream_data: Arc::new(Mutex::new(Vec::with_capacity(STREAM_DATA_VEC_CAPACITY))),
            data_size: AtomicI32::new(0),
            flushing: AtomicBool::new(false),
            status: Arc::new(RwLock::new(OhAudioStatus::default())),
            last_called_time: None,
            pause_notifier_id: 0,
        }
    }
}

impl OhAudioRender {
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

    fn flush(&mut self) {
        self.flushing.store(true, Ordering::Release);
        let mut cnt = 0;
        while (cnt < FLUSH_DELAY_CNT) && (self.flushing.load(Ordering::Acquire)) {
            thread::sleep(Duration::from_millis(FLUSH_DELAY_MS));
            cnt += 1;
        }
        // We need to wait for 100ms to ensure the audio data has
        // been flushed before stop renderer.
        thread::sleep(Duration::from_millis(FLUSH_DELAY_THRESHOLD_MS));
        let _ = self.ctx.as_ref().unwrap().flush_renderer();
    }

    #[inline(always)]
    fn get_status(&self) -> OhAudioStatus {
        *self.status.read().unwrap()
    }

    #[inline(always)]
    fn set_status(&self, status: OhAudioStatus) {
        *self.status.write().unwrap() = status;
    }

    fn register_pause_notifier(&mut self) {
        let status = self.status.clone();
        let pause_notify = Arc::new(move |paused: bool| {
            let s = *status.read().unwrap();
            if paused {
                if s == OhAudioStatus::PAUSED {
                    return;
                }
                *status.write().unwrap() = OhAudioStatus::PAUSED;
            } else {
                *status.write().unwrap() = OhAudioStatus::ERROR;
            }
        });
        self.pause_notifier_id = register_vm_pause_notifier(pause_notify);
    }
}

impl OhAudioProcess for OhAudioRender {
    fn init(&mut self, stream: &StreamData) -> bool {
        if self.ctx.is_none() {
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
        }
        match self.ctx.as_ref().unwrap().start() {
            Ok(()) => {
                self.set_status(OhAudioStatus::STARTED);
                trace::oh_scream_render_init(&self.ctx);
            }
            Err(e) => {
                error!("failed to start oh audio renderer: {}", e);
            }
        }
        self.last_called_time = None;
        self.get_status() == OhAudioStatus::STARTED
    }

    fn destroy(&mut self) {
        let status = self.get_status();

        match status {
            OhAudioStatus::PAUSED => return,
            OhAudioStatus::ERROR => {
                self.ctx = None;
                self.set_status(OhAudioStatus::READY);
                return;
            }
            OhAudioStatus::STARTED => self.flush(),
            _ => {}
        }
        self.ctx = None;
        self.stream_data.lock().unwrap().clear();
        self.data_size.store(0, Ordering::Relaxed);
        self.set_status(OhAudioStatus::READY);
        trace::oh_scream_render_destroy();
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        let mut status = self.get_status();
        if status == OhAudioStatus::PAUSED {
            return 0;
        }

        self.check_fmt_update(recv_data);

        fence(Ordering::Acquire);

        trace::trace_scope_start!(ohaudio_render_process, args = (recv_data));

        let su = StreamUnit {
            addr: recv_data.audio_base,
            len: recv_data.audio_size as u64,
        };
        let mut locked_data = self.stream_data.lock().unwrap();
        // When audio data is not consumed in time, we remove old chunk
        // and push new one. So audio-playing won't delay. One chunk means
        // 20 ms data.
        if locked_data.len() >= STREAM_DATA_VEC_CAPACITY {
            let remove_size = locked_data[0].len;
            locked_data.remove(0);
            self.data_size
                .fetch_sub(remove_size as i32, Ordering::Relaxed);
        }
        locked_data.push(su);
        self.data_size
            .fetch_add(recv_data.audio_size as i32, Ordering::Relaxed);
        drop(locked_data);

        if status == OhAudioStatus::ERROR {
            error!("Audio server error occurred. Destroy and reconnect it.");
            self.destroy();
            status = self.get_status();
        }

        if status == OhAudioStatus::READY && !self.init(recv_data) {
            error!("failed to init oh audio");
            self.destroy();
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
    status: Arc<RwLock<OhAudioStatus>>,
    last_called_time: Option<Instant>,
    pause_notifier_id: u64,
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

    #[inline(always)]
    fn get_status(&self) -> OhAudioStatus {
        *self.status.write().unwrap()
    }

    #[inline(always)]
    fn set_status(&self, status: OhAudioStatus) {
        *self.status.write().unwrap() = status;
    }

    fn register_pause_notifier(&mut self) {
        let status = self.status.clone();
        let pause_notify = Arc::new(move |paused: bool| {
            let s = *status.read().unwrap();
            if paused {
                if s == OhAudioStatus::PAUSED {
                    return;
                }
                *status.write().unwrap() = OhAudioStatus::PAUSED;
            } else {
                // Set error status to recreate capture context.
                *status.write().unwrap() = OhAudioStatus::ERROR;
            }
        });
        self.pause_notifier_id = register_vm_pause_notifier(pause_notify);
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
                self.last_called_time = None;
                self.set_status(OhAudioStatus::STARTED);
                trace::oh_scream_capture_init(&self.ctx);
                true
            }
            Err(e) => {
                error!("failed to start oh audio capturer: {}", e);
                false
            }
        }
    }

    fn destroy(&mut self) {
        let status = self.get_status();
        match status {
            OhAudioStatus::PAUSED => return,
            _ => {
                self.ctx = None;
                self.set_status(OhAudioStatus::READY);
            }
        }
        trace::oh_scream_capture_destroy();
    }

    fn preprocess(&mut self, start_addr: u64, sh_header: &ShmemStreamHeader) {
        self.align = sh_header.chunk_size;
        self.new_chunks.store(0, Ordering::Release);
        self.shm_addr = start_addr;
        self.shm_len = sh_header.max_chunks as u64 * sh_header.chunk_size as u64;
        self.cur_pos = start_addr + sh_header.chunk_idx as u64 * sh_header.chunk_size as u64;
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        let mut status = self.get_status();
        if status == OhAudioStatus::PAUSED {
            return -1;
        }
        self.check_fmt_update(recv_data);

        trace::trace_scope_start!(ohaudio_capturer_process, args = (recv_data));

        if status == OhAudioStatus::ERROR {
            self.destroy();
            status = self.get_status();
        }

        if status == OhAudioStatus::READY && !self.init(recv_data) {
            self.destroy();
            return -1;
        }
        self.new_chunks.store(0, Ordering::Release);
        while self.new_chunks.load(Ordering::Acquire) == 0 {
            status = self.get_status();
            if status == OhAudioStatus::PAUSED || status == OhAudioStatus::ERROR {
                return -1;
            }
            thread::sleep(Duration::from_millis(10));
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

    match &render.last_called_time {
        None => render.last_called_time = Some(Instant::now()),
        Some(last) => {
            let elapsed = last.elapsed().as_millis();
            if elapsed >= 1000 {
                warn!("{elapsed}ms elapsed after last on_write called. Will restart render.");
                render.set_status(OhAudioStatus::ERROR);
                return 0;
            }
            render.last_called_time = Some(Instant::now());
        }
    }

    let data_size = render.data_size.load(Ordering::Relaxed);

    trace::trace_scope_start!(ohaudio_write_cb, args = (length, data_size));

    if !render.flushing.load(Ordering::Acquire) && data_size < length {
        // SAFETY: we checked len.
        unsafe { ptr::write_bytes(buffer as *mut u8, 0, length as usize) };
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
        trace::oh_scream_on_write_data_cb(len as usize);

        dst_addr += len;
        left -= len;
        su.len -= len;
        if su.len == 0 {
            su_list.remove(0);
        } else {
            su.addr += len;
        }
    }
    render
        .data_size
        .fetch_sub(length - left as i32, Ordering::Relaxed);

    if left > 0 {
        // SAFETY: we checked len.
        unsafe { ptr::write_bytes(dst_addr as *mut u8, 0, left as usize) };
    }
    if render.flushing.load(Ordering::Acquire) && su_list.is_empty() {
        render.flushing.store(false, Ordering::Release);
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

    match &capture.last_called_time {
        None => capture.last_called_time = Some(Instant::now()),
        Some(last) => {
            let elapsed = last.elapsed().as_millis();
            if elapsed >= 1000 {
                warn!("{elapsed}ms elapsed after last on_read called. Will restart capture.");
                capture.set_status(OhAudioStatus::ERROR);
                return 0;
            }
            capture.last_called_time = Some(Instant::now());
        }
    }

    trace::trace_scope_start!(ohaudio_read_cb, args = (length));

    loop {
        if capture.get_status() != OhAudioStatus::STARTED {
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
        trace::oh_scream_on_read_data_cb(len as usize);
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
            ScreamDirection::Playback => {
                let mut processor = Box::<OhAudioRender>::default();
                processor.register_pause_notifier();
                Self { processor }
            }
            ScreamDirection::Record => {
                let mut processor = Box::<OhAudioCapture>::default();
                processor.register_pause_notifier();
                Self { processor }
            }
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

#[cfg(test)]
mod tests {
    use crate::misc::scream::ohaudio::{on_read_data_cb, on_write_data_cb, StreamUnit};
    use crate::misc::scream::ohaudio::{OhAudioCapture, OhAudioProcess, OhAudioRender};
    use crate::misc::scream::StreamData;

    use util::ohos_binding::audio::*;

    #[test]
    fn test_render_init_and_destroy() {
        let mut render = OhAudioRender::default();
        let mut stream_data = StreamData::default();

        assert!(!render.init(&stream_data));

        stream_data.fmt.size = 16;
        stream_data.fmt.rate = 1;
        render.init(&stream_data);
        assert!(render.ctx.is_some());
        assert!(render.start);
        assert_eq!(render.stream_data.lock().unwrap().len(), 0);

        render.destroy();
        assert!(!render.start);
        assert!(render.ctx.is_none());
        assert_eq!(render.stream_data.lock().unwrap().len(), 0);
        assert_eq!(render.prepared_data, 0);
    }

    #[test]
    fn test_render_check_data_ready() {
        let mut render = OhAudioRender::default();
        let mut recv_data = StreamData::default();
        recv_data.fmt.size = 16;
        recv_data.fmt.rate = 1;
        recv_data.fmt.channels = 2;
        assert!(!render.check_data_ready(&recv_data));

        render.prepared_data = 96000;
        assert!(render.check_data_ready(&recv_data));
    }

    #[test]
    fn test_render_check_fmt_update() {
        let mut render = OhAudioRender::default();
        let mut recv_data = StreamData::default();
        recv_data.fmt.size = 16;
        recv_data.fmt.rate = 158;
        recv_data.fmt.channels = 2;
        let stream_data = StreamData::default();
        render.init(&stream_data);
        render.check_fmt_update(&recv_data);
        assert!(render.ctx.is_none());
    }

    #[test]
    fn test_capture_init_and_destroy() {
        let mut capture = OhAudioCapture::default();
        let stream_data = StreamData::default();
        assert!(!capture.init(&stream_data));
    }

    #[test]
    fn test_on_write_data_cb() {
        let mut _renderer = OhAudioRenderer::default();
        let mut render = OhAudioRender::default();
        let user_data = std::ptr::addr_of!(render) as *mut ::std::os::raw::c_void;

        let mut dst: Vec<u8> = vec![25, 0, 0, 0, 0, 0, 0, 0, 0];

        let src1: Vec<u8> = vec![10, 11, 12, 13, 14];
        let su1 = StreamUnit {
            addr: src1.as_ptr() as u64,
            len: src1.len() as u64,
        };
        let src2: Vec<u8> = vec![21, 22, 23, 24, 25];
        let su2 = StreamUnit {
            addr: src2.as_ptr() as u64,
            len: src2.len() as u64,
        };

        render.stream_data.lock().unwrap().push(su1);
        render.stream_data.lock().unwrap().push(su2);
        render.start = true;

        // SAFETY: we checked len.
        let dst_ptr = unsafe { dst.as_mut_ptr().offset(1) };

        on_write_data_cb(
            &mut _renderer,
            user_data,
            dst_ptr as *mut ::std::os::raw::c_void,
            8,
        );

        let target = [25, 10, 11, 12, 13, 14, 21, 22, 23];
        assert_eq!(dst, target);
    }

    #[test]
    fn test_on_read_data_cb() {
        let mut _capturer = OhAudioCapturer::default();
        let mut capture = OhAudioCapture::default();

        let mut src: Vec<u8> = vec![10, 11, 12, 13, 14, 15, 16];
        let mut dst: Vec<u8> = vec![99, 0, 0, 0, 0, 0, 0, 0];

        let user_data = std::ptr::addr_of!(capture) as *mut ::std::os::raw::c_void;

        capture.align = dst.len() as u32;
        capture.shm_len = dst.len() as u64;
        capture.shm_addr = dst.as_mut_ptr() as u64;
        capture.start = true;
        // SAFETY: we checked len.
        capture.cur_pos = unsafe { dst.as_mut_ptr().offset(3) as u64 };

        on_read_data_cb(
            &mut _capturer,
            user_data,
            src.as_mut_ptr() as *mut ::std::os::raw::c_void,
            src.len() as i32,
        );

        assert_eq!(capture.new_chunks.into_inner(), 0);
        let target = [15, 16, 0, 10, 11, 12, 13, 14];
        assert_eq!(dst, target);
    }
}
