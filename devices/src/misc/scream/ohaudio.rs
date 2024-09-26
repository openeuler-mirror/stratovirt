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

use std::collections::VecDeque;
use std::os::raw::c_void;
use std::sync::{
    atomic::{fence, AtomicBool, Ordering},
    Arc, Condvar, Mutex, RwLock,
};
use std::{cmp, io::Read, ptr, thread, time::Duration};

use log::{error, warn};

use crate::misc::ivshmem::Ivshmem;
use crate::misc::scream::{
    AudioExtension, AudioInterface, AudioStatus, ScreamDirection, StreamData,
    IVSHMEM_VOLUME_SYNC_VECTOR,
};
use util::ohos_binding::audio::*;

const STREAM_DATA_VEC_CAPACITY: usize = 15;
const FLUSH_DELAY_MS: u64 = 5;
const FLUSH_DELAY_CNT: u64 = 200;
const SCREAM_MAX_VOLUME: u32 = 110;
const CAPTURE_WAIT_TIMEOUT: u64 = 200;

trait OhAudioProcess {
    fn init(&mut self, stream: &StreamData) -> bool;
    fn destroy(&mut self);
    fn process(&mut self, recv_data: &StreamData) -> i32;
    fn get_status(&self) -> AudioStatus;
}

#[derive(Debug, Clone, Copy)]
struct StreamUnit {
    addr: usize,
    len: usize,
}

impl Read for StreamUnit {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = cmp::min(self.len, buf.len());
        // SAFETY: all the source data are in scream BAR.
        unsafe { ptr::copy_nonoverlapping(self.addr as *const u8, buf.as_mut_ptr(), len) };
        self.len -= len;
        self.addr += len;
        Ok(len)
    }
}

impl StreamUnit {
    #[inline]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn new(addr: usize, len: usize) -> Self {
        Self { addr, len }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }
}

struct StreamQueue {
    queue: VecDeque<StreamUnit>,
    data_size: usize,
}

impl Read for StreamQueue {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = buf.len();
        let mut ret = 0_usize;
        while ret < len {
            if self.queue.is_empty() {
                break;
            }
            let unit = match self.queue.front_mut() {
                Some(u) => u,
                None => break,
            };
            let rlen = unit.read(&mut buf[ret..len]).unwrap();
            ret += rlen;
            self.data_size -= rlen;
            if unit.is_empty() {
                self.pop_front();
            }
        }
        Ok(ret)
    }

    // If there's no enough data, let's fill the whole buffer with 0.
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        let len = buf.len();
        match self.read(buf) {
            Ok(ret) => {
                if ret < len {
                    self.read_zero(&mut buf[ret..len]);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl StreamQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            data_size: 0,
        }
    }

    fn clear(&mut self) {
        self.queue.clear();
    }

    #[inline]
    fn data_size(&self) -> usize {
        self.data_size
    }

    fn pop_front(&mut self) {
        if let Some(elem) = self.queue.pop_front() {
            self.data_size -= elem.len();
        }
    }

    fn push_back(&mut self, unit: StreamUnit) {
        // When audio data is not consumed in time, this buffer
        // might be full. So let's keep the max size by dropping
        // the old data. This can guarantee sound playing can't
        // be delayed too much and the buffer won't become too
        // large.
        if self.queue.len() == self.queue.capacity() {
            self.pop_front();
        }
        self.data_size += unit.len;
        self.queue.push_back(unit);
    }

    fn read_zero(&mut self, buf: &mut [u8]) {
        // SAFETY: the buffer is guaranteed by the caller.
        unsafe {
            ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len());
        }
    }
}

struct OhAudioRender {
    ctx: Option<AudioContext>,
    stream_data: Arc<Mutex<StreamQueue>>,
    flushing: AtomicBool,
    status: AudioStatus,
}

impl Default for OhAudioRender {
    fn default() -> OhAudioRender {
        OhAudioRender {
            ctx: None,
            stream_data: Arc::new(Mutex::new(StreamQueue::new(STREAM_DATA_VEC_CAPACITY))),
            flushing: AtomicBool::new(false),
            status: AudioStatus::default(),
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
        self.set_flushing(true);
        let mut cnt = 0_u64;
        while cnt < FLUSH_DELAY_CNT {
            thread::sleep(Duration::from_millis(FLUSH_DELAY_MS));
            cnt += 1;
            if self.stream_data.lock().unwrap().data_size() == 0 {
                break;
            }
        }
    }

    fn flush_renderer(&self) {
        let _ = self.ctx.as_ref().unwrap().flush_renderer();
    }

    #[inline(always)]
    fn is_flushing(&self) -> bool {
        self.flushing.load(Ordering::Acquire)
    }

    #[inline(always)]
    fn set_flushing(&mut self, flush: bool) {
        self.flushing.store(flush, Ordering::Release);
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
                self.status = AudioStatus::Started;
                trace::oh_scream_render_init(&self.ctx);
            }
            Err(e) => {
                error!("failed to start oh audio renderer: {}", e);
            }
        }
        self.status == AudioStatus::Started
    }

    fn destroy(&mut self) {
        match self.status {
            AudioStatus::Error => {
                self.ctx = None;
                self.status = AudioStatus::Ready;
                return;
            }
            AudioStatus::Started => self.flush(),
            _ => {}
        }
        self.ctx = None;
        self.stream_data.lock().unwrap().clear();
        self.set_flushing(false);
        self.status = AudioStatus::Ready;
        trace::oh_scream_render_destroy();
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        self.check_fmt_update(recv_data);

        fence(Ordering::Acquire);

        trace::trace_scope_start!(ohaudio_render_process, args = (recv_data));

        self.stream_data.lock().unwrap().push_back(StreamUnit::new(
            recv_data.audio_base as usize,
            recv_data.audio_size as usize,
        ));

        if self.status == AudioStatus::Error {
            error!("Audio server error occurred. Destroy and reconnect it.");
            self.destroy();
        }

        if self.status == AudioStatus::Ready && !self.init(recv_data) {
            error!("failed to init oh audio");
            self.destroy();
        }
        0
    }

    fn get_status(&self) -> AudioStatus {
        self.status
    }
}

struct CaptureStream {
    cond: Condvar,
    data: Mutex<Vec<u8>>,
    expected: usize,
}

impl Default for CaptureStream {
    fn default() -> Self {
        Self {
            cond: Condvar::new(),
            data: Mutex::new(Vec::with_capacity(1 << 20)),
            expected: 0,
        }
    }
}

impl CaptureStream {
    fn wait_for_data(&mut self, buf: &mut [u8]) -> bool {
        let mut locked_data = self.data.lock().unwrap();
        self.expected = buf.len();
        while locked_data.len() < self.expected {
            let ret = self
                .cond
                .wait_timeout(locked_data, Duration::from_millis(CAPTURE_WAIT_TIMEOUT))
                .unwrap();
            if ret.1.timed_out() {
                return false;
            }
            locked_data = ret.0;
        }
        buf.copy_from_slice(&locked_data[..self.expected]);
        *locked_data = locked_data[self.expected..].to_vec();
        self.expected = 0;
        true
    }

    fn append_data(&mut self, buf: &[u8]) {
        let mut locked_data = self.data.lock().unwrap();
        locked_data.extend_from_slice(buf);
        if locked_data.len() > self.expected {
            self.cond.notify_all();
        }
    }

    fn reset(&mut self) {
        let mut locked_data = self.data.lock().unwrap();
        locked_data.clear();
        self.expected = 0;
        self.cond.notify_all();
    }
}

#[derive(Default)]
struct OhAudioCapture {
    ctx: Option<AudioContext>,
    status: AudioStatus,
    stream: CaptureStream,
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
                self.status = AudioStatus::Started;
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
        self.status = AudioStatus::Ready;
        self.ctx = None;
        self.stream.reset();
        trace::oh_scream_capture_destroy();
    }

    fn process(&mut self, recv_data: &StreamData) -> i32 {
        self.check_fmt_update(recv_data);

        trace::trace_scope_start!(ohaudio_capturer_process, args = (recv_data));

        if self.status == AudioStatus::Error {
            self.destroy();
        }

        if self.status == AudioStatus::Ready && !self.init(recv_data) {
            self.destroy();
            return -1;
        }
        // SAFETY: the buffer is from ivshmem and the caller ensures its validation.
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                recv_data.audio_base as *mut u8,
                recv_data.audio_size as usize,
            )
        };
        if !self.stream.wait_for_data(buf) {
            warn!("timed out to wait for capture audio data");
            self.status = AudioStatus::Error;
            return 0;
        }
        1
    }

    fn get_status(&self) -> AudioStatus {
        self.status
    }
}

extern "C" fn on_write_data_cb(
    _renderer: *mut OhAudioRenderer,
    user_data: *mut ::std::os::raw::c_void,
    buffer: *mut ::std::os::raw::c_void,
    length: i32,
) -> i32 {
    if buffer.is_null() || user_data.is_null() {
        error!("on_write_data_cb: Invalid input");
        return 0;
    }

    // SAFETY: we make sure that it is OhAudioRender when register callback.
    let render = unsafe {
        (user_data as *mut OhAudioRender)
            .as_mut()
            .unwrap_unchecked()
    };

    let len = length as usize;
    // SAFETY: the buffer is guaranteed by OH audio framework.
    let wbuf = unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, len) };

    trace::oh_scream_on_write_data_cb(len);
    trace::trace_scope_start!(ohaudio_write_cb, args = (len));
    match render.stream_data.lock().unwrap().read_exact(wbuf) {
        Ok(()) => {
            if render.is_flushing() {
                render.flush_renderer();
            }
        }
        Err(e) => error!("Failed to read stream data {:?}", e),
    }
    0
}

extern "C" fn on_read_data_cb(
    _capturer: *mut OhAudioCapturer,
    user_data: *mut ::std::os::raw::c_void,
    buffer: *mut ::std::os::raw::c_void,
    length: i32,
) -> i32 {
    if buffer.is_null() || user_data.is_null() {
        error!("on_read_data_cb: Invalid input");
        return 0;
    }

    // SAFETY: we make sure that it is OhAudioCapture when register callback.
    let capture = unsafe {
        (user_data as *mut OhAudioCapture)
            .as_mut()
            .unwrap_unchecked()
    };

    trace::trace_scope_start!(ohaudio_read_cb, args = (length));

    if capture.status != AudioStatus::Started {
        return 0;
    }

    // SAFETY: the buffer is checked above.
    let buf = unsafe { std::slice::from_raw_parts(buffer as *mut u8, length as usize) };
    capture.stream.append_data(buf);
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

    fn receive(&mut self, recv_data: &StreamData) -> i32 {
        self.processor.process(recv_data)
    }

    fn destroy(&mut self) {
        self.processor.destroy();
    }

    fn get_status(&self) -> AudioStatus {
        self.processor.get_status()
    }
}

pub struct OhAudioVolume {
    shm_dev: Arc<Mutex<Ivshmem>>,
    ohos_vol: RwLock<u32>,
    ohos_vol_max: u32,
    ohos_vol_min: u32,
}

// SAFETY: all unsafe fields are protected by lock
unsafe impl Send for OhAudioVolume {}
// SAFETY: all unsafe fields are protected by lock
unsafe impl Sync for OhAudioVolume {}

impl GuestVolumeNotifier for OhAudioVolume {
    fn notify(&self, vol: u32) {
        *self.ohos_vol.write().unwrap() = self.to_guest_vol(vol);
        self.shm_dev
            .lock()
            .unwrap()
            .trigger_msix(IVSHMEM_VOLUME_SYNC_VECTOR);
    }
}

impl AudioExtension for OhAudioVolume {
    fn get_host_volume(&self) -> u32 {
        *self.ohos_vol.read().unwrap()
    }

    fn set_host_volume(&self, vol: u32) {
        set_ohos_volume(self.to_host_vol(vol));
    }
}

impl OhAudioVolume {
    pub fn new(shm_dev: Arc<Mutex<Ivshmem>>) -> Arc<Self> {
        let vol = Arc::new(Self {
            shm_dev,
            ohos_vol: RwLock::new(0),
            ohos_vol_max: get_ohos_volume_max(),
            ohos_vol_min: get_ohos_volume_min(),
        });
        *vol.ohos_vol.write().unwrap() = vol.to_guest_vol(get_ohos_volume());
        register_guest_volume_notifier(vol.clone());
        vol
    }

    fn to_guest_vol(&self, h_vol: u32) -> u32 {
        if self.ohos_vol_max > self.ohos_vol_min {
            return SCREAM_MAX_VOLUME * h_vol / (self.ohos_vol_max - self.ohos_vol_min);
        }
        0
    }

    fn to_host_vol(&self, v_vol: u32) -> u32 {
        if v_vol == 0 || self.ohos_vol_max <= self.ohos_vol_min {
            return 0;
        }
        let res = (self.ohos_vol_max - self.ohos_vol_min) * v_vol / SCREAM_MAX_VOLUME + 1;
        if res > self.ohos_vol_max {
            return self.ohos_vol_max;
        }
        res
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
