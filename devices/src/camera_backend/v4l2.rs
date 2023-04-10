// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

//! V4L2 backend for vCamera device. /dev/videoX and VIDIOC_XX ioctls are used.

use std::os::unix::prelude::{AsRawFd, RawFd};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use v4l2_sys_mit::{
    v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE, v4l2_buffer, v4l2_fmtdesc, v4l2_format,
    v4l2_frmivalenum, v4l2_frmsizeenum, v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_DISCRETE,
    v4l2_memory_V4L2_MEMORY_MMAP, v4l2_requestbuffers, v4l2_streamparm, V4L2_CAP_STREAMING,
    V4L2_CAP_VIDEO_CAPTURE,
};
use vmm_sys_util::epoll::EventSet;

use machine_manager::event_loop::{register_event_helper, unregister_event_helper};
use util::aio::Iovec;
use util::loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation};

use crate::camera_backend::{
    CamBasicFmt, CameraBrokenCallback, CameraFormatList, CameraFrame, CameraHostdevOps,
    CameraNotifyCallback, FmtType, INTERVALS_PER_SEC,
};
use util::v4l2::{new_init, V4l2Backend, V4L2_FORMAT_MJPG, V4L2_FORMAT_YUYV};

const BUFFER_CNT: usize = 4;

#[derive(Default)]
pub struct Sample {
    /// Sample address.
    addr: u64,
    /// Sample used length.
    used_len: u64,
    /// Sample in which buffer.
    buf_index: u32,
}

impl Sample {
    fn reset(&mut self) {
        self.addr = 0;
        self.used_len = 0;
        self.buf_index = 0;
    }
}

pub struct V4l2CameraBackend {
    id: String,
    dev_path: String,
    /// Sample info.
    sample: Arc<Mutex<Sample>>,
    /// V4l2 backend used to get frame.
    backend: Option<Arc<V4l2Backend>>,
    /// Callback to used to notify when data is coming.
    notify_cb: Option<CameraNotifyCallback>,
    /// Callback to used to notify the broken.
    broken_cb: Option<CameraNotifyCallback>,
    /// If the video stream is on or not.  
    running: bool,
    /// If the backend fd is listening or not.
    listening: bool,
    iothread: Option<String>,
    delete_evts: Vec<RawFd>,
}

impl V4l2CameraBackend {
    pub fn new(id: String, path: String, iothread: Option<String>) -> Result<Self> {
        let backend = V4l2Backend::new(path.clone(), BUFFER_CNT)?;
        let cam = V4l2CameraBackend {
            id,
            dev_path: path,
            sample: Arc::new(Mutex::new(Sample::default())),
            backend: Some(Arc::new(backend)),
            running: false,
            listening: false,
            notify_cb: None,
            broken_cb: None,
            iothread,
            delete_evts: Vec::new(),
        };
        cam.check_cap()?;
        Ok(cam)
    }

    fn check_cap(&self) -> Result<()> {
        // SAFETY: backend is inited in outside function.
        let cap = self.backend.as_ref().unwrap().query_cap()?;
        if cap.capabilities & V4L2_CAP_VIDEO_CAPTURE != V4L2_CAP_VIDEO_CAPTURE {
            bail!(
                "Device {} not support capture capability {}",
                self.id,
                cap.capabilities
            );
        }
        if cap.device_caps & V4L2_CAP_VIDEO_CAPTURE != V4L2_CAP_VIDEO_CAPTURE {
            bail!(
                "Device caps {} not support capture capability {}",
                self.id,
                cap.device_caps
            );
        }
        if cap.capabilities & V4L2_CAP_STREAMING != V4L2_CAP_STREAMING {
            bail!(
                "Device {} not support streaming capability {}",
                self.id,
                cap.capabilities
            );
        }
        Ok(())
    }

    fn register_fd(&mut self) -> Result<()> {
        if self.listening {
            self.unregister_fd()?;
        }
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        debug!("Camera {} register fd {}", self.id, backend.as_raw_fd());
        // Register event notifier for /dev/videoX.
        let handler = Arc::new(Mutex::new(V4l2IoHander::new(
            &self.sample,
            backend,
            self.notify_cb.clone(),
            self.broken_cb.clone(),
        )));
        register_event_helper(
            EventNotifierHelper::internal_notifiers(handler),
            self.iothread.as_ref(),
            &mut self.delete_evts,
        )?;
        self.listening = true;
        Ok(())
    }

    fn unregister_fd(&mut self) -> Result<()> {
        if !self.listening {
            warn!("Camera {} is not listening", self.id);
            return Ok(());
        }
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        debug!("Camera {} unregister fd {}", self.id, backend.as_raw_fd());
        unregister_event_helper(self.iothread.as_ref(), &mut self.delete_evts)?;
        self.listening = false;
        Ok(())
    }

    fn list_frame_size(&self, pixfmt: u32) -> Result<Vec<CameraFrame>> {
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        let mut list = Vec::new();
        let mut frmsize = new_init::<v4l2_frmsizeenum>();
        frmsize.pixel_format = pixfmt;
        const FRAME_SIZE_LIMIT: u32 = 1000;
        for i in 0..FRAME_SIZE_LIMIT {
            frmsize.index = i;
            let frame_size_end = backend.enum_frame_size(&mut frmsize)?;
            if frame_size_end {
                break;
            }
            // NOTE: Only support discrete now.
            if (frmsize.type_) != v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_DISCRETE as u32 {
                continue;
            }
            let width = unsafe { frmsize.__bindgen_anon_1.discrete.width };
            let height = unsafe { frmsize.__bindgen_anon_1.discrete.height };
            let interval_list = self.list_frame_interval(pixfmt, width, height)?;
            for interval in interval_list {
                list.push(CameraFrame {
                    width,
                    height,
                    interval,
                });
            }
        }
        Ok(list)
    }

    fn list_frame_interval(&self, pixfmt: u32, width: u32, height: u32) -> Result<Vec<u32>> {
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        let mut list = Vec::new();
        let mut frame_val = new_init::<v4l2_frmivalenum>();
        frame_val.pixel_format = pixfmt;
        frame_val.width = width;
        frame_val.height = height;
        const FRAME_INTERVAL_LIMIT: u32 = 1000;
        for i in 0..FRAME_INTERVAL_LIMIT {
            frame_val.index = i;
            let interval_end = backend.enum_frame_interval(&mut frame_val)?;
            if interval_end {
                break;
            }
            let numerator = unsafe { frame_val.__bindgen_anon_1.discrete.numerator };
            let denominator = unsafe { frame_val.__bindgen_anon_1.discrete.denominator };
            if denominator == 0 {
                warn!(
                    "Invalid denominator ignore it, format {} width {} height {}",
                    frame_val.pixel_format, frame_val.width, frame_val.height
                );
                continue;
            }
            let interval =
                (numerator as u64 * INTERVALS_PER_SEC as u64 / denominator as u64) as u32;
            list.push(interval);
        }
        Ok(list)
    }
}

impl CameraHostdevOps for V4l2CameraBackend {
    fn init(&self) -> Result<()> {
        Ok(())
    }
    fn is_camera(&self) -> Result<bool> {
        Ok(true)
    }
    fn get_fmt(&self) -> Result<()> {
        Ok(())
    }
    fn set_fmt(&mut self, cam_fmt: &CamBasicFmt) -> Result<()> {
        info!("Camera {} set format {:?}", self.id, cam_fmt);
        if self.listening {
            self.unregister_fd()?;
        }

        // NOTE: Reopen backend to avoid Device or Resource busy.
        let backend = V4l2Backend::new(self.dev_path.clone(), BUFFER_CNT)?;
        debug!(
            "Camera {} set format open fd {}",
            self.id,
            backend.as_raw_fd()
        );
        self.backend = Some(Arc::new(backend));

        let mut fmt = new_init::<v4l2_format>();
        fmt.type_ = V4L2_CAP_VIDEO_CAPTURE;
        fmt.fmt.pix.width = cam_fmt.width;
        fmt.fmt.pix.height = cam_fmt.height;
        fmt.fmt.pix.pixelformat = cam_fmt_to_v4l2(&cam_fmt.fmttype);
        fmt.fmt.pix.field = 4;
        // SAFETY: backend is inited before.
        let backend = self.backend.as_ref().unwrap();
        backend.set_format(&fmt)?;

        let mut parm = new_init::<v4l2_streamparm>();
        parm.type_ = v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;
        let interval = cam_fmt.get_frame_intervals()?;
        unsafe {
            parm.parm.capture.timeperframe.numerator = 30;
            parm.parm.capture.timeperframe.denominator =
                parm.parm.capture.timeperframe.numerator * INTERVALS_PER_SEC / interval;
        }
        backend.set_stream_parameter(&parm)?;
        Ok(())
    }
    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&mut self) -> Result<()> {
        if self.running {
            warn!("Camera {} already running", self.id);
            return Ok(());
        }
        info!("Camera {} stream on", self.id);
        let mut bufs = new_init::<v4l2_requestbuffers>();
        bufs.type_ = v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;
        bufs.memory = v4l2_memory_V4L2_MEMORY_MMAP;
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        backend.request_buffers(&mut bufs)?;
        backend.stream_on(V4L2_CAP_VIDEO_CAPTURE as std::os::raw::c_int)?;
        self.register_fd()?;
        self.running = true;
        Ok(())
    }

    fn video_stream_off(&mut self) -> Result<()> {
        info!("Camera {} stream off", self.id);
        self.unregister_fd()?;
        if let Some(backend) = self.backend.as_ref() {
            backend.stream_off(V4L2_CAP_VIDEO_CAPTURE as std::os::raw::c_int)?;
            backend.release_buffers()?;
            self.backend = None;
        }
        self.running = false;
        Ok(())
    }

    fn list_format(&mut self) -> Result<Vec<CameraFormatList>> {
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        let mut list = Vec::new();
        let mut desc = new_init::<v4l2_fmtdesc>();
        desc.type_ = V4L2_CAP_VIDEO_CAPTURE;
        const FORMAT_LIMIT: u32 = 1000;
        for i in 0..FORMAT_LIMIT {
            desc.index = i;
            let format_end = backend.enum_format(&mut desc)?;
            if format_end {
                break;
            }
            list.push(CameraFormatList {
                format: cam_fmt_from_v4l2(desc.pixelformat)?,
                frame: self.list_frame_size(desc.pixelformat)?,
            });
        }
        Ok(list)
    }

    fn reset(&mut self) {
        info!("device {} reset", self.id);
        if self.running {
            if let Err(e) = self.unregister_fd() {
                warn!("Failed to unregister fd when reset {:?}", e);
            }
            if let Some(backend) = self.backend.as_ref() {
                if let Err(e) = backend.stream_off(V4L2_CAP_VIDEO_CAPTURE as std::os::raw::c_int) {
                    warn!("Failed to stream off when reset {:?}", e);
                }
                if let Err(e) = backend.release_buffers() {
                    warn!("Failed to release buffer when reset {:?}", e);
                }
                self.backend = None;
            }
        }
        self.listening = false;
        self.running = false;
        self.sample.lock().unwrap().reset();
    }

    fn get_frame_size(&self) -> usize {
        self.sample.lock().unwrap().used_len as usize
    }

    fn next_frame(&mut self) -> Result<()> {
        let mut locked_sample = self.sample.lock().unwrap();
        locked_sample.used_len = 0;
        let backend = self.backend.as_ref().with_context(|| "Backend is none")?;
        let mut buf = new_init::<v4l2_buffer>();
        buf.type_ = v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = v4l2_memory_V4L2_MEMORY_MMAP;
        buf.index = locked_sample.buf_index;
        backend.queue_buffer(&buf)?;
        Ok(())
    }

    fn get_frame(&self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize> {
        let locked_sample = self.sample.lock().unwrap();
        if frame_offset + len > locked_sample.used_len as usize {
            bail!("Invalid frame offset {} or len {}", frame_offset, len);
        }
        let mut copyed = 0;
        for iov in iovecs {
            if len == copyed {
                break;
            }
            let cnt = std::cmp::min(iov.iov_len as usize, len - copyed);
            let src_ptr = locked_sample.addr + frame_offset as u64 + copyed as u64;
            // SAFETY: the address is not out of range.
            unsafe {
                std::ptr::copy(src_ptr as *const u8, iov.iov_base as *mut u8, cnt);
            }
            copyed += cnt;
        }
        Ok(copyed)
    }

    fn register_notify_cb(&mut self, cb: CameraNotifyCallback) {
        self.notify_cb = Some(cb);
    }

    fn register_broken_cb(&mut self, cb: CameraBrokenCallback) {
        self.broken_cb = Some(cb);
    }
}

fn cam_fmt_to_v4l2(t: &FmtType) -> u32 {
    match t {
        FmtType::Uncompressed => V4L2_FORMAT_YUYV,
        FmtType::Mjpg => V4L2_FORMAT_MJPG,
    }
}

fn cam_fmt_from_v4l2(t: u32) -> Result<FmtType> {
    let fmt = match t {
        V4L2_FORMAT_YUYV => FmtType::Uncompressed,
        V4L2_FORMAT_MJPG => FmtType::Mjpg,
        _ => bail!("Invalid v4l2 type {}", t),
    };
    Ok(fmt)
}

pub struct V4l2IoHander {
    sample: Arc<Mutex<Sample>>,
    backend: Arc<V4l2Backend>,
    notify_cb: Option<CameraNotifyCallback>,
    broken_cb: Option<CameraNotifyCallback>,
}

impl V4l2IoHander {
    pub fn new(
        sample: &Arc<Mutex<Sample>>,
        backend: &Arc<V4l2Backend>,
        cb: Option<CameraNotifyCallback>,
        broken_cb: Option<CameraNotifyCallback>,
    ) -> Self {
        V4l2IoHander {
            sample: sample.clone(),
            backend: backend.clone(),
            notify_cb: cb,
            broken_cb,
        }
    }

    fn handle_sample(&mut self) -> Result<()> {
        let mut buf = new_init::<v4l2_buffer>();
        buf.type_ = v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = v4l2_memory_V4L2_MEMORY_MMAP;
        if !self.backend.dequeue_buffer(&buf)? {
            // Not ready.
            return Ok(());
        }
        if buf.bytesused > buf.length {
            bail!("Invalid buf used {} length {}", buf.bytesused, buf.length);
        }
        let locked_buf = self.backend.buffer.lock().unwrap();
        let mut locked_sample = self.sample.lock().unwrap();
        if locked_sample.used_len == 0 {
            let iov = locked_buf
                .get(buf.index as usize)
                .with_context(|| "Buffer index overflow")?;
            if buf.bytesused as u64 > iov.iov_len {
                bail!(
                    "Buffer overflow, bytesused {} iov len {}",
                    buf.bytesused,
                    iov.iov_len
                );
            }
            locked_sample.addr = iov.iov_base;
            locked_sample.used_len = buf.bytesused as u64;
            locked_sample.buf_index = buf.index;
            drop(locked_sample);
            // Notify the camera to deal with request.
            if let Some(notify_cb) = &self.notify_cb {
                notify_cb();
            }
        } else {
            self.backend
                .queue_buffer(&buf)
                .with_context(|| "Failed to queue buffer when handle sample")?;
        }
        Ok(())
    }
}

impl EventNotifierHelper for V4l2IoHander {
    fn internal_notifiers(v4l2_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let cloend_v4l2_handler = v4l2_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event, _fd: RawFd| {
            let mut locked_handler = cloend_v4l2_handler.lock().unwrap();
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                if let Some(broken_cb) = &locked_handler.broken_cb {
                    // Backend is broken.
                    broken_cb();
                }
            } else if let Err(e) = locked_handler.handle_sample() {
                error!("Failed to handle sample {:?}", e);
            }
            None
        });

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            v4l2_handler.lock().unwrap().backend.as_raw_fd(),
            None,
            EventSet::IN | EventSet::EDGE_TRIGGERED | EventSet::HANG_UP, // For unexpected device removal.
            vec![handler],
        )]
    }
}
