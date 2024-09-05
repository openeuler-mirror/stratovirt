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

use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use log::error;
use once_cell::sync::Lazy;

use crate::camera_backend::{
    CamBasicFmt, CameraBackend, CameraBrokenCallback, CameraFormatList, CameraFrame,
    CameraNotifyCallback, FmtType,
};
#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
use trace::trace_scope::Scope;
use util::aio::Iovec;
use util::ohos_binding::camera::*;
use util::ohos_binding::misc::bound_tokenid;

type OhCamCB = RwLock<HashMap<String, OhCamCallBack>>;
static OHCAM_CALLBACKS: Lazy<OhCamCB> = Lazy::new(|| RwLock::new(HashMap::new()));

// In UVC, interval's unit is 100ns.
// So, fps * interval / 10_000_000 == 1.
const FPS_INTERVAL_TRANS: u32 = 10_000_000;
const RESOLUTION_WHITELIST: [(i32, i32); 2] = [(640, 480), (1280, 720)];
const FRAME_FORMAT_WHITELIST: [i32; 2] = [CAMERA_FORMAT_YUYV422, CAMERA_FORMAT_NV12];
const FPS_WHITELIST: [i32; 1] = [30];

#[derive(Default)]
struct OhCamCallBack {
    /// Callback to used to notify when data is coming.
    notify_cb: Option<CameraNotifyCallback>,
    /// Callback to used to notify the broken.
    broken_cb: Option<CameraNotifyCallback>,
    ptr: Option<u64>,
    buffer_size: u64,
}

impl OhCamCallBack {
    fn set_buffer(&mut self, addr: u64, s: i32) {
        self.buffer_size = s as u64;
        self.ptr = Some(addr);
    }

    fn get_buffer(&self) -> (Option<u64>, u64) {
        (self.ptr, self.buffer_size)
    }

    fn clear_buffer(&mut self) {
        self.buffer_size = 0;
        self.ptr = None;
    }

    fn set_notify_cb(&mut self, cb: CameraNotifyCallback) {
        self.notify_cb = Some(cb);
    }

    fn set_broken_cb(&mut self, cb: CameraNotifyCallback) {
        self.broken_cb = Some(cb);
    }

    fn notify(&self) {
        if let Some(notify_cb) = &self.notify_cb {
            notify_cb();
        }
    }

    fn broken(&self) {
        if let Some(broken_cb) = &self.broken_cb {
            broken_cb();
        }
    }
}

#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
#[derive(Clone, Default)]
struct OhCameraAsyncScope {
    next_frame_id: u64,
    async_scope: Option<Scope>,
}

#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
impl OhCameraAsyncScope {
    fn start(&mut self) {
        self.async_scope = Some(trace::ohcam_next_frame(true, self.next_frame_id));
        self.next_frame_id += 1;
    }

    fn stop(&mut self) {
        self.async_scope = None;
    }
}

#[derive(Clone)]
pub struct OhCameraBackend {
    // ID for this OhCameraBackend.
    id: String,
    // ID of OH camera device.
    camid: String,
    profile_cnt: u8,
    ctx: OhCamera,
    fmt_list: Vec<CameraFormatList>,
    selected_profile: u8,
    stream_on: bool,
    paused: bool,
    #[cfg(any(
        feature = "trace_to_logger",
        feature = "trace_to_ftrace",
        all(target_env = "ohos", feature = "trace_to_hitrace")
    ))]
    async_scope: Box<OhCameraAsyncScope>,
    tokenid: u64,
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type.
// implementing them is safe because ctx field is access.
unsafe impl Send for OhCameraBackend {}
// SAFETY: Same reason as above.
unsafe impl Sync for OhCameraBackend {}

fn cam_fmt_from_oh(t: i32) -> Result<FmtType> {
    let fmt = match t {
        CAMERA_FORMAT_YUV420SP => FmtType::Nv12,
        CAMERA_FORMAT_NV12 => FmtType::Nv12,
        CAMERA_FORMAT_YUYV422 => FmtType::Yuy2,
        CAMERA_FORMAT_MJPEG => FmtType::Mjpg,
        _ => bail!("OHCAM: No supported type {}", t),
    };

    Ok(fmt)
}

impl Drop for OhCameraBackend {
    fn drop(&mut self) {
        OHCAM_CALLBACKS.write().unwrap().remove_entry(&self.camid);
    }
}

impl OhCameraBackend {
    pub fn new(id: String, cam_name: String, tokenid: u64) -> Result<Self> {
        let (ctx, profile_cnt) = OhCamera::new(cam_name.clone())?;

        Ok(OhCameraBackend {
            id,
            camid: cam_name,
            profile_cnt: profile_cnt as u8,
            ctx,
            fmt_list: vec![],
            selected_profile: 0,
            stream_on: false,
            paused: false,
            #[cfg(any(
                feature = "trace_to_logger",
                feature = "trace_to_ftrace",
                all(target_env = "ohos", feature = "trace_to_hitrace")
            ))]
            async_scope: Box::new(OhCameraAsyncScope::default()),
            tokenid,
        })
    }
}

impl CameraBackend for OhCameraBackend {
    fn set_fmt(&mut self, cam_fmt: &CamBasicFmt) -> Result<()> {
        for fmt in &self.fmt_list {
            if fmt.format != cam_fmt.fmttype {
                continue;
            }
            for frm in &fmt.frame {
                if frm.width != cam_fmt.width || frm.height != cam_fmt.height {
                    continue;
                }

                let fps = FPS_INTERVAL_TRANS
                    .checked_div(frm.interval)
                    .with_context(|| format!("OHCAM: Invalid interval {}", frm.interval))?;
                if fps != cam_fmt.fps {
                    continue;
                }

                self.selected_profile = fmt.fmt_index - 1;
                self.ctx.set_fmt(i32::from(self.selected_profile))?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&mut self) -> Result<()> {
        if self.tokenid != 0 {
            bound_tokenid(self.tokenid)?;
        }
        self.ctx.start_stream(on_buffer_available, on_broken)?;
        self.stream_on = true;
        Ok(())
    }

    fn video_stream_off(&mut self) -> Result<()> {
        self.ctx.stop_stream();
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        self.stream_on = false;
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.stop();
        Ok(())
    }

    fn list_format(&mut self) -> Result<Vec<CameraFormatList>> {
        let mut fmt_list: Vec<CameraFormatList> = Vec::new();

        for idx in 0..self.profile_cnt {
            match self.ctx.get_profile(i32::from(idx)) {
                Ok((fmt, width, height, fps)) => {
                    if !FRAME_FORMAT_WHITELIST.iter().any(|&x| x == fmt)
                        || !RESOLUTION_WHITELIST.iter().any(|&x| x == (width, height))
                        || !FPS_WHITELIST.iter().any(|&x| x == fps)
                    {
                        continue;
                    }

                    let frame = CameraFrame {
                        width: width as u32,
                        height: height as u32,
                        index: 1,
                        interval: FPS_INTERVAL_TRANS / fps as u32,
                    };
                    fmt_list.push(CameraFormatList {
                        format: cam_fmt_from_oh(fmt)?,
                        frame: vec![frame],
                        fmt_index: (idx) + 1,
                    });
                }
                Err(e) => error!("{:?}", e),
            }
        }
        self.fmt_list = fmt_list.clone();
        Ok(fmt_list)
    }

    fn reset(&mut self) {
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        if let Err(e) = self.ctx.reset_camera(self.camid.clone()) {
            error!("OHCAM: reset failed, err: {e}");
        }
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.stop();
    }

    fn get_format_by_index(&self, format_index: u8, frame_index: u8) -> Result<CamBasicFmt> {
        let mut out = CamBasicFmt::default();
        for fmt in &self.fmt_list {
            if fmt.fmt_index != format_index {
                continue;
            }
            out.fmttype = fmt.format;
            for frm in &fmt.frame {
                if frm.index != frame_index {
                    continue;
                }
                out.width = frm.width;
                out.height = frm.height;
                out.fps = FPS_INTERVAL_TRANS
                    .checked_div(frm.interval)
                    .with_context(|| {
                        format!(
                            "{}: Invalid interval {} for format/frame {}:{}",
                            self.id, frm.interval, format_index, frame_index
                        )
                    })?;
                return Ok(out);
            }
        }
        bail!(
            "{}: format/frame with idx {}/{} is not found",
            self.id,
            format_index,
            frame_index
        );
    }

    fn get_frame_size(&self) -> usize {
        if let Some(cb) = OHCAM_CALLBACKS.read().unwrap().get(&self.camid) {
            return cb.get_buffer().1 as usize;
        }
        0
    }

    fn next_frame(&mut self) -> Result<()> {
        #[cfg(any(
            feature = "trace_to_logger",
            feature = "trace_to_ftrace",
            all(target_env = "ohos", feature = "trace_to_hitrace")
        ))]
        self.async_scope.start();
        self.ctx.next_frame();
        if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&self.camid) {
            cb.clear_buffer();
        }
        Ok(())
    }

    fn get_frame(&self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize> {
        let (src, src_len) = OHCAM_CALLBACKS
            .read()
            .unwrap()
            .get(&self.camid)
            .with_context(|| "Invalid camid in callback table")?
            .get_buffer();

        if src.is_none() || src.unwrap() == 0 {
            bail!("Invalid frame src")
        }

        if src_len == 0_u64 {
            bail!("Invalid frame src_len {}", src_len);
        }

        if frame_offset + len > src_len as usize {
            bail!("Invalid frame offset {} or len {}", frame_offset, len);
        }

        trace::trace_scope_start!(ohcam_get_frame, args = (frame_offset, len));

        let mut copied = 0_usize;
        for iov in iovecs {
            if len == copied {
                break;
            }
            let cnt = std::cmp::min(iov.iov_len as usize, len - copied);
            let src_ptr = src.unwrap() + frame_offset as u64 + copied as u64;
            // SAFETY: the address is not out of range.
            unsafe {
                std::ptr::copy_nonoverlapping(src_ptr as *const u8, iov.iov_base as *mut u8, cnt);
            }
            copied += cnt;
        }
        Ok(copied)
    }

    fn register_notify_cb(&mut self, cb: CameraNotifyCallback) {
        OHCAM_CALLBACKS
            .write()
            .unwrap()
            .entry(self.camid.clone())
            .or_insert(OhCamCallBack::default())
            .set_notify_cb(cb);
    }

    fn register_broken_cb(&mut self, cb: CameraBrokenCallback) {
        OHCAM_CALLBACKS
            .write()
            .unwrap()
            .entry(self.camid.clone())
            .or_insert(OhCamCallBack::default())
            .set_broken_cb(cb);
    }

    fn pause(&mut self, paused: bool) {
        if self.paused == paused {
            return;
        }

        if paused {
            // If stream is off, we don't need to set self.paused.
            // Because it's not required to re-open stream while
            // vm is resuming.
            if !self.stream_on {
                return;
            }
            self.paused = true;
            self.video_stream_off().unwrap_or_else(|e| {
                error!("ohcam pause: failed to pause stream {:?}", e);
            });
        } else {
            self.paused = false;
            self.video_stream_on().unwrap_or_else(|e| {
                error!("ohcam resume: failed to resume stream {:?}", e);
            })
        }
    }
}

fn cstr_to_string(src: *const u8) -> Result<String> {
    if src.is_null() {
        bail!("cstr_to_string: src is null");
    }
    // SAFETY: we promise that 'src' ends with "null" symbol.
    let src_cstr = unsafe { CStr::from_ptr(src) };
    let target_string = src_cstr
        .to_str()
        .with_context(|| "cstr_to_string: failed to transfer camid")?
        .to_owned();

    Ok(target_string)
}

// SAFETY: use RW lock to ensure the security of resources.
unsafe extern "C" fn on_buffer_available(src_buffer: u64, length: i32, camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    if let Some(cb) = OHCAM_CALLBACKS.write().unwrap().get_mut(&cam) {
        cb.set_buffer(src_buffer, length);
        cb.notify();
    }
}

// SAFETY: use RW lock to ensure the security of resources.
unsafe extern "C" fn on_broken(camid: *const u8) {
    let cam = cstr_to_string(camid).unwrap_or_else(|e| {
        error!("{e}");
        "".to_string()
    });
    if let Some(cb) = OHCAM_CALLBACKS.read().unwrap().get(&cam) {
        cb.broken();
    }
}
