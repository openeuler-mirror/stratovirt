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

use std::os::raw::{c_int, c_void};
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use once_cell::sync::Lazy;

use super::ohcam_rapi::*;
use crate::camera_backend::{
    CamBasicFmt, CameraBackend, CameraBrokenCallback, CameraFormatList, CameraFrame,
    CameraNotifyCallback, FmtType,
};
use util::aio::Iovec;

type OhCamCB = RwLock<OhCamCallBack>;
static OHCAM_CALLBACK: Lazy<OhCamCB> = Lazy::new(|| RwLock::new(OhCamCallBack::default()));

// In UVC, interval's unit is 100ns.
// So, fps * interval / 10_000_000 == 1.
const FPS_INTERVAL_TRANS: u32 = 10_000_000;

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

#[derive(Clone)]
pub struct OhCameraBackend {
    id: String,
    camidx: u8,
    profile_cnt: u8,
    ctx: *mut c_void,
    fmt_list: Vec<CameraFormatList>,
    selected_profile: u8,
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type.
// implementing them is safe because ctx field is access.
unsafe impl Send for OhCameraBackend {}
// SAFETY: Same reason as above.
unsafe impl Sync for OhCameraBackend {}

fn cam_fmt_from_oh(t: i32) -> Result<FmtType> {
    let fmt = match t {
        CAMERA_FORMAT_YUV420SP => FmtType::Nv12,
        CAMERA_FORMAT_MJPEG => FmtType::Mjpg,
        _ => bail!("OHCAM: No supported type {}", t),
    };

    Ok(fmt)
}

impl OhCameraBackend {
    pub fn new(id: String, camid: String) -> Result<Self> {
        let p_ctx = ohcam_init()?;
        let idx = camid.parse::<u8>().with_context(|| "Invalid PATH format")?;
        check_cam_idx(idx)?;

        let profile_cnt = ohcam_get_fmt_nums(p_ctx, idx as i32)? as u8;

        Ok(OhCameraBackend {
            id,
            camidx: idx,
            profile_cnt,
            ctx: p_ctx,
            fmt_list: vec![],
            selected_profile: 0,
        })
    }
}

impl Drop for OhCameraBackend {
    fn drop(&mut self) {
        ohcam_release_camera(self.ctx);
        ohcam_drop_ctx(std::ptr::addr_of_mut!(self.ctx));
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
                ohcam_set_fmt(self.ctx, self.camidx as i32, self.selected_profile as i32)?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn set_ctl(&self) -> Result<()> {
        Ok(())
    }

    fn video_stream_on(&mut self) -> Result<()> {
        ohcam_start_stream(self.ctx, on_buffer_available, on_broken)
    }

    fn video_stream_off(&mut self) -> Result<()> {
        ohcam_stop_stream(self.ctx);
        OHCAM_CALLBACK.write().unwrap().clear_buffer();
        Ok(())
    }

    fn list_format(&mut self) -> Result<Vec<CameraFormatList>> {
        let mut fmt_list: Vec<CameraFormatList> = Vec::new();
        let mut fmt: c_int = 0;
        let mut w: c_int = 0;
        let mut h: c_int = 0;
        let mut fps: c_int = 0;
        for idx in 0..self.profile_cnt {
            if ohcam_get_profile(
                self.ctx,
                self.camidx as i32,
                idx as i32,
                &mut fmt,
                &mut w,
                &mut h,
                &mut fps,
            )
            .is_err()
            {
                continue;
            }
            // NOTE: windows camera APP doesn't support fps lower than 30, and some OH PC only support 15 fps.
            if fps < 30 {
                fps = 30;
            }
            if (fmt != CAMERA_FORMAT_YUV420SP) && (fmt != CAMERA_FORMAT_MJPEG) {
                continue;
            }
            let frame = CameraFrame {
                width: w as u32,
                height: h as u32,
                index: 1,
                interval: FPS_INTERVAL_TRANS / fps as u32,
            };
            fmt_list.push(CameraFormatList {
                format: cam_fmt_from_oh(fmt)?,
                frame: vec![frame],
                fmt_index: (idx) + 1,
            });
        }
        self.fmt_list = fmt_list.clone();
        Ok(fmt_list)
    }

    fn reset(&mut self) {
        OHCAM_CALLBACK.write().unwrap().clear_buffer();
        ohcam_reset_cam(self.ctx);
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
        OHCAM_CALLBACK.read().unwrap().get_buffer().1 as usize
    }

    fn next_frame(&mut self) -> Result<()> {
        ohcam_next_frame(self.ctx);
        OHCAM_CALLBACK.write().unwrap().clear_buffer();
        Ok(())
    }

    fn get_frame(&self, iovecs: &[Iovec], frame_offset: usize, len: usize) -> Result<usize> {
        let (src, src_len) = OHCAM_CALLBACK.read().unwrap().get_buffer();
        if src_len == 0 {
            bail!("Invalid frame src_len {}", src_len);
        }

        if frame_offset + len > src_len as usize {
            bail!("Invalid frame offset {} or len {}", frame_offset, len);
        }

        let mut copied = 0;
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
        OHCAM_CALLBACK.write().unwrap().set_notify_cb(cb);
    }

    fn register_broken_cb(&mut self, cb: CameraBrokenCallback) {
        OHCAM_CALLBACK.write().unwrap().set_broken_cb(cb);
    }
}

// SAFETY: use RW lock to ensure the security of resources.
unsafe extern "C" fn on_buffer_available(src_buffer: u64, length: i32) {
    OHCAM_CALLBACK
        .write()
        .unwrap()
        .set_buffer(src_buffer, length);
    OHCAM_CALLBACK.read().unwrap().notify();
}

// SAFETY: use RW lock to ensure the security of resources.
unsafe extern "C" fn on_broken() {
    OHCAM_CALLBACK.read().unwrap().broken();
}
