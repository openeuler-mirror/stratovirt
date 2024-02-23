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
use std::ptr;

use anyhow::{bail, Result};

use super::ohcam_bindings as capi;

// OH camera framework's related definitions
#[allow(unused)]
pub const CAMERA_FORMAT_YCBCR420: i32 = 2;
#[allow(unused)]
pub const CAMERA_FORMAT_RGB18888: i32 = 3;
pub const CAMERA_FORMAT_YUV420SP: i32 = 1003;
pub const CAMERA_FORMAT_MJPEG: i32 = 2000;

// camera path is actually the specified camera ID.
pub fn check_cam_idx(idx: u8) -> Result<()> {
    // SAFETY: We call related API sequentially for specified ctx.
    let mut ctx = unsafe { capi::OhcamCreateCtx() };
    // SAFETY: We call related API sequentially for specified ctx.
    let n = unsafe { capi::OhcamInitCameras(ctx) };
    if n < 0 {
        ohcam_drop_ctx(ptr::addr_of_mut!(ctx));
        bail!("OHCAM WRAPPER: failed to init cameras");
    } else if idx + 1 > n as u8 {
        ohcam_drop_ctx(ptr::addr_of_mut!(ctx));
        bail!("Invalid idx: {}, valid num is less than {}", idx, n);
    }
    ohcam_drop_ctx(ptr::addr_of_mut!(ctx));
    Ok(())
}

pub fn ohcam_init() -> Result<*mut c_void> {
    // SAFETY: We call related API sequentially for specified ctx.
    let mut ctx = unsafe { capi::OhcamCreateCtx() };
    if ctx.is_null() {
        bail!("OHCAM WRAPPER: create camera ctx failed");
    }
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        if capi::OhcamInitCameras(ctx) < 0 {
            ohcam_drop_ctx(ptr::addr_of_mut!(ctx));
            bail!("OHCAM WRAPPER: failed to init cameras");
        }
        if capi::OhcamInitProfiles(ctx) < 0 {
            ohcam_drop_ctx(ptr::addr_of_mut!(ctx));
            bail!("OHCAM WRAPPER: failed to init profiles");
        }
    }
    Ok(ctx)
}

pub fn ohcam_get_fmt_nums(ctx: *mut c_void, idx: c_int) -> Result<c_int> {
    // SAFETY: We call related API sequentially for specified ctx.
    let ret = unsafe { capi::OhcamGetProfileSize(ctx, idx) };
    if ret < 0 {
        bail!("OHCAM WRAPPER: invalid camera idx {}", idx);
    }
    Ok(ret)
}

pub fn ohcam_release_camera(ctx: *mut c_void) {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe { capi::OhcamRelease(ctx) };
}

pub fn ohcam_drop_ctx(p_ctx: *mut *mut c_void) {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe { capi::OhcamDestroyCtx(p_ctx) };
}

pub fn ohcam_set_fmt(ctx: *mut c_void, cam_idx: c_int, profile_idx: c_int) -> Result<()> {
    // SAFETY: We call related API sequentially for specified ctx.
    let ret = unsafe { capi::OhcamSetProfile(ctx, cam_idx, profile_idx) };
    if ret < 0 {
        bail!("OHCAM WRAPPER: Failed to ohcam_set_profile");
    }
    Ok(())
}

pub fn ohcam_start_stream(
    ctx: *mut c_void,
    buffer_proc: capi::BufferProcess,
    broken_process: capi::BrokenProcess,
) -> Result<()> {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        if capi::OhcamPreStart(ctx, buffer_proc, broken_process) != 0 {
            bail!("OHCAM WRAPPER: Pre start failed");
        }
        if capi::OhcamStart(ctx) != 0 {
            bail!("OHCAM WRAPPER: Start failed");
        }
    }
    Ok(())
}

pub fn ohcam_reset_cam(ctx: *mut c_void) {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        capi::OhcamCreateSession(ctx);
        capi::OhcamInitCameras(ctx);
        capi::OhcamInitProfiles(ctx);
    }
}

pub fn ohcam_stop_stream(ctx: *mut c_void) {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        capi::OhcamStopOutput(ctx);
        capi::OhcamReleaseSession(ctx);
    }
}

pub fn ohcam_get_profile(
    ctx: *mut c_void,
    cam_idx: c_int,
    profile_idx: c_int,
    format: *mut c_int,
    width: *mut c_int,
    height: *mut c_int,
    fps: *mut c_int,
) -> Result<()> {
    let profile_recorder = capi::ProfileRecorder::default();
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        let ret = capi::OhcamGetProfile(
            ctx,
            cam_idx,
            profile_idx,
            ptr::addr_of!(profile_recorder) as *mut c_void,
        );
        if ret < 0 {
            bail!("Failed to OhcamGetProfile");
        }
        *format = profile_recorder.fmt;
        *width = profile_recorder.width;
        *height = profile_recorder.height;
        *fps = profile_recorder.fps;
    }
    Ok(())
}

pub fn ohcam_next_frame(ctx: *mut c_void) {
    // SAFETY: We call related API sequentially for specified ctx.
    unsafe {
        capi::OhcamAllowNextFrame(ctx);
    }
}
