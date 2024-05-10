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
use std::sync::Arc;

use anyhow::{bail, Result};

use super::hwf_adapter::camera::{
    BrokenProcessFn, BufferProcessFn, CamFuncTable, OhCameraCtx, ProfileRecorder,
};
use super::hwf_adapter::hwf_adapter_camera_api;

// OH camera framework's related definitions
#[allow(unused)]
pub const CAMERA_FORMAT_YCBCR420: i32 = 2;
#[allow(unused)]
pub const CAMERA_FORMAT_RGB18888: i32 = 3;
pub const CAMERA_FORMAT_YUV420SP: i32 = 1003;
pub const CAMERA_FORMAT_MJPEG: i32 = 2000;

#[derive(Clone)]
pub struct OhCamera {
    ctx: *mut OhCameraCtx,
    capi: Arc<CamFuncTable>,
}

impl Drop for OhCamera {
    fn drop(&mut self) {
        self.release_camera();
        self.destroy_ctx();
    }
}

impl OhCamera {
    pub fn new(idx: i32) -> Result<OhCamera> {
        let capi = hwf_adapter_camera_api();
        // SAFETY: We call related API sequentially for specified ctx.
        let mut ctx = unsafe { (capi.create_ctx)() };
        if ctx.is_null() {
            bail!("OH Camera: failed to create camera ctx");
        }
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            let n = (capi.init_cameras)(ctx);
            if n < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                bail!("OH Camera: failed to init cameras");
            } else if idx >= n {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                bail!(
                    "OH Camera: invalid idx {}, valid num is less than {}",
                    idx,
                    n
                );
            }
            if (capi.init_profiles)(ctx) < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                bail!("OH Camera: failed to init profiles");
            }
        }
        Ok(Self { ctx, capi })
    }

    pub fn get_fmt_nums(&self, idx: i32) -> Result<i32> {
        // SAFETY: We call related API sequentially for specified ctx.
        let ret = unsafe { (self.capi.get_profile_size)(self.ctx, idx as c_int) };
        if ret < 0 {
            bail!("OH Camera: invalid camera idx {}", idx);
        }
        Ok(ret)
    }

    pub fn release_camera(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe { (self.capi.release)(self.ctx) }
    }

    pub fn destroy_ctx(&mut self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe { (self.capi.destroy_ctx)(ptr::addr_of_mut!(self.ctx)) }
    }

    pub fn set_fmt(&self, cam_idx: i32, profile_idx: i32) -> Result<()> {
        let ret =
            // SAFETY: We call related API sequentially for specified ctx.
            unsafe { (self.capi.set_profile)(self.ctx, cam_idx as c_int, profile_idx as c_int) };
        if ret < 0 {
            bail!("OH Camera: failed to get camera profile");
        }
        Ok(())
    }

    pub fn start_stream(
        &self,
        buffer_proc: BufferProcessFn,
        broken_proc: BrokenProcessFn,
    ) -> Result<()> {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            if (self.capi.pre_start)(self.ctx, buffer_proc, broken_proc) != 0 {
                bail!("OH Camera: failed to prestart camera stream");
            }
            if (self.capi.start)(self.ctx) != 0 {
                bail!("OH Camera: failed to start camera stream");
            }
        }
        Ok(())
    }

    pub fn reset_camera(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            (self.capi.create_session)(self.ctx);
            (self.capi.init_cameras)(self.ctx);
            (self.capi.init_profiles)(self.ctx);
        }
    }

    pub fn stop_stream(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            (self.capi.stop_output)(self.ctx);
            (self.capi.release_session)(self.ctx);
        }
    }

    pub fn get_profile(&self, cam_idx: i32, profile_idx: i32) -> Result<(i32, i32, i32, i32)> {
        let pr = ProfileRecorder::default();
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            let ret = (self.capi.get_profile)(
                self.ctx,
                cam_idx as c_int,
                profile_idx as c_int,
                ptr::addr_of!(pr) as *mut c_void,
            );
            if ret < 0 {
                bail!(
                    "OH Camera: failed to get camera {} profile {}",
                    cam_idx,
                    profile_idx
                );
            }
        }
        Ok((pr.fmt, pr.width, pr.height, pr.fps))
    }

    pub fn next_frame(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            (self.capi.allow_next_frame)(self.ctx);
        }
    }
}
