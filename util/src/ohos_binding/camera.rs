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

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use log::error;

use super::hwf_adapter::camera::{
    AvailCallBackFn, BrokenProcessFn, BufferProcessFn, CamFuncTable, OhCameraCtx,
    OnErrorCallBackFn, ProfileRecorder,
};
use super::hwf_adapter::hwf_adapter_camera_api;

// OH camera framework's related definitions
#[allow(unused)]
pub const CAMERA_FORMAT_YCBCR420: i32 = 2;
#[allow(unused)]
pub const CAMERA_FORMAT_RGB18888: i32 = 3;
pub const CAMERA_FORMAT_YUV420SP: i32 = 1003;
pub const CAMERA_FORMAT_NV12: i32 = 1004;
pub const CAMERA_FORMAT_YUYV422: i32 = 1005;
pub const CAMERA_FORMAT_MJPEG: i32 = 2000;
const CAMERA_ERRCODE_NULL_CTX: i32 = 1;
const CAMERA_ERRCODE_FAILED_GET_CAMERA: i32 = 4;

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
    pub fn new(id: String) -> Result<(OhCamera, i32), i32> {
        let capi = hwf_adapter_camera_api();
        // SAFETY: We call related API sequentially for specified ctx.
        let mut ctx = unsafe { (capi.create_ctx)() };
        if ctx.is_null() {
            error!("OH Camera: failed to create camera ctx");
            return Err(CAMERA_ERRCODE_NULL_CTX);
        }
        let id_c = match CString::new(id) {
            Ok(id) => id,
            Err(_) => {
                error!("failed to create CString id");
                return Err(CAMERA_ERRCODE_FAILED_GET_CAMERA);
            }
        };
        let fmt_cnt;
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            let n = (capi.init_camera)(ctx, id_c.as_ptr());
            if n < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                error!("OH Camera: failed to init cameras");
                return Err(-n);
            }

            fmt_cnt = (capi.init_profiles)(ctx);
            if fmt_cnt < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                error!("OH Camera: failed to init profiles");
                return Err(-fmt_cnt);
            }
        }
        if fmt_cnt > i32::from(u8::MAX) {
            error!("Invalid format counts: {fmt_cnt}");
            return Err(CAMERA_ERRCODE_FAILED_GET_CAMERA);
        }
        Ok((Self { ctx, capi }, fmt_cnt))
    }

    pub fn release_camera(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe { (self.capi.release)(self.ctx) }
    }

    pub fn destroy_ctx(&mut self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe { (self.capi.destroy_ctx)(ptr::addr_of_mut!(self.ctx)) }
    }

    pub fn set_fmt(&self, profile_idx: i32) -> Result<()> {
        let ret =
            // SAFETY: We call related API sequentially for specified ctx.
            unsafe { (self.capi.set_profile)(self.ctx, profile_idx as c_int) };
        if ret < 0 {
            bail!("OH Camera: failed to get camera profile");
        }
        Ok(())
    }

    pub fn start_stream(
        &self,
        buffer_proc: BufferProcessFn,
        broken_proc: BrokenProcessFn,
        avail_proc: AvailCallBackFn,
        error_proc: OnErrorCallBackFn,
    ) -> Result<(), i32> {
        let mut ret;
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            ret = (self.capi.create_session)(self.ctx);
            if ret != 0 {
                error!("OH Camera: failed to create session");
                return Err(-ret);
            }
            ret = (self.capi.pre_start)(self.ctx, buffer_proc, broken_proc, avail_proc, error_proc);
            if ret != 0 {
                error!("OH Camera: failed to prestart camera stream");
                return Err(-ret);
            }
            ret = (self.capi.start)(self.ctx);
            if ret != 0 {
                error!("OH Camera: failed to start camera stream");
                return Err(-ret);
            }
        }
        Ok(())
    }

    pub fn reset_camera(&self, id: String) -> Result<()> {
        let id_cstr = CString::new(id).with_context(|| "failed to create CString id")?;
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            (self.capi.init_camera)(self.ctx, id_cstr.as_ptr());
            (self.capi.init_profiles)(self.ctx);
        }
        Ok(())
    }

    pub fn stop_stream(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            (self.capi.stop_output)(self.ctx);
            (self.capi.release_session)(self.ctx);
        }
    }

    pub fn get_profile(&self, profile_idx: i32) -> Result<(i32, i32, i32, i32)> {
        let pr = ProfileRecorder::default();
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe {
            let ret = (self.capi.get_profile)(
                self.ctx,
                profile_idx as c_int,
                ptr::addr_of!(pr) as *mut c_void,
            );
            if ret < 0 {
                bail!("OH Camera: failed to get profile {}", profile_idx);
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
