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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CamConnectionType {
    BuiltIn,
    UsbPlugin,
    Remote,
}

impl TryFrom<i32> for CamConnectionType {
    type Error = &'static str;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CamConnectionType::BuiltIn),
            1 => Ok(CamConnectionType::UsbPlugin),
            2 => Ok(CamConnectionType::Remote),
            _ => Err("Unknown camera connection type"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CamPosition {
    Unspecified,
    Back,
    Front,
    FoldInner,
}

impl TryFrom<i32> for CamPosition {
    type Error = &'static str;

    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CamPosition::Unspecified),
            1 => Ok(CamPosition::Back),
            2 => Ok(CamPosition::Front),
            3 => Ok(CamPosition::FoldInner),
            _ => Err("Unknown camera position"),
        }
    }
}

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
    pub fn new(
        id: String,
    ) -> Result<(OhCamera, i32, CamConnectionType, CamPosition, Option<i32>), i32> {
        let capi = hwf_adapter_camera_api();
        // SAFETY: The memory of context is returned by C API create_ctx() and
        // we will check the returned value.
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
        let connection_type;
        let mut position = CamPosition::Unspecified;
        let mut orientation = None;

        // SAFETY: All C APIs called below only take context as the parameter
        // which is created above and we have checked its validation.
        unsafe {
            let mut ret = (capi.init_camera)(ctx, id_c.as_ptr());
            if ret < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                error!("OH Camera: failed to init cameras");
                return Err(-ret);
            }

            fmt_cnt = (capi.init_profiles)(ctx);
            if fmt_cnt < 0 {
                (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                error!("OH Camera: failed to init profiles");
                return Err(-fmt_cnt);
            }

            ret = (capi.get_connection_type)(ctx);
            connection_type = match CamConnectionType::try_from(ret) {
                Ok(v) => v,
                Err(e) => {
                    (capi.destroy_ctx)(ptr::addr_of_mut!(ctx));
                    error!("OH Camera: {:?}, type: {}", e, ret);
                    return Err(ret);
                }
            };

            if connection_type == CamConnectionType::BuiltIn {
                ret = (capi.get_position)(ctx);
                position = match CamPosition::try_from(ret) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("OH Camera: {:?}, value: {}", e, ret);
                        CamPosition::Unspecified
                    }
                };
                orientation = Some((capi.get_orientation)(ctx));
            }
        }
        if fmt_cnt > i32::from(u8::MAX) {
            error!("Invalid format counts: {fmt_cnt}");
            return Err(CAMERA_ERRCODE_FAILED_GET_CAMERA);
        }
        Ok((
            Self { ctx, capi },
            fmt_cnt,
            connection_type,
            position,
            orientation,
        ))
    }

    pub fn release_camera(&self) {
        // SAFETY: We call related API sequentially for specified ctx.
        unsafe { (self.capi.release)(self.ctx) }
    }

    pub fn destroy_ctx(&mut self) {
        // SAFETY: as the comment of destroy_ctx(), ctx can be NULL.
        unsafe { (self.capi.destroy_ctx)(ptr::addr_of_mut!(self.ctx)) }
    }

    pub fn set_fmt(&self, profile_idx: i32) -> Result<()> {
        let ret =
            // SAFETY: context is null or valid and as the comment of set_profile()
            // context can be null.
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
        // SAFETY: all C APIs called below has returned value. We check all the
        // returned value and return error to the caller. In addition, context
        // can be NULL.
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
        // SAFETY: as the comment of below C APIs, they can process context
        // with NULL value and although they have no returned value but the
        // other APIs called later will return error.
        unsafe {
            (self.capi.init_camera)(self.ctx, id_cstr.as_ptr());
            (self.capi.init_profiles)(self.ctx);
        }
        Ok(())
    }

    pub fn stop_stream(&self) {
        // SAFETY: as the comment of below C APIs, they can process context
        // with NULL value and although they have no returned value but the
        // other APIs called later will return error.
        unsafe {
            (self.capi.stop_output)(self.ctx);
            (self.capi.release_session)(self.ctx);
        }
    }

    pub fn get_profile(&self, profile_idx: i32) -> Result<(i32, i32, i32, i32)> {
        let pr = ProfileRecorder::default();
        // SAFETY: we check the returned value and return the error to the caller.
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
        // SAFETY: as the comment of allow_next_frame(), context can be NULL.
        unsafe {
            (self.capi.allow_next_frame)(self.ctx);
        }
    }
}
