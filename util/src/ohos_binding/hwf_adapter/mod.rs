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

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
mod camera;

use std::ffi::OsStr;
use std::os::raw::{c_int, c_void};
use std::sync::RwLock;

use anyhow::{Context, Result};
use libloading::Library;
use log::error;
use once_cell::sync::Lazy;

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
use camera::CamFuncTable;

static LIB_HWF_ADAPTER: Lazy<RwLock<LibHwfAdapter>> = Lazy::new(||
    // SAFETY: The dynamic library should be always existing.
    unsafe {
        RwLock::new(
            LibHwfAdapter::new(OsStr::new("/system/lib64/libhwf_adapter.so"))
                .map_err(|e| {
                    error!("failed to init LibHwfAdapter with error: {:?}", e);
                    e
                })
                .unwrap()
        )
    });

struct LibHwfAdapter {
    #[allow(unused)]
    library: Library,
    #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
    camera: CamFuncTable,
}

impl LibHwfAdapter {
    unsafe fn new(library_name: &OsStr) -> Result<LibHwfAdapter> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hwf_adapter library")?;

        #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
        let camera =
            CamFuncTable::new(&library).with_context(|| "failed to init camera function table")?;

        Ok(Self {
            library,
            #[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
            camera,
        })
    }
}

#[macro_export]
macro_rules! get_libfn {
    ( $lib: ident, $tname: ident, $fname: ident ) => {
        $lib.get::<$tname>(stringify!($fname).as_bytes())
            .with_context(|| {
                format!(
                    "failed to get function {} from libhwf_adapter",
                    stringify!($fname)
                )
            })?
            .into_raw()
    };
}

macro_rules! hwf_call {
    ( $klass: ident, $fname: ident ( $($x: expr),* ) ) => {
        (LIB_HWF_ADAPTER.read().unwrap().$klass.$fname)( $($x),* )
    };
}

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
macro_rules! hwf_camera_call {
    ( $fname: ident ( $($x: expr),* ) ) => {
        hwf_call!(camera, $fname( $($x),* ))
    };
}

/// Camera APIs in libhwf_adapter.so

#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub type ProfileRecorder = camera::ProfileRecorder;
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub type BufferProcess = camera::BufferProcessFn;
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub type BrokenProcess = camera::BrokenProcessFn;

/// # Safety
///
/// The caller must save returned value for later use.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_create_ctx() -> *mut c_void {
    hwf_camera_call!(create_ctx())
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_create_session(ctx: *mut c_void) -> c_int {
    hwf_camera_call!(create_session(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_release_session(ctx: *mut c_void) {
    hwf_camera_call!(release_session(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_init_cameras(ctx: *mut c_void) -> c_int {
    hwf_camera_call!(init_cameras(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_init_profiles(ctx: *mut c_void) -> c_int {
    hwf_camera_call!(init_profiles(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function
/// and valid profile index.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_get_profile_size(ctx: *mut c_void, idx: c_int) -> c_int {
    hwf_camera_call!(get_profile_size(ctx, idx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function,
/// valid profile pointer and valid index of camera and profile.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_get_profile(
    ctx: *mut c_void,
    cam_idx: c_int,
    profile_idx: c_int,
    profile: *mut c_void,
) -> c_int {
    hwf_camera_call!(get_profile(ctx, cam_idx, profile_idx, profile))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function
/// and valid index of camera and profile.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_set_profile(ctx: *mut c_void, cam_idx: c_int, profile_idx: c_int) -> c_int {
    hwf_camera_call!(set_profile(ctx, cam_idx, profile_idx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function
/// and take care about the logic of process callbacks.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_pre_start(
    ctx: *mut c_void,
    buffer_proc: BufferProcess,
    broken_proc: BrokenProcess,
) -> c_int {
    hwf_camera_call!(pre_start(ctx, buffer_proc, broken_proc))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_start(ctx: *mut c_void) -> c_int {
    hwf_camera_call!(start(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_stop_output(ctx: *mut c_void) {
    hwf_camera_call!(stop_output(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_release(ctx: *mut c_void) {
    hwf_camera_call!(release(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcma_destroy_ctx(ctx: *mut *mut c_void) {
    hwf_camera_call!(destroy_ctx(ctx))
}

/// # Safety
///
/// The caller must ensure the ctx is returned from OhcamCreateCtx function.
#[cfg(all(feature = "usb_camera_oh", target_env = "ohos"))]
pub unsafe fn ohcam_allow_next_frame(ctx: *mut c_void) {
    hwf_camera_call!(allow_next_frame(ctx))
}
