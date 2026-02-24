// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::ffi::OsStr;
use std::os::raw::{c_int, c_uchar};

use anyhow::{Context, Result};
use libloading::os::unix::Symbol as RawSymbol;
use libloading::Library;
use log::error;
use once_cell::sync::Lazy;

use crate::get_libfn;

#[derive(Debug)]
pub enum FilterMode {
    /// Point sample; Fastest.
    FilterNone,
    /// Filter horizontally only.
    FilterLinear,
    /// Faster than box, but lower quality scaling down.
    FilterBilinear,
    /// Highest quality.
    FilterBox,
}

#[allow(clippy::from_over_into)]
impl Into<i32> for FilterMode {
    fn into(self) -> i32 {
        match self {
            FilterMode::FilterNone => 0,
            FilterMode::FilterLinear => 1,
            FilterMode::FilterBilinear => 2,
            FilterMode::FilterBox => 3,
        }
    }
}

type NV12ToI420RotateFn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_vu: *const c_uchar,
    src_stride_vu: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_u: *mut c_uchar,
    dst_stride_u: c_int,
    dst_v: *mut c_uchar,
    dst_stride_v: c_int,
    width: c_int,
    height: c_int,
    mode: c_int,
) -> c_int;

type I420ToNV12Fn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_u: *const c_uchar,
    src_stride_u: c_int,
    src_v: *const c_uchar,
    src_stride_v: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_vu: *mut c_uchar,
    dst_stride_vu: c_int,
    width: c_int,
    height: c_int,
) -> c_int;

type YUY2ToI420Fn = unsafe extern "C" fn(
    src_yuy2: *const c_uchar,
    src_stride_yuy2: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_u: *mut c_uchar,
    dst_stride_u: c_int,
    dst_v: *mut c_uchar,
    dst_stride_v: c_int,
    width: c_int,
    height: c_int,
) -> c_int;

type I420RotateFn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_u: *const c_uchar,
    src_stride_u: c_int,
    src_v: *const c_uchar,
    src_stride_v: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_u: *mut c_uchar,
    dst_stride_u: c_int,
    dst_v: *mut c_uchar,
    dst_stride_v: c_int,
    width: c_int,
    height: c_int,
    rotation: c_int,
) -> c_int;

type I420ToYUY2Fn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_u: *const c_uchar,
    src_stride_u: c_int,
    src_v: *const c_uchar,
    src_stride_v: c_int,
    dst_yuy2: *mut c_uchar,
    dst_stride_yuy2: c_int,
    width: c_int,
    height: c_int,
) -> c_int;

type I420ScaleFn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_u: *const c_uchar,
    src_stride_u: c_int,
    src_v: *const c_uchar,
    src_stride_v: c_int,
    src_width: c_int,
    src_height: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_u: *mut c_uchar,
    dst_stride_u: c_int,
    dst_v: *mut c_uchar,
    dst_stride_v: c_int,
    dst_width: c_int,
    dst_height: c_int,
    filtering: c_int,
) -> c_int;

type I420RectFn = unsafe extern "C" fn(
    dst_y: *const c_uchar,
    dst_stride_y: c_int,
    dst_u: *const c_uchar,
    dst_stride_u: c_int,
    dst_v: *const c_uchar,
    dst_stride_v: c_int,
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    value_y: c_int,
    value_u: c_int,
    value_v: c_int,
) -> c_int;

type I420CopyFn = unsafe extern "C" fn(
    src_y: *const c_uchar,
    src_stride_y: c_int,
    src_u: *const c_uchar,
    src_stride_u: c_int,
    src_v: *const c_uchar,
    src_stride_v: c_int,
    dst_y: *mut c_uchar,
    dst_stride_y: c_int,
    dst_u: *mut c_uchar,
    dst_stride_u: c_int,
    dst_v: *mut c_uchar,
    dst_stride_v: c_int,
    width: c_int,
    height: c_int,
) -> c_int;

static LIB_YUV: Lazy<OhYuvApi> = Lazy::new(||
    // SAFETY: The dynamic library should be always existing.
    unsafe {
        OhYuvApi::new()
            .map_err(|e| {
                error!("failed to init LibHwfAdapter with error: {:?}", e);
                e
            })
            .unwrap()
    });

pub struct OhYuvApi {
    // NV12ToI420RotateFn
    nv12_to_i420_rotate: RawSymbol<NV12ToI420RotateFn>,
    // I420ToNV12Fn
    i420_to_nv12: RawSymbol<I420ToNV12Fn>,
    // YUY2ToI420Fn
    yuy2_to_i420: RawSymbol<YUY2ToI420Fn>,
    // I420RotateFn
    i420_rotate: RawSymbol<I420RotateFn>,
    // I420ToYUY2Fn
    i420_to_yuy2: RawSymbol<I420ToYUY2Fn>,
    // I420ScaleFn
    i420_scale: RawSymbol<I420ScaleFn>,
    // I420RectFn
    i420_rect: RawSymbol<I420RectFn>,
    // I420CopyFn
    i420_copy: RawSymbol<I420CopyFn>,
    #[allow(unused)]
    library: Library,
}

impl OhYuvApi {
    /// # Safety
    ///
    /// This function loads the `libyuv` dynamic library.
    pub unsafe fn new() -> Result<OhYuvApi> {
        let library_name = OsStr::new("libyuv.z.so");
        let library = Library::new(library_name).with_context(|| "failed to load yuv library")?;
        let library_ref = &library;

        Ok(Self {
            nv12_to_i420_rotate: get_libfn!(library_ref, NV12ToI420RotateFn, NV12ToI420Rotate),
            i420_to_nv12: get_libfn!(library_ref, I420ToNV12Fn, I420ToNV12),
            yuy2_to_i420: get_libfn!(library_ref, YUY2ToI420Fn, YUY2ToI420),
            i420_rotate: get_libfn!(library_ref, I420RotateFn, I420Rotate),
            i420_to_yuy2: get_libfn!(library_ref, I420ToYUY2Fn, I420ToYUY2),
            i420_scale: get_libfn!(library_ref, I420ScaleFn, I420Scale),
            i420_rect: get_libfn!(library_ref, I420RectFn, I420Rect),
            i420_copy: get_libfn!(library_ref, I420CopyFn, I420Copy),
            library,
        })
    }
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - src_vu should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_vu * height / 2
/// - dst_stride_y should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_y * height or dst_stride_y * width according to
///   the rotation degree indicated by mode.
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_u * height / 4 or dst_stride_u * width / 4
///   according to the rotation degree indicated by mode.
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_v * height / 4 or dst_stride_v * width / 4
///   according to the rotation degree indicated by mode.
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn nv12_to_i420_rotate(
    src_y: u64,
    src_stride_y: i32,
    src_vu: u64,
    src_stride_vu: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    width: i32,
    height: i32,
    mode: i32,
) -> i32 {
    (*LIB_YUV.nv12_to_i420_rotate)(
        src_y as *const u8,
        src_stride_y,
        src_vu as *const u8,
        src_stride_vu,
        dst_y as *mut u8,
        dst_stride_y,
        dst_u as *mut u8,
        dst_stride_u,
        dst_v as *mut u8,
        dst_stride_v,
        width,
        height,
        mode,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - src_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * height / 4
/// - src_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_y * height
/// - dst_vu should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_vu * height / 2
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_to_nv12(
    src_y: u64,
    src_stride_y: i32,
    src_u: u64,
    src_stride_u: i32,
    src_v: u64,
    src_stride_v: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_vu: u64,
    dst_stride_vu: i32,
    width: i32,
    height: i32,
) -> i32 {
    (*LIB_YUV.i420_to_nv12)(
        src_y as *const u8,
        src_stride_y,
        src_u as *const u8,
        src_stride_u,
        src_v as *const u8,
        src_stride_v,
        dst_y as *mut u8,
        dst_stride_y,
        dst_vu as *mut u8,
        dst_stride_vu,
        width,
        height,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_yuy2 should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_yuy2 * height
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_u * height / 4
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn yuy2_to_i420(
    src_yuy2: u64,
    src_stride_yuy2: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    width: i32,
    height: i32,
) -> i32 {
    (*LIB_YUV.yuy2_to_i420)(
        src_yuy2 as *const u8,
        src_stride_yuy2,
        dst_y as *mut u8,
        dst_stride_y,
        dst_u as *mut u8,
        dst_stride_u,
        dst_v as *mut u8,
        dst_stride_v,
        width,
        height,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - src_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * height / 4
/// - src_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_y * height or dst_stride_y * width according
///   to rotation
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_u * height / 4 or dst_stride_u * width / 4
///   according to rotation
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_v * height / 4 or dst_stride_v * width / 4
///   according to rotation
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_rotate(
    src_y: u64,
    src_stride_y: i32,
    src_u: u64,
    src_stride_u: i32,
    src_v: u64,
    src_stride_v: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    width: i32,
    height: i32,
    rotation: i32,
) -> i32 {
    (*LIB_YUV.i420_rotate)(
        src_y as *const u8,
        src_stride_y,
        src_u as *const u8,
        src_stride_u,
        src_v as *const u8,
        src_stride_v,
        dst_y as *mut u8,
        dst_stride_y,
        dst_u as *mut u8,
        dst_stride_u,
        dst_v as *mut u8,
        dst_stride_v,
        width,
        height,
        rotation,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - src_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * height / 4
/// - src_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
/// - dst_yuy2 should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_yuy2 * height
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_to_yuy2(
    src_y: u64,
    src_stride_y: i32,
    src_u: u64,
    src_stride_u: i32,
    src_v: u64,
    src_stride_v: i32,
    dst_yuy2: u64,
    dst_stride_yuy2: i32,
    width: i32,
    height: i32,
) -> i32 {
    (*LIB_YUV.i420_to_yuy2)(
        src_y as *const u8,
        src_stride_y,
        src_u as *const u8,
        src_stride_u,
        src_v as *const u8,
        src_stride_v,
        dst_yuy2 as *mut u8,
        dst_stride_yuy2,
        width,
        height,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * src_height
/// - src_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * src_height / 4
/// - src_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * src_height / 4
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_y * src_height
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_u * dst_height / 4
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_v * dst_height / 4
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_scale(
    src_y: u64,
    src_stride_y: i32,
    src_u: u64,
    src_stride_u: i32,
    src_v: u64,
    src_stride_v: i32,
    src_width: i32,
    src_height: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    dst_width: i32,
    dst_height: i32,
    filtering: i32,
) -> i32 {
    (*LIB_YUV.i420_scale)(
        src_y as *const u8,
        src_stride_y,
        src_u as *const u8,
        src_stride_u,
        src_v as *const u8,
        src_stride_v,
        src_width,
        src_height,
        dst_y as *mut u8,
        dst_stride_y,
        dst_u as *mut u8,
        dst_stride_u,
        dst_v as *mut u8,
        dst_stride_v,
        dst_width,
        dst_height,
        filtering,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_y * height
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_u * height / 4
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than dst_stride_v * height / 4
/// - the rectangle describe by (x, y, width, height) should be within the
///   dst_stride_y * height.
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_rect(
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    value_y: i32,
    value_u: i32,
    value_v: i32,
) -> i32 {
    (*LIB_YUV.i420_rect)(
        dst_y as *const u8,
        dst_stride_y,
        dst_u as *const u8,
        dst_stride_u,
        dst_v as *const u8,
        dst_stride_v,
        x,
        y,
        width,
        height,
        value_y,
        value_u,
        value_v,
    )
}

/// # Safety
///
/// This function is unsafe because we pass memory addresses to C API of libyuv.
/// The caller must ensure that the buffers are valid.
///
/// - src_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - src_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * height / 4
/// - src_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
/// - dst_y should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_y * height
/// - dst_u should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_u * height / 4
/// - dst_v should be valid address and the buffer indicated by it should be
///   equal or greater than src_stride_v * height / 4
///
/// Failure to meet these conditions will lead to undefined behavior.
#[allow(clippy::too_many_arguments)]
pub unsafe fn i420_copy(
    src_y: u64,
    src_stride_y: i32,
    src_u: u64,
    src_stride_u: i32,
    src_v: u64,
    src_stride_v: i32,
    dst_y: u64,
    dst_stride_y: i32,
    dst_u: u64,
    dst_stride_u: i32,
    dst_v: u64,
    dst_stride_v: i32,
    width: i32,
    height: i32,
) -> i32 {
    (*LIB_YUV.i420_copy)(
        src_y as *const u8,
        src_stride_y,
        src_u as *const u8,
        src_stride_u,
        src_v as *const u8,
        src_stride_v,
        dst_y as *mut u8,
        dst_stride_y,
        dst_u as *mut u8,
        dst_stride_u,
        dst_v as *mut u8,
        dst_stride_v,
        width,
        height,
    )
}
