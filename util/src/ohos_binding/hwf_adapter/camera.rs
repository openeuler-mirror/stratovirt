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

use anyhow::{Context, Result};
use libloading::os::unix::Symbol as RawSymbol;
use libloading::Library;

use crate::get_libfn;

#[repr(C)]
#[derive(Default)]
pub struct ProfileRecorder {
    pub fmt: i32,
    pub width: i32,
    pub height: i32,
    pub fps: i32,
}

pub type BufferProcessFn = unsafe extern "C" fn(src_buffer: u64, length: i32);
pub type BrokenProcessFn = unsafe extern "C" fn();

type OhcamCreateCtxFn = unsafe extern "C" fn() -> *mut c_void;
type OhcamCreateSessionFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type OhcamReleaseSessionFn = unsafe extern "C" fn(*mut c_void);
type OhcamInitCamerasFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type OhcamInitProfilesFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type OhcamGetProfileSizeFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type OhcamGetProfileFn = unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;
type OhcamSetProfileFn = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int;
type OhcamPreStartFn = unsafe extern "C" fn(*mut c_void, BufferProcessFn, BrokenProcessFn) -> c_int;
type OhcamStartFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type OhcamStopOutputFn = unsafe extern "C" fn(*mut c_void);
type OhcamReleaseFn = unsafe extern "C" fn(*mut c_void);
type OhcamDestroyCtxFn = unsafe extern "C" fn(*mut *mut c_void);
type OhcamAllowNextFrameFn = unsafe extern "C" fn(*mut c_void);

pub struct CamFuncTable {
    pub create_ctx: RawSymbol<OhcamCreateCtxFn>,
    pub create_session: RawSymbol<OhcamCreateSessionFn>,
    pub release_session: RawSymbol<OhcamReleaseSessionFn>,
    pub init_cameras: RawSymbol<OhcamInitCamerasFn>,
    pub init_profiles: RawSymbol<OhcamInitProfilesFn>,
    pub get_profile_size: RawSymbol<OhcamGetProfileSizeFn>,
    pub get_profile: RawSymbol<OhcamGetProfileFn>,
    pub set_profile: RawSymbol<OhcamSetProfileFn>,
    pub pre_start: RawSymbol<OhcamPreStartFn>,
    pub start: RawSymbol<OhcamStartFn>,
    pub stop_output: RawSymbol<OhcamStopOutputFn>,
    pub release: RawSymbol<OhcamReleaseFn>,
    pub destroy_ctx: RawSymbol<OhcamDestroyCtxFn>,
    pub allow_next_frame: RawSymbol<OhcamAllowNextFrameFn>,
}

impl CamFuncTable {
    pub unsafe fn new(library: &Library) -> Result<CamFuncTable> {
        Ok(Self {
            create_ctx: get_libfn!(library, OhcamCreateCtxFn, OhcamCreateCtx),
            create_session: get_libfn!(library, OhcamCreateSessionFn, OhcamCreateSession),
            release_session: get_libfn!(library, OhcamReleaseSessionFn, OhcamReleaseSession),
            init_cameras: get_libfn!(library, OhcamInitCamerasFn, OhcamInitCameras),
            init_profiles: get_libfn!(library, OhcamInitProfilesFn, OhcamInitProfiles),
            get_profile_size: get_libfn!(library, OhcamGetProfileSizeFn, OhcamGetProfileSize),
            get_profile: get_libfn!(library, OhcamGetProfileFn, OhcamGetProfile),
            set_profile: get_libfn!(library, OhcamSetProfileFn, OhcamSetProfile),
            pre_start: get_libfn!(library, OhcamPreStartFn, OhcamPreStart),
            start: get_libfn!(library, OhcamStartFn, OhcamStart),
            stop_output: get_libfn!(library, OhcamStopOutputFn, OhcamStopOutput),
            release: get_libfn!(library, OhcamReleaseFn, OhcamRelease),
            destroy_ctx: get_libfn!(library, OhcamDestroyCtxFn, OhcamDestroyCtx),
            allow_next_frame: get_libfn!(library, OhcamAllowNextFrameFn, OhcamAllowNextFrame),
        })
    }
}
