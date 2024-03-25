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

// SAFETY: The safety of this function is guaranteed by caller.
pub type BufferProcess = unsafe extern "C" fn(src_buffer: u64, length: i32);
// SAFETY: The safety of this function is guaranteed by caller.
pub type BrokenProcess = unsafe extern "C" fn();

#[derive(Default)]
pub struct ProfileRecorder {
    pub fmt: i32,
    pub width: i32,
    pub height: i32,
    pub fps: i32,
}

#[link(name = "hwf_adapter")]
extern "C" {
    pub fn OhcamCreateCtx() -> *mut c_void;
    pub fn OhcamCreateSession(ctx: *mut c_void) -> c_int;
    pub fn OhcamReleaseSession(ctx: *mut c_void);
    pub fn OhcamInitCameras(ctx: *mut c_void) -> c_int;
    pub fn OhcamInitProfiles(ctx: *mut c_void) -> c_int;
    pub fn OhcamGetProfileSize(ctx: *mut c_void, idx: c_int) -> c_int;
    pub fn OhcamGetProfile(
        ctx: *mut c_void,
        cam_idx: c_int,
        profile_idx: c_int,
        profile: *mut c_void,
    ) -> c_int;
    pub fn OhcamSetProfile(ctx: *mut c_void, cam_idx: c_int, profile_idx: c_int) -> c_int;
    pub fn OhcamPreStart(
        ctx: *mut c_void,
        buffer_proc: BufferProcess,
        broken_process: BrokenProcess,
    ) -> c_int;
    pub fn OhcamStart(ctx: *mut c_void) -> c_int;
    pub fn OhcamStopOutput(ctx: *mut c_void);
    pub fn OhcamRelease(ctx: *mut c_void);
    pub fn OhcamDestroyCtx(ctx: *mut *mut c_void);
    pub fn OhcamAllowNextFrame(ctx: *mut c_void);
}
