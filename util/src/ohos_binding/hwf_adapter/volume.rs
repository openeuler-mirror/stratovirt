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

use std::os::raw::c_int;

use anyhow::{Context, Result};
use libloading::os::unix::Symbol as RawSymbol;
use libloading::Library;

use crate::get_libfn;

pub type VolumeChangedCallBack = unsafe extern "C" fn(c_int);

type OhSysAudioGetVolumeFn = unsafe extern "C" fn() -> c_int;
type OhSysAudioSetVolumeFn = unsafe extern "C" fn(c_int);
type OhSysAudioRegisterVolumeChangeFn = unsafe extern "C" fn(VolumeChangedCallBack) -> c_int;

pub struct VolumeFuncTable {
    pub get_volume: RawSymbol<OhSysAudioGetVolumeFn>,
    pub set_volume: RawSymbol<OhSysAudioSetVolumeFn>,
    pub register_volume_change: RawSymbol<OhSysAudioRegisterVolumeChangeFn>,
}

impl VolumeFuncTable {
    pub unsafe fn new(library: &Library) -> Result<VolumeFuncTable> {
        Ok(Self {
            get_volume: get_libfn!(library, OhSysAudioGetVolumeFn, OhSysAudioGetVolume),
            set_volume: get_libfn!(library, OhSysAudioSetVolumeFn, OhSysAudioSetVolume),
            register_volume_change: get_libfn!(
                library,
                OhSysAudioRegisterVolumeChangeFn,
                OhSysAudioRegisterVolumeChange
            ),
        })
    }
}
