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

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct OhusbDevice {
    pub busNum: u8,
    pub devAddr: u8,
    pub fd: c_int,
}

type OhusbOpenDeviceFn = unsafe extern "C" fn(*mut OhusbDevice) -> c_int;
type OhusbCloseDeviceFn = unsafe extern "C" fn(*mut OhusbDevice) -> c_int;

pub struct UsbFuncTable {
    pub open_device: RawSymbol<OhusbOpenDeviceFn>,
    pub close_device: RawSymbol<OhusbCloseDeviceFn>,
}

impl UsbFuncTable {
    pub unsafe fn new(library: &Library) -> Result<UsbFuncTable> {
        Ok(Self {
            open_device: get_libfn!(library, OhusbOpenDeviceFn, OhusbOpenDevice),
            close_device: get_libfn!(library, OhusbCloseDeviceFn, OhusbCloseDevice),
        })
    }
}
