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

use anyhow::{bail, Result};
use libc::{c_int, c_ulong, prctl};
use nix::errno::errno;

#[allow(non_camel_case_types)]
enum PrctlOption {
    PR_SET_DUMPABLE = 4,
    PR_SET_KEEPCAPS = 8,
    PR_SET_NAME = 15,
    PR_SET_NO_NEW_PRIVS = 38,
}

pub fn set_dumpable(dumpable: bool) -> Result<()> {
    // SAFETY: FFI call with valid arguments.
    let ret = unsafe {
        prctl(
            PrctlOption::PR_SET_DUMPABLE as c_int,
            dumpable as c_ulong,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        bail!("errno {}", errno());
    }
    Ok(())
}

pub fn set_keep_capabilities(keep_capabilities: bool) -> Result<()> {
    // SAFETY: FFI call with valid arguments.
    let ret = unsafe {
        prctl(
            PrctlOption::PR_SET_KEEPCAPS as c_int,
            keep_capabilities as c_ulong,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        bail!("errno {}", errno());
    }
    Ok(())
}

pub fn set_no_new_privileges(new_privileges: bool) -> Result<()> {
    // SAFETY: FFI call with valid arguments.
    let ret = unsafe {
        prctl(
            PrctlOption::PR_SET_NO_NEW_PRIVS as c_int,
            new_privileges as c_ulong,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        bail!("errno {}", errno());
    }
    Ok(())
}

pub fn set_name(name: &str) -> Result<()> {
    let binding = CString::new(name).unwrap();
    // SAFETY: FFI call with valid arguments.
    let ret = unsafe {
        prctl(
            PrctlOption::PR_SET_NAME as c_int,
            binding.as_ptr() as c_ulong,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        bail!("errno {}", errno());
    }
    Ok(())
}
