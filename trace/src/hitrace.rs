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

use std::ffi::OsStr;

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use libloading::os::unix::Symbol;
use libloading::Library;
use log::error;

const HITRACE_TAG_VIRSE: u64 = 1u64 << 11;

lazy_static! {
    static ref HITRACE_FUNC_TABLE: HitraceFuncTable =
        // SAFETY: The dynamic library should be always existing.
        unsafe {
            HitraceFuncTable::new(OsStr::new("libhitrace_meter.so"))
                .map_err(|e| {
                    error!("failed to init HitraceFuncTable with error: {:?}", e);
                    e
                })
                .unwrap()
        };
}

macro_rules! get_libfn {
    ( $lib: ident, $tname: ident, $fname: ident ) => {
        $lib.get::<$tname>(stringify!($fname).as_bytes())
            .with_context(|| format!("failed to get function {}", stringify!($fname)))?
            .into_raw()
    };
}

type StartTraceWrapperFn = unsafe extern "C" fn(u64, *const u8);
type FinishTraceFn = unsafe extern "C" fn(u64);
type StartAsyncTraceWrapperFn = unsafe extern "C" fn(u64, *const u8, i32);
type FinishAsyncTraceWrapperFn = unsafe extern "C" fn(u64, *const u8, i32);

struct HitraceFuncTable {
    pub start_trace: Symbol<StartTraceWrapperFn>,
    pub finish_trace: Symbol<FinishTraceFn>,
    pub start_trace_async: Symbol<StartAsyncTraceWrapperFn>,
    pub finish_trace_async: Symbol<FinishAsyncTraceWrapperFn>,
}

impl HitraceFuncTable {
    unsafe fn new(library_name: &OsStr) -> Result<HitraceFuncTable> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hitrace_meter library")?;

        Ok(Self {
            start_trace: get_libfn!(library, StartTraceWrapperFn, StartTraceWrapper),
            finish_trace: get_libfn!(library, FinishTraceFn, FinishTrace),
            start_trace_async: get_libfn!(
                library,
                StartAsyncTraceWrapperFn,
                StartAsyncTraceWrapper
            ),
            finish_trace_async: get_libfn!(
                library,
                FinishAsyncTraceWrapperFn,
                FinishAsyncTraceWrapper
            ),
        })
    }
}

pub fn start_trace(value: &str) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe {
            (HITRACE_FUNC_TABLE.start_trace)(HITRACE_TAG_VIRSE, value_ptr.as_ptr() as *const u8)
        }
    }
}

pub fn finish_trace() {
    // SAFETY: All parameters have been checked.
    unsafe {
        (HITRACE_FUNC_TABLE.finish_trace)(HITRACE_TAG_VIRSE);
    }
}

pub fn start_trace_async(value: &str, task_id: i32) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe {
            (HITRACE_FUNC_TABLE.start_trace_async)(
                HITRACE_TAG_VIRSE,
                value_ptr.as_ptr() as *const u8,
                task_id,
            )
        }
    }
}

pub fn finish_trace_async(value: &str, task_id: i32) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe {
            (HITRACE_FUNC_TABLE.finish_trace_async)(
                HITRACE_TAG_VIRSE,
                value_ptr.as_ptr() as *const u8,
                task_id,
            )
        }
    }
}
