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

use std::ffi::{c_char, c_int, c_uint, c_ulonglong, CString, OsStr};

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use libloading::os::unix::Symbol;
use libloading::Library;
use log::error;

const MAX_PARAM_NAME_LENGTH: usize = 49;

#[derive(Copy, Clone, Debug)]
pub enum HiSysEventType {
    _Fault = 1,
    _Statistic,
    _Security,
    _Behavior,
}

#[derive(Copy, Clone, Debug)]
pub enum EventParamType {
    // Invalid type.
    _Invalid = 0,
    _TypeBool,
    _TypeI8,
    _TypeU8,
    _TypeI16,
    _TypeU16,
    _TypeI32,
    _TypeU32,
    _TypeI64,
    _TypeU64,
    _TypeF32,
    _TypeF64,
    _TypeString,
    _ArrayBool,
    _ArrayI8,
    _ArrayU8,
    _ArrayI16,
    _ArrayU16,
    _ArrayI32,
    _ArrayU32,
    _ArrayI64,
    _ArrayU64,
    _ArrayF32,
    _ArrayF64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union EventParamValue {
    pub bool_value: bool,
    pub i8_value: i8,
    pub u8_value: u8,
    pub i16_value: i16,
    pub u16_value: u16,
    pub i32_value: i32,
    pub u32_value: u32,
    pub i64_value: i64,
    pub u64_value: u64,
    pub f32_value: f32,
    pub f64_value: f64,
    // String.
    pub char_ptr_value: *const c_char,
    // Array.
    pub void_ptr_value: *const (),
}

pub struct EventParam<'a> {
    pub param_name: &'a str,
    pub param_type: EventParamType,
    pub param_value: EventParamValue,
    pub array_size: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct EventParamWrapper {
    pub param_name: [u8; MAX_PARAM_NAME_LENGTH],
    pub param_type: c_int,
    pub param_value: EventParamValue,
    pub array_size: c_uint,
}

lazy_static! {
    static ref HISYSEVENT_FUNC_TABLE: HiSysEventFuncTable =
        // SAFETY: The dynamic library should be always existing.
        unsafe {
            HiSysEventFuncTable::new(OsStr::new("libhisysevent.z.so"))
                .map_err(|e| {
                    error!("failed to init HiSysEventFuncTable with error: {:?}", e);
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

type HiSysEventWriteWrapperFn = unsafe extern "C" fn(
    func: *const c_char,
    line: c_ulonglong,
    domain: *const c_char,
    name: *const c_char,
    event_type: c_int,
    params: *const EventParamWrapper,
    size: c_uint,
) -> c_int;

struct HiSysEventFuncTable {
    pub hisysevent_write: Symbol<HiSysEventWriteWrapperFn>,
}

impl HiSysEventFuncTable {
    unsafe fn new(library_name: &OsStr) -> Result<HiSysEventFuncTable> {
        let library =
            Library::new(library_name).with_context(|| "failed to load hisysevent library")?;

        Ok(Self {
            hisysevent_write: get_libfn!(library, HiSysEventWriteWrapperFn, HiSysEvent_Write),
        })
    }
}

fn format_param_array(event_params: &[EventParam]) -> Vec<EventParamWrapper> {
    let mut params_wrapper: Vec<EventParamWrapper> = vec![];

    for param in event_params {
        let mut param_name = [0_u8; MAX_PARAM_NAME_LENGTH];
        let name = param.param_name.as_bytes();
        let end = std::cmp::min(name.len(), param_name.len());
        param_name[..end].copy_from_slice(&name[..end]);
        params_wrapper.push(EventParamWrapper {
            param_name,
            param_type: param.param_type as i32,
            param_value: param.param_value,
            array_size: param.array_size as u32,
        });
    }

    params_wrapper
}

// Write system event.
pub(crate) fn write_to_hisysevent(
    func_name: &str,
    event_name: &str,
    event_type: c_int,
    event_params: &[EventParam],
) {
    let func = CString::new(func_name).unwrap();
    let domain = CString::new("VM_ENGINE").unwrap();
    let event = CString::new(event_name).unwrap();

    let params_wrapper = format_param_array(event_params);

    // SAFETY: Call hisysevent function, all parameters are just read.
    let ret = unsafe {
        (HISYSEVENT_FUNC_TABLE.hisysevent_write)(
            func.as_ptr() as *const c_char,
            line!() as c_ulonglong,
            domain.as_ptr() as *const c_char,
            event.as_ptr() as *const c_char,
            event_type,
            params_wrapper.as_ptr() as *const EventParamWrapper,
            params_wrapper.len() as u32,
        )
    };
    if ret != 0 {
        error!("Failed to write event {} to hisysevent.", event_name);
    }
}
