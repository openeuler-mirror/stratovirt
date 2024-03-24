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

const HITRACE_TAG_VIRSE: u64 = 1u64 << 11;

#[link(name = "hitrace_meter")]
extern "C" {
    fn StartTraceWrapper(label: u64, value: *const u8);
    fn FinishTrace(label: u64);
    fn StartAsyncTraceWrapper(label: u64, value: *const u8, taskId: i32);
    fn FinishAsyncTraceWrapper(label: u64, value: *const u8, taskId: i32);
}

pub fn start_trace(value: &str) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe { StartTraceWrapper(HITRACE_TAG_VIRSE, value_ptr.as_ptr() as *const u8) }
    }
}

pub fn finish_trace() {
    // SAFETY: All parameters have been checked.
    unsafe {
        FinishTrace(HITRACE_TAG_VIRSE);
    }
}

pub fn start_trace_async(value: &str, task_id: i32) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe {
            StartAsyncTraceWrapper(HITRACE_TAG_VIRSE, value_ptr.as_ptr() as *const u8, task_id)
        }
    }
}

pub fn finish_trace_async(value: &str, task_id: i32) {
    if let Ok(value_ptr) = std::ffi::CString::new(value) {
        // SAFETY: All parameters have been checked.
        unsafe {
            FinishAsyncTraceWrapper(HITRACE_TAG_VIRSE, value_ptr.as_ptr() as *const u8, task_id)
        }
    }
}
