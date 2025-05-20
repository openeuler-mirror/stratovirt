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

use lazy_static::lazy_static;
use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
use crate::hitrace::{finish_trace, finish_trace_async, start_trace, start_trace_async};

#[cfg(feature = "trace_to_ftrace")]
use crate::ftrace::write_trace_marker;

lazy_static! {
    static ref TRACE_SCOPE_COUNTER: AtomicI32 = AtomicI32::new(i32::MIN);
}

#[derive(Clone)]
pub enum Scope {
    Common(TraceScope),
    Asyn(TraceScopeAsyn),
    None,
}

#[derive(Clone)]
pub struct TraceScope {}

impl TraceScope {
    pub fn new(value: String) -> Self {
        #[cfg(feature = "trace_to_logger")]
        {
            log::trace!("[SCOPE_START]{}", value);
        }
        #[cfg(feature = "trace_to_ftrace")]
        {
            write_trace_marker(&format!("[SCOPE_START]{}", value));
        }
        #[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
        {
            start_trace(&value);
        }
        TraceScope {}
    }
}

impl Drop for TraceScope {
    fn drop(&mut self) {
        #[cfg(feature = "trace_to_logger")]
        {
            log::trace!("[SCOPE_END]");
        }
        #[cfg(feature = "trace_to_ftrace")]
        {
            write_trace_marker("[SCOPE_END]");
        }
        #[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
        {
            finish_trace()
        }
    }
}

#[derive(Clone)]
pub struct TraceScopeAsyn {
    value: String,
    id: i32,
}

impl TraceScopeAsyn {
    #[allow(unused_variables)]
    pub fn new(value: String) -> Self {
        // SAFETY: AtomicI32 can be safely shared between threads.
        let id = TRACE_SCOPE_COUNTER
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(x.wrapping_add(1))
            })
            .unwrap();
        #[cfg(feature = "trace_to_logger")]
        {
            log::trace!("[SCOPE_START(id={})]{}", id, value);
        }
        #[cfg(feature = "trace_to_ftrace")]
        {
            write_trace_marker(&format!("[SCOPE_START(id={})]{}", id, value));
        }
        #[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
        {
            start_trace_async(&value, id);
        }
        TraceScopeAsyn { value, id }
    }
}

impl Drop for TraceScopeAsyn {
    fn drop(&mut self) {
        #[cfg(feature = "trace_to_logger")]
        {
            log::trace!("[SCOPE_END(id={})]{}", self.id, self.value);
        }
        #[cfg(feature = "trace_to_ftrace")]
        {
            write_trace_marker(&format!("[SCOPE_END(id={})]{}", self.id, self.value));
        }
        #[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
        {
            finish_trace_async(&self.value, self.id);
        }
    }
}
