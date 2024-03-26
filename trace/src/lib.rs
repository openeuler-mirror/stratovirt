// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

#[cfg(feature = "trace_to_ftrace")]
pub(crate) mod ftrace;
#[cfg(all(target_env = "ohos", feature = "trace_to_hitrace"))]
pub(crate) mod hitrace;
#[cfg(any(
    feature = "trace_to_logger",
    feature = "trace_to_ftrace",
    all(target_env = "ohos", feature = "trace_to_hitrace")
))]
pub mod trace_scope;

use std::{
    fmt,
    os::unix::io::RawFd,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};

use anyhow::{Ok, Result};
use lazy_static::lazy_static;
use log::warn;
use regex::Regex;
use vmm_sys_util::eventfd::EventFd;

use trace_generator::{
    add_trace_state_to, gen_trace_event_func, gen_trace_scope_func, gen_trace_state,
};

#[derive(PartialEq, Eq)]
pub enum TraceType {
    Event,
    Scope,
    Unknown,
}

struct TraceState {
    name: String,
    trace_type: TraceType,
    get_state: fn() -> bool,
    set_state: fn(bool),
}

impl TraceState {
    fn new(name: String, type_str: &str, get_state: fn() -> bool, set_state: fn(bool)) -> Self {
        let trace_type = match type_str {
            "event" => TraceType::Event,
            "scope" => TraceType::Scope,
            _ => {
                warn!("The type of {} is Unknown: {}", name, type_str);
                TraceType::Unknown
            }
        };
        TraceState {
            name,
            trace_type,
            get_state,
            set_state,
        }
    }
}

#[derive(Default)]
struct TraceStateSet {
    state_list: Vec<TraceState>,
}

impl TraceStateSet {
    fn add_trace_state(&mut self, state: TraceState) {
        self.state_list.push(state);
    }

    fn set_state_by_pattern(&self, pattern: String, target_state: bool) -> Result<()> {
        let re = Regex::new(&pattern)?;
        for state in &self.state_list {
            if re.is_match(&state.name) {
                (state.set_state)(target_state);
            }
        }
        Ok(())
    }

    fn enable_state_by_type(&self, trace_type: TraceType) -> Result<()> {
        for state in &self.state_list {
            if state.trace_type == trace_type {
                (state.set_state)(true);
            }
        }
        Ok(())
    }

    fn get_state_by_pattern(&self, pattern: String) -> Result<Vec<(String, bool)>> {
        let re = Regex::new(&pattern)?;
        let mut ret: Vec<(String, bool)> = Vec::new();
        for state in &self.state_list {
            if re.is_match(&state.name) {
                ret.push((state.name.to_string(), (state.get_state)()));
            }
        }
        Ok(ret)
    }
}

gen_trace_state! {}

lazy_static! {
    static ref TRACE_STATE_SET: TraceStateSet = {
        let mut set = TraceStateSet::default();
        add_trace_state_to!(set);
        set
    };
}

gen_trace_event_func! {}

gen_trace_scope_func! {}

#[macro_export]
macro_rules! trace_scope_start {
    ($func: ident) => {
        let _scope = trace::$func(false);
    };
    ($func: ident, args=($($args: expr),+)) => {
        let _scope = trace::$func(false, $($args),+);
    };
}

#[macro_export]
macro_rules! trace_scope_asyn_start {
    ($func: ident) => {
        let _scope = trace::$func(true);
    };
    ($func: ident, args=($($args: expr),+)) => {
        let _scope = trace::$func(true, $($args),+);
    };
}

pub fn get_state_by_pattern(pattern: String) -> Result<Vec<(String, bool)>> {
    TRACE_STATE_SET.get_state_by_pattern(pattern)
}

pub fn set_state_by_pattern(pattern: String, state: bool) -> Result<()> {
    TRACE_STATE_SET.set_state_by_pattern(pattern, state)
}

pub fn enable_state_by_type(trace_type: TraceType) -> Result<()> {
    TRACE_STATE_SET.enable_state_by_type(trace_type)
}
