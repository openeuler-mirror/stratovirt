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

use std::{
    fmt,
    os::unix::io::RawFd,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "trace_to_ftrace")]
use std::{fs::File, io::Write, sync::Mutex};

use anyhow::{Ok, Result};
use lazy_static::lazy_static;
use regex::Regex;

use trace_generator::{add_trace_event_to, gen_trace_func, gen_trace_state};

struct TraceEvent {
    name: String,
    get_state: fn() -> bool,
    set_state: fn(bool),
}

impl TraceEvent {
    fn new(name: String, get_state: fn() -> bool, set_state: fn(bool)) -> Self {
        TraceEvent {
            name,
            get_state,
            set_state,
        }
    }
}

#[derive(Default)]
struct TraceEventSet {
    event_list: Vec<TraceEvent>,
}

impl TraceEventSet {
    fn add_trace_event(&mut self, event: TraceEvent) {
        self.event_list.push(event);
    }

    fn set_state_by_pattern(&self, pattern: String, state: bool) -> Result<()> {
        let re = Regex::new(&pattern)?;
        for event in &self.event_list {
            if re.is_match(&event.name) {
                (event.set_state)(state);
            }
        }
        Ok(())
    }

    fn get_state_by_pattern(&self, pattern: String) -> Result<Vec<(String, bool)>> {
        let re = Regex::new(&pattern)?;
        let mut ret: Vec<(String, bool)> = Vec::new();
        for event in &self.event_list {
            if re.is_match(&event.name) {
                ret.push((event.name.to_string(), (event.get_state)()));
            }
        }
        Ok(ret)
    }
}

gen_trace_state! {}

lazy_static! {
    static ref TRACE_EVENT_SET: TraceEventSet = {
        let mut set = TraceEventSet::default();
        add_trace_event_to!(set);
        set
    };
}

gen_trace_func! {}

#[cfg(feature = "trace_to_ftrace")]
lazy_static! {
    static ref TRACE_MARKER_FD: Mutex<File> = Mutex::new(ftrace::open_trace_marker());
}

pub fn get_state_by_pattern(pattern: String) -> Result<Vec<(String, bool)>> {
    TRACE_EVENT_SET.get_state_by_pattern(pattern)
}

pub fn set_state_by_pattern(pattern: String, state: bool) -> Result<()> {
    TRACE_EVENT_SET.set_state_by_pattern(pattern, state)
}
