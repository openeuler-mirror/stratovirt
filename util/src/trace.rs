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

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{prelude::Write, BufRead, BufReader};
use std::ops::Deref;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use log::error;
use once_cell::sync::Lazy;

static TRACE_MARKER_FD: Lazy<Option<File>> = Lazy::new(open_trace_marker);
static TRACE_EVENTS: Lazy<ArcSwap<HashSet<String>>> =
    Lazy::new(|| ArcSwap::new(Arc::new(HashSet::new())));

fn open_trace_marker() -> Option<File> {
    let file = "/proc/mounts";
    let proc_mounts_fd = match File::open(file) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Failed to open {}: {:?}", file, e);
            return None;
        }
    };
    let mut reader = BufReader::new(proc_mounts_fd);
    let mut buf: String;
    loop {
        buf = String::new();
        match reader.read_line(&mut buf) {
            Ok(_) => {
                if buf.contains("tracefs") {
                    break;
                }
            }
            Err(e) => {
                error!("Read {} error: {:?}.", &file, e);
                return None;
            }
        }
    }

    let fields: Vec<&str> = buf.split(' ').collect();
    let tracefs_mount_point = match fields.get(1) {
        Some(s) => s.to_string(),
        None => panic!("Failed to get mount point of tracefs."),
    };

    let tracing_on = format!("{}/tracing_on", tracefs_mount_point);
    let mut tracing_on_fd = match OpenOptions::new().write(true).open(&tracing_on) {
        Ok(fd) => fd,
        Err(e) => {
            error!("Failed to open {}: {:?}", tracing_on, e);
            return None;
        }
    };
    if let Err(e) = tracing_on_fd.write(b"1") {
        error!("Failed to enable tracing_on: {:?}", e);
        return None;
    }

    let trace_marker = format!("{}/trace_marker", tracefs_mount_point);
    match OpenOptions::new().write(true).open(&trace_marker) {
        Ok(fd) => Some(fd),
        Err(e) => {
            error!("Failed to open {}: {:?}", trace_marker, e);
            None
        }
    }
}

pub fn write_trace_marker(event: &str, msg: &str) {
    if !is_trace_event_enabled(event) {
        return;
    }

    let msg = format!("[{}] {}", event, msg);
    if let Err(e) = TRACE_MARKER_FD.as_ref().unwrap().write(msg.as_bytes()) {
        error!("Write trace_marker error: {:?}", e);
    }
}

#[macro_export]
macro_rules! ftrace {
    ($func: ident) => {
        let func = stringify!($func);
        let msg = String::new();
        $crate::trace::write_trace_marker(func, &msg);
    };
    ($func: ident, $($arg: tt)*) => {
        let func = stringify!($func);
        let msg = format!("{}", format_args!($($arg)*));
        $crate::trace::write_trace_marker(func, &msg);
    };
}

pub fn enable_trace_events(file: &str) -> Result<()> {
    let fd = File::open(file).with_context(|| format!("Failed to open {}.", file))?;
    let mut reader = BufReader::new(fd);

    loop {
        let mut buf = String::new();
        let size = reader
            .read_line(&mut buf)
            .with_context(|| format!("Read {} error.", file))?;

        if size == 0 {
            return Ok(());
        }

        let mut trace_events = TRACE_EVENTS.load().deref().deref().clone();
        trace_events.insert(buf.trim().to_string());
        TRACE_EVENTS.store(Arc::new(trace_events));
    }
}

pub fn is_trace_event_enabled(event: &str) -> bool {
    if TRACE_EVENTS.load().is_empty() {
        return false;
    }

    TRACE_EVENTS.load().contains(event)
}
