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

use std::{
    fs::{File, OpenOptions},
    io::{prelude::Write, BufRead, BufReader},
};

pub(crate) fn open_trace_marker() -> File {
    let mounts_path: &str = "/proc/mounts";
    let mounts_fd = File::open(mounts_path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", mounts_path, e));
    let mut reader = BufReader::new(mounts_fd);
    let target_line = loop {
        let mut buffer = String::new();
        reader
            .read_line(&mut buffer)
            .unwrap_or_else(|e| panic!("Read {} error: {:?}", &mounts_path, e));
        match buffer.as_str() {
            "" => {
                panic!("Failed to get mount point of tracefs")
            }
            _ => {
                if buffer.contains("tracefs") {
                    break buffer;
                }
            }
        }
    };
    let fields: Vec<&str> = target_line.split(' ').collect();
    let tracefs_mount_point = fields
        .get(1)
        .unwrap_or_else(|| panic!("Failed to get mount point of tracefs"))
        .to_string();

    let tracing_on_path = format!("{}/tracing_on", tracefs_mount_point);
    let mut tracing_on_fd = OpenOptions::new()
        .write(true)
        .open(&tracing_on_path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", tracing_on_path, e));
    tracing_on_fd
        .write_all(b"1")
        .unwrap_or_else(|e| panic!("Failed to enable tracing_on: {:?}", e));

    let trace_marker_path = format!("{}/trace_marker", tracefs_mount_point);
    OpenOptions::new()
        .write(true)
        .open(&trace_marker_path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {:?}", trace_marker_path, e))
}
