// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use anyhow::{bail, Context, Result};

pub fn open_disk_file(path: &str, read_only: bool, direct: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(!read_only);
    if direct {
        options.custom_flags(libc::O_DIRECT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open the file for block {}", path))?;

    let (lockop, lockname) = if read_only {
        (libc::LOCK_SH | libc::LOCK_NB, "read lock")
    } else {
        (libc::LOCK_EX | libc::LOCK_NB, "write lock")
    };
    let ret = unsafe { libc::flock(file.as_raw_fd(), lockop) };
    if ret < 0 {
        bail!(
            "Failed to get {} on file: {}. Maybe it's used more than once.",
            lockname,
            path
        );
    }
    Ok(file)
}
