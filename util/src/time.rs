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

use anyhow::{bail, Result};
use nix::time::{clock_gettime, ClockId};

pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Converts date to seconds since 1970-01-01 00:00:00.
pub fn mktime64(year: u64, mon: u64, day: u64, hour: u64, min: u64, sec: u64) -> u64 {
    let mut y = year;
    let mut m = mon;

    if m <= 2 {
        m += 10;
        y -= 1;
    } else {
        m -= 2;
    }

    ((((y / 4 - y / 100 + y / 400 + 367 * m / 12 + day) + y * 365 - 719499) * 24 + hour) * 60 + min)
        * 60
        + sec
}

/// Get wall time.
pub fn gettime() -> Result<(u32, u32)> {
    match clock_gettime(ClockId::CLOCK_REALTIME) {
        Ok(ts) => Ok((ts.tv_sec() as u32, ts.tv_nsec() as u32)),
        Err(e) => bail!("clock_gettime failed: {:?}", e),
    }
}

/// Convert wall time to year/month/day/hour/minute/second format.
pub fn get_format_time(sec: i64) -> [i32; 6] {
    // SAFETY: No input parameter.
    let mut ti: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: The parameters of sec and ti can be guaranteed not be null.
    unsafe {
        libc::localtime_r(&sec, &mut ti);
    }

    [
        ti.tm_year + 1900,
        ti.tm_mon + 1,
        ti.tm_mday,
        ti.tm_hour,
        ti.tm_min,
        ti.tm_sec,
    ]
}
