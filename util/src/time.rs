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
