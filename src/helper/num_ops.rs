// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

//! This module implements some operations of Rust primitive types.

/// Calculate the aligned-up u64 value.
///
/// # Arguments
///
/// * `origin` - the origin value.
/// * `align` - the alignment.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::round_up;
///
/// let value = round_up(1003 as u64, 4 as u64);
/// assert!(value == Some(1004));
/// ```
pub fn round_up(origin: u64, align: u64) -> Option<u64> {
    match origin % align {
        0 => Some(origin),
        diff => origin.checked_add(align - diff),
    }
}

/// Calculate the aligned-down u64 value.
///
/// # Arguments
///
/// * `origin` - the origin value.
/// * `align` - the alignment.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::round_down;
///
/// let value = round_down(1003 as u64, 4 as u64);
/// assert!(value == Some(1000));
/// ```
pub fn round_down(origin: u64, align: u64) -> Option<u64> {
    match origin % align {
        0 => Some(origin),
        diff => origin.checked_sub(diff),
    }
}

/// Get the first half or second half of u64.
///
/// # Arguments
///
/// * `value` - The origin value to get u32 from.
/// * `page` - Value is 0 or 1, determines which half to return.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::read_u32;
///
/// let value = read_u32(0x2000_1000_0000, 1);
/// assert!(value == 0x2000);
/// ```
pub fn read_u32(value: u64, page: u32) -> u32 {
    match page {
        0 => value as u32,
        1 => (value >> 32) as u32,
        _ => 0_u32,
    }
}

/// Write the given u32 to the first or second half in u64,
/// returns the u64 value.
///
/// # Arguments
///
/// * `value` - The origin u32 value.
/// * `page` - Value is 0 or 1, determines which half to write.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::write_u32;
///
/// let value = write_u32(0x1000_0000, 1);
/// assert!(value == 0x1000_0000_0000_0000);
/// ```
pub fn write_u32(value: u32, page: u32) -> u64 {
    match page {
        0 => u64::from(value),
        1 => u64::from(value) << 32,
        _ => 0_u64,
    }
}
