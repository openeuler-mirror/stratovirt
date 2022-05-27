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

use log::error;
// This module implements some operations of Rust primitive types.

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

///  Extract from the 32 bit input @value the bit field specified by the
///  @start and @length parameters, and return it. The bit field must
///  lie entirely within the 32 bit word. It is valid to request that
///  all 32 bits are returned (ie @length 32 and @start 0).
///
/// # Arguments
///
/// * `value` - The value to extract the bit field from
/// * `start` - The lowest bit in the bit field (numbered from 0)
/// * `length` - The length of the bit field
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::extract_u32;
///
/// let value = extract_u32(0xfffa, 0, 8).unwrap();
/// assert!(value == 0xfa);
/// ```
pub fn extract_u32(value: u32, start: u32, length: u32) -> Option<u32> {
    if length > 32 - start {
        error!(
            "extract_u32: ( start {} length {} ) is out of range",
            start, length
        );
        return None;
    }

    Some((value >> start) & (!0_u32 >> (32 - length)))
}

///  Extract from the 64 bit input @value the bit field specified by the
///  @start and @length parameters, and return it. The bit field must
///  lie entirely within the 64 bit word. It is valid to request that
///  all 64 bits are returned (ie @length 64 and @start 0).
///
/// # Arguments
///
/// * `value` - The value to extract the bit field from
/// * `start` - The lowest bit in the bit field (numbered from 0)
/// * `length` - The length of the bit field
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::extract_u64;
///
/// let value = extract_u64(0xfbfba0a0ffff5a5a, 16, 16).unwrap();
/// assert!(value == 0xffff);
/// ```
pub fn extract_u64(value: u64, start: u32, length: u32) -> Option<u64> {
    if length > 64 - start {
        error!(
            "extract_u64: ( start {} length {} ) is out of range",
            start, length
        );
        return None;
    }

    Some((value >> start as u64) & (!(0_u64) >> (64 - length) as u64))
}

///  Deposit @fieldval into the 32 bit @value at the bit field specified
///  by the @start and @length parameters, and return the modified
///  @value. Bits of @value outside the bit field are not modified.
///  Bits of @fieldval above the least significant @length bits are
///  ignored. The bit field must lie entirely within the 32 bit word.
///  It is valid to request that all 32 bits are modified (ie @length
///  32 and @start 0).
///
/// # Arguments
///
/// * `value` - The value to extract the bit field from
/// * `start` - The lowest bit in the bit field (numbered from 0)
/// * `length` - The length of the bit field
/// * `fieldval` - The value to insert into the bit field
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::deposit_u32;
///
/// let value = deposit_u32(0xffff, 0, 8, 0xbaba).unwrap();
/// assert!(value == 0xffba);
/// ```
pub fn deposit_u32(value: u32, start: u32, length: u32, fieldval: u32) -> Option<u32> {
    if length > 32 - start {
        error!(
            "deposit_u32: ( start {} length {} ) is out of range",
            start, length
        );
        return None;
    }

    let mask: u32 = (!0_u32 >> (32 - length)) << start;
    Some((value & !mask) | ((fieldval << start) & mask))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_up_test() {
        let result = round_up(10001 as u64, 100 as u64);
        assert_eq!(result, Some(10100));
    }

    #[test]
    fn round_down_test() {
        let result = round_down(10001 as u64, 100 as u64);
        assert_eq!(result, Some(10000));
    }

    #[test]
    fn test_read_u32_from_u64() {
        let value = 0x1234_5678_9012_3456u64;
        assert_eq!(read_u32(value, 0), 0x9012_3456u32);
        assert_eq!(read_u32(value, 1), 0x1234_5678u32);
        assert_eq!(read_u32(value, 2), 0);
    }

    #[test]
    fn test_set_u64_from_half32bit() {
        assert_eq!(write_u32(0x1234_5678, 0), 0x1234_5678u64);
        assert_eq!(write_u32(0x1234_5678, 1), 0x1234_5678_0000_0000u64);
        assert_eq!(write_u32(0x1234_5678, 2), 0);
    }

    #[test]
    fn test_extract_u32() {
        assert_eq!(extract_u32(0xfefbfffa, 0, 33), None);
        assert_eq!(extract_u32(0xfefbfffa, 8, 32), None);

        assert_eq!(extract_u32(0xfefbfffa, 0, 8), Some(0xfa));
        assert_eq!(extract_u32(0xfefbfffa, 16, 16), Some(0xfefb));
        assert_eq!(extract_u32(0xfefbfffa, 8, 24), Some(0xfefbff));
        assert_eq!(extract_u32(0xfefbfffa, 0, 32), Some(0xfefbfffa));
    }

    #[test]
    fn test_extract_u64() {
        assert_eq!(extract_u64(0xfbfba0a0ffff5a5a, 0, 65), None);
        assert_eq!(extract_u64(0xfbfba0a0ffff5a5a, 8, 64), None);

        assert_eq!(extract_u64(0xfbfba0a0ffff5b5a, 0, 8), Some(0x5a));
        assert_eq!(extract_u64(0xfbfba0a0ffff5b5a, 16, 16), Some(0xffff));
        assert_eq!(extract_u64(0xfbfba0a0ffff5b5a, 32, 32), Some(0xfbfba0a0));
        assert_eq!(extract_u64(0xfbfba0a0ffff5b5a, 8, 40), Some(0xa0a0ffff5b));
        assert_eq!(extract_u64(0xfbfba0a0ffff5b5a, 8, 48), Some(0xfba0a0ffff5b));
        assert_eq!(
            extract_u64(0xfbfba0a0ffff5b5a, 8, 56),
            Some(0xfbfba0a0ffff5b)
        );
        assert_eq!(
            extract_u64(0xfbfba0a0ffff5b5a, 0, 64),
            Some(0xfbfba0a0ffff5b5a)
        );
    }

    #[test]
    fn test_deposit_u32() {
        assert_eq!(deposit_u32(0xffff, 0, 33, 0xbaba), None);
        assert_eq!(deposit_u32(0xffff, 8, 32, 0xbaba), None);

        assert_eq!(deposit_u32(0xfdfcfbfa, 0, 8, 0xbdbcbbba), Some(0xfdfcfbba));
        assert_eq!(deposit_u32(0xfdfcfbfa, 8, 8, 0xbdbcbbba), Some(0xfdfcbafa));
        assert_eq!(deposit_u32(0xfdfcfbfa, 16, 8, 0xbdbcbbba), Some(0xfdbafbfa));
        assert_eq!(deposit_u32(0xfdfcfbfa, 24, 8, 0xbdbcbbba), Some(0xbafcfbfa));
        assert_eq!(deposit_u32(0xfdfcfbfa, 8, 16, 0xbdbcbbba), Some(0xfdbbbafa));
        assert_eq!(deposit_u32(0xfdfcfbfa, 8, 24, 0xbdbcbbba), Some(0xbcbbbafa));
        assert_eq!(deposit_u32(0xfdfcfbfa, 0, 32, 0xbdbcbbba), Some(0xbdbcbbba));
    }
}
