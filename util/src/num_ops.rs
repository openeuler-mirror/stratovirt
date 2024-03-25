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

use std::num::ParseIntError;

use anyhow::{Context, Result};
use byteorder::{ByteOrder, LittleEndian};
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

/// Division rounded up.
///
/// # Arguments
///
/// * `dividend` - dividend.
/// * `divisor` - divisor.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::div_round_up;
///
/// let value = div_round_up(10 as u64, 4 as u64);
/// assert!(value == Some(3));
/// ```
pub fn div_round_up(dividend: u64, divisor: u64) -> Option<u64> {
    if let Some(res) = dividend.checked_div(divisor) {
        if dividend % divisor == 0 {
            return Some(res);
        } else {
            return Some(res + 1);
        }
    }
    None
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

/// Write the given u32 to the low bits in u64, keep the high bits,
/// returns the u64 value.
///
/// # Arguments
///
/// * `origin` - The origin u64 value.
/// * `value` - The set u32 value.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::write_u64_low;
///
/// let value = write_u64_low(0x1000_0000_0000_0000, 0x1000_0000);
/// assert!(value == 0x1000_0000_1000_0000);
/// ```
pub fn write_u64_low(origin: u64, value: u32) -> u64 {
    origin & 0xFFFF_FFFF_0000_0000_u64 | u64::from(value)
}

/// Write the given u32 to the high bits in u64, keep the low bits,
/// returns the u64 value.
///
/// # Arguments
///
/// * `origin` - The origin u64 value.
/// * `value` - The set u32 value.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::write_u64_high;
///
/// let value = write_u64_high(0x0000_0000_1000_0000, 0x1000_0000);
/// assert!(value == 0x1000_0000_1000_0000);
/// ```
pub fn write_u64_high(origin: u64, value: u32) -> u64 {
    u64::from(value) << 32 | (origin & 0x0000_0000_FFFF_FFFF_u64)
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

///  Write the given u16 to an array, returns the bool.
///
/// # Arguments
///
/// * `data` - The array of u8.
/// * `value` - The u16 value
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::write_data_u16;
///
/// let mut data: [u8; 2] = [0; 2];
/// let ret = write_data_u16(&mut data, 0x1234);
/// assert!(ret && data[0] == 0x34 && data[1] == 0x12);
/// ```
pub fn write_data_u16(data: &mut [u8], value: u16) -> bool {
    match data.len() {
        1 => data[0] = value as u8,
        2 => {
            LittleEndian::write_u16(data, value);
        }
        n => {
            error!("Invalid data length {} for reading value {}", n, value);
            return false;
        }
    };
    true
}

///  Write the given u32 to an array, returns the bool.
///
/// # Arguments
///
/// * `data` - The array of u8.
/// * `value` - The u32 value
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::write_data_u32;
///
/// let mut data: [u8; 4] = [0; 4];
/// let ret = write_data_u32(&mut data, 0x12345678);
/// assert!(ret && data[0] == 0x78 && data[1] == 0x56 && data[2] == 0x34 && data[3] == 0x12);
/// ```
pub fn write_data_u32(data: &mut [u8], value: u32) -> bool {
    match data.len() {
        1 => data[0] = value as u8,
        2 => {
            LittleEndian::write_u16(data, value as u16);
        }
        4 => {
            LittleEndian::write_u32(data, value);
        }
        _ => {
            error!(
                "Invalid data length: value {}, data len {}",
                value,
                data.len()
            );
            return false;
        }
    };
    true
}

///  Read the given array to an u32, returns the bool.
///
/// # Arguments
///
/// * `data` - The array of u8.
/// * `value` - The u32 value
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::read_data_u32;
///
/// let mut value = 0;
/// let ret = read_data_u32(&[0x11, 0x22, 0x33, 0x44], &mut value);
/// assert!(ret && value == 0x44332211);
/// ```
pub fn read_data_u32(data: &[u8], value: &mut u32) -> bool {
    *value = match data.len() {
        1 => data[0] as u32,
        2 => LittleEndian::read_u16(data) as u32,
        4 => LittleEndian::read_u32(data),
        _ => {
            error!("Invalid data length: data len {}", data.len());
            return false;
        }
    };
    true
}

///  Read the given array to an u16, returns the bool.
///
/// # Arguments
///
/// * `data` - The array of u8.
/// * `value` - The u16 value
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::read_data_u16;
///
/// let mut value = 0;
/// let ret = read_data_u16(&[0x11, 0x22], &mut value);
/// assert!(ret && value == 0x2211);
/// ```
pub fn read_data_u16(data: &[u8], value: &mut u16) -> bool {
    *value = match data.len() {
        1 => data[0] as u16,
        2 => LittleEndian::read_u16(data),
        _ => {
            error!("Invalid data length: data len {}", data.len());
            return false;
        }
    };
    true
}

pub trait Num {
    type ParseIntError;
    fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseIntError>
    where
        Self: Sized;
}

macro_rules! int_trait_impl {
    ($name:ident for $($t:ty)*) => ($(
        impl $name for $t {
            type ParseIntError = ::core::num::ParseIntError;
            fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseIntError> {
                <$t>::from_str_radix(s, radix)
            }
        }
    )*)
}

int_trait_impl!(Num for u8 u16 usize);

///  Parse a string to a number, decimal and hexadecimal numbers supported now.
///
/// # Arguments
///
/// * `string_in` - The string that means a number, eg. "18", "0x1c".
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::str_to_num;
///
/// let value = str_to_num::<usize>("0x17").unwrap();
/// assert!(value == 0x17);
/// let value = str_to_num::<u16>("0X17").unwrap();
/// assert!(value == 0x17);
/// let value = str_to_num::<u8>("17").unwrap();
/// assert!(value == 17);
/// ```
pub fn str_to_num<T: Num>(s: &str) -> Result<T> {
    let mut base = 10;
    if s.starts_with("0x") || s.starts_with("0X") {
        base = 16;
    }
    let without_prefix = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let num =
        T::from_str_radix(without_prefix, base).with_context(|| format!("Invalid num: {}", s))?;
    Ok(num)
}

/// Check whether two regions overlap with each other.
///
/// # Arguments
///
/// * `start1` - Start address of the first region.
/// * `size1` - Size of the first region.
/// * `start2` - Start address of the second region.
/// * `size2` - Size of the second region.
///
/// # Examples
///
/// ```rust
/// extern crate util;
/// use util::num_ops::ranges_overlap;
///
/// let value = ranges_overlap(100, 100, 150, 100).unwrap();
/// assert!(value == true);
/// ```
pub fn ranges_overlap(start1: usize, size1: usize, start2: usize, size2: usize) -> Result<bool> {
    let end1 = start1
        .checked_add(size1)
        .with_context(|| format!("range 1 overflows: start {}, size {}", start1, size1))?;
    let end2 = start2
        .checked_add(size2)
        .with_context(|| format!("range 2 overflows: start {}, size {}", start1, size1))?;

    Ok(!(start1 >= end2 || start2 >= end1))
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
    fn test_div_round_up() {
        let res = div_round_up(10, 4);
        assert_eq!(res, Some(3));
        let res = div_round_up(10, 2);
        assert_eq!(res, Some(5));
        let res = div_round_up(2, 10);
        assert_eq!(res, Some(1));
        let res = div_round_up(10, 0);
        assert_eq!(res, None);
        let res = div_round_up(0xffff_ffff_ffff_ffff_u64, 1);
        assert_eq!(res, Some(0xffff_ffff_ffff_ffff_u64));
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
    fn test_write_u64_low() {
        assert_eq!(
            write_u64_low(0x0000_0000_FFFF_FFFF_u64, 0x1234_5678),
            0x0000_0000_1234_5678_u64
        );
        assert_eq!(
            write_u64_low(0xFFFF_FFFF_0000_0000_u64, 0x1234_5678),
            0xFFFF_FFFF_1234_5678_u64
        );
    }

    #[test]
    fn test_write_u64_high() {
        assert_eq!(
            write_u64_high(0x0000_0000_FFFF_FFFF_u64, 0x1234_5678),
            0x1234_5678_FFFF_FFFF_u64
        );
        assert_eq!(
            write_u64_high(0xFFFF_FFFF_0000_0000_u64, 0x1234_5678),
            0x1234_5678_0000_0000_u64
        );
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

    #[test]
    fn test_write_data_u16() {
        let mut data: [u8; 1] = [0; 1];
        let ret = write_data_u16(&mut data, 0x11);
        assert!(ret && data[0] == 0x11);
        let mut data: [u8; 2] = [0; 2];
        let ret = write_data_u16(&mut data, 0x1122);
        assert!(ret && data[0] == 0x22 && data[1] == 0x11);
        let mut data: [u8; 3] = [0; 3];
        let ret = write_data_u16(&mut data, 0x1122);
        assert!(!ret);
    }

    #[test]
    fn test_write_data_u32() {
        let mut data: [u8; 1] = [0; 1];
        let ret = write_data_u32(&mut data, 0x11);
        assert!(ret && data[0] == 0x11);
        let mut data: [u8; 2] = [0; 2];
        let ret = write_data_u32(&mut data, 0x1122);
        assert!(ret && data[0] == 0x22 && data[1] == 0x11);
        let mut data: [u8; 3] = [0; 3];
        let ret = write_data_u32(&mut data, 0x112233);
        assert!(!ret);
        let mut data: [u8; 4] = [0; 4];
        let ret = write_data_u32(&mut data, 0x11223344);
        assert!(ret && data[0] == 0x44 && data[1] == 0x33 && data[2] == 0x22 && data[3] == 0x11);
    }

    #[test]
    fn test_read_data_u16() {
        let mut value = 0;
        let ret = read_data_u16(&[0x11], &mut value);
        assert!(ret && value == 0x11);
        let ret = read_data_u16(&[0x11, 0x22], &mut value);
        assert!(ret && value == 0x2211);
        let ret = read_data_u16(&[0x11, 0x22, 0x33], &mut value);
        assert!(!ret);
    }

    #[test]
    fn test_read_data_u32() {
        let mut value = 0;
        let ret = read_data_u32(&[0x11], &mut value);
        assert!(ret && value == 0x11);
        let ret = read_data_u32(&[0x11, 0x22], &mut value);
        assert!(ret && value == 0x2211);
        let ret = read_data_u32(&[0x11, 0x22, 0x33], &mut value);
        assert!(!ret);
        let ret = read_data_u32(&[0x11, 0x22, 0x33, 0x44], &mut value);
        assert!(ret && value == 0x44332211);
    }

    #[test]
    fn test_str_to_num() {
        let value = str_to_num::<usize>("0x17").unwrap();
        assert!(value == 0x17);
        let value = str_to_num::<u16>("0X17").unwrap();
        assert!(value == 0x17);
        let value = str_to_num::<u8>("17").unwrap();
        assert!(value == 17);
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(100, 100, 150, 100).unwrap());
        assert!(ranges_overlap(100, 100, 150, 50).unwrap());
        assert!(!ranges_overlap(100, 100, 200, 50).unwrap());
        assert!(ranges_overlap(100, 100, 100, 50).unwrap());
        assert!(!ranges_overlap(100, 100, 50, 50).unwrap());
        assert!(ranges_overlap(100, 100, 50, 100).unwrap());
        assert!(ranges_overlap(usize::MAX, 1, 100, 50).is_err())
    }
}
