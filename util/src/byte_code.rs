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

use std::mem::size_of;
use std::slice::{from_raw_parts, from_raw_parts_mut};

/// A trait bound defined for types which are safe to convert to a byte slice and
/// to create from a byte slice.
pub trait ByteCode: Default + Copy + Send + Sync {
    /// Return the contents of an object (impl trait `ByteCode`) as a slice of bytes.
    /// the inverse of this function is "from_bytes"
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: The object is guaranteed been initialized already.
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Return the contents of a mutable object (impl trait `ByteCode`) to a mutable slice of bytes.
    /// the inverse of this function is "from_bytes_mut"
    fn as_mut_bytes(&mut self) -> &mut [u8] {
        // SAFETY: The object is guaranteed been initialized already.
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u8, size_of::<Self>()) }
    }

    /// Creates an object (impl trait `ByteCode`) from a slice of bytes
    ///
    /// # Arguments
    ///
    /// * `data` - the slice of bytes that will be constructed as an object.
    fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() != size_of::<Self>() {
            return None;
        }

        // SAFETY: The pointer is properly aligned and point to an initialized instance of T.
        unsafe { data.as_ptr().cast::<Self>().as_ref() }
    }

    /// Creates an mutable object (impl trait `ByteCode`) from a mutable slice of bytes
    ///
    /// # Arguments
    ///
    /// * `data` - the slice of bytes that will be constructed as an mutable object.
    fn from_mut_bytes(data: &mut [u8]) -> Option<&mut Self> {
        if data.len() != size_of::<Self>() {
            return None;
        }

        // SAFETY: The pointer is properly aligned and point to an initialized instance of T.
        unsafe { data.as_mut_ptr().cast::<Self>().as_mut() }
    }
}

// Integer types of Rust satisfy the requirements of `trait ByteCode`
impl ByteCode for usize {}
impl ByteCode for u8 {}
impl ByteCode for u16 {}
impl ByteCode for u32 {}
impl ByteCode for u64 {}
impl ByteCode for u128 {}
impl ByteCode for isize {}
impl ByteCode for i8 {}
impl ByteCode for i16 {}
impl ByteCode for i32 {}
impl ByteCode for i64 {}
impl ByteCode for i128 {}

#[cfg(test)]
mod test {
    use super::*;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct TestData {
        type_id: [u8; 8],
        time_sec: u64,
    }

    impl ByteCode for TestData {}

    #[test]
    fn test_bytecode_plain_data() {
        let num1: u32 = 0x1234_5678;
        assert_eq!(num1.as_bytes().to_vec(), vec![0x78, 0x56, 0x34, 0x12]);

        let bytes = [0x34_u8, 0x56, 0x12, 0x05];
        assert_eq!(*u32::from_bytes(&bytes).unwrap(), 0x0512_5634);

        // Convert failed because byte stream's length is not equal to u32's size
        let miss_bytes = [0x0_u8, 0x0, 0x12];
        assert!(u32::from_bytes(&miss_bytes).is_none());
    }

    #[test]
    fn test_bytecode_struct() {
        let data = TestData {
            type_id: *b"bytecode",
            time_sec: 0x12345679,
        };

        let mut target = Vec::new();
        target.extend_from_slice(b"bytecode");
        target.extend_from_slice(&[0x79, 0x56, 0x34, 0x12]);
        target.extend_from_slice(&[0_u8; 4]);
        assert_eq!(data.as_bytes().to_vec(), target);

        // Convert failed because byte stream's length is not equal to size of struct.
        target.remove(target.len() - 1);
        assert!(TestData::from_bytes(&target).is_none());
    }

    #[test]
    fn test_byte_code_mut() {
        let mut num1 = 0x1234_5678_u32;

        let res_bytes = num1.as_mut_bytes();
        assert_eq!(res_bytes.to_vec(), vec![0x78, 0x56, 0x34, 0x12]);
        res_bytes[3] = 0x99;

        let res_num = u32::from_mut_bytes(res_bytes).unwrap();
        assert_eq!(*res_num, 0x9934_5678);
    }
}
