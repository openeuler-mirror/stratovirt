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
        unsafe { from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }

    /// Return the contents of a mutable object (impl trait `ByteCode`) to a mutable slice of bytes.
    /// the inverse of this function is "from_bytes_mut"
    fn as_mut_bytes(&mut self) -> &mut [u8] {
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
        let obj_array = unsafe { from_raw_parts::<Self>(data.as_ptr() as *const _, data.len()) };
        Some(&obj_array[0])
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
        let obj_array =
            unsafe { from_raw_parts_mut::<Self>(data.as_mut_ptr() as *mut _, data.len()) };
        Some(&mut obj_array[0])
    }
}

// Integer types of Rust satisfy the requirements of `trait ByteCode`
impl ByteCode for usize {}
impl ByteCode for u8 {}
impl ByteCode for u16 {}
impl ByteCode for u32 {}
impl ByteCode for u64 {}
impl ByteCode for isize {}
impl ByteCode for i8 {}
impl ByteCode for i16 {}
impl ByteCode for i32 {}
impl ByteCode for i64 {}
