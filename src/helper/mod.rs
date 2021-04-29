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

pub mod byte_code;
pub mod checksum;
#[cfg(target_arch = "x86_64")]
pub mod cpuid;
#[cfg(target_arch = "aarch64")]
pub mod device_tree;
pub mod epoll;
pub mod num_ops;

/// Macro: Calculate offset of specified field in a type.
#[macro_export]
macro_rules! __offset_of {
    ($type_name:ty, $field:ident) => {
        unsafe { &(*(std::ptr::null::<$type_name>())).$field as *const _ as usize }
    };
}

/// Macro: Calculate offset of a field in a recursive type.
///
/// # Arguments
///
/// The Arguments is: a type name and its field name,
/// follows by a series of sub-type's name and its field's name.
#[macro_export]
macro_rules! offset_of {
    ($type_name:ty, $field:ident) => { crate::__offset_of!($type_name, $field) };
    ($type_name:ty, $field:ident, $($sub_type_name:ty, $sub_field:ident), +) => {
        crate::__offset_of!($type_name, $field) + crate::offset_of!($($sub_type_name, $sub_field), +)
    };
}
