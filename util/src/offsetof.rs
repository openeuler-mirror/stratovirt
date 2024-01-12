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

/// Macro: Calculate offset of specified field in a type.
#[macro_export]
macro_rules! __offset_of {
    ($type_name:ty, $field:ident) => {{
        let tmp = core::mem::MaybeUninit::<$type_name>::uninit();
        let outer = tmp.as_ptr();
        // SAFETY: The pointer is valid and aligned, just not initialised; `addr_of` ensures
        // that we don't actually read from `outer` (which would be UB) nor create an
        // intermediate reference.
        let inner = unsafe { core::ptr::addr_of!((*outer).$field) } as *const u8;
        // SAFETY: Two pointers are within the same allocation block.
        unsafe { inner.offset_from(outer as *const u8) as usize }
    }};
}

/// Macro: Calculate offset of a field in a recursive type.
///
/// # Arguments
///
/// The Arguments is: a type name and its field name,
/// follows by a series of sub-type's name and its field's name.
///
/// # Examples
///
/// ```rust
/// #[macro_use]
/// extern crate util;
///
/// fn main() {
///     struct Rectangle {
///         pub length: u64,
///         pub width: u64,
///     }
///     assert_eq!(offset_of!(Rectangle, length), 0);
///     assert_eq!(offset_of!(Rectangle, width), 8);
/// }
/// ```
#[macro_export]
macro_rules! offset_of {
    ($type_name:ty, $field:ident) => { $crate::__offset_of!($type_name, $field) };
    ($type_name:ty, $field:ident, $($sub_type_name:ty, $sub_field:ident), +) => {
        $crate::__offset_of!($type_name, $field) + offset_of!($($sub_type_name, $sub_field), +)
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_offset_of() {
        #[repr(C)]
        pub struct Student {
            student_id: u32,
            weight: u8,
            age: u8,
            marks: u32,
            is_male: bool,
        }
        assert_eq!(offset_of!(Student, student_id), 0);
        assert_eq!(offset_of!(Student, weight), 4);
        assert_eq!(offset_of!(Student, age), 5);
        assert_eq!(offset_of!(Student, marks), 8);
        assert_eq!(offset_of!(Student, is_male), 12);

        #[repr(C, packed)]
        pub struct Student_packed {
            student_id: u32,
            weight: u8,
            age: u8,
            marks: u32,
            is_male: bool,
        }
        assert_eq!(offset_of!(Student_packed, student_id), 0);
        assert_eq!(offset_of!(Student_packed, weight), 4);
        assert_eq!(offset_of!(Student_packed, age), 5);
        assert_eq!(offset_of!(Student_packed, marks), 6);
        assert_eq!(offset_of!(Student_packed, is_male), 10);
    }

    #[test]
    fn test_offset_of_recursive() {
        mod recursive {
            #[repr(C)]
            pub struct grand_parent {
                pub a: u8,
                pub b: u32,
                pub c: parent,
            }

            #[repr(C)]
            pub struct parent {
                pub a: u16,
                pub b: i32,
                pub c: son,
            }

            #[repr(C)]
            pub struct son {
                pub a: u32,
                pub b: u8,
                pub c: u64,
            }
        }

        assert_eq!(offset_of!(recursive::grand_parent, a), 0);
        assert_eq!(offset_of!(recursive::grand_parent, b), 4);
        assert_eq!(offset_of!(recursive::grand_parent, c), 8);
        assert_eq!(
            offset_of!(recursive::grand_parent, c, recursive::parent, a),
            8
        );
        assert_eq!(
            offset_of!(recursive::grand_parent, c, recursive::parent, b),
            12
        );
        assert_eq!(
            offset_of!(recursive::grand_parent, c, recursive::parent, c),
            16
        );
        assert_eq!(
            offset_of!(
                recursive::grand_parent,
                c,
                recursive::parent,
                c,
                recursive::son,
                a
            ),
            16
        );
        assert_eq!(
            offset_of!(
                recursive::grand_parent,
                c,
                recursive::parent,
                c,
                recursive::son,
                b
            ),
            20
        );
        assert_eq!(
            offset_of!(
                recursive::grand_parent,
                c,
                recursive::parent,
                c,
                recursive::son,
                c
            ),
            24
        );

        mod recursive_packed {
            #[repr(C, packed)]
            pub struct grand_parent {
                pub a: u32,
                pub b: u8,
                pub c: parent,
            }

            #[repr(C, packed)]
            pub struct parent {
                pub a: u16,
                pub b: i32,
                pub c: son,
            }

            #[repr(C, packed)]
            pub struct son {
                pub a: u32,
                pub b: u8,
                pub c: u64,
            }
        }

        assert_eq!(offset_of!(recursive_packed::grand_parent, a), 0);
        assert_eq!(offset_of!(recursive_packed::grand_parent, b), 4);
        assert_eq!(offset_of!(recursive_packed::grand_parent, c), 5);
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                a
            ),
            5
        );
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                b
            ),
            7
        );
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                c
            ),
            11
        );
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                c,
                recursive_packed::son,
                a
            ),
            11
        );
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                c,
                recursive_packed::son,
                b
            ),
            15
        );
        assert_eq!(
            offset_of!(
                recursive_packed::grand_parent,
                c,
                recursive_packed::parent,
                c,
                recursive_packed::son,
                c
            ),
            16
        );
    }
}
