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

use libc::{c_char, c_int, c_void};
use std::ffi::CString;

pub const CLK_PHANDLE: u32 = 1;
pub const GIC_PHANDLE: u32 = 2;
pub const GIC_ITS_PHANDLE: u32 = 3;
pub const CPU_PHANDLE_START: u32 = 10;

pub const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
pub const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
pub const IRQ_TYPE_EDGE_RISING: u32 = 1;
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

pub const FDT_MAX_SIZE: u32 = 0x1_0000;

extern "C" {
    fn fdt_create(buf: *mut c_void, bufsize: c_int) -> c_int;
    fn fdt_finish_reservemap(fdt: *mut c_void) -> c_int;
    fn fdt_begin_node(fdt: *mut c_void, name: *const c_char) -> c_int;
    fn fdt_end_node(fdt: *mut c_void) -> c_int;
    fn fdt_finish(fdt: *const c_void) -> c_int;
    fn fdt_open_into(fdt: *const c_void, buf: *mut c_void, size: c_int) -> c_int;

    fn fdt_path_offset(fdt: *const c_void, path: *const c_char) -> c_int;
    fn fdt_add_subnode(fdt: *mut c_void, offset: c_int, name: *const c_char) -> c_int;
    fn fdt_setprop(
        fdt: *mut c_void,
        offset: c_int,
        name: *const c_char,
        val: *const c_void,
        len: c_int,
    ) -> c_int;
}

pub fn create_device_tree(fdt: &mut Vec<u8>) {
    let mut ret = unsafe { fdt_create(fdt.as_mut_ptr() as *mut c_void, FDT_MAX_SIZE as c_int) };
    if ret < 0 {
        panic!("Failed to fdt_create, return {}.", ret);
    }

    ret = unsafe { fdt_finish_reservemap(fdt.as_mut_ptr() as *mut c_void) };
    if ret < 0 {
        panic!("Failed to fdt_finish_reservemap, return {}.", ret);
    }

    let c_str = CString::new("").unwrap();
    ret = unsafe { fdt_begin_node(fdt.as_mut_ptr() as *mut c_void, c_str.as_ptr()) };
    if ret < 0 {
        panic!("Failed to fdt_begin_node, return {}.", ret);
    }

    ret = unsafe { fdt_end_node(fdt.as_mut_ptr() as *mut c_void) };
    if ret < 0 {
        panic!("Failed to fdt_end_node, return {}.", ret);
    }

    ret = unsafe { fdt_finish(fdt.as_mut_ptr() as *mut c_void) };
    if ret < 0 {
        panic!("Failed to fdt_finish, return {}.", ret);
    }

    ret = unsafe {
        fdt_open_into(
            fdt.as_ptr() as *mut c_void,
            fdt.as_mut_ptr() as *mut c_void,
            FDT_MAX_SIZE as c_int,
        )
    };
    if ret < 0 {
        panic!("Failed to fdt_open_into, return {}.", ret);
    }
}

pub fn add_sub_node(fdt: &mut Vec<u8>, node_path: &str) {
    let names: Vec<&str> = node_path.split('/').collect();
    if names.len() < 2 {
        panic!("Failed to add sub node, node_path: {} invalid.", node_path);
    }

    let node_name = names[names.len() - 1];
    let pare_name = names[0..names.len() - 1].join("/");

    let c_str = if pare_name.is_empty() {
        CString::new("/").unwrap()
    } else {
        CString::new(pare_name).unwrap()
    };

    let offset = unsafe { fdt_path_offset(fdt.as_ptr() as *const c_void, c_str.as_ptr()) };
    if offset < 0 {
        panic!("Failed to fdt_path_offset, return {}.", offset);
    }

    let c_str = CString::new(node_name).unwrap();
    let ret = unsafe { fdt_add_subnode(fdt.as_mut_ptr() as *mut c_void, offset, c_str.as_ptr()) };
    if ret < 0 {
        panic!("Failed to fdt_add_subnode, return {}.", ret);
    }
}

pub fn set_property(fdt: &mut Vec<u8>, node_path: &str, prop: &str, val: Option<&[u8]>) {
    let c_str = CString::new(node_path).unwrap();
    let offset = unsafe { fdt_path_offset(fdt.as_ptr() as *const c_void, c_str.as_ptr()) };
    if offset < 0 {
        panic!("Failed to fdt_path_offset, return {}.", offset);
    }

    let (ptr, len) = if let Some(val) = val {
        (val.as_ptr() as *const c_void, val.len() as i32)
    } else {
        (std::ptr::null::<c_void>(), 0)
    };

    let c_str = CString::new(prop).unwrap();
    let ret = unsafe {
        fdt_setprop(
            fdt.as_mut_ptr() as *mut c_void,
            offset,
            c_str.as_ptr(),
            ptr,
            len,
        )
    };
    if ret < 0 {
        panic!("Failed to fdt_setprop, return {}.", ret);
    }
}

pub fn set_property_string(fdt: &mut Vec<u8>, node_path: &str, prop: &str, val: &str) {
    set_property(
        fdt,
        node_path,
        prop,
        Some(&([val.as_bytes(), &[0_u8]].concat())),
    )
}

pub fn set_property_u32(fdt: &mut Vec<u8>, node_path: &str, prop: &str, val: u32) {
    set_property(fdt, node_path, prop, Some(&val.to_be_bytes()))
}

pub fn set_property_u64(fdt: &mut Vec<u8>, node_path: &str, prop: &str, val: u64) {
    set_property(fdt, node_path, prop, Some(&val.to_be_bytes()))
}

pub fn set_property_array_u32(fdt: &mut Vec<u8>, node_path: &str, prop: &str, array: &[u32]) {
    let mut bytes: Vec<u8> = Vec::new();
    for &val in array {
        bytes.append(&mut val.to_be_bytes().to_vec());
    }
    set_property(fdt, node_path, prop, Some(&bytes))
}

pub fn set_property_array_u64(fdt: &mut Vec<u8>, node_path: &str, prop: &str, array: &[u64]) {
    let mut bytes: Vec<u8> = Vec::new();
    for &val in array {
        bytes.append(&mut val.to_be_bytes().to_vec());
    }
    set_property(fdt, node_path, prop, Some(&bytes))
}

pub fn dump_dtb(fdt: &[u8], file_path: &str) {
    use std::fs::File;
    use std::io::Write;

    let mut f = File::create(file_path).unwrap();
    for i in fdt.iter() {
        f.write_all(&[*i]).expect("Unable to write data");
    }
}

/// Trait for devices to be added to the Flattened Device Tree.
pub trait CompileFDT {
    /// function to generate fdt node
    ///
    /// # Arguments
    ///
    /// * `fdt` - the fdt slice to be expended.
    fn generate_fdt_node(&self, fdt: &mut Vec<u8>);
}
