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
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use std::ptr;

pub type pixman_bool_t = libc::c_int;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct pixman_box16 {
    pub x1: i16,
    pub y1: i16,
    pub x2: i16,
    pub y2: i16,
}
pub type pixman_box16_t = pixman_box16;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct pixman_color {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
    pub alpha: u16,
}
pub type pixman_color_t = pixman_color;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum pixman_format_code_t {
    PIXMAN_a8r8g8b8 = 537036936,
    PIXMAN_x8r8g8b8 = 537004168,
    PIXMAN_a8b8g8r8 = 537102472,
    PIXMAN_x8b8g8r8 = 537069704,
    PIXMAN_b8g8r8a8 = 537430152,
    PIXMAN_b8g8r8x8 = 537397384,
    PIXMAN_r8g8b8a8 = 537495688,
    PIXMAN_r8g8b8x8 = 537462920,
    PIXMAN_x14r6g6b6 = 537003622,
    PIXMAN_x2r10g10b10 = 537004714,
    PIXMAN_a2r10g10b10 = 537012906,
    PIXMAN_x2b10g10r10 = 537070250,
    PIXMAN_a2b10g10r10 = 537078442,
    PIXMAN_a8r8g8b8_sRGB = 537561224,
    PIXMAN_r8g8b8 = 402786440,
    PIXMAN_b8g8r8 = 402851976,
    PIXMAN_r5g6b5 = 268567909,
    PIXMAN_b5g6r5 = 268633445,
    PIXMAN_a1r5g5b5 = 268571989,
    PIXMAN_x1r5g5b5 = 268567893,
    PIXMAN_a1b5g5r5 = 268637525,
    PIXMAN_x1b5g5r5 = 268633429,
    PIXMAN_a4r4g4b4 = 268584004,
    PIXMAN_x4r4g4b4 = 268567620,
    PIXMAN_a4b4g4r4 = 268649540,
    PIXMAN_x4b4g4r4 = 268633156,
    PIXMAN_a8 = 134316032,
    PIXMAN_r3g3b2 = 134349618,
    PIXMAN_b2g3r3 = 134415154,
    PIXMAN_a2r2g2b2 = 134357538,
    PIXMAN_a2b2g2r2 = 134423074,
    PIXMAN_c8 = 134479872,
    PIXMAN_g8 = 134545408,
    PIXMAN_x4a4 = 134299648,
    PIXMAN_a4 = 67190784,
    PIXMAN_r1g2b1 = 67240225,
    PIXMAN_b1g2r1 = 67305761,
    PIXMAN_a1r1g1b1 = 67244305,
    PIXMAN_a1b1g1r1 = 67309841,
    PIXMAN_c4 = 67371008,
    PIXMAN_g4 = 67436544,
    PIXMAN_a1 = 16846848,
    PIXMAN_g1 = 17104896,
    PIXMAN_yuy2 = 268828672,
    PIXMAN_yv12 = 201785344,
}

#[repr(C)]
#[derive(Default, Debug, Copy, Clone)]
pub struct pixman_image {
    _unused: [u8; 0],
}
pub type pixman_image_t = pixman_image;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct pixman_rectangle16 {
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
}
pub type pixman_rectangle16_t = pixman_rectangle16;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct pixman_region16_data {
    pub size: libc::c_long,
    pub numRects: libc::c_long,
}
pub type pixman_region16_data_t = pixman_region16_data;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct pixman_region16 {
    pub extents: pixman_box16_t,
    pub data: *mut pixman_region16_data_t,
}
pub type pixman_region16_t = pixman_region16;
impl Default for pixman_region16 {
    fn default() -> Self {
        pixman_region16 {
            extents: pixman_box16_t::default(),
            data: ptr::null_mut(),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum pixman_op_t {
    PIXMAN_OP_CLEAR = 0,
    PIXMAN_OP_SRC = 1,
    PIXMAN_OP_DST = 2,
    PIXMAN_OP_OVER = 3,
    PIXMAN_OP_OVER_REVERSE = 4,
    PIXMAN_OP_IN = 5,
    PIXMAN_OP_IN_REVERSE = 6,
    PIXMAN_OP_OUT = 7,
    PIXMAN_OP_OUT_REVERSE = 8,
    PIXMAN_OP_ATOP = 9,
    PIXMAN_OP_ATOP_REVERSE = 10,
    PIXMAN_OP_XOR = 11,
    PIXMAN_OP_ADD = 12,
    PIXMAN_OP_SATURATE = 13,
    PIXMAN_OP_DISJOINT_CLEAR = 16,
    PIXMAN_OP_DISJOINT_SRC = 17,
    PIXMAN_OP_DISJOINT_DST = 18,
    PIXMAN_OP_DISJOINT_OVER = 19,
    PIXMAN_OP_DISJOINT_OVER_REVERSE = 20,
    PIXMAN_OP_DISJOINT_IN = 21,
    PIXMAN_OP_DISJOINT_IN_REVERSE = 22,
    PIXMAN_OP_DISJOINT_OUT = 23,
    PIXMAN_OP_DISJOINT_OUT_REVERSE = 24,
    PIXMAN_OP_DISJOINT_ATOP = 25,
    PIXMAN_OP_DISJOINT_ATOP_REVERSE = 26,
    PIXMAN_OP_DISJOINT_XOR = 27,
    PIXMAN_OP_CONJOINT_CLEAR = 32,
    PIXMAN_OP_CONJOINT_SRC = 33,
    PIXMAN_OP_CONJOINT_DST = 34,
    PIXMAN_OP_CONJOINT_OVER = 35,
    PIXMAN_OP_CONJOINT_OVER_REVERSE = 36,
    PIXMAN_OP_CONJOINT_IN = 37,
    PIXMAN_OP_CONJOINT_IN_REVERSE = 38,
    PIXMAN_OP_CONJOINT_OUT = 39,
    PIXMAN_OP_CONJOINT_OUT_REVERSE = 40,
    PIXMAN_OP_CONJOINT_ATOP = 41,
    PIXMAN_OP_CONJOINT_ATOP_REVERSE = 42,
    PIXMAN_OP_CONJOINT_XOR = 43,
    PIXMAN_OP_MULTIPLY = 48,
    PIXMAN_OP_SCREEN = 49,
    PIXMAN_OP_OVERLAY = 50,
    PIXMAN_OP_DARKEN = 51,
    PIXMAN_OP_LIGHTEN = 52,
    PIXMAN_OP_COLOR_DODGE = 53,
    PIXMAN_OP_COLOR_BURN = 54,
    PIXMAN_OP_HARD_LIGHT = 55,
    PIXMAN_OP_SOFT_LIGHT = 56,
    PIXMAN_OP_DIFFERENCE = 57,
    PIXMAN_OP_EXCLUSION = 58,
    PIXMAN_OP_HSL_HUE = 59,
    PIXMAN_OP_HSL_SATURATION = 60,
    PIXMAN_OP_HSL_COLOR = 61,
    PIXMAN_OP_HSL_LUMINOSITY = 62,
}

pub type pixman_image_destroy_func_t = ::std::option::Option<
    unsafe extern "C" fn(image: *mut pixman_image_t, data: *mut libc::c_void),
>;

pub extern "C" fn virtio_gpu_unref_resource_callback(
    _image: *mut pixman_image_t,
    data: *mut libc::c_void,
) {
    // SAFETY: The safety of this function is guaranteed by caller.
    unsafe { pixman_image_unref(data.cast()) };
}

fn pixman_format_reshift(val: u32, ofs: u32, num: u32) -> u32 {
    ((val >> (ofs)) & ((1 << (num)) - 1)) << ((val >> 22) & 3)
}
pub fn pixman_format_bpp(val: u32) -> u8 {
    pixman_format_reshift(val, 24, 8) as u8
}

pub fn pixman_format_a(val: u32) -> u8 {
    pixman_format_reshift(val, 12, 4) as u8
}
pub fn pixman_format_r(val: u32) -> u8 {
    pixman_format_reshift(val, 8, 4) as u8
}
pub fn pixman_format_g(val: u32) -> u8 {
    pixman_format_reshift(val, 4, 4) as u8
}
pub fn pixman_format_b(val: u32) -> u8 {
    pixman_format_reshift(val, 0, 4) as u8
}
pub fn pixman_format_depth(val: u32) -> u8 {
    pixman_format_a(val) + pixman_format_r(val) + pixman_format_g(val) + pixman_format_b(val)
}

extern "C" {
    pub fn pixman_format_supported_source(format: pixman_format_code_t) -> pixman_bool_t;
    pub fn pixman_image_composite(
        op: pixman_op_t,
        src: *mut pixman_image_t,
        mask: *mut pixman_image_t,
        dest: *mut pixman_image_t,
        src_x: i16,
        src_y: i16,
        mask_x: i16,
        mask_y: i16,
        dest_x: i16,
        dest_y: i16,
        width: u16,
        height: u16,
    );
    pub fn pixman_image_create_bits(
        format: pixman_format_code_t,
        width: libc::c_int,
        height: libc::c_int,
        bits: *mut u32,
        rowstride_bytes: libc::c_int,
    ) -> *mut pixman_image_t;
    pub fn pixman_image_create_solid_fill(color: *const pixman_color_t) -> *mut pixman_image_t;
    pub fn pixman_image_fill_rectangles(
        op: pixman_op_t,
        image: *mut pixman_image_t,
        color: *const pixman_color_t,
        n_rects: libc::c_int,
        rects: *const pixman_rectangle16_t,
    ) -> pixman_bool_t;
    pub fn pixman_image_get_data(image: *mut pixman_image_t) -> *mut u32;
    pub fn pixman_image_get_format(image: *mut pixman_image_t) -> pixman_format_code_t;
    pub fn pixman_image_get_height(image: *mut pixman_image_t) -> libc::c_int;
    pub fn pixman_image_get_stride(image: *mut pixman_image_t) -> libc::c_int;
    pub fn pixman_image_get_width(image: *mut pixman_image_t) -> libc::c_int;
    pub fn pixman_image_ref(image: *mut pixman_image_t) -> *mut pixman_image_t;
    pub fn pixman_image_set_destroy_function(
        image: *mut pixman_image_t,
        function: pixman_image_destroy_func_t,
        data: *mut libc::c_void,
    );
    pub fn pixman_image_unref(image: *mut pixman_image_t) -> pixman_bool_t;
    pub fn pixman_region_extents(region: *mut pixman_region16_t) -> *mut pixman_box16_t;
    pub fn pixman_region_fini(region: *mut pixman_region16_t);
    pub fn pixman_region_init(region: *mut pixman_region16_t);
    pub fn pixman_region_init_rect(
        region: *mut pixman_region16_t,
        x: libc::c_int,
        y: libc::c_int,
        width: libc::c_uint,
        height: libc::c_uint,
    );
    pub fn pixman_region_intersect(
        new_reg: *mut pixman_region16_t,
        reg1: *mut pixman_region16_t,
        reg2: *mut pixman_region16_t,
    ) -> pixman_bool_t;
    pub fn pixman_region_translate(region: *mut pixman_region16_t, x: libc::c_int, y: libc::c_int);
}
