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

use bitintr::Popcnt;
use util::pixman::{
    pixman_format_a, pixman_format_b, pixman_format_bpp, pixman_format_code_t, pixman_format_depth,
    pixman_format_g, pixman_format_r, pixman_image_get_data, pixman_image_get_format,
    pixman_image_get_height, pixman_image_get_stride, pixman_image_get_width, pixman_image_t,
    pixman_image_unref,
};

#[derive(Clone, Default)]
pub struct ColorInfo {
    /// Mask color.
    pub mask: u32,
    /// Shift to the lowest bit
    pub shift: u8,
    /// Max bits.
    pub max: u8,
    /// Color bits.
    pub bits: u8,
}

impl ColorInfo {
    pub fn set_color_info(&mut self, shift: u8, max: u16) {
        self.mask = (max as u32) << (shift as u32);
        self.shift = shift;
        self.max = if max == 0 { 0xFF } else { max as u8 };
        self.bits = max.popcnt() as u8;
    }
}

#[derive(Clone, Default)]
pub struct PixelFormat {
    /// Bits per pixel.
    pub pixel_bits: u8,
    /// Bytes per pixel.
    pub pixel_bytes: u8,
    /// Color depth.
    pub depth: u8,
    /// Red info.
    pub red: ColorInfo,
    /// Green info.
    pub green: ColorInfo,
    /// Blue info.
    pub blue: ColorInfo,
    /// Alpha channel.
    pub alpha_chl: ColorInfo,
}

impl PixelFormat {
    // Pixelformat_from_pixman.
    pub fn init_pixelformat(&mut self) {
        let fmt = pixman_format_code_t::PIXMAN_x8r8g8b8 as u32;
        self.pixel_bits = pixman_format_bpp(fmt);
        self.pixel_bytes = self.pixel_bits / 8;
        self.depth = pixman_format_depth(fmt);

        self.alpha_chl.bits = pixman_format_a(fmt);
        self.red.bits = pixman_format_r(fmt);
        self.green.bits = pixman_format_g(fmt);
        self.blue.bits = pixman_format_b(fmt);

        self.alpha_chl.shift = self.blue.bits + self.green.bits + self.red.bits;
        self.red.shift = self.blue.bits + self.green.bits;
        self.green.shift = self.blue.bits;
        self.blue.shift = 0;

        self.alpha_chl.max = ((1 << self.alpha_chl.bits) - 1) as u8;
        self.red.max = ((1 << self.red.bits) - 1) as u8;
        self.green.max = ((1 << self.green.bits) - 1) as u8;
        self.blue.max = ((1 << self.blue.bits) - 1) as u8;

        self.alpha_chl.mask = self.alpha_chl.max.wrapping_shl(self.alpha_chl.shift as u32) as u32;
        self.red.mask = self.red.max.wrapping_shl(self.red.shift as u32) as u32;
        self.green.mask = self.green.max.wrapping_shl(self.green.shift as u32) as u32;
        self.blue.mask = self.blue.max.wrapping_shl(self.blue.shift as u32) as u32;
    }

    pub fn is_default_pixel_format(&self) -> bool {
        // Check if type is PIXMAN_TYPE_ARGB.
        if self.red.shift <= self.green.shift
            || self.green.shift <= self.blue.shift
            || self.blue.shift != 0
        {
            return false;
        }

        // Check if format is PIXMAN_x8r8g8b8.
        if self.pixel_bits != 32
            || self.alpha_chl.bits != 0
            || self.red.bits != 8
            || self.green.bits != 8
            || self.blue.bits != 8
        {
            return false;
        }

        true
    }
}

pub fn get_image_width(image: *mut pixman_image_t) -> i32 {
    unsafe { pixman_image_get_width(image as *mut pixman_image_t) as i32 }
}

pub fn get_image_height(image: *mut pixman_image_t) -> i32 {
    unsafe { pixman_image_get_height(image as *mut pixman_image_t) as i32 }
}

pub fn get_image_stride(image: *mut pixman_image_t) -> i32 {
    unsafe { pixman_image_get_stride(image as *mut pixman_image_t) }
}

pub fn get_image_data(image: *mut pixman_image_t) -> *mut u32 {
    unsafe { pixman_image_get_data(image as *mut pixman_image_t) }
}

pub fn get_image_format(image: *mut pixman_image_t) -> pixman_format_code_t {
    unsafe { pixman_image_get_format(image as *mut pixman_image_t) }
}

/// Bpp: bit per pixel
pub fn bytes_per_pixel() -> usize {
    ((pixman_format_bpp(pixman_format_code_t::PIXMAN_x8r8g8b8 as u32) + 7) / 8) as usize
}

/// Decrease the reference of image
/// # Arguments
///
/// * `image` - the pointer to image in pixman
pub fn unref_pixman_image(image: *mut pixman_image_t) {
    if image.is_null() {
        return;
    }
    unsafe { pixman_image_unref(image as *mut pixman_image_t) };
}
