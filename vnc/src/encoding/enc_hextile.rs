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

use crate::client::{DisplayMode, Rectangle};
use crate::pixman::{bytes_per_pixel, get_image_data, get_image_stride};
use crate::vnc::write_pixel;
use std::{cmp, mem};
use util::pixman::pixman_image_t;

/// Size of subrectangle.
const HEXTILE_BLOCK_SIZE: usize = 16;
/// SubEncoding type of hextile.
const RAW: u8 = 0x01;
const BACKGROUND_SPECIFIC: u8 = 0x02;
const FOREGROUND_SPECIFIC: u8 = 0x04;
const ANY_SUBRECTS: u8 = 0x08;
const SUBRECTS_COLOURED: u8 = 0x10;

/// Compress data by hextile algorithm before sending.
/// Rectangles are split up into 16 * 16 tiles.
///
/// # Arguments
///
/// * `image` - pointer to the data need to be send.
/// * `rect` - dirty area of image.
/// * `client_dpm` - Output mode information of client display.
/// * `buf` - send buffer.
pub fn hextile_send_framebuffer_update(
    image: *mut pixman_image_t,
    rect: &Rectangle,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
) -> i32 {
    let mut last_bg: Option<u32> = None;
    let mut last_fg: Option<u32> = None;
    for j in (0..rect.h).step_by(HEXTILE_BLOCK_SIZE) {
        for i in (0..rect.w).step_by(HEXTILE_BLOCK_SIZE) {
            let sub_rect = Rectangle::new(
                rect.x + i,
                rect.y + j,
                cmp::min(HEXTILE_BLOCK_SIZE as i32, rect.w - i),
                cmp::min(HEXTILE_BLOCK_SIZE as i32, rect.h - j),
            );
            compress_each_tile(
                image,
                &sub_rect,
                client_dpm,
                buf,
                &mut last_bg,
                &mut last_fg,
            );
        }
    }
    1
}

/// Compress each tiles by hextile algorithm.
///
/// # Arguments
///
/// * `image` - pointer to the data need to be send.
/// * `sub_rect` - area of tile.
/// * `client_dpm` - Output mode information of client display.
/// * `buf` - send buffer.
/// * `last_bg` - background of last tile.
/// * `last_fg` - foreground of last tile.
fn compress_each_tile<'a>(
    image: *mut pixman_image_t,
    sub_rect: &Rectangle,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
    last_bg: &'a mut Option<u32>,
    last_fg: &'a mut Option<u32>,
) {
    let stride = get_image_stride(image);
    let mut data_ptr = get_image_data(image) as *mut u8;
    data_ptr = (data_ptr as usize
        + (sub_rect.y * stride) as usize
        + sub_rect.x as usize * bytes_per_pixel()) as *mut u8;
    let mut flag: u8 = 0; // Subencoding mask.
    let mut bg: u32 = 0; // Pixel value of background.
    let mut fg: u32 = 0; // Pixel value of foreground.
    let n_colors = pixel_statistical(data_ptr, stride, sub_rect, &mut bg, &mut fg);
    let mut n_subtiles = 0; // Number of subrectangle.
    let mut tmp_buf: Vec<u8> = Vec::new();

    if last_bg.is_none() || Some(bg) != *last_bg {
        flag |= BACKGROUND_SPECIFIC;
        *last_bg = Some(bg);
    }
    if n_colors < 3 && (last_fg.is_none() || Some(fg) != *last_fg) {
        flag |= FOREGROUND_SPECIFIC;
        *last_fg = Some(fg);
    }

    match n_colors {
        2 => {
            flag |= ANY_SUBRECTS;
            n_subtiles =
                subrectangle_of_foreground(sub_rect, data_ptr, bg, fg, stride, &mut tmp_buf);
        }
        3 => {
            flag |= ANY_SUBRECTS | SUBRECTS_COLOURED;
            if last_bg.is_none() || Some(bg) != *last_bg {
                flag |= BACKGROUND_SPECIFIC;
            }
            n_subtiles = subrectangle_with_pixel_value(
                sub_rect,
                data_ptr,
                bg,
                stride,
                client_dpm,
                &mut tmp_buf,
            );
            //If the length becomes longer after compression, give up compression.
            if tmp_buf.len() > (sub_rect.h * sub_rect.w * client_dpm.pf.pixel_bytes as i32) as usize
            {
                flag = RAW;
                *last_bg = None;
            }
            *last_fg = None;
        }
        _ => {}
    }

    buf.append(&mut flag.to_be_bytes().to_vec()); // SubEncoding-mask.
    if flag & RAW == 0 {
        if flag & BACKGROUND_SPECIFIC != 0 {
            write_pixel(
                bg.to_ne_bytes().as_ptr() as *mut u8,
                bytes_per_pixel(),
                client_dpm,
                buf,
            );
        }
        if flag & FOREGROUND_SPECIFIC != 0 {
            write_pixel(
                fg.to_ne_bytes().as_ptr() as *mut u8,
                bytes_per_pixel(),
                client_dpm,
                buf,
            );
        }
        if n_subtiles != 0 {
            buf.append(&mut (n_subtiles as u8).to_be_bytes().to_vec()); // Num of SubRectanges.
            buf.append(&mut tmp_buf); // SubrectsColoured.
        }
    } else {
        // Send data directly without compression.
        for j in 0..sub_rect.h {
            let ptr = (data_ptr as usize + (j * stride) as usize) as *mut u8;
            write_pixel(ptr, (sub_rect.w * 4) as usize, client_dpm, buf);
        }
    }
}

/// Specifies all subrectangles of foreground colour in this tile.
///
/// # Arguments
///
/// * `sub_rect` - area of tile.
/// * `data_ptr` - pointer to the data of image.
/// * `bg` - background of current tile.
/// * `fg` - foreground of current tile.
/// * `stride` -  stride of image.
/// * `buf` - send buffer.
fn subrectangle_of_foreground(
    sub_rect: &Rectangle,
    data_ptr: *mut u8,
    bg: u32,
    fg: u32,
    stride: i32,
    buf: &mut Vec<u8>,
) -> i32 {
    let mut n_subtiles = 0;
    for j in 0..sub_rect.h {
        let ptr = (data_ptr as usize + (j * stride) as usize) as *mut u32;
        let mut x_begin = -1;
        for i in 0..sub_rect.w {
            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            let value = unsafe { *ptr.add(i as usize) };
            if value == fg && x_begin == -1 {
                x_begin = i;
            } else if value == bg && x_begin != -1 {
                hextile_enc_sub_coloured(buf, x_begin, j, i - x_begin, 1);
                n_subtiles += 1;
                x_begin = -1;
            }
        }
        if x_begin != -1 {
            hextile_enc_sub_coloured(buf, x_begin, j, sub_rect.w - x_begin, 1);
            n_subtiles += 1;
        }
    }
    n_subtiles
}

/// Specifies all subrectangles with pixel value.
///
/// # Arguments
///
/// * `sub_rect` - area of tile.
/// * `data_ptr` -  pointer to the data of image.
/// * `bg` - background of current tile.
/// * `stride` - stride of image.
/// * `client_dpm` -  Output mode information of client display.
/// * `buf` - send buffer.
fn subrectangle_with_pixel_value(
    sub_rect: &Rectangle,
    data_ptr: *mut u8,
    bg: u32,
    stride: i32,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
) -> i32 {
    let mut n_subtiles = 0;
    for j in 0..sub_rect.h {
        let mut x_begin = -1;
        let mut last_color: Option<u32> = None;
        let ptr = (data_ptr as usize + (j * stride) as usize) as *mut u32;
        for i in 0..sub_rect.w {
            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            let value = unsafe { *ptr.offset(i as isize) };
            match last_color {
                Some(color) => {
                    if color != value {
                        last_color = None;
                        write_pixel(
                            color.to_ne_bytes().as_ptr() as *mut u8,
                            bytes_per_pixel(),
                            client_dpm,
                            buf,
                        );
                        hextile_enc_sub_coloured(buf, x_begin, j, i - x_begin, 1);
                        n_subtiles += 1;
                        x_begin = -1;
                        if value != bg {
                            last_color = Some(value);
                            x_begin = i;
                        }
                    }
                }
                None => {
                    if value == bg {
                        continue;
                    }
                    last_color = Some(value);
                    x_begin = i;
                }
            }
        }
        if let Some(color) = last_color {
            write_pixel(
                color.to_ne_bytes().as_ptr() as *mut u8,
                bytes_per_pixel(),
                client_dpm,
                buf,
            );
            n_subtiles += 1;
            hextile_enc_sub_coloured(buf, x_begin, j, sub_rect.w - x_begin, 1)
        }
    }

    n_subtiles
}

/// Encode SubrectsColoured.
/// First Byte: x-and-y-position
/// Second Byte: width-and-height-position.
fn hextile_enc_sub_coloured(buf: &mut Vec<u8>, x: i32, y: i32, w: i32, h: i32) {
    buf.append(
        &mut (((x & 0x0f) << 4 | (y & 0x0f)) as u8)
            .to_be_bytes()
            .to_vec(),
    );
    buf.append(
        &mut ((((w - 1) & 0x0f) << 4 | ((h - 1) & 0x0f)) as u8)
            .to_be_bytes()
            .to_vec(),
    );
}

/// Count the total number of different pixels in rectangle.
///
/// # Arguments
///
/// * `data_ptr` - pointer to the data.
/// * `stride` - number of bytes for one line of image data.
/// * `sub_rect` - subrectangle.
/// * `bg` - background.
/// * `fg` - foreground.
fn pixel_statistical<'a>(
    data_ptr: *mut u8,
    stride: i32,
    sub_rect: &Rectangle,
    bg: &'a mut u32,
    fg: &'a mut u32,
) -> usize {
    let mut n_colors = 0;
    let mut bg_count = 0; // Number of background.
    let mut fg_count = 0; // Number of foreground.

    for j in 0..sub_rect.h {
        let ptr = (data_ptr as usize + (j * stride) as usize) as *mut u32;
        for i in 0..sub_rect.w {
            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            let value = unsafe { *ptr.offset(i as isize) };
            match n_colors {
                0 => {
                    *bg = value;
                    n_colors = 1;
                }
                1 => {
                    if *bg != value {
                        *fg = value;
                        n_colors = 2;
                    }
                }
                2 => {
                    if value == *bg {
                        bg_count += 1;
                    } else if value == *fg {
                        fg_count += 1;
                    } else {
                        n_colors = 3;
                    }
                }
                _ => {
                    break;
                }
            }
        }
        if n_colors > 2 {
            break;
        }
    }

    if n_colors > 1 && fg_count > bg_count {
        mem::swap(bg, fg);
    }

    n_colors
}

#[cfg(test)]
mod tests {
    use super::hextile_send_framebuffer_update;
    use crate::{
        client::{DisplayMode, Rectangle, ENCODING_HEXTILE},
        encoding::test_hextile_image_data::{
            IMAGE_DATA_MULTI_PIXELS, IMAGE_DATA_SINGLE_PIXEL, IMAGE_DATA_TWO_PIXEL,
            TARGET_DATA_MULTI_PIXELS, TARGET_DATA_SINGLE_PIXEL, TARGET_DATA_TWO_PIXEL,
        },
        pixman::{create_pixman_image, PixelFormat},
    };
    use util::pixman::pixman_format_code_t;
    fn color_init() -> PixelFormat {
        let mut pf = PixelFormat::default();
        pf.red.set_color_info(16, 255);
        pf.green.set_color_info(8, 255);
        pf.blue.set_color_info(0, 255);
        pf.pixel_bits = 32;
        pf.pixel_bytes = 4;
        pf.depth = 24;
        pf
    }

    #[test]
    fn test_hextile_send_framebuffer_single_pixel() {
        let pf = color_init();
        let convert = false;
        let client_be = false;
        let enc = ENCODING_HEXTILE;
        let client_dpm = DisplayMode::new(enc, client_be, convert, pf);
        let image_data = IMAGE_DATA_SINGLE_PIXEL;
        let target_data = TARGET_DATA_SINGLE_PIXEL;
        let image_width: i32 = 32;
        let image_height: i32 = 32;
        let image_stride: i32 = 128;

        let image = create_pixman_image(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            image_width as i32,
            image_height as i32,
            image_data.as_ptr() as *mut u32,
            image_stride,
        );
        let mut buf: Vec<u8> = Vec::new();
        let rect = Rectangle {
            x: 0,
            y: 0,
            w: image_width,
            h: image_height,
        };
        hextile_send_framebuffer_update(image, &rect, &client_dpm, &mut buf);
        assert_eq!(buf, target_data);
    }

    #[test]
    fn test_hextile_send_framebuffer_two_pixels() {
        let pf = color_init();
        let convert = false;
        let client_be = false;
        let enc = ENCODING_HEXTILE;
        let client_dpm = DisplayMode::new(enc, client_be, convert, pf);
        let image_data = IMAGE_DATA_TWO_PIXEL;
        let target_data = TARGET_DATA_TWO_PIXEL;
        let image_width: i32 = 40;
        let image_height: i32 = 40;
        let image_stride: i32 = 160;

        let image = create_pixman_image(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            image_width as i32,
            image_height as i32,
            image_data.as_ptr() as *mut u32,
            image_stride,
        );
        let mut buf: Vec<u8> = Vec::new();
        let rect = Rectangle {
            x: 0,
            y: 0,
            w: image_width,
            h: image_height,
        };
        hextile_send_framebuffer_update(image, &rect, &client_dpm, &mut buf);
        assert_eq!(buf, target_data);
    }

    #[test]
    fn test_hextile_send_framebuffer_multi_pixels() {
        let pf = color_init();
        let convert = false;
        let client_be = false;
        let enc = ENCODING_HEXTILE;
        let client_dpm = DisplayMode::new(enc, client_be, convert, pf);
        let image_data = IMAGE_DATA_MULTI_PIXELS;
        let target_data = TARGET_DATA_MULTI_PIXELS;
        let image_width: i32 = 40;
        let image_height: i32 = 40;
        let image_stride: i32 = 160;

        let image = create_pixman_image(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            image_width as i32,
            image_height as i32,
            image_data.as_ptr() as *mut u32,
            image_stride,
        );
        let mut buf: Vec<u8> = Vec::new();
        let rect = Rectangle {
            x: 0,
            y: 0,
            w: image_width,
            h: image_height,
        };
        hextile_send_framebuffer_update(image, &rect, &client_dpm, &mut buf);
        assert_eq!(buf, target_data);
    }
}
