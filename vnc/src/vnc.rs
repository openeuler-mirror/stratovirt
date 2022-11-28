// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights r&eserved.
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

use crate::VncError;
use crate::{
    client::{
        RectInfo, Rectangle, ServerMsg, VncClient, VncFeatures, ENCODING_ALPHA_CURSOR,
        ENCODING_RAW, ENCODING_RICH_CURSOR,
    },
    pixman::{
        bytes_per_pixel, get_image_data, get_image_height, get_image_stride, get_image_width,
        unref_pixman_image, PixelFormat,
    },
    round_up, round_up_div,
    server::VncServer,
};
use anyhow::{anyhow, Result};
use core::time;
use log::error;
use machine_manager::{
    config::{ObjectConfig, VncConfig},
    event_loop::EventLoop,
};
use once_cell::sync::Lazy;
use std::{
    cmp,
    net::TcpListener,
    ptr,
    sync::{Arc, Mutex},
    thread,
};
use util::{
    bitmap::Bitmap,
    loop_context::EventNotifierHelper,
    pixman::{pixman_format_code_t, pixman_image_create_bits, pixman_image_ref, pixman_image_t},
};
use vmm_sys_util::eventfd::EventFd;

/// The number of dirty pixels represented bt one bit in dirty bitmap.
pub const DIRTY_PIXELS_NUM: u16 = 16;
/// The default max window width.
pub const MAX_WINDOW_WIDTH: u16 = round_up(2560, DIRTY_PIXELS_NUM as u64) as u16;
/// The default max window height.
pub const MAX_WINDOW_HEIGHT: u16 = 2048;
pub const DIRTY_WIDTH_BITS: u16 = MAX_WINDOW_WIDTH / DIRTY_PIXELS_NUM;
pub const VNC_BITMAP_WIDTH: u64 =
    round_up_div(DIRTY_WIDTH_BITS as u64, u64::BITS as u64) * u64::BITS as u64;

const DEFAULT_REFRESH_INTERVAL: u64 = 30;
pub const BIT_PER_BYTE: u32 = 8;
const MILLI_PER_SEC: u64 = 1_000_000;
pub const DISPLAY_UPDATE_INTERVAL_DEFAULT: u32 = 30;
pub const DISPLAY_UPDATE_INTERVAL_INC: u32 = 50;
pub const DISPLAY_UPDATE_INTERVAL_MAX: u32 = 3_000;

/// Struct to record image information
#[derive(Clone, Copy)]
pub struct DisplaySurface {
    /// image format
    pub format: pixman_format_code_t,
    /// pointer to image
    pub image: *mut pixman_image_t,
}

impl Default for DisplaySurface {
    fn default() -> Self {
        DisplaySurface {
            format: pixman_format_code_t::PIXMAN_a1,
            image: ptr::null_mut(),
        }
    }
}

/// Struct to record mouse information
#[derive(Clone, Default)]
pub struct DisplayMouse {
    pub width: u32,
    pub height: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub data: Vec<u8>,
}

/// Initizlization function of vnc
///
/// # Arguments
///
/// * `VncConfig` `object`- vnc related parameters
pub fn vnc_init(vnc: &Option<VncConfig>, object: &ObjectConfig) -> Result<()> {
    let vnc_cfg;
    if let Some(v) = vnc {
        vnc_cfg = v;
    } else {
        return Ok(());
    }

    let addr = format!("{}:{}", vnc_cfg.ip, vnc_cfg.port);
    let listener: TcpListener;
    match TcpListener::bind(&addr.as_str()) {
        Ok(l) => listener = l,
        Err(e) => {
            let msg = format!("Bind {} failed {}", addr, e);
            error!("{}", e);
            return Err(anyhow!(VncError::TcpBindFailed(msg)));
        }
    }

    listener
        .set_nonblocking(true)
        .expect("Set noblocking for vnc socket failed");

    let mut server = VncServer::new(Arc::new(Mutex::new(listener)), get_client_image());

    // Parameter configuation for VncServeer.
    if let Err(err) = server.make_config(vnc_cfg, object) {
        return Err(err);
    }

    // Add an VncServer.
    add_vnc_server(server);

    // Vnc_thread: a thread to send the framebuffer
    if let Err(err) = start_vnc_thread() {
        return Err(err);
    }

    EventLoop::update_event(
        EventNotifierHelper::internal_notifiers(VNC_SERVERS.lock().unwrap()[0].clone()),
        None,
    )?;
    Ok(())
}

fn start_vnc_thread() -> Result<()> {
    let interval = DEFAULT_REFRESH_INTERVAL;
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let _handle = thread::Builder::new()
        .name("vnc_worker".to_string())
        .spawn(move || loop {
            if VNC_RECT_INFO.lock().unwrap().is_empty() {
                thread::sleep(time::Duration::from_millis(interval));
                continue;
            }

            let mut rect_info;
            match VNC_RECT_INFO.lock().unwrap().get_mut(0) {
                Some(rect) => {
                    rect_info = rect.clone();
                }
                None => {
                    thread::sleep(time::Duration::from_millis(interval));
                    continue;
                }
            }
            VNC_RECT_INFO.lock().unwrap().remove(0);

            let mut num_rects: i32 = 0;
            let mut buf = Vec::new();
            buf.append(&mut [0_u8; 2].to_vec());

            let locked_server = server.lock().unwrap();
            for rect in rect_info.rects.iter_mut() {
                if check_rect(rect, rect_info.width, rect_info.height) {
                    let n = send_framebuffer_update(
                        rect_info.image,
                        rect_info.encoding,
                        rect,
                        rect_info.convert,
                        rect_info.big_endian,
                        &rect_info.pixel_format,
                        &mut buf,
                    );
                    if n >= 0 {
                        num_rects += n;
                    }
                }
            }
            buf.insert(2, num_rects as u8);
            buf.insert(2, (num_rects >> 8) as u8);

            let client = if let Some(client) = locked_server.clients.get(&rect_info.addr) {
                client.clone()
            } else {
                continue;
            };
            drop(locked_server);
            client.lock().unwrap().write_msg(&buf);
        })
        .unwrap();
    Ok(())
}

/// Add a vnc server during initialization.
fn add_vnc_server(server: VncServer) {
    VNC_SERVERS
        .lock()
        .unwrap()
        .push(Arc::new(Mutex::new(server)));
}

/// Set dirty in bitmap.
pub fn set_area_dirty(
    dirty: &mut Bitmap<u64>,
    mut x: i32,
    mut y: i32,
    mut w: i32,
    mut h: i32,
    g_w: i32,
    g_h: i32,
) {
    let width: i32 = vnc_width(g_w);
    let height: i32 = vnc_height(g_h);

    w += x % DIRTY_PIXELS_NUM as i32;
    x -= x % DIRTY_PIXELS_NUM as i32;

    x = cmp::min(x, width);
    y = cmp::min(y, height);
    w = cmp::min(x + w, width) - x;
    h = cmp::min(y + h, height);
    while y < h {
        let pos = y * VNC_BITMAP_WIDTH as i32 + x / DIRTY_PIXELS_NUM as i32;
        for i in 0..round_up_div(w as u64, DIRTY_PIXELS_NUM as u64) as i32 {
            dirty.set((pos + i) as usize).unwrap();
        }
        y += 1;
    }
    REFRESH_EVT.lock().unwrap().write(1).unwrap();
}

pub fn vnc_display_update(x: i32, y: i32, w: i32, h: i32) {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return;
    }
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let mut locked_server = server.lock().unwrap();
    let g_w = get_image_width(locked_server.guest_image);
    let g_h = get_image_height(locked_server.guest_image);
    set_area_dirty(&mut locked_server.guest_dirty_bitmap, x, y, w, h, g_w, g_h);
}

fn vnc_get_display_update_interval() -> u32 {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return DISPLAY_UPDATE_INTERVAL_DEFAULT;
    }
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let locked_server = server.lock().unwrap();

    locked_server.update_interval
}

pub fn vnc_loop_update_display(x: i32, y: i32, width: i32, height: i32) {
    let func = Box::new(move || {
        vnc_display_update(x, y, width as i32, height as i32);
        vnc_loop_update_display(x, y, width, height);
    });

    if let Some(ctx) = EventLoop::get_ctx(None) {
        ctx.delay_call(
            func,
            vnc_get_display_update_interval() as u64 * MILLI_PER_SEC,
        );
    }
}

/// Get the width of image.
pub fn vnc_width(width: i32) -> i32 {
    cmp::min(
        MAX_WINDOW_WIDTH as i32,
        round_up(width as u64, DIRTY_PIXELS_NUM as u64) as i32,
    )
}

/// Get the height of image.
fn vnc_height(height: i32) -> i32 {
    cmp::min(MAX_WINDOW_HEIGHT as i32, height)
}

/// Update Client image
pub fn update_client_surface(server: &mut VncServer) {
    unref_pixman_image(server.server_image);
    server.server_image = ptr::null_mut();
    // Server image changes, clear the task queue.
    VNC_RECT_INFO.lock().unwrap().clear();
    if server.clients.is_empty() {
        return;
    }

    for client in server.clients.values_mut() {
        client.lock().unwrap().server_image = ptr::null_mut();
    }

    let g_width = get_image_width(server.guest_image);
    let g_height = get_image_height(server.guest_image);
    let width = vnc_width(g_width);
    let height = vnc_height(g_height);
    server.true_width = cmp::min(MAX_WINDOW_WIDTH as i32, g_width);
    server.server_image = unsafe {
        pixman_image_create_bits(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            width,
            height,
            ptr::null_mut(),
            0,
        )
    };
    for client in server.clients.values_mut() {
        client.lock().unwrap().server_image = server.server_image;
        client.lock().unwrap().width = width;
        client.lock().unwrap().height = height;
    }
    server.guest_dirty_bitmap.clear_all();
    set_area_dirty(
        &mut server.guest_dirty_bitmap,
        0,
        0,
        width,
        height,
        g_width,
        g_height,
    );
}

/// Check if the suface for VncClient is need update
fn check_surface(surface: &mut DisplaySurface) -> bool {
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let locked_server = server.lock().unwrap();
    if surface.image.is_null()
        || locked_server.server_image.is_null()
        || locked_server.guest_format != surface.format
        || get_image_width(locked_server.server_image) != get_image_width(surface.image)
        || get_image_height(locked_server.server_image) != get_image_height(surface.image)
    {
        return true;
    }

    false
}

/// Check if rectangle is in spec
fn check_rect(rect: &mut Rectangle, width: i32, height: i32) -> bool {
    if rect.x >= width {
        return false;
    }

    rect.w = cmp::min(width - rect.x, rect.w);
    if rect.w == 0 {
        return false;
    }

    if rect.y >= height {
        return false;
    }

    rect.h = cmp::min(height - rect.y, rect.h);
    if rect.h == 0 {
        return false;
    }

    true
}

/// Send updated pixel information to client
///
/// # Arguments
///
/// * `x` `y` `w` `h` - coordinate, width, height
/// * `buf` - send buffer
pub fn framebuffer_upadate(x: i32, y: i32, w: i32, h: i32, encoding: i32, buf: &mut Vec<u8>) {
    buf.append(&mut (x as u16).to_be_bytes().to_vec());
    buf.append(&mut (y as u16).to_be_bytes().to_vec());
    buf.append(&mut (w as u16).to_be_bytes().to_vec());
    buf.append(&mut (h as u16).to_be_bytes().to_vec());
    buf.append(&mut encoding.to_be_bytes().to_vec());
}

/// Convert the sent information to a format supported  
/// by the client depend on byte arrangement
///
/// # Arguments
///
/// * `ptr` = pointer to the data need to be convert
/// * `big_endian` - byte arrangement
/// * `pf` - pixelformat
/// * `buf` - send buffer
/// * `size` - total number of bytes need to convert
fn convert_pixel(ptr: *mut u32, big_endian: bool, pf: &PixelFormat, buf: &mut Vec<u8>, size: u32) {
    let num = size >> 2;
    for i in 0..num {
        let value = unsafe { *ptr.offset(i as isize) };
        let mut ret = [0u8; 4];
        let red = (((value >> 16) & 0xff) << pf.red.bits) >> 8;
        let green = (((value >> 8) & 0xff) << pf.green.bits) >> 8;
        let blue = ((value & 0xff) << pf.blue.bits) >> 8;
        let v = (red << pf.red.shift) | (green << pf.green.shift) | (blue << pf.blue.shift);
        match pf.pixel_bytes {
            1 => {
                ret[0] = v as u8;
            }
            2 => {
                if big_endian {
                    ret[0] = (v >> 8) as u8;
                    ret[1] = v as u8;
                } else {
                    ret[1] = (v >> 8) as u8;
                    ret[0] = v as u8;
                }
            }
            4 => {
                if big_endian {
                    ret = (v as u32).to_be_bytes();
                } else {
                    ret = (v as u32).to_le_bytes();
                }
            }
            _ => {
                if big_endian {
                    ret = (v as u32).to_be_bytes();
                } else {
                    ret = (v as u32).to_le_bytes();
                }
            }
        }
        buf.append(&mut ret[..pf.pixel_bytes as usize].to_vec());
    }
}

/// Send raw data directly without compression
///
/// # Arguments
///
/// * `image` = pointer to the data need to be send
/// * `rect` - dirty area of image
/// * `convert` - is need to be convert
/// * `big_endian` - send buffer
/// * `pixel_format` - pixelformat
/// * `buf` - send buffer
fn raw_send_framebuffer_update(
    image: *mut pixman_image_t,
    rect: &Rectangle,
    convert: bool,
    big_endian: bool,
    pixel_format: &PixelFormat,
    buf: &mut Vec<u8>,
) -> i32 {
    let mut data_ptr = get_image_data(image) as *mut u8;
    let stride = get_image_stride(image);
    data_ptr = (data_ptr as usize
        + (rect.y * stride) as usize
        + rect.x as usize * bytes_per_pixel()) as *mut u8;

    let copy_bytes = rect.w as usize * bytes_per_pixel();

    for _i in 0..rect.h {
        if !convert {
            let mut con = vec![0; copy_bytes];
            unsafe {
                ptr::copy(data_ptr, con.as_mut_ptr(), copy_bytes);
            }
            buf.append(&mut con);
        } else {
            convert_pixel(
                data_ptr as *mut u32,
                big_endian,
                pixel_format,
                buf,
                copy_bytes as u32,
            );
        }

        data_ptr = (data_ptr as usize + stride as usize) as *mut u8;
    }

    1
}

/// Send data according to compression algorithm
///
/// # Arguments
///
/// * `image` = pointer to the data need to be send
/// * `rect` - dirty area of image
/// * `convert` - is need to be convert
/// * `big_endian` - send buffer
/// * `pixel_format` - pixelformat
/// * `buf` - send buffer
fn send_framebuffer_update(
    image: *mut pixman_image_t,
    encoding: i32,
    rect: &Rectangle,
    convert: bool,
    big_endian: bool,
    pixel_format: &PixelFormat,
    buf: &mut Vec<u8>,
) -> i32 {
    framebuffer_upadate(rect.x, rect.y, rect.w, rect.h, encoding, buf);
    /*
    match encoding {
        ENCODING_ZLIB => { /* ing... */ }
        _ => {
            VncServer::framebuffer_upadate(rect, encoding, buf);
            n = VncServer::raw_send_framebuffer_update(image, rect, buf);
        }
    }
    */
    raw_send_framebuffer_update(image, rect, convert, big_endian, pixel_format, buf)
}

/// Initialize a default image
/// Default: width is 640, height is 480, stride is 640 * 4
fn get_client_image() -> *mut pixman_image_t {
    unsafe {
        pixman_image_create_bits(
            pixman_format_code_t::PIXMAN_x8r8g8b8,
            640,
            480,
            ptr::null_mut(),
            640 * 4,
        )
    }
}

/// Update guest_image
/// Send a resize command to the client based on whether the image size has changed
pub fn vnc_display_switch(surface: &mut DisplaySurface) {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return;
    }
    let need_resize = check_surface(surface);
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let mut locked_server = server.lock().unwrap();
    unref_pixman_image(locked_server.guest_image);

    // Vnc_pixman_image_ref
    locked_server.guest_image = unsafe { pixman_image_ref(surface.image) };
    locked_server.guest_format = surface.format;

    let guest_width: i32 = get_image_width(locked_server.guest_image);
    let guest_height: i32 = get_image_height(locked_server.guest_image);
    if !need_resize {
        set_area_dirty(
            &mut locked_server.guest_dirty_bitmap,
            0,
            0,
            guest_width,
            guest_height,
            guest_width,
            guest_height,
        );
        return;
    }
    update_client_surface(&mut locked_server);
    // Cursor.
    let mut cursor: DisplayMouse = DisplayMouse::default();
    let mut mask: Vec<u8> = Vec::new();
    if let Some(c) = &locked_server.cursor {
        cursor = c.clone();
    }
    if let Some(m) = &locked_server.mask {
        mask = m.clone();
    }

    for client in locked_server.clients.values_mut() {
        let width = vnc_width(guest_width);
        let height = vnc_height(guest_height);
        let mut locked_client = client.lock().unwrap();
        // Set Color depth.
        locked_client.set_color_depth();
        // Desktop_resize.
        locked_client.desktop_resize();
        // Cursor define.
        if !cursor.data.is_empty() {
            display_cursor_define(&mut locked_client, &mut cursor, &mut mask);
        }
        locked_client.dirty_bitmap.clear_all();
        set_area_dirty(
            &mut locked_client.dirty_bitmap,
            0,
            0,
            width,
            height,
            guest_width,
            guest_height,
        );
    }
}

pub fn vnc_display_cursor(cursor: &mut DisplayMouse) {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return;
    }
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let width = cursor.width as u64;
    let height = cursor.height as u64;
    let bpl = round_up_div(width as u64, BIT_PER_BYTE as u64);
    // Set the bit for mask.
    let bit_mask: u8 = 0x80;

    let mut mask: Vec<u8> = vec![0; (bpl * height) as usize];
    let first_bit = if cfg!(target_endian = "big") {
        0_usize
    } else {
        (bytes_per_pixel() - 1) as usize
    };

    for j in 0..height {
        let mut bit = bit_mask;
        for i in 0..width {
            let idx = ((i + j * width) as usize) * bytes_per_pixel() + first_bit;
            if let Some(n) = cursor.data.get(idx as usize) {
                if *n == 0xff {
                    mask[(j * bpl + i / BIT_PER_BYTE as u64) as usize] |= bit;
                }
            }
            bit >>= 1;
            if bit == 0 {
                bit = bit_mask;
            }
        }
    }

    server.lock().unwrap().cursor = Some(cursor.clone());
    server.lock().unwrap().mask = Some(mask.clone());

    // Send the framebuff for each client.
    for client in server.lock().unwrap().clients.values_mut() {
        display_cursor_define(&mut client.lock().unwrap(), cursor, &mut mask);
    }
}

/// Send framebuf of mouse to the client.
pub fn display_cursor_define(
    client: &mut VncClient,
    cursor: &mut DisplayMouse,
    mask: &mut Vec<u8>,
) {
    if cursor.data.len() != ((cursor.width * cursor.height) as usize) * bytes_per_pixel() {
        return;
    }
    let mut buf = Vec::new();
    if client.has_feature(VncFeatures::VncFeatureAlphaCursor) {
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // padding
        buf.append(&mut (1_u16).to_be_bytes().to_vec()); // number of rects

        framebuffer_upadate(
            cursor.hot_x as i32,
            cursor.hot_y as i32,
            cursor.width as i32,
            cursor.height as i32,
            ENCODING_ALPHA_CURSOR as i32,
            &mut buf,
        );
        buf.append(&mut (ENCODING_RAW as u32).to_be_bytes().to_vec());
        buf.append(&mut cursor.data);
        client.write_msg(&buf);
        return;
    }

    if client.has_feature(VncFeatures::VncFeatureRichCursor) {
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // padding
        buf.append(&mut (1_u16).to_be_bytes().to_vec()); // number of rects

        framebuffer_upadate(
            cursor.hot_x as i32,
            cursor.hot_y as i32,
            cursor.width as i32,
            cursor.height as i32,
            ENCODING_RICH_CURSOR as i32,
            &mut buf,
        );
        let big_endian = client.big_endian;
        let pixel_format = &client.pixel_format;
        let size = cursor.width * cursor.height * pixel_format.pixel_bytes as u32;
        let ptr = cursor.data.as_ptr() as *mut u32;
        convert_pixel(ptr, big_endian, pixel_format, &mut buf, size);
        buf.append(mask);
        client.write_msg(&buf);
    }
}

pub static VNC_SERVERS: Lazy<Mutex<Vec<Arc<Mutex<VncServer>>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));
pub static VNC_RECT_INFO: Lazy<Arc<Mutex<Vec<RectInfo>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));
pub static REFRESH_EVT: Lazy<Arc<Mutex<EventFd>>> =
    Lazy::new(|| Arc::new(Mutex::new(EventFd::new(libc::EFD_NONBLOCK).unwrap())));
