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

use crate::{
    client::{
        desktop_resize, display_cursor_define, get_rects, set_color_depth, vnc_flush,
        vnc_update_output_throttle, vnc_write, DisplayMode, RectInfo, Rectangle, ServerMsg,
        ENCODING_HEXTILE, ENCODING_RAW,
    },
    console::{
        graphic_hardware_update, register_display, DisplayChangeListener,
        DisplayChangeListenerOperations, DisplayMouse, DisplaySurface,
        DISPLAY_UPDATE_INTERVAL_DEFAULT, DISPLAY_UPDATE_INTERVAL_INC, DISPLAY_UPDATE_INTERVAL_MAX,
    },
    data::keycode::KEYSYM2KEYCODE,
    encoding::enc_hextile::hextile_send_framebuffer_update,
    input::KeyBoardState,
    pixman::{
        bytes_per_pixel, create_pixman_image, get_image_data, get_image_height, get_image_stride,
        get_image_width, ref_pixman_image, unref_pixman_image,
    },
    round_up, round_up_div,
    server::{make_server_config, VncConnHandler, VncServer, VncSurface},
    VncError,
};
use anyhow::{anyhow, Result};
use core::time;
use log::error;
use machine_manager::{
    config::{ObjectConfig, VncConfig},
    event_loop::EventLoop,
    qmp::qmp_schema::{VncClientInfo, VncInfo},
};
use once_cell::sync::Lazy;
use std::{
    cell::RefCell,
    cmp,
    collections::HashMap,
    net::TcpListener,
    ptr,
    rc::Rc,
    sync::{Arc, Mutex},
    thread,
};
use util::{
    bitmap::Bitmap,
    loop_context::EventNotifierHelper,
    pixman::{pixman_format_code_t, pixman_image_t},
};

/// The number of dirty pixels represented bt one bit in dirty bitmap.
pub const DIRTY_PIXELS_NUM: u16 = 16;
/// The default max window width.
pub const MAX_WINDOW_WIDTH: u16 = round_up(2560, DIRTY_PIXELS_NUM as u64) as u16;
/// The default max window height.
pub const MAX_WINDOW_HEIGHT: u16 = 2048;
pub const DIRTY_WIDTH_BITS: u16 = MAX_WINDOW_WIDTH / DIRTY_PIXELS_NUM;
pub const VNC_BITMAP_WIDTH: u64 =
    round_up_div(DIRTY_WIDTH_BITS as u64, u64::BITS as u64) * u64::BITS as u64;
pub const MAX_IMAGE_SIZE: i32 = 65535;

/// Output throttle scale.
pub const OUTPUT_THROTTLE_SCALE: i32 = 5;
/// Min size of output buffer.
pub const MIN_OUTPUT_LIMIT: i32 = 1024 * 1024 * OUTPUT_THROTTLE_SCALE;
const DEFAULT_REFRESH_INTERVAL: u64 = 30;
pub const BIT_PER_BYTE: u32 = 8;

#[derive(Default)]
pub struct VncInterface {}
impl DisplayChangeListenerOperations for VncInterface {
    /// Update guest_image
    /// Send a resize command to the client based on whether the image size has changed
    fn dpy_switch(&self, surface: &DisplaySurface) {
        if VNC_SERVERS.lock().unwrap().is_empty() {
            return;
        }
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        let mut locked_vnc_surface = server.vnc_surface.lock().unwrap();
        let need_resize = check_surface(&mut locked_vnc_surface, surface);
        unref_pixman_image(locked_vnc_surface.guest_image);

        // Vnc_pixman_image_ref
        locked_vnc_surface.guest_image = ref_pixman_image(surface.image);
        locked_vnc_surface.guest_format = surface.format;

        let guest_width: i32 = get_image_width(locked_vnc_surface.guest_image);
        let guest_height: i32 = get_image_height(locked_vnc_surface.guest_image);
        if !need_resize {
            set_area_dirty(
                &mut locked_vnc_surface.guest_dirty_bitmap,
                0,
                0,
                guest_width,
                guest_height,
                guest_width,
                guest_height,
            );
            return;
        }
        drop(locked_vnc_surface);
        update_server_surface(&server);

        let mut locked_handlers = server.client_handlers.lock().unwrap();
        for client in locked_handlers.values_mut() {
            let width = vnc_width(guest_width);
            let height = vnc_height(guest_height);
            let mut buf: Vec<u8> = Vec::new();
            // Set Color depth.
            set_color_depth(client, &mut buf);
            // Desktop_resize.
            desktop_resize(client, &server, &mut buf);
            // Cursor define.
            display_cursor_define(client, &server, &mut buf);
            vnc_write(client, buf);
            vnc_flush(client);
            client.dirty_bitmap.lock().unwrap().clear_all();
            set_area_dirty(
                &mut client.dirty_bitmap.lock().unwrap(),
                0,
                0,
                width,
                height,
                guest_width,
                guest_height,
            );
            vnc_update_output_throttle(client);
        }
    }

    /// Refresh server_image to guest_image.
    fn dpy_refresh(&self, dcl: &Arc<Mutex<DisplayChangeListener>>) {
        if VNC_SERVERS.lock().unwrap().is_empty() {
            return;
        }
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        if server.client_handlers.lock().unwrap().is_empty() {
            return;
        }
        let con_id = dcl.lock().unwrap().con_id;
        graphic_hardware_update(con_id);

        // Update refresh interval.
        let mut update_interval = dcl.lock().unwrap().update_interval;
        let dirty_num = server.vnc_surface.lock().unwrap().update_server_image();
        if dirty_num != 0 {
            update_interval /= 2;
            if update_interval < DISPLAY_UPDATE_INTERVAL_DEFAULT {
                update_interval = DISPLAY_UPDATE_INTERVAL_DEFAULT
            }
        } else {
            update_interval += DISPLAY_UPDATE_INTERVAL_INC;
            if update_interval > DISPLAY_UPDATE_INTERVAL_MAX {
                update_interval = DISPLAY_UPDATE_INTERVAL_MAX;
            }
        }
        dcl.lock().unwrap().update_interval = update_interval;

        let mut locked_handlers = server.client_handlers.lock().unwrap();
        for client in locked_handlers.values_mut() {
            get_rects(client, dirty_num);
        }
    }

    fn dpy_image_update(&self, x: i32, y: i32, w: i32, h: i32) {
        if VNC_SERVERS.lock().unwrap().is_empty() {
            return;
        }
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        let mut locked_vnc_surface = server.vnc_surface.lock().unwrap();
        let g_w = get_image_width(locked_vnc_surface.guest_image);
        let g_h = get_image_height(locked_vnc_surface.guest_image);
        set_area_dirty(
            &mut locked_vnc_surface.guest_dirty_bitmap,
            x,
            y,
            w,
            h,
            g_w,
            g_h,
        );
        drop(locked_vnc_surface);
    }

    fn dpy_cursor_update(&self, cursor: &mut DisplayMouse) {
        if VNC_SERVERS.lock().unwrap().is_empty() {
            return;
        }
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        let width = cursor.width as u64;
        let height = cursor.height as u64;
        let bpl = round_up_div(width, BIT_PER_BYTE as u64);
        // Set the bit for mask.
        let bit_mask: u8 = 0x80;

        let mut mask: Vec<u8> = vec![0; (bpl * height) as usize];
        let first_bit = if cfg!(target_endian = "big") {
            0_usize
        } else {
            bytes_per_pixel() - 1
        };

        for j in 0..height {
            let mut bit = bit_mask;
            for i in 0..width {
                let idx = ((i + j * width) as usize) * bytes_per_pixel() + first_bit;
                if let Some(n) = cursor.data.get(idx) {
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

        server.vnc_cursor.lock().unwrap().cursor = Some(cursor.clone());
        server.vnc_cursor.lock().unwrap().mask = Some(mask.clone());

        let mut locked_handler = server.client_handlers.lock().unwrap();
        // Send the framebuff for each client.
        for client in locked_handler.values_mut() {
            let mut buf: Vec<u8> = Vec::new();
            display_cursor_define(client, &server, &mut buf);
            vnc_write(client, buf);
            vnc_flush(client);
        }
    }
}

/// Initizlization function of vnc
///
/// # Arguments
///
/// * `VncConfig` `object`- vnc related parameters
pub fn vnc_init(vnc: &Option<VncConfig>, object: &ObjectConfig) -> Result<()> {
    let vnc_cfg = match vnc {
        Some(cfg) => cfg,
        None => return Ok(()),
    };

    let addr = format!("{}:{}", vnc_cfg.ip, vnc_cfg.port);
    let listener: TcpListener = match TcpListener::bind(addr.as_str()) {
        Ok(l) => l,
        Err(e) => {
            let msg = format!("Bind {} failed {}", addr, e);
            error!("{}", e);
            return Err(anyhow!(VncError::TcpBindFailed(msg)));
        }
    };

    listener
        .set_nonblocking(true)
        .expect("Set noblocking for vnc socket failed");

    let mut keysym2keycode: HashMap<u16, u16> = HashMap::new();

    let mut max_keycode: u16 = 0;
    // Mapping ASCII to keycode.
    for &(k, v) in KEYSYM2KEYCODE.iter() {
        max_keycode = cmp::max(max_keycode, v);
        keysym2keycode.insert(k, v);
    }
    // Record keyboard state.
    let keyboard_state: Rc<RefCell<KeyBoardState>> =
        Rc::new(RefCell::new(KeyBoardState::new(max_keycode as usize)));

    let vnc_opts = Arc::new(VncInterface::default());
    let dcl = Arc::new(Mutex::new(DisplayChangeListener::new(None, vnc_opts)));

    let server = Arc::new(VncServer::new(
        get_client_image(),
        keyboard_state,
        keysym2keycode,
        Some(Arc::downgrade(&dcl)),
    ));

    // Parameter configuation for VncServeer.
    make_server_config(&server, vnc_cfg, object)?;

    // Add an VncServer.
    add_vnc_server(server.clone());

    // Register in display console.
    register_display(&dcl)?;

    // Register the event to listen for client's connection.
    let vnc_io = Arc::new(Mutex::new(VncConnHandler::new(listener, server)));

    // Vnc_thread: a thread to send the framebuffer
    start_vnc_thread()?;

    EventLoop::update_event(EventNotifierHelper::internal_notifiers(vnc_io), None)?;
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
            buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
            buf.append(&mut (0_u8).to_be_bytes().to_vec());
            buf.append(&mut [0_u8; 2].to_vec());

            for rect in rect_info.rects.iter_mut() {
                let locked_surface = server.vnc_surface.lock().unwrap();
                let dpm = rect_info.client.client_dpm.lock().unwrap().clone();
                let width = dpm.client_width;
                let height = dpm.client_height;
                if check_rect(rect, width, height) {
                    let n =
                        send_framebuffer_update(locked_surface.server_image, rect, &dpm, &mut buf);
                    if n >= 0 {
                        num_rects += n;
                    }
                }
            }
            buf[2] = (num_rects >> 8) as u8;
            buf[3] = num_rects as u8;

            let client = rect_info.client;
            vnc_write(&client, buf);
            vnc_flush(&client);
        })?;
    Ok(())
}

/// Add a vnc server during initialization.
fn add_vnc_server(server: Arc<VncServer>) {
    VNC_SERVERS.lock().unwrap().push(server);
}

/// Qmp: return the information about current VNC server.
pub fn qmp_query_vnc() -> Option<VncInfo> {
    let mut vnc_info = VncInfo::default();
    if VNC_SERVERS.lock().unwrap().is_empty() {
        vnc_info.enabled = false;
        return Some(vnc_info);
    }
    vnc_info.enabled = true;
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    vnc_info.family = "ipv4".to_string();

    let mut locked_handler = server.client_handlers.lock().unwrap();
    for client in locked_handler.values_mut() {
        let mut client_info = VncClientInfo {
            host: client.addr.clone(),
            ..Default::default()
        };
        client_info.family = "ipv4".to_string();
        vnc_info.clients.push(client_info);
    }

    Some(vnc_info)
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
        let pos = (y * VNC_BITMAP_WIDTH as i32 + x / DIRTY_PIXELS_NUM as i32) as usize;
        let len = round_up_div(w as u64, DIRTY_PIXELS_NUM as u64) as usize;
        if let Err(e) = dirty.set_range(pos, len) {
            error!("set bitmap error: {:?}", e);
            return;
        }
        y += 1;
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

/// Update server image
pub fn update_server_surface(server: &Arc<VncServer>) {
    let mut locked_vnc_surface = server.vnc_surface.lock().unwrap();
    unref_pixman_image(locked_vnc_surface.server_image);
    locked_vnc_surface.server_image = ptr::null_mut();
    // Server image changes, clear the task queue.
    VNC_RECT_INFO.lock().unwrap().clear();
    if server.client_handlers.lock().unwrap().is_empty() {
        return;
    }

    let g_width = get_image_width(locked_vnc_surface.guest_image);
    let g_height = get_image_height(locked_vnc_surface.guest_image);
    let width = vnc_width(g_width);
    let height = vnc_height(g_height);
    locked_vnc_surface.server_image = create_pixman_image(
        pixman_format_code_t::PIXMAN_x8r8g8b8,
        width,
        height,
        ptr::null_mut(),
        0,
    );

    locked_vnc_surface.guest_dirty_bitmap.clear_all();
    set_area_dirty(
        &mut locked_vnc_surface.guest_dirty_bitmap,
        0,
        0,
        width,
        height,
        g_width,
        g_height,
    );
}

/// Check if the suface for VncClient is need update
fn check_surface(locked_vnc_surface: &mut VncSurface, surface: &DisplaySurface) -> bool {
    let guest_width = get_image_width(surface.image);
    let guest_height = get_image_height(surface.image);
    let server_width = get_image_width(locked_vnc_surface.server_image);
    let server_height = get_image_height(locked_vnc_surface.server_image);
    if !(0..=MAX_IMAGE_SIZE).contains(&guest_width) || !(0..=MAX_IMAGE_SIZE).contains(&guest_height)
    {
        return false;
    }

    if surface.image.is_null()
        || locked_vnc_surface.server_image.is_null()
        || locked_vnc_surface.guest_format != surface.format
        || guest_width != server_width
        || guest_height != server_height
    {
        return true;
    }

    false
}

/// Check if rectangle is in spec
fn check_rect(rect: &mut Rectangle, width: i32, height: i32) -> bool {
    if rect.x >= width || rect.y >= height {
        return false;
    }

    rect.w = cmp::min(width - rect.x, rect.w);
    rect.h = cmp::min(height - rect.y, rect.h);
    if rect.w <= 0 || rect.h <= 0 {
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

/// Write pixel to client.
///
/// # Arguments
///
/// * `data_ptr` - pointer to the data need.
/// * `copy_bytes` - total pixel to write.
/// * `client_dpm` - Output mod of client display.
/// * `buf` - send buffer.
pub fn write_pixel(
    data_ptr: *mut u8,
    copy_bytes: usize,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
) {
    if !client_dpm.convert {
        let mut con = vec![0; copy_bytes];
        // SAFETY: it can be ensure the raw pointer will not exceed the range.
        unsafe {
            ptr::copy(data_ptr as *mut u8, con.as_mut_ptr(), copy_bytes);
        }
        buf.append(&mut con);
    } else if client_dpm.convert && bytes_per_pixel() == 4 {
        let num = copy_bytes >> 2;
        let ptr = data_ptr as *mut u32;
        for i in 0..num {
            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            let color = unsafe { *ptr.add(i) };
            convert_pixel(client_dpm, buf, color);
        }
    }
}

/// Convert the sent information to a format supported  
/// by the client depend on byte arrangement
///
/// # Arguments
///
/// * `client_dpm` - Output mod of client display.
/// * `buf` - send buffer.
/// * `color` - the pixel value need to be convert.
pub fn convert_pixel(client_dpm: &DisplayMode, buf: &mut Vec<u8>, color: u32) {
    let mut ret = [0u8; 4];
    let r = ((color & 0x00ff0000) >> 16) << client_dpm.pf.red.bits >> 8;
    let g = ((color & 0x0000ff00) >> 8) << client_dpm.pf.green.bits >> 8;
    let b = (color & 0x000000ff) << client_dpm.pf.blue.bits >> 8;
    let v = (r << client_dpm.pf.red.shift)
        | (g << client_dpm.pf.green.shift)
        | (b << client_dpm.pf.blue.shift);
    match client_dpm.pf.pixel_bytes {
        1 => {
            ret[0] = v as u8;
        }
        2 => {
            if client_dpm.client_be {
                ret[0] = (v >> 8) as u8;
                ret[1] = v as u8;
            } else {
                ret[1] = (v >> 8) as u8;
                ret[0] = v as u8;
            }
        }
        4 => {
            if client_dpm.client_be {
                ret = v.to_be_bytes();
            } else {
                ret = v.to_le_bytes();
            }
        }
        _ => {
            if client_dpm.client_be {
                ret = v.to_be_bytes();
            } else {
                ret = v.to_le_bytes();
            }
        }
    }
    buf.append(&mut ret[..client_dpm.pf.pixel_bytes as usize].to_vec());
}

/// Send raw data directly without compression
///
/// # Arguments
///
/// * `image` - pointer to the data need to be send.
/// * `rect` - dirty area of image.
/// * `client_dpm` - Output mod information of client display.
/// * `buf` - send buffer.
pub fn raw_send_framebuffer_update(
    image: *mut pixman_image_t,
    rect: &Rectangle,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
) -> i32 {
    let mut data_ptr = get_image_data(image) as *mut u8;
    let stride = get_image_stride(image);
    data_ptr = (data_ptr as usize
        + (rect.y * stride) as usize
        + rect.x as usize * bytes_per_pixel()) as *mut u8;

    let copy_bytes = rect.w as usize * bytes_per_pixel();

    for _i in 0..rect.h {
        write_pixel(data_ptr, copy_bytes, client_dpm, buf);
        data_ptr = (data_ptr as usize + stride as usize) as *mut u8;
    }

    1
}

/// Send data according to compression algorithm
///
/// # Arguments
///
/// * `image` = pointer to the data need to be send.
/// * `rect` - dirty area of image.
/// * `client_dpm` - Output mod information of client display.
/// * `buf` - send buffer.
fn send_framebuffer_update(
    image: *mut pixman_image_t,
    rect: &Rectangle,
    client_dpm: &DisplayMode,
    buf: &mut Vec<u8>,
) -> i32 {
    match client_dpm.enc {
        ENCODING_HEXTILE => {
            framebuffer_upadate(rect.x, rect.y, rect.w, rect.h, ENCODING_HEXTILE, buf);
            hextile_send_framebuffer_update(image, rect, client_dpm, buf)
        }
        _ => {
            framebuffer_upadate(rect.x, rect.y, rect.w, rect.h, ENCODING_RAW, buf);
            raw_send_framebuffer_update(image, rect, client_dpm, buf)
        }
    }
}

/// Initialize a default image
/// Default: width is 640, height is 480, stride is 640 * 4
fn get_client_image() -> *mut pixman_image_t {
    create_pixman_image(
        pixman_format_code_t::PIXMAN_x8r8g8b8,
        640,
        480,
        ptr::null_mut(),
        640 * 4,
    )
}

pub static VNC_SERVERS: Lazy<Mutex<Vec<Arc<VncServer>>>> = Lazy::new(|| Mutex::new(Vec::new()));
pub static VNC_RECT_INFO: Lazy<Arc<Mutex<Vec<RectInfo>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));
