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

use super::errors::{ErrorKind, Result};
use machine_manager::{
    config::{ObjConfig, VncConfig},
    event_loop::EventLoop,
};
use once_cell::sync::Lazy;
use std::{
    cmp,
    collections::HashMap,
    net::TcpListener,
    ptr,
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::EventNotifierHelper,
    pixman::{
        pixman_format_code_t, pixman_image_create_bits, pixman_image_ref, pixman_image_t,
        pixman_image_unref,
    },
};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    bytes_per_pixel, get_image_data, get_image_height, get_image_stride, get_image_width, round_up,
    round_up_div, PixelFormat, VncClient, VncFeatures, VncServer, ENCODING_ALPHA_CURSOR,
    ENCODING_RAW, ENCODING_RICH_CURSOR,
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

const DEFAULT_REFRESH_INTERVAL: u64 = 30;
const BIT_PER_BYTE: u32 = 8;

pub fn vnc_init(vnc_cfg: &VncConfig, object: &HashMap<String, ObjConfig>) -> Result<()> {
    let addr = format!("{}:{}", vnc_cfg.ip, vnc_cfg.port);
    let listener: TcpListener;
    match TcpListener::bind(&addr.as_str()) {
        Ok(l) => listener = l,
        Err(e) => {
            let msg = format!("Bind {} failed {}", addr, e);
            error!("{}", e);
            return Err(ErrorKind::TcpBindFailed(msg).into());
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

    EventLoop::update_event(
        EventNotifierHelper::internal_notifiers(VNC_SERVERS.lock().unwrap()[0].clone()),
        None,
    )?;

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
        for i in 0..w / DIRTY_PIXELS_NUM as i32 {
            dirty.set((pos + i) as usize).unwrap();
        }
        y += 1;
    }
    REFRESH_EVT.lock().unwrap().write(1).unwrap();
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

/// Decrease the reference of image
/// # Arguments
///
/// * `image` - the pointer to image in pixman
fn vnc_pixman_image_unref(image: *mut pixman_image_t) {
    if image.is_null() {
        return;
    }
    unsafe { pixman_image_unref(image) };
}

/// Update Client image
pub fn update_client_surface(server: &mut VncServer) {
    vnc_pixman_image_unref(server.server_image);
    server.server_image = ptr::null_mut();

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
    }
    server.guest_dirtymap.clear_all();
    set_area_dirty(
        &mut server.guest_dirtymap,
        0,
        0,
        width,
        height,
        g_width,
        g_height,
    );
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

pub static VNC_SERVERS: Lazy<Mutex<Vec<Arc<Mutex<VncServer>>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));
pub static REFRESH_EVT: Lazy<Arc<Mutex<EventFd>>> =
    Lazy::new(|| Arc::new(Mutex::new(EventFd::new(libc::EFD_NONBLOCK).unwrap())));
