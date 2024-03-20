// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
//
// Stratovirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

pub mod channel;
pub mod msg;
pub mod msg_handle;

use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};

use anyhow::{anyhow, Result};
use log::{error, info};
use once_cell::sync::OnceCell;
use vmm_sys_util::epoll::EventSet;

use crate::{
    console::{
        graphic_hardware_update, register_display, DisplayChangeListener,
        DisplayChangeListenerOperations, DisplayMouse, DisplaySurface,
        DISPLAY_UPDATE_INTERVAL_DEFAULT,
    },
    pixman::{bytes_per_pixel, get_image_data, ref_pixman_image, unref_pixman_image},
};
use address_space::FileBackend;
use channel::*;
use machine_manager::{
    config::{DisplayConfig, VIRTIO_GPU_ENABLE_BAR0_SIZE},
    event_loop::register_event_helper,
    temp_cleaner::TempCleaner,
};
use msg_handle::*;
use util::{
    loop_context::{
        gen_delete_notifiers, EventNotifier, EventNotifierHelper, NotifierCallback,
        NotifierOperation,
    },
    pixman::{pixman_format_code_t, pixman_image_t},
    unix::do_mmap,
};

#[derive(Debug, Clone)]
struct GuestSurface {
    /// Image from display device.
    guest_image: *mut pixman_image_t,
    /// Image format of pixman.
    guest_format: pixman_format_code_t,
    stride: i32,
    width: i32,
    height: i32,
}

// SAFETY: Send and Sync is not auto-implemented for `*mut pixman_image_t` type.
// implementing them is safe because GuestSurface will be protected by
// RwLock
unsafe impl Sync for GuestSurface {}
// SAFETY: Same as 'Sync for GuestSurface'
unsafe impl Send for GuestSurface {}

impl GuestSurface {
    fn new() -> GuestSurface {
        GuestSurface {
            guest_image: ptr::null_mut::<pixman_image_t>(),
            guest_format: pixman_format_code_t::PIXMAN_x8r8g8b8,
            stride: 0,
            width: 0,
            height: 0,
        }
    }
}

const CURSOR_SIZE: u64 = 16 * 1024;

pub struct OhUiServer {
    // framebuffer passthru to the guest
    passthru: OnceCell<bool>,
    // guest surface for framebuffer
    surface: RwLock<GuestSurface>,
    // transfer channel via unix sock
    channel: Arc<OhUiChannel>,
    // message handler
    msg_handler: OhUiMsgHandler,
    // connected or not
    connected: AtomicBool,
    // iothread processing unix socket
    iothread: OnceCell<Option<String>>,
    // address of cursor buffer
    cursorbuffer: u64,
    //address of framebuffer
    framebuffer: u64,
    // framebuffer file backend
    fb_file: Option<FileBackend>,
    // tokenID of OHUI client
    pub token_id: Arc<RwLock<u64>>,
}

impl OhUiServer {
    fn init_channel(path: &String) -> Result<Arc<OhUiChannel>> {
        let file_path = Path::new(path.as_str()).join("ohui.sock");
        let sock_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_channel: Failed to get str from {}", path))?;
        TempCleaner::add_path(sock_file.to_string());
        Ok(Arc::new(OhUiChannel::new(sock_file)))
    }

    fn init_fb_file(path: &String) -> Result<(Option<FileBackend>, u64)> {
        let file_path = Path::new(path.as_str()).join("ohui-fb");
        let fb_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_fb_file: Failed to get str from {}", path))?;
        let fb_backend = FileBackend::new_mem(fb_file, VIRTIO_GPU_ENABLE_BAR0_SIZE)?;
        TempCleaner::add_path(fb_file.to_string());

        let host_addr = do_mmap(
            &Some(fb_backend.file.as_ref()),
            VIRTIO_GPU_ENABLE_BAR0_SIZE,
            0,
            false,
            true,
            false,
        )?;

        Ok((Some(fb_backend), host_addr))
    }

    fn init_cursor_file(path: &String) -> Result<u64> {
        let file_path = Path::new(path.as_str()).join("ohui-cursor");
        let cursor_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_cursor_file: Failed to get str from {}", path))?;
        let cursor_backend = FileBackend::new_mem(cursor_file, CURSOR_SIZE)?;
        TempCleaner::add_path(cursor_file.to_string());

        let cursorbuffer = do_mmap(
            &Some(cursor_backend.file.as_ref()),
            CURSOR_SIZE,
            0,
            false,
            true,
            false,
        )?;

        Ok(cursorbuffer)
    }

    pub fn new(path: String) -> Result<Self> {
        let channel = Self::init_channel(&path)?;
        let (fb_file, framebuffer) = Self::init_fb_file(&path)?;
        let cursorbuffer = Self::init_cursor_file(&path)?;

        Ok(OhUiServer {
            passthru: OnceCell::new(),
            surface: RwLock::new(GuestSurface::new()),
            channel: channel.clone(),
            msg_handler: OhUiMsgHandler::new(channel),
            connected: AtomicBool::new(false),
            iothread: OnceCell::new(),
            cursorbuffer,
            framebuffer,
            fb_file,
            token_id: Arc::new(RwLock::new(0)),
        })
    }

    pub fn set_passthru(&self, passthru: bool) {
        self.passthru
            .set(passthru)
            .unwrap_or_else(|_| error!("Failed to initialize passthru of OHUI Server."));
    }

    #[inline(always)]
    fn get_channel(&self) -> &OhUiChannel {
        self.channel.as_ref()
    }

    #[inline(always)]
    pub fn get_ohui_fb(&self) -> Option<FileBackend> {
        self.fb_file.clone()
    }

    fn handle_recv(&self) -> Result<()> {
        if !self.connected() {
            return Err(anyhow!("connection has not establish".to_string()));
        }
        self.msg_handler.handle_msg(self.token_id.clone())
    }

    fn raw_update_dirty_area(
        &self,
        surface_data: *mut u32,
        stride: i32,
        pos: (i32, i32),
        size: (i32, i32),
    ) {
        let (x, y) = pos;
        let (w, h) = size;

        if self.framebuffer == 0 || *self.passthru.get_or_init(|| false) {
            return;
        }

        let offset = (x * bytes_per_pixel() as i32 + y * stride) as u64;
        let mut src_ptr = surface_data as u64 + offset;
        let mut dst_ptr = self.framebuffer + offset;

        for _ in 0..h {
            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            unsafe {
                ptr::copy_nonoverlapping(
                    src_ptr as *const u8,
                    dst_ptr as *mut u8,
                    w as usize * bytes_per_pixel(),
                );
            }
            src_ptr += stride as u64;
            dst_ptr += stride as u64;
        }
    }

    fn send_window_info(&self) {
        let locked_surface = self.surface.read().unwrap();

        if locked_surface.guest_image.is_null() {
            return;
        }

        self.msg_handler
            .send_windowinfo(locked_surface.width as u32, locked_surface.height as u32);
    }

    #[inline(always)]
    fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn set_connect(&self, conn: bool) {
        self.connected.store(conn, Ordering::Relaxed);
    }

    fn set_iothread(&self, iothread: Option<String>) {
        if self.iothread.set(iothread).is_err() {
            error!("Failed to initialize iothread of OHUI Server.");
        }
    }
}

impl DisplayChangeListenerOperations for OhUiServer {
    fn dpy_switch(&self, surface: &DisplaySurface) -> Result<()> {
        let mut locked_surface = self.surface.write().unwrap();

        unref_pixman_image(locked_surface.guest_image);

        locked_surface.guest_image = ref_pixman_image(surface.image);
        locked_surface.guest_format = surface.format;
        locked_surface.stride = surface.stride();
        locked_surface.width = surface.width();
        locked_surface.height = surface.height();
        drop(locked_surface);
        let locked_surface = self.surface.read().unwrap();
        self.raw_update_dirty_area(
            get_image_data(locked_surface.guest_image),
            locked_surface.stride,
            (0, 0),
            (locked_surface.width, locked_surface.height),
        );

        if !self.connected() {
            return Ok(());
        }
        self.msg_handler
            .send_windowinfo(locked_surface.width as u32, locked_surface.height as u32);
        Ok(())
    }

    fn dpy_refresh(&self, dcl: &Arc<Mutex<DisplayChangeListener>>) -> Result<()> {
        let con_id = dcl.lock().unwrap().con_id;
        graphic_hardware_update(con_id);
        Ok(())
    }

    fn dpy_image_update(&self, x: i32, y: i32, w: i32, h: i32) -> Result<()> {
        if !self.connected() {
            return Ok(());
        }

        let locked_surface = self.surface.read().unwrap();
        if locked_surface.guest_image.is_null() {
            return Ok(());
        }

        self.raw_update_dirty_area(
            get_image_data(locked_surface.guest_image),
            locked_surface.stride,
            (x, y),
            (w, h),
        );

        self.msg_handler
            .handle_dirty_area(x as u32, y as u32, w as u32, h as u32);
        Ok(())
    }

    fn dpy_cursor_update(&self, cursor: &DisplayMouse) -> Result<()> {
        if self.cursorbuffer == 0 {
            error!("Hwcursor not set.");
            // No need to return Err for this situation is not fatal
            return Ok(());
        }

        let len = cursor.width * cursor.height * size_of::<i32>() as u32;
        if len > CURSOR_SIZE as u32 {
            error!("Too large cursor length {}.", len);
            // No need to return Err for this situation is not fatal
            return Ok(());
        }

        // SAFETY: len is checked before copying,it's safe to do this.
        unsafe {
            ptr::copy_nonoverlapping(
                cursor.data.as_ptr(),
                self.cursorbuffer as *mut u8,
                len as usize,
            );
        }

        self.msg_handler.handle_cursor_define(
            cursor.width,
            cursor.height,
            cursor.hot_x,
            cursor.hot_y,
            size_of::<i32>() as u32,
        );
        Ok(())
    }
}

pub fn ohui_init(ohui_srv: Arc<OhUiServer>, cfg: &DisplayConfig) -> Result<()> {
    // set iothread
    ohui_srv.set_iothread(cfg.ohui_config.iothread.clone());
    // Register ohui interface
    let dcl = Arc::new(Mutex::new(DisplayChangeListener::new(
        None,
        ohui_srv.clone(),
    )));
    dcl.lock().unwrap().update_interval = DISPLAY_UPDATE_INTERVAL_DEFAULT;
    register_display(&dcl)?;
    // start listener
    ohui_start_listener(ohui_srv)
}

struct OhUiTrans {
    server: Arc<OhUiServer>,
}

impl OhUiTrans {
    pub fn new(server: Arc<OhUiServer>) -> Self {
        OhUiTrans { server }
    }

    fn handle_disconnect(&self) {
        self.server.set_connect(false);
        if let Err(e) = ohui_start_listener(self.server.clone()) {
            error!("Failed to restart listener: {:?}.", e)
        }
    }

    fn handle_recv(&self) -> Result<()> {
        self.server.handle_recv()
    }

    fn get_fd(&self) -> RawFd {
        self.server.get_channel().get_stream_raw_fd()
    }
}

impl EventNotifierHelper for OhUiTrans {
    fn internal_notifiers(trans: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let trans_ref = trans.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event: EventSet, fd: RawFd| {
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                error!("OhUiTrans: disconnected.");
                trans_ref.lock().unwrap().handle_disconnect();
                // Delete stream notifiers
                return Some(gen_delete_notifiers(&[fd]));
            } else if event & EventSet::IN == EventSet::IN {
                let locked_trans = trans_ref.lock().unwrap();
                // Handle incoming data
                if let Err(e) = locked_trans.handle_recv() {
                    error!("{}.", e);
                    locked_trans.handle_disconnect();
                    return Some(gen_delete_notifiers(&[fd]));
                }
            }
            None
        });

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            trans.lock().unwrap().get_fd(),
            None,
            EventSet::IN | EventSet::HANG_UP,
            vec![handler],
        )]
    }
}

struct OhUiListener {
    server: Arc<OhUiServer>,
}

impl OhUiListener {
    fn new(server: Arc<OhUiServer>) -> Self {
        OhUiListener { server }
    }

    fn handle_connection(&self) -> Result<()> {
        // Set stream sock with nonblocking
        self.server.get_channel().set_nonblocking(true)?;
        // Register OhUiTrans read notifier
        ohui_register_event(OhUiTrans::new(self.server.clone()), self.server.clone())?;
        self.server.set_connect(true);
        // Send window info to the client
        self.server.send_window_info();
        Ok(())
    }

    fn accept(&self) -> Result<()> {
        self.server.get_channel().accept()
    }

    fn get_fd(&self) -> RawFd {
        self.server.get_channel().get_listener_raw_fd()
    }
}

impl EventNotifierHelper for OhUiListener {
    fn internal_notifiers(listener: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let listener_ref = listener.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_event: EventSet, fd: RawFd| {
            let locked_listener = listener_ref.lock().unwrap();
            match locked_listener.accept() {
                Ok(()) => match locked_listener.handle_connection() {
                    Ok(()) => info!("New connection accepted."),
                    Err(e) => {
                        error!("Failed to start connection and going to restart listening {e}.");
                        return None;
                    }
                },
                Err(e) => {
                    error!("Accept failed: {:?}.", e);
                    return None;
                }
            }
            // Only support one connection so remove listener
            Some(gen_delete_notifiers(&[fd]))
        });

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            listener.lock().unwrap().get_fd(),
            None,
            EventSet::IN,
            vec![handler],
        )]
    }
}

fn ohui_register_event<T: EventNotifierHelper>(e: T, srv: Arc<OhUiServer>) -> Result<()> {
    let notifiers = EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(e)));
    let mut evts: Vec<RawFd> = Vec::new();
    register_event_helper(
        notifiers,
        srv.iothread.get_or_init(|| None).as_ref(),
        &mut evts,
    )
}

fn ohui_start_listener(server: Arc<OhUiServer>) -> Result<()> {
    // Bind and set listener nonblocking
    let channel = server.get_channel();
    channel.bind()?;
    channel.set_listener_nonblocking(true)?;
    ohui_register_event(OhUiListener::new(server.clone()), server.clone())?;
    info!("Successfully start listener.");
    Ok(())
}
