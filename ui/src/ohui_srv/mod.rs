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
pub mod touchpad;

use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
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
    event_loop::{register_event_helper, EventLoop},
    temp_cleaner::TempCleaner,
};
use migration::snapshot::OHUI_SNAPSHOT_ID;
use migration::{DeviceStateDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use msg_handle::*;
use util::{
    loop_context::{
        gen_delete_notifiers, EventNotifier, EventNotifierHelper, NotifierCallback,
        NotifierOperation,
    },
    pixman::{pixman_format_code_t, pixman_image_t},
    unix::{do_mmap, limit_permission},
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

struct CursorInfo {
    buffer: u64,
    width: u32,
    height: u32,
    hot_x: u32,
    hot_y: u32,
    _file: FileBackend,
}

pub struct OhUiServer {
    // framebuffer passthru to the guest
    passthru: OnceCell<bool>,
    // guest surface for framebuffer
    surface: RwLock<GuestSurface>,
    // transfer channel via unix sock
    channel: Arc<Mutex<OhUiChannel>>,
    // message handler
    msg_handler: OhUiMsgHandler,
    // connected or not
    connected: AtomicBool,
    // iothread processing unix socket
    iothread: OnceCell<Option<String>>,
    //address of framebuffer
    framebuffer: u64,
    // framebuffer file backend
    fb_file: Option<FileBackend>,
    // tokenID of OHUI client
    pub token_id: Arc<RwLock<u64>>,
    // Cursor
    cursor: Arc<Mutex<CursorInfo>>,
}

impl OhUiServer {
    fn init_channel(path: &String) -> Result<Arc<Mutex<OhUiChannel>>> {
        let file_path = Path::new(path.as_str()).join("ohui.sock");
        let sock_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_channel: Failed to get str from {}", path))?;
        TempCleaner::add_path(sock_file.to_string());
        Ok(Arc::new(Mutex::new(OhUiChannel::new(sock_file)?)))
    }

    fn init_fb_file(path: &String) -> Result<(Option<FileBackend>, u64)> {
        let file_path = Path::new(path.as_str()).join("ohui-fb");
        let fb_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_fb_file: Failed to get str from {}", path))?;
        let fb_backend = FileBackend::new_mem(fb_file, VIRTIO_GPU_ENABLE_BAR0_SIZE)?;
        TempCleaner::add_path(fb_file.to_string());
        limit_permission(fb_file).unwrap_or_else(|e| {
            error!(
                "Failed to limit permission for ohui-fb {}, err: {:?}",
                fb_file, e
            );
        });

        let host_addr = do_mmap(
            &Some(fb_backend.file.as_ref()),
            VIRTIO_GPU_ENABLE_BAR0_SIZE,
            0,
            false,
            true,
            false,
        )?;

        let ret =
        // SAFETY: host_addr and size must be valid if called do_mmap successfully.
        unsafe {
            libc::mlock(
                host_addr as *const libc::c_void,
                VIRTIO_GPU_ENABLE_BAR0_SIZE as libc::size_t,
            )
        };
        if ret != 0 {
            error!(
                "Failed to lock ohui-fb, ret val as {}",
                std::io::Error::last_os_error()
            );
        }

        Ok((Some(fb_backend), host_addr))
    }

    fn init_cursor_file(path: &String) -> Result<(FileBackend, u64)> {
        let file_path = Path::new(path.as_str()).join("ohui-cursor");
        let cursor_file = file_path
            .to_str()
            .ok_or_else(|| anyhow!("init_cursor_file: Failed to get str from {}", path))?;
        let cursor_backend = FileBackend::new_mem(cursor_file, CURSOR_SIZE)?;
        TempCleaner::add_path(cursor_file.to_string());
        limit_permission(cursor_file).unwrap_or_else(|e| {
            error!(
                "Failed to limit permission for ohui-cursor {}, err: {:?}",
                cursor_file, e
            );
        });

        let cursorbuffer = do_mmap(
            &Some(cursor_backend.file.as_ref()),
            CURSOR_SIZE,
            0,
            false,
            true,
            false,
        )?;

        // SAFETY: cursorbuffer and CURSOR_SIZE must be valid if called do_mmap successfully.
        unsafe {
            ptr::write_bytes(cursorbuffer as *mut u8, 0, CURSOR_SIZE as usize);
        }

        Ok((cursor_backend, cursorbuffer))
    }

    pub fn new(ui_path: String, sock_path: String) -> Result<Arc<Self>> {
        let channel = Self::init_channel(&sock_path)?;
        let (fb_file, framebuffer) = Self::init_fb_file(&ui_path)?;
        let (cursor_file, cursorbuffer) = Self::init_cursor_file(&ui_path)?;
        let cursor = Arc::new(Mutex::new(CursorInfo {
            buffer: cursorbuffer,
            width: 0,
            height: 0,
            hot_x: 0,
            hot_y: 0,
            _file: cursor_file,
        }));
        let ohui_srv = Arc::new(OhUiServer {
            passthru: OnceCell::new(),
            surface: RwLock::new(GuestSurface::new()),
            channel,
            msg_handler: OhUiMsgHandler::new(),
            connected: AtomicBool::new(false),
            iothread: OnceCell::new(),
            framebuffer,
            fb_file,
            token_id: Arc::new(RwLock::new(0)),
            cursor: cursor.clone(),
        });

        MigrationManager::register_device_instance(
            OhUiMigrationState::descriptor(),
            Arc::new(Mutex::new(OhUiMigration {
                cursor,
                ohui_srv: ohui_srv.clone(),
            })),
            OHUI_SNAPSHOT_ID,
        );

        Ok(ohui_srv)
    }

    pub fn set_passthru(&self, passthru: bool) {
        self.passthru
            .set(passthru)
            .unwrap_or_else(|_| error!("Failed to initialize passthru of OHUI Server."));
    }

    #[inline(always)]
    fn get_channel(&self) -> Arc<Mutex<OhUiChannel>> {
        self.channel.clone()
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

    /// # Safety
    ///
    /// This function is unsafe because it copies the data from the buffer pointed by
    /// `surface_data` parameter to the framebuffer.
    /// The caller must ensure that:
    ///
    /// - the source buffer is valid and the actual copied buffer can't exceed the source buffer.
    /// - the size of source buffer is less or equal to the size of framebuffer.
    /// - the source buffer should not be overlapped with the framebuffer.
    ///
    /// Failure to meet these conditions will lead to undefined behavior.
    unsafe fn raw_update_dirty_area(
        &self,
        surface_data: *mut u32,
        stride: i32,
        pos: (i32, i32),
        size: (i32, i32),
        force_copy: bool,
    ) {
        let (x, y) = pos;
        let (w, h) = size;

        if self.framebuffer == 0
            || surface_data.is_null()
            || (!force_copy && *self.passthru.get_or_init(|| false))
        {
            return;
        }

        let offset = (x * bytes_per_pixel() as i32 + y * stride) as u64;
        let mut src_ptr = surface_data as u64 + offset;
        let mut dst_ptr = self.framebuffer + offset;

        for _ in 0..h {
            ptr::copy_nonoverlapping(
                src_ptr as *const u8,
                dst_ptr as *mut u8,
                w as usize * bytes_per_pixel(),
            );
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

    fn send_input_device_state(&self) {
        self.msg_handler.send_input_device_state();
    }

    #[inline(always)]
    fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    #[inline(always)]
    fn set_connect(&self, conn: bool) {
        self.connected.store(conn, Ordering::Relaxed);
        if conn {
            self.msg_handler.update_sock(self.channel.clone());
        } else {
            self.msg_handler.reset();
            self.channel.lock().unwrap().disconnect();
        }
    }

    fn set_iothread(&self, iothread: Option<String>) {
        if self.iothread.set(iothread).is_err() {
            error!("Failed to initialize iothread of OHUI Server.");
        }
    }
}

impl DisplayChangeListenerOperations for OhUiServer {
    fn dpy_switch(&self, surface: &DisplaySurface) -> Result<()> {
        let height = surface.height() as u64;
        let stride = surface.stride() as u64;
        if self.framebuffer != 0 && height * stride > VIRTIO_GPU_ENABLE_BAR0_SIZE {
            bail!(
                "surface size is larger than ohui buffer size {}",
                VIRTIO_GPU_ENABLE_BAR0_SIZE
            );
        }

        let mut locked_surface = self.surface.write().unwrap();

        unref_pixman_image(locked_surface.guest_image);

        locked_surface.guest_image = ref_pixman_image(surface.image);
        locked_surface.guest_format = surface.format;
        locked_surface.stride = surface.stride();
        locked_surface.width = surface.width();
        locked_surface.height = surface.height();
        drop(locked_surface);
        let locked_surface = self.surface.read().unwrap();
        // SAFETY: we have checked the new surafce and it should not be larger than framebuffer.
        unsafe {
            self.raw_update_dirty_area(
                get_image_data(locked_surface.guest_image),
                locked_surface.stride,
                (0, 0),
                (locked_surface.width, locked_surface.height),
                true,
            )
        };

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

        if locked_surface.width < x
            || locked_surface.height < y
            || locked_surface.width < x.saturating_add(w)
            || locked_surface.height < y.saturating_add(h)
        {
            bail!("dpy_image_update: invalid dirty area");
        }

        // SAFETY: we have checked the buffer indicated by (x,y,w,h) and it should not
        // exceed the image buffer stored in the surface which has been checked in dpy_switch().
        unsafe {
            self.raw_update_dirty_area(
                get_image_data(locked_surface.guest_image),
                locked_surface.stride,
                (x, y),
                (w, h),
                false,
            )
        };

        self.msg_handler
            .handle_dirty_area(x as u32, y as u32, w as u32, h as u32);
        Ok(())
    }

    fn dpy_cursor_update(&self, cursor: &DisplayMouse) -> Result<()> {
        let mut locked_cursor = self.cursor.lock().unwrap();
        if locked_cursor.buffer == 0 {
            error!("Hwcursor not set.");
            // No need to return Err for this situation is not fatal
            return Ok(());
        }

        let len = cursor
            .width
            .checked_mul(cursor.height)
            .with_context(|| "Invalid cursor width * height")?
            .checked_mul(bytes_per_pixel() as u32)
            .with_context(|| "Invalid cursor size")?;
        if len > CURSOR_SIZE as u32 || len > cursor.data.len().try_into()? {
            error!("Too large cursor length {}.", len);
            // No need to return Err for this situation is not fatal
            return Ok(());
        }

        // SAFETY: len and dest buffer has been checked before copying, it's safe to do this.
        unsafe {
            ptr::copy_nonoverlapping(
                cursor.data.as_ptr(),
                locked_cursor.buffer as *mut u8,
                len as usize,
            );
        }
        locked_cursor.width = cursor.width;
        locked_cursor.height = cursor.height;
        locked_cursor.hot_x = cursor.hot_x;
        locked_cursor.hot_y = cursor.hot_y;

        self.msg_handler.handle_cursor_define(
            cursor.width,
            cursor.height,
            cursor.hot_x,
            cursor.hot_y,
            bytes_per_pixel() as u32,
        );
        Ok(())
    }
}

pub fn ohui_init(ohui_srv: Arc<OhUiServer>, cfg: &DisplayConfig) -> Result<()> {
    // set iothread
    ohui_srv.set_iothread(cfg.iothread.clone());
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
        self.server
            .get_channel()
            .lock()
            .unwrap()
            .get_stream_raw_fd()
            .unwrap()
    }

    fn delay_close_fd(&self, fd: RawFd) {
        let func = Box::new(move || {
            // SAFETY: the fd is duplicated from connected socket so it's valid.
            let ret = unsafe { libc::close(fd) };
            if ret != 0 {
                error!("Failed to close fd, {:?}", std::io::Error::last_os_error());
            }
        });
        EventLoop::get_ctx(self.server.iothread.get_or_init(|| None).as_ref())
            .unwrap()
            .timer_add(func, Duration::ZERO);
    }
}

impl EventNotifierHelper for OhUiTrans {
    fn internal_notifiers(trans: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let trans_ref = trans.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event: EventSet, fd: RawFd| {
            if event & EventSet::HANG_UP == EventSet::HANG_UP {
                error!("OhUiTrans: disconnected.");
                let locked_trans = trans_ref.lock().unwrap();
                locked_trans.handle_disconnect();
                locked_trans.delay_close_fd(fd);
                // Delete stream notifiers
                return Some(gen_delete_notifiers(&[fd]));
            } else if event & EventSet::IN == EventSet::IN {
                let locked_trans = trans_ref.lock().unwrap();
                // Handle incoming data
                if let Err(e) = locked_trans.handle_recv() {
                    error!("{}.", e);
                    locked_trans.handle_disconnect();
                    locked_trans.delay_close_fd(fd);
                    return Some(gen_delete_notifiers(&[fd]));
                }
            }
            None
        });

        let fd = trans.lock().unwrap().get_fd();
        let new_fd = dup_fd(fd);

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            new_fd,
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
        // Register OhUiTrans read notifier
        ohui_register_event(OhUiTrans::new(self.server.clone()), self.server.clone())?;
        self.server.set_connect(true);
        // Send window info to the client
        self.server.send_window_info();
        // Send input device state
        self.server.send_input_device_state();
        Ok(())
    }

    fn accept(&self) -> Result<()> {
        self.server.get_channel().lock().unwrap().accept()
    }

    fn get_fd(&self) -> RawFd {
        self.server
            .get_channel()
            .lock()
            .unwrap()
            .get_listener_raw_fd()
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
    ohui_register_event(OhUiListener::new(server.clone()), server)?;
    info!("Successfully start listener.");
    Ok(())
}

pub fn dup_fd(fd: RawFd) -> RawFd {
    // SAFETY: The caller may pass an invalid fd. We attempt to duplicate it
    // and return either the duplicated fd or the original fd on failure.
    // Prefer an atomic dup+close-on-exec where available to avoid a race.
    let new_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if new_fd != -1 {
        return new_fd;
    }

    let err = std::io::Error::last_os_error();
    error!(
        "Failed to fcntl(F_DUPFD_CLOEXEC) for fd {}: {:?}. Returning original fd.",
        fd, err
    );
    return fd;
}

/// Migration
#[derive(Clone, Debug, Default, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
struct OhUiMigrationState {
    cursor_img: Vec<u8>,
    width: u32,
    height: u32,
    hot_x: u32,
    hot_y: u32,
}

struct OhUiMigration {
    cursor: Arc<Mutex<CursorInfo>>,
    ohui_srv: Arc<OhUiServer>,
}

impl StateTransfer for OhUiMigration {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = OhUiMigrationState::default();
        state.cursor_img.resize(CURSOR_SIZE as usize, 0);

        let cursor = self.cursor.lock().unwrap();
        // SAFETY: the buffer is initialized and being kept for the whole VM lifecycle.
        unsafe {
            ptr::copy_nonoverlapping(
                cursor.buffer as *const u8,
                state.cursor_img.as_mut_ptr(),
                CURSOR_SIZE as usize,
            );
        }
        state.width = cursor.width;
        state.height = cursor.height;
        state.hot_x = cursor.hot_x;
        state.hot_y = cursor.hot_y;
        Ok(serde_json::to_vec(&state)?)
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        let mgt_state: OhUiMigrationState = serde_json::from_slice(state)
            .with_context(|| migration::error::MigrationError::FromBytesError("OHUI"))?;
        let mut cursor = self.cursor.lock().unwrap();
        // SAFETY: the buffer is initialized and being kept for the whole VM lifecycle.
        unsafe {
            ptr::copy_nonoverlapping(
                mgt_state.cursor_img.as_ptr(),
                cursor.buffer as *mut u8,
                CURSOR_SIZE as usize,
            );
        }
        cursor.width = mgt_state.width;
        cursor.height = mgt_state.height;
        cursor.hot_x = mgt_state.hot_x;
        cursor.hot_y = mgt_state.hot_y;
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&OhUiMigrationState::descriptor().name).unwrap_or(0)
    }
}

impl MigrationHook for OhUiMigration {
    fn resume(&mut self) -> Result<()> {
        let cursor = self.cursor.lock().unwrap();
        self.ohui_srv.msg_handler.handle_cursor_define(
            cursor.width,
            cursor.height,
            cursor.hot_x,
            cursor.hot_y,
            bytes_per_pixel() as u32,
        );
        Ok(())
    }
}
