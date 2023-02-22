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
    auth::SaslAuth,
    auth::{AuthState, SaslConfig, SubAuthState},
    client::vnc_write,
    client::{vnc_flush, ClientIoHandler, ClientState},
    console::{DisplayChangeListener, DisplayMouse},
    input::KeyBoardState,
    pixman::{
        bytes_per_pixel, get_image_data, get_image_format, get_image_height, get_image_stride,
        get_image_width, pixman_image_linebuf_create, pixman_image_linebuf_fill,
        unref_pixman_image,
    },
    round_up_div,
    vencrypt::{make_vencrypt_config, TlsCreds, ANON_CERT, X509_CERT},
    vnc::{
        update_server_surface, DIRTY_PIXELS_NUM, MAX_WINDOW_HEIGHT, MAX_WINDOW_WIDTH,
        VNC_BITMAP_WIDTH, VNC_SERVERS,
    },
    VncError,
};
use anyhow::{anyhow, Result};
use log::{error, info};
use machine_manager::{
    config::{ObjectConfig, VncConfig},
    event_loop::EventLoop,
};
use std::{
    cell::RefCell,
    cmp,
    collections::HashMap,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::prelude::{AsRawFd, RawFd},
    ptr,
    rc::Rc,
    sync::{Arc, Mutex, Weak},
};
use util::{
    bitmap::Bitmap,
    loop_context::{
        read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
    },
    pixman::{pixman_format_bpp, pixman_format_code_t, pixman_image_t},
};
use vmm_sys_util::epoll::EventSet;

const CONNECTION_LIMIT: usize = 1;

/// Information of VncServer.
pub struct VncServer {
    /// Client io handler.
    pub client_handlers: Arc<Mutex<HashMap<String, Arc<ClientState>>>>,
    /// Security Type for connection.
    pub security_type: Rc<RefCell<SecurityType>>,
    /// keyboard status.
    pub keyboard_state: Rc<RefCell<KeyBoardState>>,
    /// Mapping ASCII to keycode.
    pub keysym2keycode: HashMap<u16, u16>,
    /// Image data of surface.
    pub vnc_surface: Arc<Mutex<VncSurface>>,
    /// Data for cursor image.
    pub vnc_cursor: Arc<Mutex<VncCursor>>,
    /// Display Change Listener.
    pub display_listener: Option<Weak<Mutex<DisplayChangeListener>>>,
    /// Connection limit.
    pub conn_limits: usize,
}

// SAFETY:
// 1. The raw pointer in rust doesn't impl Send, the target thread can only read the memory of image by this pointer.
// 2. It can be sure that Rc<RefCell<SecurityType>> and Rc<RefCell<KeyBoardState>> are used only in single thread.
// So implement Send and Sync is safe.
unsafe impl Send for VncServer {}
unsafe impl Sync for VncServer {}

impl VncServer {
    /// Create a new VncServer.
    pub fn new(
        guest_image: *mut pixman_image_t,
        keyboard_state: Rc<RefCell<KeyBoardState>>,
        keysym2keycode: HashMap<u16, u16>,
        display_listener: Option<Weak<Mutex<DisplayChangeListener>>>,
    ) -> Self {
        VncServer {
            client_handlers: Arc::new(Mutex::new(HashMap::new())),
            security_type: Rc::new(RefCell::new(SecurityType::default())),
            keyboard_state,
            keysym2keycode,
            vnc_surface: Arc::new(Mutex::new(VncSurface::new(guest_image))),
            vnc_cursor: Arc::new(Mutex::new(VncCursor::default())),
            display_listener,
            conn_limits: CONNECTION_LIMIT,
        }
    }
}

pub struct VncConnHandler {
    /// Tcp connection listened by server.
    listener: TcpListener,
    /// VncServer.
    server: Arc<VncServer>,
}

impl VncConnHandler {
    pub fn new(listener: TcpListener, server: Arc<VncServer>) -> Self {
        VncConnHandler { listener, server }
    }
}

/// Internal_notifiers for VncServer.
impl EventNotifierHelper for VncConnHandler {
    fn internal_notifiers(vnc_io: Arc<Mutex<VncConnHandler>>) -> Vec<EventNotifier> {
        let vnc_io_clone = vnc_io.clone();
        let server = vnc_io.lock().unwrap().server.clone();
        // Register event notifier for connection.
        let handler: Rc<NotifierCallback> = Rc::new(move |_event, fd: RawFd| {
            read_fd(fd);
            match vnc_io_clone.clone().lock().unwrap().listener.accept() {
                Ok((stream, addr)) => {
                    if let Err(e) = handle_connection(&server, stream, addr) {
                        error!("{:?}", e);
                    }
                }
                Err(e) => {
                    error!("Connect failed: {:?}", e);
                }
            }
            None
        });
        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            vnc_io.lock().unwrap().listener.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        )]
    }
}

/// Info of image.
/// stride is not always equal to stride because of memory alignment.
pub struct ImageInfo {
    /// The start pointer to image.
    data: *mut u8,
    /// The memory size of each line for image.
    stride: i32,
    /// The memory size of each line to store pixel for image
    length: i32,
    /// Middle pointer.
    ptr: *mut u8,
}

impl Default for ImageInfo {
    fn default() -> Self {
        ImageInfo {
            data: ptr::null_mut(),
            stride: 0,
            length: 0,
            ptr: ptr::null_mut(),
        }
    }
}

impl ImageInfo {
    fn new(image: *mut pixman_image_t) -> Self {
        let bpp = pixman_format_bpp(get_image_format(image) as u32);
        let length = get_image_width(image) * round_up_div(bpp as u64, 8) as i32;
        ImageInfo {
            data: get_image_data(image) as *mut u8,
            stride: get_image_stride(image),
            length,
            ptr: ptr::null_mut(),
        }
    }
}

/// Security type for connection and transport.
pub struct SecurityType {
    /// Configuration for tls connection.
    pub tlscreds: Option<TlsCreds>,
    /// Authentication for connection
    pub saslauth: Option<SaslAuth>,
    /// Configuration for sasl Authentication.
    pub saslconfig: SaslConfig,
    /// Configuration to make tls channel.
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Auth type.
    pub auth: AuthState,
    /// Subauth type.
    pub subauth: SubAuthState,
}

impl Default for SecurityType {
    fn default() -> Self {
        SecurityType {
            tlscreds: None,
            saslauth: None,
            saslconfig: SaslConfig::default(),
            tls_config: None,
            auth: AuthState::No,
            subauth: SubAuthState::VncAuthVencryptPlain,
        }
    }
}

impl SecurityType {
    // Set security config.
    fn set_security_config(&mut self, vnc_cfg: &VncConfig, object: &ObjectConfig) -> Result<()> {
        // Tls configuration.
        if let Some(tls_cred) = object.tls_object.get(&vnc_cfg.tls_creds) {
            let tlscred = TlsCreds {
                cred_type: tls_cred.cred_type.clone(),
                dir: tls_cred.dir.clone(),
                endpoint: tls_cred.endpoint.clone(),
                verifypeer: tls_cred.verifypeer,
            };

            match make_vencrypt_config(&tlscred) {
                Ok(tls_config) => {
                    self.tls_config = Some(tls_config);
                }
                Err(e) => {
                    return Err(e);
                }
            }
            self.tlscreds = Some(tlscred);
        }

        // Sasl configuration.
        if let Some(sasl_auth) = object.sasl_object.get(&vnc_cfg.sasl_authz) {
            self.saslauth = Some(SaslAuth::new(sasl_auth.identity.clone()));
        }

        Ok(())
    }

    /// Encryption configuration.
    fn set_auth(&mut self) -> Result<()> {
        let is_x509: bool;
        let is_anon: bool;
        let is_sasl: bool = self.saslauth.is_some();

        if let Some(tlscred) = self.tlscreds.clone() {
            is_x509 = tlscred.cred_type == *X509_CERT;
            is_anon = tlscred.cred_type == *ANON_CERT;
            self.auth = AuthState::Vencrypt;
        } else {
            self.auth = AuthState::No;
            self.subauth = SubAuthState::VncAuthVencryptPlain;
            return Ok(());
        }

        if !is_x509 && !is_anon {
            error!("Unsupported tls cred type");
            return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                "Unsupported tls cred type",
            ))));
        }
        if is_sasl {
            if is_x509 {
                self.subauth = SubAuthState::VncAuthVencryptX509Sasl;
            } else {
                self.subauth = SubAuthState::VncAuthVencryptTlssasl;
            }
        } else if is_x509 {
            self.subauth = SubAuthState::VncAuthVencryptX509None;
        } else {
            self.subauth = SubAuthState::VncAuthVencryptTlNone;
        }
        Ok(())
    }
}

/// Image date of cursor.
#[derive(Default)]
pub struct VncCursor {
    /// Cursor property.
    pub cursor: Option<DisplayMouse>,
    /// Identify the area need update for cursor.
    pub mask: Option<Vec<u8>>,
}

/// The image data for vnc display surface.
pub struct VncSurface {
    /// Image from display device.
    pub guest_image: *mut pixman_image_t,
    /// Identify the image update area for guest image.
    pub guest_dirty_bitmap: Bitmap<u64>,
    /// Image refresh to vnc client.
    pub server_image: *mut pixman_image_t,
    /// Image format of pixman.
    pub guest_format: pixman_format_code_t,
}

impl VncSurface {
    fn new(guest_image: *mut pixman_image_t) -> Self {
        VncSurface {
            guest_image,
            guest_dirty_bitmap: Bitmap::<u64>::new(
                MAX_WINDOW_HEIGHT as usize
                    * round_up_div(
                        (MAX_WINDOW_WIDTH / DIRTY_PIXELS_NUM) as u64,
                        u64::BITS as u64,
                    ) as usize,
            ),
            server_image: ptr::null_mut(),
            guest_format: pixman_format_code_t::PIXMAN_x8r8g8b8,
        }
    }

    /// Get min width.
    fn get_min_width(&self) -> i32 {
        cmp::min(
            get_image_width(self.server_image),
            get_image_width(self.guest_image),
        )
    }

    /// Get min height.
    fn get_min_height(&self) -> i32 {
        cmp::min(
            get_image_height(self.server_image),
            get_image_height(self.guest_image),
        )
    }

    /// Flush dirty data from guest_image to server_image.
    /// Return the number of dirty area.
    pub fn update_server_image(&mut self) -> i32 {
        let mut dirty_num = 0;
        let height = self.get_min_height() as usize;
        let g_bpl = self.guest_dirty_bitmap.vol() / MAX_WINDOW_HEIGHT as usize;
        let total_dirty_bits = height.checked_mul(g_bpl).unwrap_or(0);
        let mut offset = self
            .guest_dirty_bitmap
            .find_next_bit(0)
            .unwrap_or(total_dirty_bits);

        if offset >= total_dirty_bits {
            return dirty_num;
        }

        let mut s_info = ImageInfo::new(self.server_image);
        let mut g_info = ImageInfo::new(self.guest_image);

        // The guset image is not changed, so there is no
        // need to update the server image.
        let cmp_bytes = cmp::min(
            DIRTY_PIXELS_NUM as usize * bytes_per_pixel(),
            s_info.stride as usize,
        );

        let mut line_buf = ptr::null_mut();
        if self.guest_format != pixman_format_code_t::PIXMAN_x8r8g8b8 {
            line_buf = pixman_image_linebuf_create(
                pixman_format_code_t::PIXMAN_x8r8g8b8,
                get_image_width(self.server_image),
            );
            g_info.stride = s_info.stride;
            g_info.length = g_info.stride;
        }

        loop {
            let mut y = offset / g_bpl;
            let x = offset % g_bpl;
            s_info.ptr =
                (s_info.data as usize + y * s_info.stride as usize + x * cmp_bytes) as *mut u8;

            if self.guest_format != pixman_format_code_t::PIXMAN_x8r8g8b8 {
                pixman_image_linebuf_fill(
                    line_buf,
                    self.guest_image,
                    self.get_min_width(),
                    0_i32,
                    y as i32,
                );
                g_info.ptr = get_image_data(line_buf) as *mut u8;
            } else {
                g_info.ptr = (g_info.data as usize + y * g_info.stride as usize) as *mut u8;
            }
            g_info.ptr = (g_info.ptr as usize + x * cmp_bytes) as *mut u8;
            dirty_num += self.update_one_line(x, y, &mut s_info, &mut g_info, cmp_bytes);
            y += 1;
            offset = self
                .guest_dirty_bitmap
                .find_next_bit(y * g_bpl)
                .unwrap_or(total_dirty_bits);
            if offset >= total_dirty_bits {
                break;
            }
        }

        unref_pixman_image(line_buf);
        dirty_num
    }

    /// Update each line
    ///
    /// # Arguments
    ///
    /// * `x` `y` - start coordinate in image to refresh
    /// * `s_info` - Info of Server image.
    /// * `g_info` - Info of Guest image.
    fn update_one_line(
        &mut self,
        mut x: usize,
        y: usize,
        s_info: &mut ImageInfo,
        g_info: &mut ImageInfo,
        cmp_bytes: usize,
    ) -> i32 {
        let mut count = 0;
        let width = self.get_min_width();
        let line_bytes = cmp::min(s_info.stride, g_info.length);

        while x < round_up_div(width as u64, DIRTY_PIXELS_NUM as u64) as usize {
            if !self
                .guest_dirty_bitmap
                .contain(x + y * VNC_BITMAP_WIDTH as usize)
                .unwrap_or(false)
            {
                x += 1;
                g_info.ptr = (g_info.ptr as usize + cmp_bytes) as *mut u8;
                s_info.ptr = (s_info.ptr as usize + cmp_bytes) as *mut u8;
                continue;
            }
            self.guest_dirty_bitmap
                .clear(x + y * VNC_BITMAP_WIDTH as usize)
                .unwrap_or_else(|e| error!("Error occurrs during clearing the bitmap: {:?}", e));
            let mut _cmp_bytes = cmp_bytes;
            if (x + 1) * cmp_bytes > line_bytes as usize {
                _cmp_bytes = line_bytes as usize - x * cmp_bytes;
            }

            // SAFETY: it can be ensure the raw pointer will not exceed the range.
            unsafe {
                if libc::memcmp(
                    s_info.ptr as *mut libc::c_void,
                    g_info.ptr as *mut libc::c_void,
                    _cmp_bytes,
                ) == 0
                {
                    x += 1;
                    g_info.ptr = (g_info.ptr as usize + cmp_bytes) as *mut u8;
                    s_info.ptr = (s_info.ptr as usize + cmp_bytes) as *mut u8;
                    continue;
                }

                ptr::copy(g_info.ptr, s_info.ptr, _cmp_bytes);
            };

            set_dirty_for_each_clients(x, y);
            count += 1;

            x += 1;
            g_info.ptr = (g_info.ptr as usize + cmp_bytes) as *mut u8;
            s_info.ptr = (s_info.ptr as usize + cmp_bytes) as *mut u8;
        }

        count
    }
}

/// Set diry for each client.
///
/// # Arguments
///
/// * `x` `y`- coordinates of dirty area.
fn set_dirty_for_each_clients(x: usize, y: usize) {
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    let mut locked_handlers = server.client_handlers.lock().unwrap();
    for client in locked_handlers.values_mut() {
        client
            .dirty_bitmap
            .lock()
            .unwrap()
            .set(x + y * VNC_BITMAP_WIDTH as usize)
            .unwrap_or_else(|e| error!("{:?}", e));
    }
}

/// Accpet client's connection.
///
/// # Arguments
///
/// * `stream` - TcpStream.
/// * `addr`- SocketAddr.
pub fn handle_connection(
    server: &Arc<VncServer>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<()> {
    info!("New Connection: {:?}", stream);
    stream
        .set_nonblocking(true)
        .expect("set nonblocking failed");

    // Register event notifier for vnc client.
    let client = Arc::new(ClientState::new(addr.to_string()));
    let client_io = Arc::new(Mutex::new(ClientIoHandler::new(
        stream,
        client.clone(),
        server.clone(),
    )));
    vnc_write(&client, "RFB 003.008\n".as_bytes().to_vec());
    vnc_flush(&client);
    server
        .client_handlers
        .lock()
        .unwrap()
        .insert(addr.to_string(), client);

    EventLoop::update_event(EventNotifierHelper::internal_notifiers(client_io), None)?;

    update_server_surface(server);
    Ok(())
}

/// make configuration for VncServer
///
/// # Arguments
///
/// * `vnc_cfg` - configure of vnc.
/// * `object` - configure of sasl and tls.
pub fn make_server_config(
    server: &Arc<VncServer>,
    vnc_cfg: &VncConfig,
    object: &ObjectConfig,
) -> Result<()> {
    // Set security config.
    server
        .security_type
        .borrow_mut()
        .set_security_config(vnc_cfg, object)?;
    // Set auth type.
    server.security_type.borrow_mut().set_auth()?;

    Ok(())
}
