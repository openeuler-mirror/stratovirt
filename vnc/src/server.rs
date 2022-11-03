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
    auth::{AuthState, SubAuthState},
    client::VncClient,
    data::keycode::KEYSYM2KEYCODE,
    pixman::{
        bytes_per_pixel, get_image_data, get_image_format, get_image_height, get_image_stride,
        get_image_width, unref_pixman_image,
    },
    round_up_div,
    vencrypt::{make_vencrypt_config, TlsCreds, ANON_CERT, X509_CERT},
    vnc::{
        update_client_surface, DisplayMouse, DIRTY_PIXELS_NUM, DISPLAY_UPDATE_INTERVAL_DEFAULT,
        DISPLAY_UPDATE_INTERVAL_INC, DISPLAY_UPDATE_INTERVAL_MAX, MAX_WINDOW_HEIGHT,
        MAX_WINDOW_WIDTH, REFRESH_EVT, VNC_BITMAP_WIDTH, VNC_SERVERS,
    },
    VncError,
};
use anyhow::{anyhow, Result};
use machine_manager::{
    config::{ObjConfig, VncConfig},
    event_loop::EventLoop,
};
use std::{
    cmp,
    collections::HashMap,
    net::{Shutdown, TcpListener},
    os::unix::prelude::{AsRawFd, RawFd},
    ptr,
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::{read_fd, EventNotifier, EventNotifierHelper, NotifierOperation},
    pixman::{
        pixman_format_bpp, pixman_format_code_t, pixman_image_composite, pixman_image_create_bits,
        pixman_image_t, pixman_op_t,
    },
};
use vmm_sys_util::epoll::EventSet;
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

/// VncServer
pub struct VncServer {
    /// Tcp connection listened by server.
    listener: Arc<Mutex<TcpListener>>,
    /// Clients connected to vnc.
    pub clients: HashMap<String, Arc<Mutex<VncClient>>>,
    /// Configuration for tls connection.
    pub tlscreds: Option<TlsCreds>,
    /// Configuration for sasl Authentication.
    pub saslauth: Option<SaslAuth>,
    /// Configuration to make tls channel.
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    /// Auth type.
    pub auth: AuthState,
    /// Subauth type.
    pub subauth: SubAuthState,
    /// Mapping ASCII to keycode.
    pub keysym2keycode: HashMap<u16, u16>,
    /// Image refresh to VncClient.
    pub server_image: *mut pixman_image_t,
    /// Image from gpu.
    pub guest_image: *mut pixman_image_t,
    /// Identify the image update area for guest image.
    pub guest_dirty_bitmap: Bitmap<u64>,
    /// Image format of pixman.
    pub guest_format: pixman_format_code_t,
    /// Cursor property.
    pub cursor: Option<DisplayMouse>,
    /// Identify the area need update for cursor.
    pub mask: Option<Vec<u8>>,
    /// Connection limit.
    conn_limits: usize,
    /// Width of current image.
    pub true_width: i32,
    /// updating interval of display devices.
    pub update_interval: u32,
}

unsafe impl Send for VncServer {}

impl VncServer {
    /// Create a new VncServer.
    pub fn new(listener: Arc<Mutex<TcpListener>>, guest_image: *mut pixman_image_t) -> Self {
        VncServer {
            listener,
            clients: HashMap::new(),
            tlscreds: None,
            saslauth: None,
            tls_config: None,
            auth: AuthState::No,
            subauth: SubAuthState::VncAuthVencryptPlain,
            keysym2keycode: HashMap::new(),
            server_image: ptr::null_mut(),
            guest_image,
            guest_dirty_bitmap: Bitmap::<u64>::new(
                MAX_WINDOW_HEIGHT as usize
                    * round_up_div(
                        (MAX_WINDOW_WIDTH / DIRTY_PIXELS_NUM) as u64,
                        u64::BITS as u64,
                    ) as usize,
            ),
            guest_format: pixman_format_code_t::PIXMAN_x8r8g8b8,
            cursor: None,
            mask: None,
            conn_limits: 1,
            true_width: 0,
            update_interval: 0,
        }
    }

    /// make configuration for VncServer
    ///
    /// # Arguments
    ///
    /// * `vnc_cfg` - configure of vnc.
    /// * `object` - configure of sasl and tls.
    pub fn make_config(
        &mut self,
        vnc_cfg: &VncConfig,
        object: &HashMap<String, ObjConfig>,
    ) -> Result<()> {
        // Tls configuration.
        if let Some(ObjConfig::Tls(tls_cred)) = object.get(&vnc_cfg.tls_creds) {
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
        if let Some(ObjConfig::Sasl(sasl_auth)) = object.get(&vnc_cfg.sasl_authz) {
            let saslauth = SaslAuth {
                identity: sasl_auth.identity.clone(),
            };
            self.saslauth = Some(saslauth);
        }

        // Server.auth.
        if let Err(err) = self.setup_auth() {
            return Err(err);
        }

        // Mapping ASCII to keycode.
        for &(k, v) in KEYSYM2KEYCODE.iter() {
            self.keysym2keycode.insert(k, v);
        }
        Ok(())
    }

    /// Encryption configuration.
    pub fn setup_auth(&mut self) -> Result<()> {
        if let Some(tlscred) = &self.tlscreds {
            self.auth = AuthState::Vencrypt;
            if tlscred.cred_type != *X509_CERT && tlscred.cred_type != *ANON_CERT {
                error!("Unsupported tls cred type");
                return Err(anyhow!(VncError::MakeTlsConnectionFailed(String::from(
                    "Unsupported tls cred type",
                ))));
            }
            if self.saslauth.is_some() {
                if tlscred.cred_type == *"x509" {
                    self.subauth = SubAuthState::VncAuthVencryptX509Sasl;
                } else {
                    self.subauth = SubAuthState::VncAuthVencryptTlssasl;
                }
            } else {
                self.subauth = SubAuthState::VncAuthVencryptX509None;
            }
        } else {
            self.auth = AuthState::No;
            self.subauth = SubAuthState::VncAuthVencryptPlain;
        }

        Ok(())
    }

    /// Set diry for client
    ///
    /// # Arguments
    ///
    /// * `x` `y`- coordinates of dirty area.
    fn set_dirty_for_clients(&mut self, x: usize, y: usize) {
        for client in self.clients.values_mut() {
            client
                .lock()
                .unwrap()
                .dirty_bitmap
                .set(x + y * VNC_BITMAP_WIDTH as usize)
                .unwrap();
        }
    }

    /// Transfer dirty data to buff in one line
    ///
    /// # Arguments
    ///
    /// * `s_info` - Info of Server image.
    /// * `g_info` - Info of Guest image.
    fn get_one_line_buf(
        &self,
        s_info: &mut ImageInfo,
        g_info: &mut ImageInfo,
    ) -> *mut pixman_image_t {
        let mut line_buf = ptr::null_mut();
        if self.guest_format != pixman_format_code_t::PIXMAN_x8r8g8b8 {
            line_buf = unsafe {
                pixman_image_create_bits(
                    pixman_format_code_t::PIXMAN_x8r8g8b8,
                    get_image_width(self.server_image),
                    1,
                    ptr::null_mut(),
                    0,
                )
            };
            g_info.stride = s_info.stride;
            g_info.length = g_info.stride;
        }

        line_buf
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
                .unwrap()
            {
                x += 1;
                g_info.ptr = (g_info.ptr as usize + cmp_bytes) as *mut u8;
                s_info.ptr = (s_info.ptr as usize + cmp_bytes) as *mut u8;
                continue;
            }
            self.guest_dirty_bitmap
                .clear(x + y * VNC_BITMAP_WIDTH as usize)
                .unwrap();
            let mut _cmp_bytes = cmp_bytes;
            if (x + 1) * cmp_bytes > line_bytes as usize {
                _cmp_bytes = line_bytes as usize - x * cmp_bytes;
            }

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

            self.set_dirty_for_clients(x, y);
            count += 1;

            x += 1;
            g_info.ptr = (g_info.ptr as usize + cmp_bytes) as *mut u8;
            s_info.ptr = (s_info.ptr as usize + cmp_bytes) as *mut u8;
        }

        count
    }

    /// Flush dirty data from guest_image to server_image.
    /// Return the number of dirty area.
    pub fn update_server_image(&mut self) -> i32 {
        let mut dirty_num = 0;
        let height = self.get_min_height();
        let g_bpl = self.guest_dirty_bitmap.vol() / MAX_WINDOW_HEIGHT as usize;

        let mut offset = self.guest_dirty_bitmap.find_next_bit(0).unwrap();
        if offset >= (height as usize) * g_bpl {
            return dirty_num;
        }

        let mut s_info = ImageInfo::new(self.server_image);
        let mut g_info = ImageInfo::new(self.guest_image);

        let cmp_bytes = cmp::min(
            DIRTY_PIXELS_NUM as usize * bytes_per_pixel(),
            s_info.stride as usize,
        );

        let line_buf = self.get_one_line_buf(&mut s_info, &mut g_info);
        loop {
            let mut y = offset / g_bpl;
            let x = offset % g_bpl;
            s_info.ptr =
                (s_info.data as usize + y * s_info.stride as usize + x * cmp_bytes) as *mut u8;

            if self.guest_format != pixman_format_code_t::PIXMAN_x8r8g8b8 {
                unsafe {
                    pixman_image_composite(
                        pixman_op_t::PIXMAN_OP_SRC,
                        self.guest_image,
                        ptr::null_mut(),
                        line_buf,
                        0,
                        y as i16,
                        0,
                        0,
                        0,
                        0,
                        self.get_min_width() as u16,
                        1,
                    );
                };
                g_info.ptr = get_image_data(line_buf) as *mut u8;
            } else {
                g_info.ptr = (g_info.data as usize + y * g_info.stride as usize) as *mut u8;
            }
            g_info.ptr = (g_info.ptr as usize + x * cmp_bytes) as *mut u8;
            dirty_num += self.update_one_line(x, y, &mut s_info, &mut g_info, cmp_bytes);
            y += 1;
            offset = self.guest_dirty_bitmap.find_next_bit(y * g_bpl).unwrap();
            if offset >= (height as usize) * g_bpl {
                break;
            }
            unref_pixman_image(line_buf);
        }

        dirty_num
    }

    /// Listen to the port and accpet client's connection.
    pub fn handle_connection(&mut self) -> Result<()> {
        match self.listener.lock().unwrap().accept() {
            Ok((stream, addr)) => {
                if self.clients.len() >= self.conn_limits {
                    stream.shutdown(Shutdown::Both).unwrap();
                    return Ok(());
                }
                info!("New Client: {:?}", addr);
                stream
                    .set_nonblocking(true)
                    .expect("set nonblocking failed");

                let server = VNC_SERVERS.lock().unwrap()[0].clone();
                let mut client = VncClient::new(
                    stream,
                    addr.to_string(),
                    self.auth,
                    self.subauth,
                    server,
                    self.server_image,
                );
                if let Some(saslauth) = &self.saslauth {
                    client.sasl.identity = saslauth.identity.clone();
                }
                client.write_msg("RFB 003.008\n".to_string().as_bytes());
                info!("{:?}", client.stream);

                let tmp_client = Arc::new(Mutex::new(client));
                self.clients.insert(addr.to_string(), tmp_client.clone());

                EventLoop::update_event(EventNotifierHelper::internal_notifiers(tmp_client), None)?;
            }
            Err(e) => {
                info!("Connect failed: {:?}", e);
            }
        }

        update_client_surface(self);

        Ok(())
    }
}

/// Internal_notifiers for VncServer.
impl EventNotifierHelper for VncServer {
    fn internal_notifiers(server_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let server = server_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, fd: RawFd| {
                read_fd(fd);

                if event & EventSet::HANG_UP == EventSet::HANG_UP {
                    info!("Client Closed");
                } else if event == EventSet::IN {
                    let mut locked_handler = server.lock().unwrap();
                    if let Err(e) = locked_handler.handle_connection() {
                        error!("Failed to handle vnc client connection, error is {}", e);
                    }
                    drop(locked_handler);
                }

                None as Option<Vec<EventNotifier>>
            });

        let mut notifiers = vec![
            (EventNotifier::new(
                NotifierOperation::AddShared,
                server_handler
                    .lock()
                    .unwrap()
                    .listener
                    .lock()
                    .unwrap()
                    .as_raw_fd(),
                None,
                EventSet::IN | EventSet::HANG_UP,
                vec![Arc::new(Mutex::new(handler))],
            )),
        ];

        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |_event, fd: RawFd| {
                read_fd(fd);
                vnc_refresh();
                None as Option<Vec<EventNotifier>>
            });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            REFRESH_EVT.lock().unwrap().as_raw_fd(),
            None,
            EventSet::IN,
            vec![Arc::new(Mutex::new(handler))],
        ));
        notifiers
    }
}

/// Refresh server_image to guest_image.
fn vnc_refresh() {
    if VNC_SERVERS.lock().unwrap().is_empty() {
        return;
    }
    let server = VNC_SERVERS.lock().unwrap()[0].clone();
    if server.lock().unwrap().clients.is_empty() {
        return;
    }

    let mut locked_server = server.lock().unwrap();
    let dirty_num = locked_server.update_server_image();
    if dirty_num != 0 {
        locked_server.update_interval /= 2;
        if locked_server.update_interval < DISPLAY_UPDATE_INTERVAL_DEFAULT {
            locked_server.update_interval = DISPLAY_UPDATE_INTERVAL_DEFAULT
        }
    } else {
        locked_server.update_interval += DISPLAY_UPDATE_INTERVAL_INC;
        if locked_server.update_interval > DISPLAY_UPDATE_INTERVAL_MAX {
            locked_server.update_interval = DISPLAY_UPDATE_INTERVAL_MAX;
        }
    }

    let mut _rects: i32 = 0;
    for client in locked_server.clients.values_mut() {
        _rects += client.lock().unwrap().get_rects(dirty_num);
    }
}
