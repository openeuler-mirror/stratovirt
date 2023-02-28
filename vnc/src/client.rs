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
    auth::AuthState,
    console::DisplayMouse,
    pixman::{bytes_per_pixel, get_image_height, get_image_width, PixelFormat},
    round_up_div,
    server::VncServer,
    utils::BuffPool,
    vnc::{
        framebuffer_upadate, set_area_dirty, write_pixel, BIT_PER_BYTE, DIRTY_PIXELS_NUM,
        DIRTY_WIDTH_BITS, MAX_IMAGE_SIZE, MAX_WINDOW_HEIGHT, MIN_OUTPUT_LIMIT,
        OUTPUT_THROTTLE_SCALE, VNC_RECT_INFO,
    },
    VncError,
};
use anyhow::{anyhow, Result};
use log::error;
use rustls::ServerConnection;
use sscanf::scanf;
use std::{
    cmp,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    os::unix::prelude::{AsRawFd, RawFd},
    rc::Rc,
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::{
        gen_delete_notifiers, read_fd, EventNotifier, EventNotifierHelper, NotifierCallback,
        NotifierOperation,
    },
};
use vmm_sys_util::{epoll::EventSet, eventfd::EventFd};

pub const APP_NAME: &str = "stratovirt";
const MAX_RECVBUF_LEN: usize = 1024;
const MAX_SEND_LEN: usize = 64 * 1024;
const NUM_OF_COLORMAP: u16 = 256;

// VNC encodings types.
pub const ENCODING_RAW: i32 = 0;
pub const ENCODING_HEXTILE: i32 = 5;
const ENCODING_ZLIB: i32 = 6;
const ENCODING_TIGHT: i32 = 7;
const ENCODING_ZRLE: i32 = 16;
const ENCODING_ZYWRLE: i32 = 17;
const ENCODING_DESKTOPRESIZE: i32 = -223;
pub const ENCODING_RICH_CURSOR: i32 = -239;
const ENCODING_POINTER_TYPE_CHANGE: i32 = -257;
const ENCODING_LED_STATE: i32 = -261;
const ENCODING_DESKTOP_RESIZE_EXT: i32 = -308;
pub const ENCODING_ALPHA_CURSOR: i32 = -314;
const ENCODING_WMVI: i32 = 1464686185;

/// Image display feature.
pub enum VncFeatures {
    VncFeatureResize,
    VncFeatureResizeExt,
    VncFeatureHextile,
    VncFeaturePointerTypeChange,
    VncFeatureWmvi,
    VncFeatureTight,
    VncFeatureZlib,
    VncFeatureRichCursor,
    VncFeatureAlphaCursor,
    VncFeatureTightPng,
    VncFeatureZrle,
    VncFeatureZywrle,
    VncFeatureLedState,
    VncFeatureXvp,
    VncFeatureClipboardExt,
}

/// Client to server message in Remote Framebuffer Protocol.
pub enum ClientMsg {
    SetPixelFormat = 0,
    SetEncodings = 2,
    FramebufferUpdateRequest = 3,
    KeyEvent = 4,
    PointerEvent = 5,
    ClientCutText = 6,
    InvalidMsg,
}

/// Server to client message in Remote Framebuffer Protocol.
pub enum ServerMsg {
    FramebufferUpdate = 0,
    SetColourMapEntries = 1,
}

impl From<u8> for ClientMsg {
    fn from(v: u8) -> Self {
        match v {
            0 => ClientMsg::SetPixelFormat,
            2 => ClientMsg::SetEncodings,
            3 => ClientMsg::FramebufferUpdateRequest,
            4 => ClientMsg::KeyEvent,
            5 => ClientMsg::PointerEvent,
            6 => ClientMsg::ClientCutText,
            _ => ClientMsg::InvalidMsg,
        }
    }
}

/// RFB protocol version.
#[derive(Clone)]
pub struct VncVersion {
    pub major: u16,
    pub minor: u16,
}

impl VncVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        VncVersion { major, minor }
    }
}

impl Default for VncVersion {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

#[derive(PartialEq, Eq)]
pub enum UpdateState {
    No,
    Incremental,
    Force,
}

/// Dirty area of image
#[derive(Clone)]
pub struct Rectangle {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rectangle {
    pub fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Rectangle { x, y, w, h }
    }
}

/// Display Output mode information of client.
#[derive(Clone)]
pub struct DisplayMode {
    /// Vnc display feature.
    feature: i32,
    /// Width of client display.
    pub client_width: i32,
    /// Height of client display.
    pub client_height: i32,
    /// Encoding type.
    pub enc: i32,
    /// Data storage type for client.
    pub client_be: bool,
    /// The pixel need to convert.
    pub convert: bool,
    /// Image pixel format in pixman.
    pub pf: PixelFormat,
}

impl DisplayMode {
    pub fn new(enc: i32, client_be: bool, convert: bool, pf: PixelFormat) -> Self {
        DisplayMode {
            feature: 0,
            client_width: 0,
            client_height: 0,
            enc,
            client_be,
            convert,
            pf,
        }
    }

    pub fn has_feature(&self, feature: VncFeatures) -> bool {
        self.feature & (1 << feature as usize) != 0
    }
}

impl Default for DisplayMode {
    fn default() -> Self {
        Self::new(0, false, false, PixelFormat::default())
    }
}

pub struct RectInfo {
    /// Vnc client state.
    pub client: Arc<ClientState>,
    /// Dirty area of image.
    pub rects: Vec<Rectangle>,
}

impl RectInfo {
    pub fn new(client: &Arc<ClientState>, rects: Vec<Rectangle>) -> Self {
        RectInfo {
            client: client.clone(),
            rects,
        }
    }
}

impl Clone for RectInfo {
    fn clone(&self) -> Self {
        let mut rects = Vec::new();
        for rect in &self.rects {
            rects.push(rect.clone());
        }
        Self {
            client: self.client.clone(),
            rects,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

/// The connection state of vnc client.
pub struct ConnState {
    /// Dirty number need to update.
    dirty_num: i32,
    /// Connection status.
    pub dis_conn: bool,
    /// State flags whether the image needs to be updated for the client.
    update_state: UpdateState,
    /// RFB protocol version.
    pub version: VncVersion,
}

impl Default for ConnState {
    fn default() -> Self {
        ConnState {
            dirty_num: 0,
            dis_conn: false,
            update_state: UpdateState::No,
            version: VncVersion::default(),
        }
    }
}

impl ConnState {
    pub fn is_disconnect(&mut self) -> bool {
        self.dis_conn
    }

    /// Whether the client's image data needs to be updated.
    pub fn is_need_update(&mut self) -> bool {
        if self.is_disconnect() {
            return false;
        }

        match self.update_state {
            UpdateState::No => false,
            UpdateState::Incremental => self.dirty_num > 0,
            UpdateState::Force => true,
        }
    }

    pub fn clear_update_state(&mut self) {
        self.dirty_num = 0;
        self.update_state = UpdateState::No;
    }
}

/// Struct to record the state with the vnc client.
pub struct ClientState {
    /// Tcp listening address.
    pub addr: String,
    /// Disconnect event fd.
    pub disconn_evt: Arc<Mutex<EventFd>>,
    /// Write event fd.
    write_fd: Arc<Mutex<EventFd>>,
    /// TcpStream receive buffer.
    pub in_buffer: Arc<Mutex<BuffPool>>,
    /// TcpStream write buffer.
    pub out_buffer: Arc<Mutex<BuffPool>>,
    /// Output mode information of client display.
    pub client_dpm: Arc<Mutex<DisplayMode>>,
    /// The connection state of vnc client.
    pub conn_state: Arc<Mutex<ConnState>>,
    /// Identify the image update area.
    pub dirty_bitmap: Arc<Mutex<Bitmap<u64>>>,
}

impl ClientState {
    pub fn new(addr: String) -> Self {
        ClientState {
            addr,
            disconn_evt: Arc::new(Mutex::new(EventFd::new(libc::EFD_NONBLOCK).unwrap())),
            write_fd: Arc::new(Mutex::new(EventFd::new(libc::EFD_NONBLOCK).unwrap())),
            in_buffer: Arc::new(Mutex::new(BuffPool::new())),
            out_buffer: Arc::new(Mutex::new(BuffPool::new())),
            client_dpm: Arc::new(Mutex::new(DisplayMode::default())),
            conn_state: Arc::new(Mutex::new(ConnState::default())),
            dirty_bitmap: Arc::new(Mutex::new(Bitmap::<u64>::new(
                MAX_WINDOW_HEIGHT as usize
                    * round_up_div(DIRTY_WIDTH_BITS as u64, u64::BITS as u64) as usize,
            ))),
        }
    }
}

/// Handle the message with vnc client.
pub struct ClientIoHandler {
    /// TcpStream connected with client.
    pub stream: TcpStream,
    /// Tls server connection.
    pub tls_conn: Option<rustls::ServerConnection>,
    /// Message handler.
    pub msg_handler: fn(&mut ClientIoHandler) -> Result<()>,
    /// Size of buff in next handle.
    pub expect: usize,
    /// State with vnc client.
    pub client: Arc<ClientState>,
    /// Configure for vnc server.
    pub server: Arc<VncServer>,
}

impl ClientIoHandler {
    pub fn new(stream: TcpStream, client: Arc<ClientState>, server: Arc<VncServer>) -> Self {
        ClientIoHandler {
            stream,
            tls_conn: None,
            msg_handler: ClientIoHandler::handle_version,
            expect: 12,
            client,
            server,
        }
    }
}

impl ClientIoHandler {
    /// This function interacts with the client interface, it includs several
    /// steps: Read the data stream from the fd, save the data in buffer,
    /// and then process the data by io handle function.
    fn client_handle_read(&mut self) -> Result<(), anyhow::Error> {
        self.read_msg()?;

        let client = self.client.clone();
        while client.in_buffer.lock().unwrap().len() >= self.expect {
            (self.msg_handler)(self)?;

            if self.client.conn_state.lock().unwrap().dis_conn {
                return Err(anyhow!(VncError::Disconnection));
            }

            if self.expect == 0 {
                break;
            }
        }

        Ok(())
    }

    /// Write a chunk of data to client socket. If there is some
    /// error in io channel, then return and break the connnection.
    fn client_handle_write(&mut self) {
        let client = self.client.clone();
        if client.conn_state.lock().unwrap().dis_conn {
            return;
        }

        let mut locked_buffer = client.out_buffer.lock().unwrap();
        while let Some(bytes) = locked_buffer.read_front_chunk() {
            let message_len = bytes.len();
            let send_len = match self.write_msg(bytes) {
                Ok(ret) => ret,
                Err(_e) => {
                    self.client.conn_state.lock().unwrap().dis_conn = true;
                    return;
                }
            };

            locked_buffer.remove_front(send_len);
            if send_len != message_len {
                break;
            }
        }

        if !locked_buffer.is_empty() {
            vnc_flush(&client);
        }

        drop(locked_buffer);
    }

    /// Read buf from stream, return the size.
    fn read_msg(&mut self) -> Result<usize> {
        let mut buf = Vec::new();
        let mut len: usize = 0;
        if self.tls_conn.is_none() {
            match self.read_plain_msg(&mut buf) {
                Ok(n) => len = n,
                Err(e) => return Err(e),
            }
        }
        if let Some(tc) = &self.tls_conn {
            if tc.is_handshaking() {
                return Ok(0_usize);
            }
        }
        if self.tls_conn.is_some() {
            match self.read_tls_msg(&mut buf) {
                Ok(n) => len = n,
                Err(e) => return Err(e),
            }
        }
        if len > 0 {
            buf = buf[..len].to_vec();
            self.client.in_buffer.lock().unwrap().append_limit(buf);
        }

        Ok(len)
    }

    // Read from vencrypt channel.
    fn read_tls_msg(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        if self.tls_conn.is_none() {
            return Ok(0_usize);
        }
        let tc: &mut ServerConnection = match &mut self.tls_conn {
            Some(sc) => sc,
            None => return Ok(0_usize),
        };

        if let Err(e) = tc.read_tls(&mut self.stream) {
            error!("tls_conn read error {:?}", e);
            return Err(anyhow!(VncError::ReadMessageFailed(format!(
                "tls_conn read error {:?}",
                e
            ))));
        }

        if let Ok(io_state) = tc.process_new_packets() {
            if io_state.plaintext_bytes_to_read() > 0 {
                len = io_state.plaintext_bytes_to_read();
                buf.resize(len, 0u8);
                if let Err(e) = tc.reader().read_exact(buf) {
                    error!("tls_conn read error {:?}", e);
                    buf.clear();
                    return Err(anyhow!(VncError::ReadMessageFailed(format!(
                        "tls_conn read error {:?}",
                        e
                    ))));
                }
            }
        }
        Ok(len)
    }

    /// Read plain txt.
    fn read_plain_msg(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        buf.resize(MAX_RECVBUF_LEN, 0u8);
        match self.stream.read(buf) {
            Ok(ret) => len = ret,
            Err(e) => error!("read msg error: {:?}", e),
        }

        Ok(len)
    }

    /// Write buf to stream
    /// Choose different channel according to whether or not to encrypt
    pub fn write_msg(&mut self, buf: &[u8]) -> Result<usize> {
        if self.tls_conn.is_none() {
            self.write_plain_msg(buf)
        } else {
            self.write_tls_msg(buf)
        }
    }

    // Send vencrypt message.
    fn write_tls_msg(&mut self, buf: &[u8]) -> Result<usize> {
        let buf_size = buf.len();
        let mut offset = 0;

        let tc: &mut ServerConnection = match &mut self.tls_conn {
            Some(ts) => ts,
            None => {
                return Err(anyhow!(VncError::Disconnection));
            }
        };

        while offset < buf_size {
            let next = cmp::min(buf_size, offset + MAX_SEND_LEN);
            let tmp_buf = &buf[offset..next].to_vec();
            if let Err(e) = tc.writer().write_all(tmp_buf) {
                error!("write msg error: {:?}", e);
                return Err(anyhow!(VncError::Disconnection));
            }
            if let Err(_e) = vnc_write_tls_message(tc, &mut self.stream) {
                self.client.conn_state.lock().unwrap().dis_conn = true;
                return Err(anyhow!(VncError::Disconnection));
            }
            offset = next;
        }

        Ok(buf_size)
    }

    /// Send plain txt.
    fn write_plain_msg(&mut self, buf: &[u8]) -> Result<usize> {
        let buf_size = buf.len();
        let mut offset = 0;
        while offset < buf_size {
            let tmp_buf = &buf[offset..];
            match self.stream.write(tmp_buf) {
                Ok(ret) => {
                    offset += ret;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(offset);
                }
                Err(e) => {
                    error!("write msg error: {:?}", e);
                    return Err(anyhow!(VncError::Disconnection));
                }
            }
        }

        Ok(buf_size)
    }

    /// Exchange RFB protocol version with client.
    fn handle_version(&mut self) -> Result<()> {
        let client = self.client.clone();
        let buf = self.read_incoming_msg();
        let res = String::from_utf8_lossy(&buf);
        let ver_str = &res[0..12].to_string();
        let ver = match scanf!(ver_str, "RFB {usize:/\\d\\{3\\}/}.{usize:/\\d\\{3\\}/}\n") {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("Unsupport RFB version: {}", e);
                error!("{}", msg);
                return Err(anyhow!(VncError::UnsupportRFBProtocolVersion));
            }
        };

        let mut version = VncVersion::new(ver.0 as u16, ver.1 as u16);
        if version.major != 3 || ![3, 4, 5, 7, 8].contains(&version.minor) {
            let mut buf = Vec::new();
            buf.append(&mut (AuthState::Invalid as u32).to_be_bytes().to_vec());
            vnc_write(&client, buf);
            vnc_flush(&client);
            return Err(anyhow!(VncError::UnsupportRFBProtocolVersion));
        }

        if [4, 5].contains(&version.minor) {
            version.minor = 3;
        }
        self.client.conn_state.lock().unwrap().version = version;
        let auth = self.server.security_type.borrow().auth;

        if self.client.conn_state.lock().unwrap().version.minor == 3 {
            error!("Waiting for handle minor=3 ...");
            match auth {
                AuthState::No => {
                    let mut buf = Vec::new();
                    buf.append(&mut (AuthState::No as u32).to_be_bytes().to_vec());
                    vnc_write(&client, buf);
                    self.update_event_handler(1, ClientIoHandler::handle_client_init);
                }
                _ => {
                    self.auth_failed("Unsupported auth method");
                    return Err(anyhow!(VncError::AuthFailed(String::from(
                        "Unsupported auth method"
                    ))));
                }
            }
        } else {
            let mut buf = [0u8; 2];
            buf[0] = 1; // Number of security types.
            buf[1] = auth as u8;
            vnc_write(&client, buf.to_vec());
            self.update_event_handler(1, ClientIoHandler::handle_auth);
        }
        vnc_flush(&client);
        Ok(())
    }

    /// Initialize the connection of vnc client.
    pub fn handle_client_init(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        // If the total number of connection exceeds the limit,
        // then the old client will be disconnected.
        let server = self.server.clone();
        let client = self.client.clone();
        let addr = client.addr.clone();
        let mut locked_clients = server.client_handlers.lock().unwrap();
        let mut len = locked_clients.len() as i32;
        for client in locked_clients.values_mut() {
            if len <= server.conn_limits as i32 {
                break;
            }
            if client.addr != addr {
                vnc_disconnect_start(client);
                len -= 1;
            }
        }
        drop(locked_clients);

        // Send server framebuffer info.
        let locked_surface = self.server.vnc_surface.lock().unwrap();
        let width = get_image_width(locked_surface.server_image);
        let height = get_image_height(locked_surface.server_image);
        drop(locked_surface);
        if !(0..=MAX_IMAGE_SIZE).contains(&width) || !(0..=MAX_IMAGE_SIZE).contains(&height) {
            error!("Invalid Image Size!");
            return Err(anyhow!(VncError::InvalidImageSize));
        }
        let mut locked_dpm = client.client_dpm.lock().unwrap();
        locked_dpm.client_width = width;
        locked_dpm.client_height = height;
        drop(locked_dpm);

        buf.append(&mut (width as u16).to_be_bytes().to_vec());
        buf.append(&mut (height as u16).to_be_bytes().to_vec());
        pixel_format_message(&client, &mut buf);

        buf.append(&mut (APP_NAME.to_string().len() as u32).to_be_bytes().to_vec());
        buf.append(&mut APP_NAME.to_string().as_bytes().to_vec());
        vnc_write(&client, buf);
        vnc_flush(&client);
        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
        Ok(())
    }

    /// Authentication
    fn handle_auth(&mut self) -> Result<()> {
        let buf = self.read_incoming_msg();
        let auth = self.server.security_type.borrow().auth;
        let client = self.client.clone();
        let version = client.conn_state.lock().unwrap().version.clone();

        if buf[0] != auth as u8 {
            self.auth_failed("Authentication failed");
            error!("handle_auth");
            return Err(anyhow!(VncError::AuthFailed(String::from("handle_auth"))));
        }

        match auth {
            AuthState::No => {
                if version.minor >= 8 {
                    let buf = [0u8; 4];
                    vnc_write(&client, buf.to_vec());
                }
                self.update_event_handler(1, ClientIoHandler::handle_client_init);
            }
            AuthState::Vencrypt => {
                // Send VeNCrypt version 0.2.
                let mut buf = [0u8; 2];
                buf[0] = 0_u8;
                buf[1] = 2_u8;

                vnc_write(&client, buf.to_vec());
                self.update_event_handler(2, ClientIoHandler::client_vencrypt_init);
            }
            _ => {
                self.auth_failed("Unhandled auth method");
                error!("handle_auth");
                return Err(anyhow!(VncError::AuthFailed(String::from("handle_auth"))));
            }
        }
        vnc_flush(&client);
        Ok(())
    }

    /// Process the data sent by the client
    pub fn handle_protocol_msg(&mut self) -> Result<()> {
        // According to RFB protocol, first byte identifies the event type.
        let buf = self.read_incoming_msg();
        match ClientMsg::from(buf[0]) {
            ClientMsg::SetPixelFormat => {
                return self.set_pixel_format();
            }
            ClientMsg::SetEncodings => {
                return self.set_encodings();
            }
            ClientMsg::FramebufferUpdateRequest => {
                self.update_frame_buff();
            }
            ClientMsg::KeyEvent => {
                self.key_envent();
            }
            ClientMsg::PointerEvent => {
                self.point_event();
            }
            ClientMsg::ClientCutText => {
                self.client_cut_event();
            }
            _ => {
                self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
            }
        }
        Ok(())
    }

    /// Tell the client that the specified pixel values should be
    /// mapped to the given RGB intensities.
    fn send_color_map(&mut self) {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(
            &mut (ServerMsg::SetColourMapEntries as u8)
                .to_be_bytes()
                .to_vec(),
        );
        buf.append(&mut (0_u8).to_be_bytes().to_vec());
        // First color.
        buf.append(&mut (0_u16).to_be_bytes().to_vec());
        // Number of colors.
        buf.append(&mut NUM_OF_COLORMAP.to_be_bytes().to_vec());

        let pf = self.client.client_dpm.lock().unwrap().pf.clone();
        for i in 0..NUM_OF_COLORMAP {
            let r = ((i >> pf.red.shift) & pf.red.max as u16) << (16 - pf.red.bits);
            let g = ((i >> pf.green.shift) & pf.green.max as u16) << (16 - pf.green.bits);
            let b = ((i >> pf.blue.shift) & pf.blue.max as u16) << (16 - pf.blue.bits);
            buf.append(&mut r.to_be_bytes().to_vec());
            buf.append(&mut g.to_be_bytes().to_vec());
            buf.append(&mut b.to_be_bytes().to_vec());
        }

        let client = self.client.clone();
        vnc_write(&client, buf);
        vnc_flush(&client);
    }

    /// Set image format.
    fn set_pixel_format(&mut self) -> Result<()> {
        if self.expect == 1 {
            self.expect = 20;
            return Ok(());
        }

        let buf = self.read_incoming_msg();
        let mut bit_per_pixel: u8 = buf[4];
        let big_endian_flag = buf[6];
        let true_color_flag: u8 = buf[7];
        let mut red_max: u16 = u16::from_be_bytes([buf[8], buf[9]]);
        let mut green_max: u16 = u16::from_be_bytes([buf[10], buf[11]]);
        let mut blue_max: u16 = u16::from_be_bytes([buf[12], buf[13]]);
        let mut red_shift: u8 = buf[14];
        let mut green_shift: u8 = buf[15];
        let mut blue_shift: u8 = buf[16];
        if true_color_flag == 0 {
            bit_per_pixel = 8;
            red_max = 7;
            green_max = 7;
            blue_max = 3;
            red_shift = 0;
            green_shift = 3;
            blue_shift = 6;
        }

        // Verify the validity of pixel format.
        // bit_per_pixel: Bits occupied by each pixel.
        if ![8, 16, 32].contains(&bit_per_pixel) {
            self.client.conn_state.lock().unwrap().dis_conn = true;
            error!("Worng format of bits_per_pixel");
            return Err(anyhow!(VncError::ProtocolMessageFailed(String::from(
                "set pixel format"
            ))));
        }

        let mut locked_dpm = self.client.client_dpm.lock().unwrap();
        locked_dpm.pf.red.set_color_info(red_shift, red_max);
        locked_dpm.pf.green.set_color_info(green_shift, green_max);
        locked_dpm.pf.blue.set_color_info(blue_shift, blue_max);
        locked_dpm.pf.pixel_bits = bit_per_pixel;
        locked_dpm.pf.pixel_bytes = bit_per_pixel / BIT_PER_BYTE as u8;
        // Standard pixel format, depth is equal to 24.
        locked_dpm.pf.depth = if bit_per_pixel == 32 {
            24
        } else {
            bit_per_pixel
        };
        locked_dpm.client_be = big_endian_flag != 0;

        if !locked_dpm.pf.is_default_pixel_format() {
            locked_dpm.convert = true;
        }
        drop(locked_dpm);
        if true_color_flag == 0 {
            self.send_color_map();
        }

        VNC_RECT_INFO.lock().unwrap().clear();
        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
        Ok(())
    }

    /// Set encoding.
    fn set_encodings(&mut self) -> Result<()> {
        let client = self.client.clone();
        let server = self.server.clone();
        let buf = self.read_incoming_msg();
        if self.expect == 1 {
            self.expect = 4;
            return Ok(());
        }

        let mut num_encoding: u16;
        if self.expect == 4 {
            num_encoding = u16::from_be_bytes([buf[2], buf[3]]);
            if num_encoding > 0 {
                self.expect = 4 + (num_encoding as usize) * 4;
                return Ok(());
            }
        } else {
            num_encoding = u16::from_be_bytes([buf[2], buf[3]]);
        }

        let mut locked_dpm = self.client.client_dpm.lock().unwrap();
        locked_dpm.feature = 0;
        locked_dpm.enc = 0;
        while num_encoding > 0 {
            let offset = (4 * num_encoding) as usize;
            let enc = i32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]);
            match enc {
                ENCODING_RAW => {
                    locked_dpm.enc = enc;
                }
                ENCODING_HEXTILE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureHextile as usize;
                    locked_dpm.enc = enc;
                }
                ENCODING_TIGHT => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureTight as usize;
                    locked_dpm.enc = enc;
                }
                ENCODING_ZLIB => {
                    // ZRLE compress better than ZLIB, so prioritize ZRLE.
                    if locked_dpm.feature & (1 << VncFeatures::VncFeatureZrle as usize) == 0 {
                        locked_dpm.feature |= 1 << VncFeatures::VncFeatureZlib as usize;
                        locked_dpm.enc = enc;
                    }
                }
                ENCODING_ZRLE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureZrle as usize;
                    locked_dpm.enc = enc;
                }
                ENCODING_ZYWRLE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureZywrle as usize;
                    locked_dpm.enc = enc;
                }
                ENCODING_DESKTOPRESIZE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureResize as usize;
                }
                ENCODING_DESKTOP_RESIZE_EXT => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureResizeExt as usize;
                }
                ENCODING_POINTER_TYPE_CHANGE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeaturePointerTypeChange as usize;
                }
                ENCODING_RICH_CURSOR => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureRichCursor as usize;
                }
                ENCODING_ALPHA_CURSOR => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureAlphaCursor as usize;
                }
                ENCODING_WMVI => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureWmvi as usize;
                }
                ENCODING_LED_STATE => {
                    locked_dpm.feature |= 1 << VncFeatures::VncFeatureLedState as usize;
                }
                _ => {}
            }

            num_encoding -= 1;
        }

        drop(locked_dpm);
        let mut buf: Vec<u8> = Vec::new();
        // VNC desktop resize.
        desktop_resize(&client, &server, &mut buf);
        // VNC display cursor define.
        display_cursor_define(&client, &server, &mut buf);
        vnc_write(&client, buf);
        vnc_flush(&client);
        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
        Ok(())
    }

    /// Update image for client.
    fn update_frame_buff(&mut self) {
        if self.expect == 1 {
            self.expect = 10;
            return;
        }
        let buf = self.read_incoming_msg();
        let locked_dpm = self.client.client_dpm.lock().unwrap();
        let width = locked_dpm.client_width;
        let height = locked_dpm.client_height;
        drop(locked_dpm);
        let client = self.client.clone();
        let mut locked_state = client.conn_state.lock().unwrap();
        if buf[1] != 0 {
            if locked_state.update_state != UpdateState::Force {
                locked_state.update_state = UpdateState::Incremental;
            }
        } else {
            locked_state.update_state = UpdateState::Force;
            let x = u16::from_be_bytes([buf[2], buf[3]]) as i32;
            let y = u16::from_be_bytes([buf[4], buf[5]]) as i32;
            let w = u16::from_be_bytes([buf[6], buf[7]]) as i32;
            let h = u16::from_be_bytes([buf[8], buf[9]]) as i32;
            set_area_dirty(
                &mut client.dirty_bitmap.lock().unwrap(),
                x,
                y,
                w,
                h,
                width,
                height,
            );
        }
        drop(locked_state);
        self.update_event_handler(1, ClientIoHandler::handle_protocol_msg);
    }

    /// Invalid authentication, send 1 to reject.
    fn auth_failed(&mut self, msg: &str) {
        let auth_rej: u8 = 1;
        let mut buf: Vec<u8> = vec![1u8];
        buf.append(&mut (auth_rej as u32).to_be_bytes().to_vec());
        // If the RFB protocol version is above 3.8, an error reason will be returned.
        if self.client.conn_state.lock().unwrap().version.minor >= 8 {
            let err_msg = msg;
            buf.append(&mut (err_msg.len() as u32).to_be_bytes().to_vec());
            buf.append(&mut err_msg.as_bytes().to_vec());
        }
        let client = self.client.clone();
        vnc_write(&client, buf);
        vnc_flush(&client);
    }

    /// Read the data from the receiver buffer.
    pub fn read_incoming_msg(&mut self) -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0_u8; self.expect];
        let mut locked_in_buffer = self.client.in_buffer.lock().unwrap();
        let _size: usize = locked_in_buffer.read_front(&mut buf, self.expect);
        buf
    }

    /// Action token after the event.
    ///
    /// # Arguments
    ///
    /// * `expect` - the size of bytes of next callback function.
    /// * `msg_handler` - callback function of the next event.
    pub fn update_event_handler(
        &mut self,
        expect: usize,
        msg_handler: fn(&mut ClientIoHandler) -> Result<()>,
    ) {
        self.client
            .in_buffer
            .lock()
            .unwrap()
            .remove_front(self.expect);
        self.expect = expect;
        self.msg_handler = msg_handler;
    }

    fn disconn_evt_handler(&mut self) -> Vec<EventNotifier> {
        let notifiers_fds = vec![
            self.stream.as_raw_fd(),
            self.client.write_fd.lock().unwrap().as_raw_fd(),
            self.client.disconn_evt.lock().unwrap().as_raw_fd(),
        ];
        gen_delete_notifiers(&notifiers_fds)
    }
}

/// Internal notifiers for Client message.
impl EventNotifierHelper for ClientIoHandler {
    fn internal_notifiers(client_io_handler: Arc<Mutex<ClientIoHandler>>) -> Vec<EventNotifier> {
        let mut notifiers: Vec<EventNotifier> = Vec::new();

        // Register event notifier for read.
        let client_io = client_io_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |event, _fd: RawFd| {
            let mut locked_client_io = client_io.lock().unwrap();
            let client = locked_client_io.client.clone();
            if event & EventSet::ERROR == EventSet::ERROR
                || event & EventSet::HANG_UP == EventSet::HANG_UP
                || event & EventSet::READ_HANG_UP == EventSet::READ_HANG_UP
            {
                client.conn_state.lock().unwrap().dis_conn = true;
            } else if event & EventSet::IN == EventSet::IN {
                if let Err(_e) = locked_client_io.client_handle_read() {
                    client.conn_state.lock().unwrap().dis_conn = true;
                }
            }
            // Do disconnection event.
            if client.conn_state.lock().unwrap().is_disconnect() {
                vnc_disconnect_start(&client);
            }
            drop(locked_client_io);
            None
        });
        let client_io = client_io_handler.clone();
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            client_io.lock().unwrap().stream.as_raw_fd(),
            None,
            EventSet::IN | EventSet::READ_HANG_UP,
            vec![handler],
        ));

        // Register event notifier for write.
        let client_io = client_io_handler.clone();
        let client = client_io.lock().unwrap().client.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_event, fd| {
            read_fd(fd);
            let mut locked_client_io = client_io.lock().unwrap();
            let client = locked_client_io.client.clone();
            locked_client_io.client_handle_write();
            // do disconnection event.
            if client.conn_state.lock().unwrap().is_disconnect() {
                vnc_disconnect_start(&client);
            }
            drop(locked_client_io);
            None
        });
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            client.write_fd.lock().unwrap().as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        // Register event for disconnect.
        let client_io = client_io_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_event, fd| {
            read_fd(fd);
            // Drop client info from vnc server.
            let mut locked_client_io = client_io.lock().unwrap();
            let client = locked_client_io.client.clone();
            let addr = client.addr.clone();
            let server = locked_client_io.server.clone();
            let notifiers = locked_client_io.disconn_evt_handler();
            // Shutdown stream.
            if let Err(e) = locked_client_io.stream.shutdown(Shutdown::Both) {
                error!("Shutdown stream failed: {}", e);
            }
            drop(locked_client_io);
            server.client_handlers.lock().unwrap().remove(&addr);
            Some(notifiers)
        });
        let client = client_io_handler.lock().unwrap().client.clone();
        notifiers.push(EventNotifier::new(
            NotifierOperation::AddShared,
            client.disconn_evt.lock().unwrap().as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        ));

        notifiers
    }
}

/// Generate the data that needs to be sent.
/// Add to send queue
pub fn get_rects(client: &Arc<ClientState>, dirty_num: i32) {
    let mut locked_state = client.conn_state.lock().unwrap();
    let num = locked_state.dirty_num;
    locked_state.dirty_num = num.checked_add(dirty_num).unwrap_or(0);
    if !locked_state.is_need_update() {
        return;
    }
    drop(locked_state);

    let mut x: u64;
    let mut y: u64 = 0;
    let mut h: u64;
    let mut x2: u64;
    let mut rects = Vec::new();
    let locked_dpm = client.client_dpm.lock().unwrap();
    let height = locked_dpm.client_height as u64;
    let width = locked_dpm.client_width as u64;
    drop(locked_dpm);
    let mut locked_dirty = client.dirty_bitmap.lock().unwrap();
    let bpl = locked_dirty.vol() / MAX_WINDOW_HEIGHT as usize;

    loop {
        // Find the first non-zero bit in dirty bitmap.
        let offset = locked_dirty.find_next_bit(y as usize * bpl).unwrap() as u64;
        if offset >= height * bpl as u64 {
            break;
        }

        x = offset % bpl as u64;
        y = offset / bpl as u64;
        // Find value in one line to the end.
        x2 = locked_dirty.find_next_zero(offset as usize).unwrap() as u64 % bpl as u64;
        let mut i = y;
        while i < height {
            if !locked_dirty.contain((i * bpl as u64 + x) as usize).unwrap() {
                break;
            }
            let start = (i * bpl as u64 + x) as usize;
            let len = (x2 - x) as usize;
            if let Err(e) = locked_dirty.clear_range(start, len) {
                error!("clear bitmap error: {:?}", e);
                return;
            }
            i += 1;
        }

        h = i - y;
        x2 = cmp::min(x2, width / DIRTY_PIXELS_NUM as u64);
        if x2 > x {
            rects.push(Rectangle::new(
                (x * DIRTY_PIXELS_NUM as u64) as i32,
                y as i32,
                ((x2 - x) * DIRTY_PIXELS_NUM as u64) as i32,
                h as i32,
            ));
        }

        if x == 0 && x2 == width / DIRTY_PIXELS_NUM as u64 {
            y += h;
            if y == height {
                break;
            }
        }
    }

    drop(locked_dirty);
    VNC_RECT_INFO
        .lock()
        .unwrap()
        .push(RectInfo::new(client, rects));

    client.conn_state.lock().unwrap().clear_update_state();
}

fn vnc_write_tls_message(tc: &mut ServerConnection, stream: &mut TcpStream) -> Result<()> {
    while tc.wants_write() {
        match tc.write_tls(stream) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    stream.flush().unwrap();
                    continue;
                } else {
                    error!("write msg error: {:?}", e);
                    return Err(anyhow!(VncError::Disconnection));
                }
            }
        }
    }

    Ok(())
}

/// Set pixformat for client.
pub fn pixel_format_message(client: &Arc<ClientState>, buf: &mut Vec<u8>) {
    let mut locked_dpm = client.client_dpm.lock().unwrap();
    locked_dpm.pf.init_pixelformat();
    let big_endian: u8 = u8::from(cfg!(target_endian = "big"));
    buf.append(&mut locked_dpm.pf.pixel_bits.to_be_bytes().to_vec()); // Bit per pixel.
    buf.append(&mut locked_dpm.pf.depth.to_be_bytes().to_vec()); // Depth.
    buf.append(&mut big_endian.to_be_bytes().to_vec()); // Big-endian flag.
    buf.append(&mut (1_u8).to_be_bytes().to_vec()); // True-color flag.
    buf.append(&mut (locked_dpm.pf.red.max as u16).to_be_bytes().to_vec()); // Red max.
    buf.append(&mut (locked_dpm.pf.green.max as u16).to_be_bytes().to_vec()); // Green max.
    buf.append(&mut (locked_dpm.pf.blue.max as u16).to_be_bytes().to_vec()); // Blue max.
    buf.append(&mut locked_dpm.pf.red.shift.to_be_bytes().to_vec()); // Red shift.
    buf.append(&mut locked_dpm.pf.green.shift.to_be_bytes().to_vec()); // Green shift.
    buf.append(&mut locked_dpm.pf.blue.shift.to_be_bytes().to_vec()); // Blue shift.
    buf.append(&mut [0; 3].to_vec()); // Padding.
    drop(locked_dpm);
}

/// Set Desktop Size.
pub fn desktop_resize(client: &Arc<ClientState>, server: &Arc<VncServer>, buf: &mut Vec<u8>) {
    let locked_surface = server.vnc_surface.lock().unwrap();
    let width = get_image_width(locked_surface.server_image);
    let height = get_image_height(locked_surface.server_image);
    if !(0..=MAX_IMAGE_SIZE as i32).contains(&width)
        || !(0..=MAX_IMAGE_SIZE as i32).contains(&height)
    {
        error!("Invalid Image Size!");
        return;
    }
    drop(locked_surface);
    let mut locked_dpm = client.client_dpm.lock().unwrap();
    if (!locked_dpm.has_feature(VncFeatures::VncFeatureResizeExt)
        && !locked_dpm.has_feature(VncFeatures::VncFeatureResize))
        || (locked_dpm.client_width == width && locked_dpm.client_height == height)
    {
        return;
    }
    locked_dpm.client_width = width;
    locked_dpm.client_height = height;
    drop(locked_dpm);

    buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
    buf.append(&mut (0_u8).to_be_bytes().to_vec());
    buf.append(&mut (1_u16).to_be_bytes().to_vec());
    framebuffer_upadate(0, 0, width, height, ENCODING_DESKTOPRESIZE, buf);
}

/// Set color depth for client.
pub fn set_color_depth(client: &Arc<ClientState>, buf: &mut Vec<u8>) {
    let mut locked_dpm = client.client_dpm.lock().unwrap();
    if locked_dpm.has_feature(VncFeatures::VncFeatureWmvi) {
        let width = client.client_dpm.lock().unwrap().client_width;
        let height = client.client_dpm.lock().unwrap().client_height;
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // Padding.
        buf.append(&mut (1_u16).to_be_bytes().to_vec()); // Number of pixel block.
        framebuffer_upadate(0, 0, width, height, ENCODING_WMVI, buf);
        buf.append(&mut (ENCODING_RAW as u32).to_be_bytes().to_vec());
        pixel_format_message(client, buf);
    } else if !locked_dpm.pf.is_default_pixel_format() {
        locked_dpm.convert = true;
    }
}

/// Send framebuf of mouse to the client.
pub fn display_cursor_define(
    client: &Arc<ClientState>,
    server: &Arc<VncServer>,
    buf: &mut Vec<u8>,
) {
    let mut cursor: DisplayMouse;
    let mut mask: Vec<u8>;
    let locked_cursor = server.vnc_cursor.lock().unwrap();
    match &locked_cursor.cursor {
        Some(c) => {
            cursor = c.clone();
        }
        None => {
            return;
        }
    }
    match &locked_cursor.mask {
        Some(m) => {
            mask = m.clone();
        }
        None => {
            return;
        }
    }
    drop(locked_cursor);
    if cursor.data.is_empty()
        || cursor.data.len() != ((cursor.width * cursor.height) as usize) * bytes_per_pixel()
    {
        return;
    }
    if client
        .client_dpm
        .lock()
        .unwrap()
        .has_feature(VncFeatures::VncFeatureAlphaCursor)
    {
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // padding
        buf.append(&mut (1_u16).to_be_bytes().to_vec()); // number of rects

        framebuffer_upadate(
            cursor.hot_x as i32,
            cursor.hot_y as i32,
            cursor.width as i32,
            cursor.height as i32,
            ENCODING_ALPHA_CURSOR,
            buf,
        );
        buf.append(&mut (ENCODING_RAW as u32).to_be_bytes().to_vec());
        buf.append(&mut cursor.data);
        return;
    }

    if client
        .client_dpm
        .lock()
        .unwrap()
        .has_feature(VncFeatures::VncFeatureRichCursor)
    {
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // padding
        buf.append(&mut (1_u16).to_be_bytes().to_vec()); // number of rects

        framebuffer_upadate(
            cursor.hot_x as i32,
            cursor.hot_y as i32,
            cursor.width as i32,
            cursor.height as i32,
            ENCODING_RICH_CURSOR,
            buf,
        );
        let dpm = client.client_dpm.lock().unwrap().clone();
        let data_size = cursor.width * cursor.height * dpm.pf.pixel_bytes as u32;
        let data_ptr = cursor.data.as_ptr() as *mut u8;
        write_pixel(data_ptr, data_size as usize, &dpm, buf);
        buf.append(&mut mask);
    }
}

pub fn vnc_write(client: &Arc<ClientState>, buf: Vec<u8>) {
    if client.conn_state.lock().unwrap().dis_conn {
        return;
    }
    let mut locked_buffer = client.out_buffer.lock().unwrap();
    if !locked_buffer.is_enough(buf.len()) {
        client.conn_state.lock().unwrap().dis_conn = true;
        return;
    }
    locked_buffer.append_limit(buf);
}

/// Set the limit size of the output buffer to prevent the client
/// from stopping receiving data.
pub fn vnc_update_output_throttle(client: &Arc<ClientState>) {
    let locked_dpm = client.client_dpm.lock().unwrap();
    let width = locked_dpm.client_width;
    let height = locked_dpm.client_height;
    let bytes_per_pixel = locked_dpm.pf.pixel_bytes;
    let mut offset = width * height * (bytes_per_pixel as i32) * OUTPUT_THROTTLE_SCALE;
    drop(locked_dpm);

    offset = cmp::max(offset, MIN_OUTPUT_LIMIT);
    client
        .out_buffer
        .lock()
        .unwrap()
        .set_limit(Some(offset as usize));
}

/// Flush the output buffer.
pub fn vnc_flush(client: &Arc<ClientState>) {
    client
        .write_fd
        .lock()
        .unwrap()
        .write(1)
        .unwrap_or_else(|e| error!("Error occurrs during data flush:{:?}", e));
}

/// Disconnect for vnc client.
pub fn vnc_disconnect_start(client: &Arc<ClientState>) {
    client
        .disconn_evt
        .lock()
        .unwrap()
        .write(1)
        .unwrap_or_else(|e| error!("Error occurrs during disconnection: {:?}", e));
}
