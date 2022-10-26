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
    auth::{AuthState, SubAuthState},
    pixman::{get_image_height, get_image_width, PixelFormat},
    round_up_div,
    server::VncServer,
    utils::BuffPool,
    vnc::{
        framebuffer_upadate, set_area_dirty, update_client_surface, BIT_PER_BYTE, DIRTY_PIXELS_NUM,
        DIRTY_WIDTH_BITS, MAX_WINDOW_HEIGHT, MAX_WINDOW_WIDTH, VNC_RECT_INFO, VNC_SERVERS,
    },
};
use anyhow::{anyhow, Result};
use machine_manager::event_loop::EventLoop;
use sscanf::scanf;
use std::{
    cmp,
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    os::unix::prelude::{AsRawFd, RawFd},
    sync::{Arc, Mutex},
};
use util::{
    bitmap::Bitmap,
    loop_context::{EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation},
    pixman::pixman_image_t,
};
use vmm_sys_util::epoll::EventSet;

const MAX_RECVBUF_LEN: usize = 1024;
const NUM_OF_COLORMAP: u16 = 256;

// VNC encodings types.
pub const ENCODING_RAW: i32 = 0;
const ENCODING_HEXTILE: i32 = 5;
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
struct VncVersion {
    major: u16,
    minor: u16,
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

#[derive(PartialEq)]
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

unsafe impl Send for RectInfo {}
pub struct RectInfo {
    /// TcpStream address.
    pub addr: String,
    /// Dirty area of image.
    pub rects: Vec<Rectangle>,
    pub width: i32,
    pub height: i32,
    /// Encoding type.
    pub encoding: i32,
    /// The pixel need to convert.
    pub convert: bool,
    /// Data storage type for client.
    pub big_endian: bool,
    /// Image pixel format in pixman.
    pub pixel_format: PixelFormat,
    /// Image
    pub image: *mut pixman_image_t,
}

impl RectInfo {
    pub fn new(client: &VncClient, rects: Vec<Rectangle>) -> Self {
        RectInfo {
            addr: client.addr.clone(),
            rects,
            width: client.width,
            height: client.height,
            encoding: client.encoding,
            convert: client.pixel_convert,
            big_endian: client.big_endian,
            pixel_format: client.pixel_format.clone(),
            image: client.server_image,
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
            addr: self.addr.clone(),
            rects,
            width: self.width,
            height: self.height,
            encoding: self.encoding,
            convert: self.convert,
            big_endian: self.big_endian,
            pixel_format: self.pixel_format.clone(),
            image: self.image,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

/// VncClient struct to record the information of connnection.
pub struct VncClient {
    /// TcpStream connected with client.
    pub stream: TcpStream,
    /// TcpStream receive buffer.
    pub buffpool: BuffPool,
    /// Size of buff in next handle.
    pub expect: usize,
    /// Connection status.
    pub dis_conn: bool,
    /// RFB protocol version.
    version: VncVersion,
    /// Auth type.
    auth: AuthState,
    /// SubAuth type.
    pub subauth: SubAuthState,
    /// Message handler.
    pub handle_msg: fn(&mut VncClient) -> Result<()>,
    /// The function handling the connection.
    pub handlers: Vec<Arc<Mutex<Box<NotifierCallback>>>>,
    /// Pointer to VncServer.
    pub server: Arc<Mutex<VncServer>>,
    /// Data storage type for client.
    pub big_endian: bool,
    /// State flags whether the image needs to be updated for the client.
    state: UpdateState,
    /// Identify the image update area.
    pub dirty_bitmap: Bitmap<u64>,
    /// Number of dirty data.
    dirty_num: i32,
    /// Image pixel format in pixman.
    pub pixel_format: PixelFormat,
    /// Image pointer.
    pub server_image: *mut pixman_image_t,
    /// Tcp listening address.
    pub addr: String,
    /// Image width.
    pub width: i32,
    /// Image height.
    pub height: i32,
    /// Encoding type.
    encoding: i32,
    /// Image display feature.
    feature: i32,
    /// The pixel need to convert.
    pixel_convert: bool,
}

impl VncClient {
    pub fn new(
        stream: TcpStream,
        addr: String,
        auth: AuthState,
        subauth: SubAuthState,
        server: Arc<Mutex<VncServer>>,
        image: *mut pixman_image_t,
    ) -> Self {
        VncClient {
            stream,
            buffpool: BuffPool::new(),
            expect: 12,
            dis_conn: false,
            version: VncVersion::default(),
            auth,
            subauth,
            handle_msg: VncClient::handle_version,
            handlers: Vec::new(),
            server,
            big_endian: false,
            state: UpdateState::No,
            dirty_bitmap: Bitmap::<u64>::new(
                MAX_WINDOW_HEIGHT as usize
                    * round_up_div(DIRTY_WIDTH_BITS as u64, u64::BITS as u64) as usize,
            ),
            dirty_num: 0,
            pixel_format: PixelFormat::default(),
            server_image: image,
            addr,
            width: 0,
            height: 0,
            encoding: 0,
            feature: 0,
            pixel_convert: false,
        }
    }

    /// Whether the client's image data needs to be updated.
    pub fn is_need_update(&self) -> bool {
        match self.state {
            UpdateState::No => false,
            UpdateState::Incremental => {
                // throttle_output_offset
                true
            }
            UpdateState::Force => {
                // force_update_offset
                true
            }
        }
    }

    /// Generate the data that needs to be sent.
    /// Add to send queue
    pub fn get_rects(&mut self, dirty_num: i32) -> i32 {
        self.dirty_num += dirty_num;
        if !self.is_need_update() || (self.dirty_num == 0 && self.state != UpdateState::Force) {
            return 0;
        }

        let mut num_rects = 0;
        let mut x: u64;
        let mut y: u64 = 0;
        let mut h: u64;
        let mut x2: u64;
        let mut rects = Vec::new();
        let bpl = self.dirty_bitmap.vol() / MAX_WINDOW_HEIGHT as usize;

        let height = get_image_height(self.server_image) as u64;
        let width = get_image_width(self.server_image) as u64;
        loop {
            // Find the first non-zero bit in dirty bitmap.
            let offset = self.dirty_bitmap.find_next_bit(y as usize * bpl).unwrap() as u64;
            if offset >= height as u64 * bpl as u64 {
                break;
            }

            x = offset % bpl as u64;
            y = offset / bpl as u64;
            // Find value in one line to the end.
            x2 = self.dirty_bitmap.find_next_zero(offset as usize).unwrap() as u64 % bpl as u64;
            let mut i = y;
            while i < height {
                if !self
                    .dirty_bitmap
                    .contain((i * bpl as u64 + x) as usize)
                    .unwrap()
                {
                    break;
                }
                for j in x..x2 {
                    self.dirty_bitmap
                        .clear((i * bpl as u64 + j) as usize)
                        .unwrap();
                }
                i += 1;
            }

            h = i - y;
            x2 = cmp::min(x2, width / DIRTY_PIXELS_NUM as u64);
            if x2 > x as u64 {
                rects.push(Rectangle::new(
                    (x * DIRTY_PIXELS_NUM as u64) as i32,
                    y as i32,
                    ((x2 - x) * DIRTY_PIXELS_NUM as u64) as i32,
                    h as i32,
                ));
                num_rects += 1;
            }

            if x == 0 && x2 == width / DIRTY_PIXELS_NUM as u64 {
                y += h;
                if y == height {
                    break;
                }
            }
        }

        VNC_RECT_INFO
            .lock()
            .unwrap()
            .push(RectInfo::new(self, rects));

        self.state = UpdateState::No;
        self.dirty_num = 0;

        num_rects
    }

    /// Modify event notifiers to  event loop
    ///
    /// # Arguments
    ///
    /// * `op` - Notifier operation.
    /// * `idx` - Idx of event in server.handlers
    pub fn modify_event(&mut self, op: NotifierOperation, idx: usize) -> Result<()> {
        let mut handlers = Vec::new();

        if let NotifierOperation::Modify = op {
            if self.handlers.len() <= idx {
                return Ok(());
            }
            handlers.push(self.handlers[idx].clone());
        }

        EventLoop::update_event(
            vec![EventNotifier::new(
                op,
                self.stream.as_raw_fd(),
                None,
                EventSet::IN | EventSet::READ_HANG_UP,
                handlers,
            )],
            None,
        )?;

        Ok(())
    }

    /// Read plain txt.
    pub fn read_plain_msg(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        buf.resize(MAX_RECVBUF_LEN, 0u8);
        match self.stream.read(buf) {
            Ok(ret) => {
                len = ret;
            }
            Err(e) => {
                error!("read msg error: {:?}", e);
            }
        }

        Ok(len)
    }

    /// Send plain txt.
    pub fn write_plain_msg(&mut self, buf: &[u8]) {
        let buf_size = buf.len();
        let mut offset = 0;
        loop {
            let tmp_buf = &buf[offset..];
            match self.stream.write(tmp_buf) {
                Ok(ret) => {
                    offset += ret;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        self.stream.flush().unwrap();
                        continue;
                    } else {
                        error!("write msg error: {:?}", e);
                        return;
                    }
                }
            }
            self.stream.flush().unwrap();
            if offset >= buf_size {
                break;
            }
        }
    }

    /// Write buf to stream
    /// Choose different channel according to whether or not to encrypt
    ///
    /// # Arguments
    /// * `buf` - Data to be send.
    pub fn write_msg(&mut self, buf: &[u8]) {
        self.write_plain_msg(buf);
    }

    /// Read buf from stream, return the size of buff.
    pub fn read_msg(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        self.read_plain_msg(buf)
    }

    /// Read buf from tcpstream.
    pub fn from_tcpstream_to_buff(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        match self.read_msg(&mut buf) {
            Ok(len) => {
                self.buffpool.read(&mut buf[0..len].to_vec());
            }
            Err(e) => {
                return Err(e);
            }
        }

        Ok(())
    }

    /// Exchange RFB protocol version with client.
    fn handle_version(&mut self) -> Result<()> {
        let buf = self.buffpool.read_front(self.expect);
        let res = String::from_utf8_lossy(buf);
        let ver_str = &res[0..12].to_string();
        let ver;
        match scanf!(ver_str, "RFB {usize:/\\d\\{3\\}/}.{usize:/\\d\\{3\\}/}\n") {
            Ok(v) => {
                ver = v;
            }
            Err(e) => {
                let msg = format!("Unsupport RFB version: {}", e);
                error!("{}", msg);
                return Err(anyhow!(VncError::UnsupportRFBProtocolVersion));
            }
        }
        self.version.major = ver.0 as u16;
        self.version.minor = ver.1 as u16;
        if self.version.major != 3 || ![3, 4, 5, 7, 8].contains(&self.version.minor) {
            let mut buf = Vec::new();
            buf.append(&mut (AuthState::Invalid as u32).to_be_bytes().to_vec());
            self.write_msg(&buf);
            return Err(anyhow!(VncError::UnsupportRFBProtocolVersion));
        }

        if [4, 5].contains(&self.version.minor) {
            self.version.minor = 3;
        }

        if self.version.minor == 3 {
            error!("Waiting for handle minor=3 ...");
            match self.auth {
                AuthState::No => {
                    let mut buf = Vec::new();
                    buf.append(&mut (AuthState::No as u32).to_be_bytes().to_vec());
                    self.write_msg(&buf);
                    self.update_event_handler(1, VncClient::handle_client_init);
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
            buf[1] = self.auth as u8;
            self.write_msg(&buf);
            self.update_event_handler(1, VncClient::handle_auth);
        }
        Ok(())
    }

    /// Invalid authentication, send 1 to reject.
    fn auth_failed(&mut self, msg: &str) {
        let auth_rej: u8 = 1;
        let mut buf: Vec<u8> = vec![1u8];
        buf.append(&mut (auth_rej as u32).to_be_bytes().to_vec());
        if self.version.minor >= 8 {
            let err_msg = msg;
            buf.append(&mut (err_msg.len() as u32).to_be_bytes().to_vec());
            buf.append(&mut err_msg.as_bytes().to_vec());
        }
        self.write_msg(&buf);
    }

    /// Authentication
    fn handle_auth(&mut self) -> Result<()> {
        let buf = self.buffpool.read_front(self.expect);

        if buf[0] != self.auth as u8 {
            self.auth_failed("Authentication failed");
            error!("handle_auth");
            return Err(anyhow!(VncError::AuthFailed(String::from("handle_auth"))));
        }

        match self.auth {
            AuthState::No => {
                if self.version.minor >= 8 {
                    let buf = [0u8; 4];
                    self.write_msg(&buf);
                }
                self.update_event_handler(1, VncClient::handle_client_init);
            }
            AuthState::Vencrypt => {
                // Send VeNCrypt version 0.2.
                let mut buf = [0u8; 2];
                buf[0] = 0_u8;
                buf[1] = 2_u8;

                self.write_msg(&buf);
                self.update_event_handler(2, VncClient::protocol_client_vencrypt_init);
            }
            _ => {
                self.auth_failed("Unhandled auth method");
                error!("handle_auth");
                return Err(anyhow!(VncError::AuthFailed(String::from("handle_auth"))));
            }
        }
        Ok(())
    }

    /// Set color depth for client.
    pub fn set_color_depth(&mut self) {
        if self.has_feature(VncFeatures::VncFeatureWmvi) {
            let mut buf = Vec::new();
            buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
            buf.append(&mut (0_u8).to_be_bytes().to_vec()); // Padding.
            buf.append(&mut (1_u16).to_be_bytes().to_vec()); // Number of pixel block.
            framebuffer_upadate(0, 0, self.width, self.height, ENCODING_WMVI, &mut buf);
            buf.append(&mut (ENCODING_RAW as u32).to_be_bytes().to_vec());
            self.pixel_format_message(&mut buf);
            self.write_msg(&buf);
        } else if !self.pixel_format.is_default_pixel_format() {
            self.pixel_convert = true;
        }
    }

    /// Set pixformat for client.
    pub fn pixel_format_message(&mut self, buf: &mut Vec<u8>) {
        self.pixel_format.init_pixelformat();
        buf.append(&mut (self.pixel_format.pixel_bits as u8).to_be_bytes().to_vec()); // Bit per pixel.
        buf.append(&mut (self.pixel_format.depth as u8).to_be_bytes().to_vec()); // Depth.
        buf.append(&mut (0_u8).to_be_bytes().to_vec()); // Big-endian flag.
        buf.append(&mut (1_u8).to_be_bytes().to_vec()); // True-color flag.
        buf.append(&mut (self.pixel_format.red.max as u16).to_be_bytes().to_vec()); // Red max.
        buf.append(&mut (self.pixel_format.green.max as u16).to_be_bytes().to_vec()); // Green max.
        buf.append(&mut (self.pixel_format.blue.max as u16).to_be_bytes().to_vec()); // Blue max.
        buf.append(&mut (self.pixel_format.red.shift as u8).to_be_bytes().to_vec()); // Red shift.
        buf.append(&mut (self.pixel_format.green.shift as u8).to_be_bytes().to_vec()); // Green shift.
        buf.append(&mut (self.pixel_format.blue.shift as u8).to_be_bytes().to_vec()); // Blue shift.
        buf.append(&mut [0; 3].to_vec()); // Padding.
    }

    /// Initialize the connection of vnc client.
    pub fn handle_client_init(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        // Send server framebuffer info.
        self.width = get_image_width(self.server_image);
        if self.width < 0 || self.width > MAX_WINDOW_WIDTH as i32 {
            error!("Invalid Image Size!");
            return Err(anyhow!(VncError::InvalidImageSize));
        }
        buf.append(&mut (self.width as u16).to_be_bytes().to_vec());
        self.height = get_image_height(self.server_image);
        if self.height < 0 || self.height > MAX_WINDOW_HEIGHT as i32 {
            error!("Invalid Image Size!");
            return Err(anyhow!(VncError::InvalidImageSize));
        }
        buf.append(&mut (self.height as u16).to_be_bytes().to_vec());
        self.pixel_format_message(&mut buf);

        buf.append(
            &mut ("StratoVirt".to_string().len() as u32)
                .to_be_bytes()
                .to_vec(),
        );
        buf.append(&mut "StratoVirt".to_string().as_bytes().to_vec());
        self.write_msg(&buf);
        self.update_event_handler(1, VncClient::handle_protocol_msg);
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
        buf.append(&mut (NUM_OF_COLORMAP as u16).to_be_bytes().to_vec());

        let pf = self.pixel_format.clone();
        for i in 0..NUM_OF_COLORMAP as u16 {
            let r = ((i >> pf.red.shift) & pf.red.max as u16) << (16 - pf.red.bits);
            let g = ((i >> pf.green.shift) & pf.green.max as u16) << (16 - pf.green.bits);
            let b = ((i >> pf.blue.shift) & pf.blue.max as u16) << (16 - pf.blue.bits);
            buf.append(&mut (r as u16).to_be_bytes().to_vec());
            buf.append(&mut (g as u16).to_be_bytes().to_vec());
            buf.append(&mut (b as u16).to_be_bytes().to_vec());
        }

        self.write_msg(&buf);
    }

    /// Set image format.
    fn set_pixel_format(&mut self) -> Result<()> {
        if self.expect == 1 {
            self.expect = 20;
            return Ok(());
        }

        let buf = self.buffpool.read_front(self.expect).to_vec();
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
            self.dis_conn = true;
            error!("Worng format of bits_per_pixel");
            return Err(anyhow!(VncError::ProtocolMessageFailed(String::from(
                "set pixel format"
            ))));
        }

        self.pixel_format.red.set_color_info(red_shift, red_max);
        self.pixel_format
            .green
            .set_color_info(green_shift, green_max);
        self.pixel_format.blue.set_color_info(blue_shift, blue_max);
        self.pixel_format.pixel_bits = bit_per_pixel;
        self.pixel_format.pixel_bytes = bit_per_pixel / BIT_PER_BYTE as u8;
        // Standard pixel format, depth is equal to 24.
        self.pixel_format.depth = if bit_per_pixel == 32 {
            24
        } else {
            bit_per_pixel
        };
        self.big_endian = big_endian_flag != 0;
        if true_color_flag == 0 {
            self.send_color_map();
        }
        if !self.pixel_format.is_default_pixel_format() {
            self.pixel_convert = true;
        }

        self.update_event_handler(1, VncClient::handle_protocol_msg);
        Ok(())
    }

    /// Update image for client.
    fn update_frame_buff(&mut self) {
        if self.expect == 1 {
            self.expect = 10;
            return;
        }
        let buf = self.buffpool.read_front(self.expect);
        if buf[1] != 0 {
            if self.state != UpdateState::Force {
                self.state = UpdateState::Incremental;
            }
        } else {
            self.state = UpdateState::Force;
            let x = u16::from_be_bytes([buf[2], buf[3]]) as i32;
            let y = u16::from_be_bytes([buf[4], buf[5]]) as i32;
            let w = u16::from_be_bytes([buf[6], buf[7]]) as i32;
            let h = u16::from_be_bytes([buf[8], buf[9]]) as i32;
            set_area_dirty(
                &mut self.dirty_bitmap,
                x,
                y,
                w,
                h,
                get_image_width(self.server_image),
                get_image_height(self.server_image),
            );
        }
        self.update_event_handler(1, VncClient::handle_protocol_msg);
    }

    /// Set encoding.
    fn set_encodings(&mut self) -> Result<()> {
        let buf = self.buffpool.read_front(self.expect);
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

        info!("Set encoding");
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
                    self.encoding = enc;
                }
                ENCODING_HEXTILE => {
                    self.feature |= 1 << VncFeatures::VncFeatureHextile as usize;
                    self.encoding = enc;
                }
                ENCODING_TIGHT => {
                    self.feature |= 1 << VncFeatures::VncFeatureTight as usize;
                    self.encoding = enc;
                }
                ENCODING_ZLIB => {
                    // ZRLE compress better than ZLIB, so prioritize ZRLE.
                    if self.feature & (1 << VncFeatures::VncFeatureZrle as usize) == 0 {
                        self.feature |= 1 << VncFeatures::VncFeatureZlib as usize;
                        self.encoding = enc;
                    }
                }
                ENCODING_ZRLE => {
                    self.feature |= 1 << VncFeatures::VncFeatureZrle as usize;
                    self.encoding = enc;
                }
                ENCODING_ZYWRLE => {
                    self.feature |= 1 << VncFeatures::VncFeatureZywrle as usize;
                    self.encoding = enc;
                }
                ENCODING_DESKTOPRESIZE => {
                    self.feature |= 1 << VncFeatures::VncFeatureResize as usize;
                }
                ENCODING_DESKTOP_RESIZE_EXT => {
                    self.feature |= 1 << VncFeatures::VncFeatureResizeExt as usize;
                }
                ENCODING_POINTER_TYPE_CHANGE => {
                    self.feature |= 1 << VncFeatures::VncFeaturePointerTypeChange as usize;
                }
                ENCODING_RICH_CURSOR => {
                    self.feature |= 1 << VncFeatures::VncFeatureRichCursor as usize;
                }
                ENCODING_ALPHA_CURSOR => {
                    self.feature |= 1 << VncFeatures::VncFeatureAlphaCursor as usize;
                }
                ENCODING_WMVI => {
                    self.feature |= 1 << VncFeatures::VncFeatureWmvi as usize;
                }
                ENCODING_LED_STATE => {
                    self.feature |= 1 << VncFeatures::VncFeatureLedState as usize;
                }
                _ => {}
            }

            num_encoding -= 1;
        }

        self.encoding = 0;
        self.desktop_resize();

        self.update_event_handler(1, VncClient::handle_protocol_msg);
        Ok(())
    }

    pub fn has_feature(&mut self, feature: VncFeatures) -> bool {
        self.feature & (1 << feature as usize) != 0
    }

    /// Set Desktop Size.
    pub fn desktop_resize(&mut self) {
        if !self.has_feature(VncFeatures::VncFeatureResizeExt)
            && !self.has_feature(VncFeatures::VncFeatureResize)
        {
            return;
        }
        self.width = get_image_width(self.server_image);
        self.height = get_image_height(self.server_image);
        if self.width < 0
            || self.width > MAX_WINDOW_WIDTH as i32
            || self.height < 0
            || self.height > MAX_WINDOW_HEIGHT as i32
        {
            error!("Invalid Image Size!");
            return;
        }

        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (ServerMsg::FramebufferUpdate as u8).to_be_bytes().to_vec());
        buf.append(&mut (0_u8).to_be_bytes().to_vec());
        buf.append(&mut (1_u16).to_be_bytes().to_vec());
        framebuffer_upadate(
            0,
            0,
            self.width,
            self.height,
            ENCODING_DESKTOPRESIZE,
            &mut buf,
        );

        self.write_msg(&buf);
    }

    /// Process the data sent by the client
    pub fn handle_protocol_msg(&mut self) -> Result<()> {
        // According to RFB protocol, first byte identifies the event type.
        let buf = self.buffpool.read_front(self.expect);
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
                self.update_event_handler(1, VncClient::handle_protocol_msg);
            }
        }
        Ok(())
    }

    /// Action token after the event.
    ///
    /// # Arguments
    ///
    /// * `expect` - the size of bytes of next callback function.
    /// * `handle_msg` - callback function of the next event.
    pub fn update_event_handler(
        &mut self,
        expect: usize,
        handle_msg: fn(&mut VncClient) -> Result<()>,
    ) {
        self.buffpool.remov_front(self.expect);
        self.expect = expect;
        self.handle_msg = handle_msg;
    }

    /// Clear the data when disconnected from client.
    pub fn disconnect(&mut self) {
        if let Err(e) = self.modify_event(NotifierOperation::Delete, 0) {
            error!("Failed to delete event, error is {}", format!("{:?}", e));
        }

        if let Err(e) = self.stream.shutdown(Shutdown::Both) {
            info!("Shutdown stream failed: {}", e);
        }
        self.handlers.clear();
    }
}

/// Internal_notifiers for VncClient.
impl EventNotifierHelper for VncClient {
    fn internal_notifiers(client_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let client = client_handler.clone();
        let handler: Box<dyn Fn(EventSet, RawFd) -> Option<Vec<EventNotifier>>> =
            Box::new(move |event, _| {
                let mut dis_conn = false;
                if event & EventSet::READ_HANG_UP == EventSet::READ_HANG_UP {
                    dis_conn = true;
                } else if event == EventSet::IN {
                    let mut locked_client = client.lock().unwrap();
                    if let Err(e) = locked_client.from_tcpstream_to_buff() {
                        error!("Failed to read_msg, error is {}", format!("{:?}", e));
                        dis_conn = true;
                    }
                }

                if !dis_conn {
                    let mut locked_client = client.lock().unwrap();
                    while locked_client.buffpool.len() >= locked_client.expect {
                        if let Err(e) = (locked_client.handle_msg)(&mut locked_client) {
                            error!("Failed to read_msg, error is {}", format!("{:?}", e));
                            dis_conn = true;
                            break;
                        }
                    }
                }

                if dis_conn {
                    let addr = client.lock().unwrap().addr.clone();
                    info!("Client disconnect : {:?}", addr);
                    let server = VNC_SERVERS.lock().unwrap()[0].clone();
                    let mut locked_server = server.lock().unwrap();
                    locked_server.clients.remove(&addr);
                    if locked_server.clients.is_empty() {
                        update_client_surface(&mut locked_server);
                    }
                    drop(locked_server);
                    client.lock().unwrap().disconnect();
                }

                None as Option<Vec<EventNotifier>>
            });

        let mut locked_client = client_handler.lock().unwrap();
        locked_client.handlers.push(Arc::new(Mutex::new(handler)));

        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            locked_client.stream.as_raw_fd(),
            None,
            EventSet::IN | EventSet::READ_HANG_UP,
            vec![locked_client.handlers[0].clone()],
        )]
    }
}
