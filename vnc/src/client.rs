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
use error_chain::ChainedError;
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
};
use vmm_sys_util::epoll::EventSet;

use crate::{AuthState, BuffPool, SubAuthState, VncServer, VNC_SERVERS};

const MAX_RECVBUF_LEN: usize = 1024;

// VNC encodings types
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

// According to Remote Framebuffer Protocol
pub enum ClientMsg {
    SetPixelFormat = 0,
    SetEncodings = 2,
    FramebufferUpdateRequest = 3,
    KeyEvent = 4,
    PointerEvent = 5,
    ClientCutText = 6,
    InvalidMsg,
}

// Message id of server
pub enum ServerMsg {
    FramebufferUpdate = 0,
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
    big_endian: bool,
    /// State flags whether the image needs to be updated for the client.
    state: UpdateState,
    /// Tcp listening address.
    pub addr: String,
    /// Image width.
    width: i32,
    /// Image height.
    height: i32,
    /// Encoding type.
    encoding: i32,
    /// Image display feature.
    feature: i32,
    /// The pixel need to convert.
    pixel_convert: bool,
}

impl VncClient {
    pub fn new(stream: TcpStream, addr: String, server: Arc<Mutex<VncServer>>) -> Self {
        VncClient {
            stream,
            buffpool: BuffPool::new(),
            expect: 12,
            dis_conn: false,
            version: VncVersion::default(),
            handle_msg: VncClient::handle_version,
            auth: AuthState::No,
            subauth: SubAuthState::VncAuthVencryptPlain,
            handlers: Vec::new(),
            server,
            big_endian: false,
            state: UpdateState::No,
            addr,
            width: 0,
            height: 0,
            encoding: 0,
            feature: 0,
            pixel_convert: false,
        }
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

    /// Read plain txt
    pub fn read_plain_msg(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        buf.resize(MAX_RECVBUF_LEN, 0u8);
        match self.stream.read(buf) {
            Ok(ret) => {
                len = ret;
            }
            Err(e) => {
                error!("read msg error: {}", e);
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
                    error!("write msg error: {:?}", e);
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
                return Err(ErrorKind::UnsupportRFBProtocolVersion.into());
            }
        }
        self.version.major = ver.0 as u16;
        self.version.minor = ver.1 as u16;
        if self.version.major != 3 || ![3, 4, 5, 7, 8].contains(&self.version.minor) {
            let mut buf = Vec::new();
            buf.append(&mut (AuthState::Invalid as u32).to_be_bytes().to_vec());
            self.write_msg(&buf);
            return Err(ErrorKind::UnsupportRFBProtocolVersion.into());
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
                    return Err(
                        ErrorKind::AuthFailed(String::from("Unsupported auth method")).into(),
                    );
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
            return Err(ErrorKind::AuthFailed(String::from("handle_auth")).into());
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
                return Err(ErrorKind::AuthFailed(String::from("handle_auth")).into());
            }
        }
        Ok(())
    }

    /// Initialize the connection of vnc client
    pub fn handle_client_init(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        self.write_msg(&buf);
        self.update_event_handler(1, VncClient::handle_protocol_msg);
        Ok(())
    }

    /// Set image format
    fn set_pixel_format(&mut self) -> Result<()> {
        if self.expect == 1 {
            self.expect = 20;
            return Ok(());
        }

        let mut buf = self.buffpool.read_front(self.expect).to_vec();

        self.update_event_handler(1, VncClient::handle_protocol_msg);
        Ok(())
    }

    /// Update image for client
    fn update_frame_buff(&mut self) {
        if self.expect == 1 {
            self.expect = 10;
            return;
        }
        let buf = self.buffpool.read_front(self.expect);

        self.update_event_handler(1, VncClient::handle_protocol_msg);
    }

    /// Set encoding
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
                // ENCODING_EXT_KEY_EVENT => {}
                // ENCODING_AUDIO => {}
                // VNC_ENCODING_XVP => {}
                // ENCODING_CLIPBOARD_EXT => {}
                // ENCODING_COMPRESSLEVEL0 ..= ENCODING_COMPRESSLEVEL0 + 9 => {}
                // ENCODING_QUALITYLEVEL0 ..= ENCODING_QUALITYLEVEL0 + 9 => {}
                _ => {
                    error!("Unknow encoding");
                }
            }

            num_encoding -= 1;
        }

        self.encoding = 0;
        self.desktop_resize();

        self.update_event_handler(1, VncClient::handle_protocol_msg);
        Ok(())
    }

    fn has_feature(&mut self, feature: VncFeatures) -> bool {
        self.feature & (1 << feature as usize) != 0
    }

    fn desktop_resize(&mut self) {
        // If hash feature VNC_FEATURE_RESIZE
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
        let server = VNC_SERVERS.lock().unwrap()[0].clone();
        let mut locked_server = server.lock().unwrap();
        locked_server.clients.remove(&self.addr);

        drop(locked_server);

        if let Err(e) = self.modify_event(NotifierOperation::Delete, 0) {
            error!("Failed to delete event, error is {}", e.display_chain());
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
                        error!("Failed to read_msg, error is {}", e.display_chain());
                        dis_conn = true;
                    }
                }

                if !dis_conn {
                    let mut locked_client = client.lock().unwrap();
                    while locked_client.buffpool.len() >= locked_client.expect {
                        if let Err(e) = (locked_client.handle_msg)(&mut locked_client) {
                            error!("Failed to read_msg, error is {}", e.display_chain());
                            dis_conn = true;
                            break;
                        }
                    }
                }

                if dis_conn {
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
