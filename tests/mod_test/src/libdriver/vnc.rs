// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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
    libdriver::vnc::EncodingType::*,
    libtest::{test_init, TestState},
};
use anyhow::{bail, Result};
use core::time;
use std::{
    cell::RefCell,
    cmp,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    os::unix::prelude::AsRawFd,
    rc::Rc,
    thread::sleep,
    time::Duration,
};
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};

use super::{
    machine::TestStdMachine,
    malloc::GuestAllocator,
    pci::{PCIBarAddr, TestPciDev, PCI_VENDOR_ID},
    pci_bus::TestPciBus,
};

const EPOLL_DEFAULT_TIMEOUT: i32 = 1000;
pub const MAX_RECVBUF_LEN: usize = 1024;
pub const READ_TIME_OUT: u64 = 30;
pub const RFB_PORT_OFFSET: u16 = 5900;
/// Size of subrectangle.
const HEXTILE_BLOCK_SIZE: usize = 16;
/// SubEncoding type of hextile.
const RAW: u8 = 0x01;
const BACKGROUND_SPECIFIC: u8 = 0x02;
const FOREGROUND_SPECIFIC: u8 = 0x04;
const ANY_SUBRECTS: u8 = 0x08;
const SUBRECTS_COLOURED: u8 = 0x10;

pub const PIXMAN_A8B8G8R8: u32 = 0;
pub const PIXMAN_X2R10G10B10: u32 = 1;
pub const PIXMAN_R8G8B8: u32 = 2;
pub const PIXMAN_A1: u32 = 3;
pub const PIXMAN_YUY2: u32 = 4;
pub const REFRESH_TIME_INTERVAL: u64 = 3000 * 1000 * 1000;

/// Input event.
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    KbdEvent = 0,
    MouseEvent = 1,
    InvalidEvent = 255,
}

impl Default for InputEvent {
    fn default() -> Self {
        InputEvent::InvalidEvent
    }
}

impl From<u8> for InputEvent {
    fn from(v: u8) -> Self {
        match v {
            0 => InputEvent::KbdEvent,
            1 => InputEvent::MouseEvent,
            _ => InputEvent::InvalidEvent,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InputMessage {
    pub event_type: InputEvent,
    pub keycode: u16,
    pub down: u8,
    pub button: u32,
    pub x: u32,
    pub y: u32,
}

/// GPU device Event.
#[derive(Debug, Clone, Copy)]
pub enum GpuEvent {
    ReplaceSurface = 0,
    ReplaceCursor = 1,
    GraphicUpdateArea = 2,
    GraphicUpdateDirty = 3,
    Deactive = 4,
}

impl Default for GpuEvent {
    fn default() -> Self {
        GpuEvent::Deactive
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TestGpuCmd {
    pub event_type: GpuEvent,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub data_len: u32,
}

// Encodings Type
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum EncodingType {
    EncodingRaw = 0x00000000,
    EncodingCopyrect = 0x00000001,
    EncodingHextile = 0x00000005,
    EncodingZlib = 0x00000006,
    EncodingTight = 0x00000007,
    EncodingZrle = 0x00000010,
    EncodingZywrle = 0x00000011,
    EncodingCompresslevel0 = 0xFFFFFF00,
    EncodingQualitylevel0 = 0xFFFFFFE0,
    EncodingRichCursor = 0xFFFFFF11,
    EncodingAlphaCursor = 0xFFFFFEC6,
    EncodingDesktopresize = 0xFFFFFF21,
    EncodingPointerTypeChange = 0xFFFFFEFF,
    EncodingExtKeyEvent = 0xFFFFFEFE,
    EncodingAudio = 0xFFFFFEFD,
    EncodingTightPng = 0xFFFFFEFC,
    EncodingLedState = 0xFFFFFEFB,
    EncodingWmvi = 0x574D5669,
    EncodingInvalid = 0xFFFFFFFF,
}

impl EncodingType {
    pub const ENCODINGTYPE: [Self; 18] = [
        EncodingRaw,
        EncodingCopyrect,
        EncodingHextile,
        EncodingZlib,
        EncodingTight,
        EncodingZrle,
        EncodingZywrle,
        EncodingCompresslevel0,
        EncodingQualitylevel0,
        EncodingRichCursor,
        EncodingAlphaCursor,
        EncodingDesktopresize,
        EncodingPointerTypeChange,
        EncodingExtKeyEvent,
        EncodingAudio,
        EncodingTightPng,
        EncodingLedState,
        EncodingWmvi,
    ];
}

impl From<u32> for EncodingType {
    fn from(v: u32) -> Self {
        match v {
            0x00000000 => EncodingType::EncodingRaw,
            0x00000001 => EncodingType::EncodingCopyrect,
            0x00000005 => EncodingType::EncodingHextile,
            0x00000006 => EncodingType::EncodingZlib,
            0x00000007 => EncodingType::EncodingTight,
            0x00000010 => EncodingType::EncodingZrle,
            0x00000011 => EncodingType::EncodingZywrle,
            0xFFFFFF00 => EncodingType::EncodingCompresslevel0,
            0xFFFFFFE0 => EncodingType::EncodingQualitylevel0,
            0xFFFFFF11 => EncodingType::EncodingRichCursor,
            0xFFFFFEC6 => EncodingType::EncodingAlphaCursor,
            0xFFFFFF21 => EncodingType::EncodingDesktopresize,
            0xFFFFFEFF => EncodingType::EncodingPointerTypeChange,
            0xFFFFFEFE => EncodingType::EncodingExtKeyEvent,
            0xFFFFFEFD => EncodingType::EncodingAudio,
            0xFFFFFEFC => EncodingType::EncodingTightPng,
            0xFFFFFEFB => EncodingType::EncodingLedState,
            0x574D5669 => EncodingType::EncodingWmvi,
            _ => EncodingType::EncodingInvalid,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum RfbServerMsg {
    FramebufferUpdate = 0,
    SetColourMapEntries = 1,
    InvalidMsg,
}

impl From<u8> for RfbServerMsg {
    fn from(v: u8) -> Self {
        match v {
            0 => RfbServerMsg::FramebufferUpdate,
            1 => RfbServerMsg::SetColourMapEntries,
            _ => RfbServerMsg::InvalidMsg,
        }
    }
}

#[derive(Clone, Copy)]
pub enum UpdateState {
    NotIncremental = 0,
    Incremental = 1,
}

#[derive(Clone, Copy)]
pub enum TestAuthType {
    Invalid = 0,
    VncAuthNone = 1,
}

#[derive(Clone, Copy, Default, Debug)]
pub struct RfbPixelFormat {
    bit_per_pixel: u8,
    depth: u8,
    big_endian: u8,
    true_color_flag: u8,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,
    pad1: u8,
    pad2: u16,
}

impl RfbPixelFormat {
    pub fn new(
        bit_per_pixel: u8,
        depth: u8,
        big_endian: u8,
        true_color_flag: u8,
        red_max: u16,
        green_max: u16,
        blue_max: u16,
        red_shift: u8,
        green_shift: u8,
        blue_shift: u8,
    ) -> Self {
        Self {
            bit_per_pixel,
            depth,
            big_endian,
            true_color_flag,
            red_max,
            green_max,
            blue_max,
            red_shift,
            green_shift,
            blue_shift,
            pad1: 0_u8,
            pad2: 0_u16,
        }
    }

    fn from_bytes(&mut self, buf: &Vec<u8>) {
        self.bit_per_pixel = buf[0];
        self.depth = buf[1];
        self.big_endian = buf[2];
        self.true_color_flag = buf[3];
        self.red_max = u16::from_be_bytes([buf[4], buf[5]]);
        self.green_max = u16::from_be_bytes([buf[6], buf[7]]);
        self.blue_max = u16::from_be_bytes([buf[8], buf[9]]);
        self.red_shift = buf[10];
        self.green_shift = buf[11];
        self.blue_shift = buf[12];
        self.pad1 = buf[13];
        self.pad2 = u16::from_be_bytes([buf[14], buf[15]]);
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut self.bit_per_pixel.to_be_bytes().to_vec());
        buf.append(&mut self.depth.to_be_bytes().to_vec());
        buf.append(&mut self.big_endian.to_be_bytes().to_vec());
        buf.append(&mut self.true_color_flag.to_be_bytes().to_vec());
        buf.append(&mut self.red_max.to_be_bytes().to_vec());
        buf.append(&mut self.green_max.to_be_bytes().to_vec());
        buf.append(&mut self.blue_max.to_be_bytes().to_vec());
        buf.append(&mut self.red_shift.to_be_bytes().to_vec());
        buf.append(&mut self.green_shift.to_be_bytes().to_vec());
        buf.append(&mut self.blue_shift.to_be_bytes().to_vec());
        buf.append(&mut self.pad1.to_be_bytes().to_vec());
        buf.append(&mut self.pad2.to_be_bytes().to_vec());
        buf
    }
}

pub struct RfbFrameBuffHead {
    pub flag: RfbServerMsg,
    pub pad0: u8,
    pub num_rects: u16,
}

impl RfbFrameBuffHead {
    fn new(buf: &Vec<u8>) -> Self {
        assert!(buf.len() >= 4);
        Self {
            flag: RfbServerMsg::from(buf[0]),
            pad0: buf[1],
            num_rects: u16::from_be_bytes([buf[2], buf[3]]),
        }
    }
}

#[derive(Debug)]
pub struct RfbFrameBuff {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub enc: u32,
}

impl RfbFrameBuff {
    fn new(buf: &Vec<u8>) -> Self {
        assert!(buf.len() >= 12);
        Self {
            x: u16::from_be_bytes([buf[0], buf[1]]),
            y: u16::from_be_bytes([buf[2], buf[3]]),
            w: u16::from_be_bytes([buf[4], buf[5]]),
            h: u16::from_be_bytes([buf[6], buf[7]]),
            enc: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        }
    }
}

pub struct RfbSetColourMap {
    pub flag: RfbServerMsg,
    pub pad0: u8,
    pub first_color: u16,
    pub num_of_colurs: u16,
}

impl RfbSetColourMap {
    fn new(buf: &Vec<u8>) -> Self {
        assert!(buf.len() >= 6);
        Self {
            flag: RfbServerMsg::from(buf[0]),
            pad0: buf[1],
            first_color: u16::from_be_bytes([buf[2], buf[3]]),
            num_of_colurs: u16::from_be_bytes([buf[4], buf[5]]),
        }
    }
}

pub trait TestEventOperation {
    fn to_be_bytes(&self) -> Vec<u8>;
}

#[derive(Clone, Copy)]
pub enum RfbClientMessage {
    RrbSetPixelFormat = 0,
    RfbSetEncoding = 2,
    RfbUpdateRequest = 3,
    RfbKeyEvent = 4,
    RfbPointerEvent = 5,
    RfbClientCutText = 6,
}

pub struct TestPointEvent {
    pub evnet_type: RfbClientMessage,
    pub button_mask: u8,
    pub x: u16,
    pub y: u16,
}

impl TestPointEvent {
    fn new(button_mask: u8, x: u16, y: u16) -> Self {
        Self {
            evnet_type: RfbClientMessage::RfbPointerEvent,
            button_mask,
            x,
            y,
        }
    }
}

impl TestEventOperation for TestPointEvent {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (self.evnet_type as u8).to_be_bytes().to_vec());
        buf.append(&mut self.button_mask.to_be_bytes().to_vec());
        buf.append(&mut self.x.to_be_bytes().to_vec());
        buf.append(&mut self.y.to_be_bytes().to_vec());
        buf
    }
}

pub struct TestKeyEvent {
    pub event_type: RfbClientMessage,
    pub down: u8,
    pub pad: u16,
    pub keysym: u32,
}

impl TestKeyEvent {
    fn new(down: u8, keysym: u32) -> Self {
        Self {
            event_type: RfbClientMessage::RfbKeyEvent,
            down,
            pad: 0_u16,
            keysym,
        }
    }
}

impl TestEventOperation for TestKeyEvent {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (self.event_type as u8).to_be_bytes().to_vec());
        buf.append(&mut self.down.to_be_bytes().to_vec());
        buf.append(&mut self.pad.to_be_bytes().to_vec());
        buf.append(&mut self.keysym.to_be_bytes().to_vec());
        buf
    }
}

pub struct TestSetupEncoding {
    pub event_type: RfbClientMessage,
    pub pad: u8,
    pub num_encodings: u16,
    pub encs: Vec<EncodingType>,
}

impl TestSetupEncoding {
    fn new() -> Self {
        Self {
            event_type: RfbClientMessage::RfbSetEncoding,
            pad: 0_u8,
            num_encodings: 0_u16,
            encs: Vec::new(),
        }
    }
}

impl TestEventOperation for TestSetupEncoding {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (self.event_type as u8).to_be_bytes().to_vec());
        buf.append(&mut self.pad.to_be_bytes().to_vec());
        buf.append(&mut self.num_encodings.to_be_bytes().to_vec());
        for enc in self.encs.iter() {
            buf.append(&mut (*enc as u32).to_be_bytes().to_vec());
        }
        buf
    }
}

pub struct TestUpdateFrameBuffer {
    pub event_type: RfbClientMessage,
    pub incremental: UpdateState,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl TestUpdateFrameBuffer {
    fn new(incremental: UpdateState, x: u16, y: u16, w: u16, h: u16) -> Self {
        Self {
            event_type: RfbClientMessage::RfbUpdateRequest,
            incremental,
            x,
            y,
            w,
            h,
        }
    }
}

impl TestEventOperation for TestUpdateFrameBuffer {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (self.event_type as u8).to_be_bytes().to_vec());
        buf.append(&mut (self.incremental as u8).to_be_bytes().to_vec());
        buf.append(&mut self.x.to_be_bytes().to_vec());
        buf.append(&mut self.y.to_be_bytes().to_vec());
        buf.append(&mut self.w.to_be_bytes().to_vec());
        buf.append(&mut self.h.to_be_bytes().to_vec());
        buf
    }
}

pub struct TestSetPixelFormat {
    pub event_type: RfbClientMessage,
    pub pad0: u8,
    pub pad1: u16,
    pub pf: RfbPixelFormat,
}

impl TestSetPixelFormat {
    fn new(pf: RfbPixelFormat) -> Self {
        Self {
            event_type: RfbClientMessage::RrbSetPixelFormat,
            pad0: 0_u8,
            pad1: 0_u16,
            pf,
        }
    }
}

impl TestEventOperation for TestSetPixelFormat {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut (self.event_type as u8).to_be_bytes().to_vec());
        buf.append(&mut self.pad0.to_be_bytes().to_vec());
        buf.append(&mut self.pad1.to_be_bytes().to_vec());
        buf.append(&mut self.pf.to_be_bytes());
        buf
    }
}

pub struct TestClientCut {
    pub event_type: RfbClientMessage,
    pub pad0: u8,
    pub pad1: u16,
    pub length: u32,
    pub text: String,
}

impl TestEventOperation for TestClientCut {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(
            &mut (RfbClientMessage::RfbClientCutText as u8)
                .to_be_bytes()
                .to_vec(),
        );
        buf.append(&mut self.pad0.to_be_bytes().to_vec());
        buf.append(&mut self.pad1.to_be_bytes().to_vec());
        buf.append(&mut (self.text.len()).to_be_bytes().to_vec());
        buf.append(&mut self.text.as_bytes().to_vec());
        buf
    }
}

/// Display mode information.
#[derive(Default)]
pub struct DisplayMode {
    pub width: u16,
    pub height: u16,
    pub test_pf: RfbPixelFormat,
    pub app_name: String,
}

impl DisplayMode {
    pub fn from_bytes(&mut self, buf: &mut Vec<u8>) {
        self.width = u16::from_be_bytes([buf[0], buf[1]]);
        self.height = u16::from_be_bytes([buf[2], buf[3]]);
        buf.drain(..4);

        // Pixel format message.
        self.test_pf.from_bytes(&buf[..16].to_vec());
        buf.drain(..16);

        // Application name + len.
        let name_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf.drain(..4);
        self.app_name = String::from_utf8(buf[..name_len as usize].to_vec()).unwrap();
        buf.drain(..name_len as usize);

        println!(
            "Display infomation set by server:\n \
            application name: {:?} Image size: width: {:?}, height: {:?}\n \
            big endian: {:?}, true color flag: {:?} red max {:?} red shift {:?}\n \
            green max {:?} green shift {:?} blue max {:?} blue shift {:?}\n",
            self.app_name,
            self.width,
            self.height,
            self.test_pf.big_endian,
            self.test_pf.true_color_flag,
            self.test_pf.red_max,
            self.test_pf.red_shift,
            self.test_pf.green_max,
            self.test_pf.green_shift,
            self.test_pf.blue_max,
            self.test_pf.blue_shift
        );
    }

    pub fn check(&mut self) {
        assert!(0 < self.width && self.width <= 2560);
        assert!(0 < self.height && self.height <= 2048);
        assert!(self.app_name.len() <= 100);
    }
}

pub trait IoOperations {
    fn channel_write_full(&mut self, buf: &[u8]) -> Result<usize>;
    fn channel_read_full(&mut self, buf: &mut Vec<u8>) -> Result<usize>;
}

pub struct IoChannel {
    stream: TcpStream,
}

impl IoChannel {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl IoOperations for IoChannel {
    fn channel_write_full(&mut self, buf: &[u8]) -> Result<usize> {
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
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    bail!("Unable to write msg on socket: {:?}", e);
                }
            }
        }

        Ok(buf_size)
    }

    fn channel_read_full(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        let mut len = 0_usize;
        loop {
            let mut bytes = vec![0_u8; MAX_RECVBUF_LEN];
            match self.stream.read(&mut bytes) {
                Ok(ret) => {
                    buf.append(&mut bytes[..ret].to_vec());
                    len += ret;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(len);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    bail!("Unable to read msg from socket: {:?}", e);
                }
            }
            break;
        }

        Ok(len)
    }
}

pub struct VncClient {
    pub stream: TcpStream,
    pub io_channel: Rc<RefCell<dyn IoOperations>>,
    test_state: Rc<RefCell<TestState>>,
    pub display_mod: DisplayMode,
    epoll: Epoll,
    pub ready_events: Vec<EpollEvent>,
}

impl VncClient {
    pub fn new(
        stream: TcpStream,
        io_channel: Rc<RefCell<dyn IoOperations>>,
        test_state: Rc<RefCell<TestState>>,
    ) -> Self {
        let epoll = Epoll::new().unwrap();
        Self {
            stream,
            io_channel,
            test_state,
            display_mod: DisplayMode::default(),
            epoll,
            ready_events: vec![EpollEvent::default(); 1],
        }
    }

    pub fn epoll_ctl(&mut self, event: EpollEvent) -> io::Result<()> {
        self.epoll
            .ctl(ControlOperation::Add, self.stream.as_raw_fd() as i32, event)
    }

    /// Wait for events on the epoll.
    /// or wait util the timeout.
    /// Step:
    /// 1. Switch listening event.
    /// 2. Return if event happen or time out.
    pub fn epoll_wait(&mut self, event_set: EventSet) -> io::Result<usize> {
        let event = EpollEvent::new(event_set, self.stream.as_raw_fd() as u64);
        if let Err(e) = self.epoll.ctl(
            ControlOperation::Modify,
            self.stream.as_raw_fd() as i32,
            event,
        ) {
            return Err(e);
        }
        self.epoll
            .wait(EPOLL_DEFAULT_TIMEOUT, &mut self.ready_events[..])
    }

    /// Read the data in the Stream util empty.
    pub fn stream_read_to_end(&mut self) -> Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        let event = EpollEvent::new(EventSet::IN, self.stream.as_raw_fd() as u64);
        self.epoll.ctl(
            ControlOperation::Modify,
            self.stream.as_raw_fd() as i32,
            event,
        )?;

        match self
            .epoll
            .wait(EPOLL_DEFAULT_TIMEOUT, &mut self.ready_events[..])
        {
            Ok(event_counts) if event_counts > 0 => {
                self.io_channel.borrow_mut().channel_read_full(&mut buf)?;
                buf.clear();
            }
            _ => return Ok(()),
        }

        Ok(())
    }

    /// Read message until the total number of bytes is exceed the expect.
    pub fn read_msg(&mut self, buf: &mut Vec<u8>, expect: usize) -> Result<usize> {
        let mut total_received: usize = 0;
        loop {
            if buf.len() >= expect {
                break;
            }
            // Wait event.
            match self.epoll_wait(EventSet::IN) {
                Ok(n) if n > 0 => {}
                _ => bail!("Io Channel is broken"),
            }
            let mut tmp_buf: Vec<u8> = Vec::new();
            let len = match self.io_channel.borrow_mut().channel_read_full(&mut tmp_buf) {
                Ok(n) => {
                    total_received += n;
                    n
                }
                Err(e) => return Err(e),
            };
            buf.append(&mut tmp_buf[..len].to_vec());
        }

        Ok(total_received)
    }

    /// Write message.
    pub fn write_msg(&mut self, buf: &[u8]) -> Result<usize> {
        let total_byte = buf.len();
        loop {
            let mut send_bytes: usize = 0;
            match self.io_channel.borrow_mut().channel_write_full(buf) {
                Ok(len) => send_bytes += len,
                Err(e) => return Err(e),
            }

            if send_bytes >= total_byte {
                break;
            }
        }
        Ok(total_byte)
    }

    pub fn connect(&mut self, sec_type: TestAuthType) -> Result<()> {
        let mut buf: Vec<u8> = Vec::new();
        println!("Connect to server.");
        // Step 1: Exchange RFB Protocol: RFB 003.008.
        self.read_msg(&mut buf, 12)?;
        if "RFB 003.008\n".as_bytes().to_vec() != buf[..12].to_vec() {
            bail!("Unsupport RFB version");
        }
        self.write_msg(&"RFB 003.008\n".as_bytes().to_vec())?;
        buf.drain(..12);

        // Step 2: Auth num is 1.
        self.read_msg(&mut buf, 1)?;
        let auth_num = buf[0];
        assert!(auth_num > 0);
        buf.drain(..1);
        self.read_msg(&mut buf, auth_num as usize)?;
        if sec_type as u8 != buf[0] {
            bail!("Unsupport security type!");
        }
        buf.drain(..auth_num as usize);
        self.write_msg(&(sec_type as u8).to_be_bytes().to_vec())?;

        match sec_type {
            TestAuthType::VncAuthNone => {
                // Step 3. Handle_auth: Authstate::No, Server accept auth and client send share mode.
                self.read_msg(&mut buf, 4)?;
                if buf[..4].to_vec() != [0_u8; 4].to_vec() {
                    bail!("Reject by vnc server");
                }
                self.write_msg(&0_u8.to_be_bytes().to_vec())?;
                buf.drain(..4);

                // Step 4. display mode information init: width + height + pixelformat + app_name.
                self.read_msg(&mut buf, 24)?;
                self.display_mod.from_bytes(&mut buf);
                self.display_mod.check();
            }
            _ => {}
        }
        self.stream_read_to_end()?;
        println!("Connection established!");
        Ok(())
    }

    /// Send point event to VncServer.
    pub fn test_point_event(&mut self, buttom_mask: u8, x: u16, y: u16) -> Result<()> {
        println!("Test point event.");
        let test_event = TestPointEvent::new(buttom_mask, x, y);
        self.write_msg(&mut test_event.to_be_bytes())?;
        Ok(())
    }

    /// Send point event to VncServer.
    pub fn test_key_event(&mut self, down: u8, keysym: u32) -> Result<()> {
        println!("Test key event.");
        let test_event = TestKeyEvent::new(down, keysym);
        self.write_msg(&mut test_event.to_be_bytes())?;
        Ok(())
    }

    /// Send set encodings to VncServer.
    ///
    /// # Arguments.
    ///
    /// * `enc_num` - total number of feature support by VncClient.
    /// * `enc` - features supported by VncClient.
    pub fn test_setup_encodings(
        &mut self,
        enc_num: Option<u16>,
        enc: Option<EncodingType>,
    ) -> Result<()> {
        println!("Test setup encodings");
        let mut test_event = TestSetupEncoding::new();
        if let Some(encoding) = enc {
            test_event.encs.push(encoding);
            test_event.num_encodings = match enc_num {
                Some(num) => num,
                None => 1_u16,
            };
        } else {
            for encoding in EncodingType::ENCODINGTYPE {
                test_event.encs.push(encoding);
            }
            test_event.num_encodings = match enc_num {
                Some(num) => num,
                None => EncodingType::ENCODINGTYPE.len() as u16,
            };
        }
        self.write_msg(&mut test_event.to_be_bytes())?;
        Ok(())
    }

    /// Sent update framebuffer request to VncServer.
    pub fn test_update_request(
        &mut self,
        incremental: UpdateState,
        x: u16,
        y: u16,
        w: u16,
        h: u16,
    ) -> Result<()> {
        println!("Test update frambuff request.");
        let test_event = TestUpdateFrameBuffer::new(incremental, x, y, w, h);
        self.write_msg(&mut test_event.to_be_bytes())?;
        Ok(())
    }

    /// Send set pixel format to VncClient.
    pub fn test_set_pixel_format(&mut self, pf: RfbPixelFormat) -> Result<()> {
        println!("Test set pixel format.");
        let test_event = TestSetPixelFormat::new(pf);
        self.write_msg(&mut test_event.to_be_bytes())?;
        Ok(())
    }

    /// Send client cut event to VncServer.
    pub fn test_send_client_cut(&mut self, client_cut: TestClientCut) -> Result<()> {
        println!("Test send client cut evnet.");
        self.write_msg(&mut client_cut.to_be_bytes())?;
        Ok(())
    }

    /// Receive the framebuferr data, and verify the format.
    ///
    /// # Arguments
    /// * `pf` - Pixel format set to server.
    /// * `enc` - Image encoding type.
    pub fn test_recv_server_data(
        &mut self,
        pf: RfbPixelFormat,
    ) -> Result<Vec<(RfbServerMsg, EncodingType)>> {
        let mut buf: Vec<u8> = Vec::new();
        let mut rfb_event: Vec<(RfbServerMsg, EncodingType)> = Vec::new();
        sleep(Duration::from_millis(50));
        self.test_state
            .borrow_mut()
            .clock_step_ns(REFRESH_TIME_INTERVAL);
        loop {
            // Wait event.
            match self.epoll_wait(EventSet::IN) {
                Ok(n) if n > 0 => {}
                _ => break,
            }

            self.read_msg(&mut buf, 1)?;
            match RfbServerMsg::from(buf[0]) {
                RfbServerMsg::FramebufferUpdate => {
                    self.read_msg(&mut buf, 4)?;
                    let frame_head = RfbFrameBuffHead::new(&mut buf);
                    buf.drain(..4);
                    println!("Total number of rects : {:?}", frame_head.num_rects);
                    for i in 0..frame_head.num_rects {
                        println!("Rect: {:?}", i + 1);
                        self.read_msg(&mut buf, 12)?;
                        let frame_buff = RfbFrameBuff::new(&mut buf);
                        buf.drain(..12);
                        rfb_event.push((
                            RfbServerMsg::FramebufferUpdate,
                            EncodingType::from(frame_buff.enc),
                        ));
                        self.handle_server_msg(pf, frame_buff, &mut buf)?;
                    }
                }
                RfbServerMsg::SetColourMapEntries => {
                    rfb_event.push((
                        RfbServerMsg::SetColourMapEntries,
                        EncodingType::EncodingInvalid,
                    ));
                    self.read_msg(&mut buf, 6)?;
                    let colour_map = RfbSetColourMap::new(&buf);
                    buf.drain(..6);
                    let message_len = colour_map.num_of_colurs * 6;
                    self.read_msg(&mut buf, message_len as usize)?;
                    buf.drain(..message_len as usize);
                    assert_eq!(buf.len(), 0_usize);
                    println!(
                        "Set Color Map Entries, total num of colours:{:?}",
                        colour_map.num_of_colurs
                    );
                }
                _ => {
                    assert!(false);
                }
            }
        }
        Ok(rfb_event)
    }

    /// Handle messages from Vnc Server.
    fn handle_server_msg(
        &mut self,
        pf: RfbPixelFormat,
        frame_buff: RfbFrameBuff,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        match EncodingType::from(frame_buff.enc) {
            EncodingType::EncodingRaw => {
                self.parse_raw_image_data(pf, frame_buff, buf)?;
            }
            EncodingType::EncodingHextile => {
                self.parse_hextile_image_data(pf, frame_buff, buf)?;
            }
            EncodingType::EncodingDesktopresize => {
                self.display_mod.width = frame_buff.w;
                self.display_mod.height = frame_buff.h;
            }
            EncodingType::EncodingRichCursor => {
                let data_len = frame_buff.w * frame_buff.h * 4;
                // cursor.data + mask
                let mask_len = (frame_buff.w + 8 - 1) / 8 * frame_buff.h;
                self.read_msg(buf, (data_len + mask_len) as usize)?;
                buf.drain(..(data_len + mask_len) as usize);
            }
            EncodingType::EncodingAlphaCursor => {
                let data_len = frame_buff.w * frame_buff.h * 4;
                // EncodingType + cursor.data
                self.read_msg(buf, (4 + data_len) as usize)?;
                buf.drain(..(4 + data_len) as usize);
            }
            _ => {
                assert!(
                    false,
                    "unsupport event type from client: {}",
                    frame_buff.enc
                );
            }
        }
        Ok(())
    }

    fn parse_raw_image_data(
        &mut self,
        pf: RfbPixelFormat,
        frame_buff: RfbFrameBuff,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        let message_len: usize =
            frame_buff.w as usize * frame_buff.h as usize * (pf.bit_per_pixel as usize / 8);
        println!("Total bytes of image data: {:?}", message_len);
        self.read_msg(buf, message_len as usize)?;
        buf.drain(..message_len);
        Ok(())
    }

    fn parse_hextile_image_data(
        &mut self,
        pf: RfbPixelFormat,
        frame_buff: RfbFrameBuff,
        buf: &mut Vec<u8>,
    ) -> Result<()> {
        let bytes_per_pixel: usize = (pf.bit_per_pixel / 8) as usize;
        let mut total_received: usize = 0;
        for j in (0..frame_buff.h).step_by(HEXTILE_BLOCK_SIZE) {
            for i in (0..frame_buff.w).step_by(HEXTILE_BLOCK_SIZE) {
                self.read_msg(buf, 1)?;
                let flag = buf[0];
                buf.drain(..1);
                total_received += 1;
                if flag & RAW != 0 {
                    let w = cmp::min(HEXTILE_BLOCK_SIZE as u16, frame_buff.w - i);
                    let h = cmp::min(HEXTILE_BLOCK_SIZE as u16, frame_buff.h - j);
                    let expect = w as usize * h as usize * bytes_per_pixel;
                    self.read_msg(buf, expect)?;
                    total_received += expect;
                    buf.drain(..expect);
                } else {
                    // Background colour.
                    if flag & BACKGROUND_SPECIFIC != 0 {
                        self.read_msg(buf, bytes_per_pixel)?;
                        total_received += bytes_per_pixel;
                        buf.drain(..bytes_per_pixel);
                    }
                    // Foreground colour.
                    if flag & FOREGROUND_SPECIFIC != 0 {
                        self.read_msg(buf, bytes_per_pixel)?;
                        total_received += bytes_per_pixel;
                        buf.drain(..bytes_per_pixel);
                    }

                    if flag & ANY_SUBRECTS != 0 {
                        self.read_msg(buf, 1)?;
                        total_received += 1;
                        let num_tiles = buf[0] as usize;
                        buf.drain(..1);
                        let expect = match flag & SUBRECTS_COLOURED == 0 {
                            true => num_tiles * 2,
                            false => num_tiles * (bytes_per_pixel + 2),
                        };
                        self.read_msg(buf, expect)?;
                        total_received += expect;
                        buf.drain(..expect);
                    }
                }
            }
        }
        println!("Total bytes encoded by Hextile: {:?}", total_received);
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<()> {
        self.stream.shutdown(Shutdown::Both)?;
        Ok(())
    }
}

/// Create a new vnc client.
///
/// # Arguments
///
/// * `port` - Local port listened by vnc server.
pub fn create_new_client(test_state: Rc<RefCell<TestState>>, port: u16) -> Result<VncClient> {
    let port = port + RFB_PORT_OFFSET;
    let addrs = [SocketAddr::from(([127, 0, 0, 1], port))];
    let stream = TcpStream::connect(&addrs[..]).unwrap();
    stream
        .set_nonblocking(true)
        .expect("set nonblocking failed");
    stream
        .set_read_timeout(Some(time::Duration::from_millis(READ_TIME_OUT)))
        .unwrap();
    let stream_clone = stream.try_clone().expect("clone failed...");
    let io_channel = Rc::new(RefCell::new(IoChannel::new(stream_clone)));
    let mut vnc_client = VncClient::new(stream, io_channel, test_state);
    // Register epoll event.
    let event = EpollEvent::new(
        EventSet::READ_HANG_UP | EventSet::IN,
        vnc_client.stream.as_raw_fd() as u64,
    );
    vnc_client.epoll_ctl(event)?;
    Ok(vnc_client)
}

pub struct TestDemoGpuDevice {
    pub pci_dev: TestPciDev,
    pub bar_addr: PCIBarAddr,
    bar_idx: u8,
    allocator: Rc<RefCell<GuestAllocator>>,
}

impl TestDemoGpuDevice {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>, allocator: Rc<RefCell<GuestAllocator>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar_addr: 0,
            bar_idx: 0,
            allocator,
        }
    }

    /// Send the deactive event to demo gpu.
    pub fn deactive(&mut self) {
        let cmd = TestGpuCmd {
            event_type: GpuEvent::Deactive,
            ..Default::default()
        };
        self.do_gpu_event(&cmd);
    }

    /// Replace the surface of the display.
    /// The width and height corresponding the width and height of the suface.
    pub fn replace_surface(&mut self, width: u32, height: u32, pixman_format: u32) {
        let cmd = TestGpuCmd {
            event_type: GpuEvent::ReplaceSurface,
            w: width,
            h: height,
            data_len: pixman_format,
            ..Default::default()
        };
        self.do_gpu_event(&cmd);
    }

    /// Update the cursor image for display.
    pub fn replace_cursor(
        &mut self,
        width: u32,
        height: u32,
        hot_x: u32,
        hot_y: u32,
        mouse_data: u32,
    ) {
        let cmd = TestGpuCmd {
            event_type: GpuEvent::ReplaceCursor,
            x: hot_x,
            y: hot_y,
            w: width,
            h: height,
            data_len: mouse_data,
        };
        self.do_gpu_event(&cmd);
    }

    /// Change the pixel data of the specified area,
    /// (x, y, w, h) represents the specific area on the image.
    pub fn update_image_area(&mut self, x: u32, y: u32, w: u32, h: u32) {
        let cmd = TestGpuCmd {
            event_type: GpuEvent::GraphicUpdateArea,
            x,
            y,
            w,
            h,
            ..Default::default()
        };
        self.do_gpu_event(&cmd);
    }

    /// Notify VNC that the specific area of pixel has been updated.
    pub fn set_area_dirty(&mut self, x: u32, y: u32, w: u32, h: u32) {
        let cmd = TestGpuCmd {
            event_type: GpuEvent::GraphicUpdateDirty,
            x,
            y,
            w,
            h,
            ..Default::default()
        };
        self.do_gpu_event(&cmd);
    }

    /// Send a gpu cmd.
    pub fn do_gpu_event(&mut self, cmd: &TestGpuCmd) {
        // Malloc a memory, and write the data in this addr.
        let addr = self.allocator.borrow_mut().alloc(21);
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();
        test_state.borrow_mut().writeb(addr, cmd.event_type as u8);
        test_state.borrow_mut().writel(addr + 1, cmd.x);
        test_state.borrow_mut().writel(addr + 5, cmd.y);
        test_state.borrow_mut().writel(addr + 9, cmd.w);
        test_state.borrow_mut().writel(addr + 13, cmd.h);
        test_state.borrow_mut().writel(addr + 17, cmd.data_len);
        // Write to specific address.
        self.pci_dev.io_writeq(self.bar_addr, 0 as u64, addr);
        test_state.borrow().clock_step_ns(REFRESH_TIME_INTERVAL);
        println!("cmd : {:?}", cmd);
    }

    pub fn set_devfn(&mut self, devfn: u8) {
        self.pci_dev.devfn = devfn;
    }

    pub fn find_pci_device(&mut self, devfn: u8) -> bool {
        self.set_devfn(devfn);
        if self.pci_dev.config_readw(PCI_VENDOR_ID) == 0xFFFF {
            return false;
        }
        true
    }

    pub fn init(&mut self, pci_slot: u8) {
        let devfn = pci_slot << 3;
        assert!(self.find_pci_device(devfn));

        self.pci_dev.enable();
        self.bar_addr = self.pci_dev.io_map(self.bar_idx);
    }
}

pub struct TestDemoInputDevice {
    pub pci_dev: TestPciDev,
    pub bar_addr: PCIBarAddr,
    bar_idx: u8,
    mem_addr: u64,
    allocator: Rc<RefCell<GuestAllocator>>,
}

impl TestDemoInputDevice {
    pub fn new(pci_bus: Rc<RefCell<TestPciBus>>, allocator: Rc<RefCell<GuestAllocator>>) -> Self {
        Self {
            pci_dev: TestPciDev::new(pci_bus),
            bar_addr: 0,
            bar_idx: 0,
            mem_addr: 0,
            allocator,
        }
    }

    /// Alloc a memory space, and write the address to the input device configuration space.
    pub fn activate(&mut self) {
        let addr = self.allocator.borrow_mut().alloc(100);
        self.mem_addr = addr;
        self.pci_dev.io_writeq(self.bar_addr, 0, addr)
    }

    /// Read an input event from a memory.
    pub fn read_input_event(&mut self) -> InputMessage {
        sleep(Duration::from_millis(50));
        let addr = self.mem_addr;
        let test_state = self.pci_dev.pci_bus.borrow_mut().test_state.clone();

        let mut msg = InputMessage::default();
        msg.event_type = InputEvent::from(test_state.borrow_mut().readb(addr));
        msg.keycode = test_state.borrow_mut().readw(addr + 1);
        msg.down = test_state.borrow_mut().readb(addr + 3);
        msg.button = test_state.borrow_mut().readl(addr + 4);
        msg.x = test_state.borrow_mut().readl(addr + 8);
        msg.y = test_state.borrow_mut().readl(addr + 12);
        println!("kbd mouse event: {:?}", msg);
        msg
    }

    pub fn set_devfn(&mut self, devfn: u8) {
        self.pci_dev.devfn = devfn;
    }

    pub fn find_pci_device(&mut self, devfn: u8) -> bool {
        self.set_devfn(devfn);
        if self.pci_dev.config_readw(PCI_VENDOR_ID) == 0xFFFF {
            return false;
        }
        true
    }

    pub fn init(&mut self, pci_slot: u8) {
        let devfn = pci_slot << 3;
        assert!(self.find_pci_device(devfn));

        self.pci_dev.enable();
        self.bar_addr = self.pci_dev.io_map(self.bar_idx);
        self.activate();
    }
}

pub struct DemoGpuConfig {
    pub pci_slot: u8,
    pub id: String,
}

pub struct InputConfig {
    pub pci_slot: u8,
    pub id: String,
}

/// Environment Setup.
pub fn set_up(
    gpu_conf: Vec<DemoGpuConfig>,
    input_conf: InputConfig,
    port: u16,
) -> (
    Vec<Rc<RefCell<TestDemoGpuDevice>>>,
    Rc<RefCell<TestDemoInputDevice>>,
    Rc<RefCell<TestState>>,
) {
    let mut args: Vec<String> = Vec::new();
    // vm args.
    let vm_args = String::from("-machine virt");
    let vm_args: Vec<&str> = vm_args[..].split(' ').collect();
    let mut vm_args = vm_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut vm_args);
    // Log.
    let vm_args = String::from("-D /tmp/vnc_test.log");
    let vm_args: Vec<&str> = vm_args[..].split(' ').collect();
    let mut vm_args = vm_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut vm_args);
    // Demo GPU Device.
    for conf in &gpu_conf {
        let gpu_args = format!(
            "-device {},bus=pcie.0,addr={}.0,id={},bar_num=3,device_type=demo-gpu,bar_size=4096",
            "pcie-demo-dev", conf.pci_slot, conf.id,
        );
        let gpu_args: Vec<&str> = gpu_args[..].split(' ').collect();
        let mut gpu_args = gpu_args.into_iter().map(|s| s.to_string()).collect();
        args.append(&mut gpu_args);
    }
    // Demo Input Device.
    let input_args = format!(
        "-device {},bus=pcie.0,addr={}.0,id={},bar_num=3,device_type=demo-input,bar_size=4096",
        "pcie-demo-dev", input_conf.pci_slot, input_conf.id,
    );
    let input_args: Vec<&str> = input_args[..].split(' ').collect();
    let mut input_args = input_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut input_args);

    // VNC server
    let vnc_args = format!("-vnc 0.0.0.0:{}", port);
    let vnc_args: Vec<&str> = vnc_args[..].split(' ').collect();
    let mut vnc_args = vnc_args.into_iter().map(|s| s.to_string()).collect();
    args.append(&mut vnc_args);
    let args = args.iter().map(AsRef::as_ref).collect();

    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let allocator = machine.allocator.clone();

    let mut gpu_lists: Vec<Rc<RefCell<TestDemoGpuDevice>>> = Vec::new();
    for conf in gpu_conf {
        let demo_gpu = Rc::new(RefCell::new(TestDemoGpuDevice::new(
            machine.pci_bus.clone(),
            allocator.clone(),
        )));
        demo_gpu.borrow_mut().init(conf.pci_slot);
        demo_gpu
            .borrow_mut()
            .replace_surface(640, 480, PIXMAN_A8B8G8R8);
        gpu_lists.push(demo_gpu);
    }

    let input = Rc::new(RefCell::new(TestDemoInputDevice::new(
        machine.pci_bus.clone(),
        allocator,
    )));
    input.borrow_mut().init(input_conf.pci_slot);
    test_state.borrow().clock_step_ns(REFRESH_TIME_INTERVAL);
    (gpu_lists, input, test_state)
}

pub fn tear_down(
    gpu_list: Vec<Rc<RefCell<TestDemoGpuDevice>>>,
    _input: Rc<RefCell<TestDemoInputDevice>>,
    test_state: Rc<RefCell<TestState>>,
) {
    for demo_gpu in gpu_list {
        demo_gpu.borrow_mut().deactive();
    }
    test_state.borrow_mut().stop();
}

/// Key mapping.
/// Vnc client send keysym -> vnc server
/// Vnc server send keycode -> usb.
pub const KEYEVENTLIST: [(&str, u16, u16); 41] = [
    ("space", 0x0020, 0x0039),
    ("0", 0x0030, 0x000b),
    ("1", 0x0031, 0x0002),
    ("2", 0x0032, 0x0003),
    ("3", 0x0033, 0x0004),
    ("4", 0x0034, 0x0005),
    ("5", 0x0035, 0x0006),
    ("6", 0x0036, 0x0007),
    ("7", 0x0037, 0x0008),
    ("8", 0x0038, 0x0009),
    ("9", 0x0039, 0x000a),
    ("a", 0x0061, 0x001e),
    ("b", 0x0062, 0x0030),
    ("c", 0x0063, 0x002e),
    ("d", 0x0064, 0x0020),
    ("e", 0x0065, 0x0012),
    ("f", 0x0066, 0x0021),
    ("g", 0x0067, 0x0022),
    ("h", 0x0068, 0x0023),
    ("i", 0x0069, 0x0017),
    ("j", 0x006a, 0x0024),
    ("k", 0x006b, 0x0025),
    ("l", 0x006c, 0x0026),
    ("m", 0x006d, 0x0032),
    ("n", 0x006e, 0x0031),
    ("o", 0x006f, 0x0018),
    ("p", 0x0070, 0x0019),
    ("q", 0x0071, 0x0010),
    ("r", 0x0072, 0x0013),
    ("s", 0x0073, 0x001f),
    ("t", 0x0074, 0x0014),
    ("u", 0x0075, 0x0016),
    ("v", 0x0076, 0x002f),
    ("w", 0x0077, 0x0011),
    ("x", 0x0078, 0x002d),
    ("y", 0x0079, 0x0015),
    ("z", 0x007a, 0x002c),
    ("ctl", 0xFFE3, 0x001d),
    ("alt", 0xFFE9, 0x0038),
    ("caps_lock", 0xFFE5, 0x003a),
    ("num_lock", 0xFF7F, 0x0045),
];

// Event type of Point.
pub const INPUT_POINT_LEFT: u8 = 0x01;
pub const INPUT_POINT_MIDDLE: u8 = 0x02;
pub const INPUT_POINT_RIGHT: u8 = 0x04;

// Coordinates of pointer movement on the desktop.
pub const POINTEVENTLIST: [(u8, u16, u16); 16] = [
    (INPUT_POINT_LEFT, 0x0070, 0x0002),
    (INPUT_POINT_RIGHT, 0x0000, 0x0005),
    (INPUT_POINT_LEFT, 0x0005, 0x0005),
    (INPUT_POINT_RIGHT, 0x0005, 0x0136),
    (INPUT_POINT_MIDDLE, 0x0005, 0x0011),
    (INPUT_POINT_LEFT, 0x0005, 0x0017),
    (INPUT_POINT_RIGHT, 0x00aa, 0x0016),
    (INPUT_POINT_LEFT, 0x0013, 0x0018),
    (INPUT_POINT_RIGHT, 0x000b, 0x001b),
    (INPUT_POINT_MIDDLE, 0x0078, 0x001b),
    (INPUT_POINT_LEFT, 0x0011, 0x001b),
    (INPUT_POINT_LEFT, 0x0011, 0x00c8),
    (INPUT_POINT_MIDDLE, 0x0043, 0x00d2),
    (INPUT_POINT_LEFT, 0x006d, 0x00c8),
    (INPUT_POINT_MIDDLE, 0x00be, 0x00c8),
    (INPUT_POINT_RIGHT, 0x00be, 0x0122),
];

pub const TEST_CLIENT_RAND_MSG: [u8; 256] = [
    0x67, 0xa5, 0x3a, 0xeb, 0x4e, 0x30, 0xb0, 0x8d, 0xd7, 0x5e, 0x63, 0x3a, 0xdb, 0xb5, 0xd6, 0x51,
    0x54, 0x66, 0xb7, 0x38, 0xe3, 0xea, 0x89, 0x3b, 0xfa, 0x64, 0xfd, 0xed, 0xc7, 0xe5, 0xbb, 0x4d,
    0x60, 0x0e, 0x8c, 0xc8, 0x6d, 0x97, 0x1b, 0x17, 0xe8, 0x4c, 0x9a, 0xfa, 0x28, 0x03, 0xdb, 0x03,
    0xb5, 0x7f, 0xf1, 0x45, 0x5c, 0xb8, 0x8b, 0xe9, 0x1b, 0x62, 0xe3, 0xb6, 0x7c, 0x94, 0x96, 0xa1,
    0xbf, 0xd0, 0xc9, 0xde, 0x12, 0x3e, 0x21, 0x8a, 0x14, 0x0b, 0x3e, 0x4f, 0x9e, 0xc6, 0x92, 0xb3,
    0xed, 0x5b, 0x71, 0xa3, 0x88, 0x8e, 0x0b, 0x63, 0x66, 0x66, 0xd9, 0xf6, 0xfb, 0xa9, 0x2d, 0x98,
    0xea, 0x6b, 0x05, 0xe3, 0x21, 0xcf, 0x4a, 0xc9, 0x76, 0x1e, 0x6d, 0x00, 0xde, 0x0b, 0x9d, 0xa5,
    0xd0, 0xd1, 0xe4, 0x24, 0x92, 0x19, 0xb8, 0x66, 0xde, 0x6d, 0x1d, 0x98, 0x91, 0x63, 0xa7, 0x03,
    0xdf, 0xbc, 0x98, 0x56, 0x04, 0x8f, 0xf6, 0x92, 0xfe, 0xe5, 0x3b, 0xaf, 0x2e, 0x10, 0x85, 0x94,
    0xa9, 0xc1, 0xed, 0x0a, 0x39, 0x4a, 0xe9, 0x8a, 0x52, 0xa9, 0x8d, 0x13, 0x40, 0x28, 0x21, 0x43,
    0x8b, 0x75, 0x01, 0xf1, 0xf9, 0xde, 0x6e, 0xc6, 0x2c, 0xb0, 0x42, 0x78, 0x2b, 0xf8, 0x34, 0x24,
    0x7a, 0x71, 0xc7, 0x94, 0xac, 0xa8, 0x7d, 0x9b, 0x85, 0xfe, 0x47, 0xc9, 0xd4, 0x70, 0x07, 0x7a,
    0x63, 0x07, 0xb8, 0x83, 0xcb, 0xee, 0x1a, 0x24, 0x58, 0xb3, 0xc3, 0x48, 0xb8, 0xa2, 0x01, 0x8c,
    0x20, 0x3a, 0xe0, 0xe6, 0xa7, 0xf8, 0x5b, 0x1a, 0xd8, 0xfe, 0x7f, 0x4b, 0x50, 0x14, 0x4d, 0xe5,
    0x6f, 0x6f, 0x2f, 0xfa, 0xbb, 0x95, 0x85, 0xfc, 0x33, 0xe7, 0xcf, 0x0d, 0xe1, 0x28, 0x0e, 0xc0,
    0xba, 0xe8, 0xbd, 0x23, 0xc3, 0x7b, 0x25, 0x11, 0xf5, 0x30, 0x30, 0x5f, 0xb8, 0x57, 0xfe, 0xd5,
];
