// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::BTreeMap;
use std::fs::File;

use anyhow::{bail, Result};
use libc::c_int;
use log::error;
use vmm_sys_util::{ioctl::ioctl_with_mut_ref, ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

use crate::byte_code::ByteCode;

/// Event Code type, used for autorepeating devices.
pub const EV_REP: u8 = 0x14;
/// Max event type.
pub const EV_MAX: u8 = 0x1F;
/// Max ABS_* event type.
pub const ABS_MAX: u8 = 0x3F;

/// Sync event type.
pub const EV_SYN: u16 = 0x00;
/// Synchronization event.
pub const SYN_REPORT: u16 = 0x00;

/// The payload(union) size of the virtio_input_config.
pub const VIRTIO_INPUT_CFG_PAYLOAD_SIZE: usize = 128;

#[derive(Copy, Clone)]
pub struct EvdevBuf {
    pub buf: [u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
    pub len: usize,
}

impl EvdevBuf {
    pub fn new() -> Self {
        Self {
            buf: [0_u8; VIRTIO_INPUT_CFG_PAYLOAD_SIZE],
            len: 0,
        }
    }

    pub fn get_bit(&self, bit: usize) -> bool {
        if (bit + 7) / 8 > self.len {
            return false;
        }
        let idx = bit / 8;
        let offset = bit % 8;
        self.buf[idx] & (1u8 << offset) != 0
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.buf[0..self.len].to_vec()
    }
}

impl Default for EvdevBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl ByteCode for EvdevBuf {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct EvdevId {
    pub bustype: u16,
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
}

impl EvdevId {
    pub fn from_buf(buf: EvdevBuf) -> Self {
        *Self::from_bytes(buf.to_vec().as_slice()).unwrap()
    }
}

impl ByteCode for EvdevId {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct InputAbsInfo {
    pub value: u32,
    pub minimum: u32,
    pub maximum: u32,
    pub fuzz: u32,
    pub flat: u32,
    pub resolution: u32,
}

const EVDEV: u32 = 69; // 'E'
ioctl_ior_nr!(EVIOCGVERSION, EVDEV, 0x01, c_int);
ioctl_ior_nr!(EVIOCGID, EVDEV, 0x02, EvdevId);
ioctl_ior_nr!(EVIOCGNAME, EVDEV, 0x06, EvdevBuf);
ioctl_ior_nr!(EVIOCGUNIQ, EVDEV, 0x08, EvdevBuf);
ioctl_ior_nr!(EVIOCGPROP, EVDEV, 0x09, EvdevBuf);
ioctl_ior_nr!(EVIOCGBIT, EVDEV, 0x20 + evt, EvdevBuf, evt);
ioctl_ior_nr!(EVIOCGABS, EVDEV, 0x40 + abs, InputAbsInfo, abs);
ioctl_iow_nr!(EVIOCGRAB, EVDEV, 0x90, c_int);

pub fn evdev_ioctl(fd: &File, req: u64, len: usize) -> EvdevBuf {
    let mut evbuf = EvdevBuf::new();
    // SAFETY: file is `evdev` fd, and we check the return.
    let ret = unsafe { ioctl_with_mut_ref(fd, req, &mut evbuf.buf) };
    if ret < 0 {
        error!(
            "Ioctl {} failed, error is {}.",
            req,
            std::io::Error::last_os_error()
        );
        evbuf.len = 0;
        return evbuf;
    }

    evbuf.len = len;
    if evbuf.len == 0 {
        if ret != 0 {
            evbuf.len = ret as usize;
        } else {
            evbuf.len = VIRTIO_INPUT_CFG_PAYLOAD_SIZE;
        }
    }

    evbuf
}

pub fn evdev_evt_supported(fd: &File) -> Result<BTreeMap<u8, EvdevBuf>> {
    let mut evts: BTreeMap<u8, EvdevBuf> = BTreeMap::new();
    let evt_type = evdev_ioctl(fd, EVIOCGBIT(0), 0);
    if evt_type.len == 0 {
        bail!(format!(
            "Failed to get bit 0, error {}",
            std::io::Error::last_os_error()
        ))
    }
    for ev in 1..EV_MAX {
        if ev == EV_REP || !evt_type.get_bit(ev as usize) {
            // Not supported event
            continue;
        }
        evts.insert(ev, evdev_ioctl(fd, EVIOCGBIT(ev as u32), 0));
    }

    Ok(evts)
}

pub fn evdev_abs(fd: &File) -> Result<BTreeMap<u8, InputAbsInfo>> {
    let mut absinfo_db: BTreeMap<u8, InputAbsInfo> = BTreeMap::new();
    for abs in 0..ABS_MAX {
        let mut absinfo = InputAbsInfo::default();
        // SAFETY: file is `evdev` fd, and we check the return.
        let len = unsafe { ioctl_with_mut_ref(fd, EVIOCGABS(abs as u32), &mut absinfo) };
        if len == 0 {
            absinfo_db.insert(abs, absinfo);
        }
    }

    Ok(absinfo_db)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InputEvent {
    pub timestamp: [u64; 2],
    pub ev_type: u16,
    pub code: u16,
    pub value: i32,
}

impl ByteCode for InputEvent {}
