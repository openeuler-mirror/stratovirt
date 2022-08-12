// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use crate::config::*;
use std::sync::{Arc, Mutex, Weak};

use address_space::AddressSpace;

use crate::usb::UsbPort;
use crate::xhci::xhci_controller::XhciDevice;

/// Capability offset or size.
pub const XHCI_CAP_LENGTH: u32 = 0x40;
pub const XHCI_OFF_DOORBELL: u32 = 0x2000;
pub const XHCI_OFF_RUNTIME: u32 = 0x1000;

/// XHCI Operation Registers
#[derive(Default, Copy, Clone)]
pub struct XchiOperReg {
    /// USB Command
    pub usb_cmd: u32,
    /// USB Status
    pub usb_status: u32,
    /// Device Notify Control
    pub dev_notify_ctrl: u32,
    /// Command Ring Control
    pub cmd_ring_ctrl: u64,
    /// Device Context Base Address Array Pointer
    pub dcbaap: u64,
    /// Configure
    pub config: u32,
}

impl XchiOperReg {
    pub fn new() -> Self {
        Self {
            usb_cmd: 0,
            usb_status: 0,
            dev_notify_ctrl: 0,
            cmd_ring_ctrl: 0,
            dcbaap: 0,
            config: 0,
        }
    }

    pub fn reset(&mut self) {
        self.usb_cmd = 0;
        self.usb_status = USB_STS_HCH;
        self.dev_notify_ctrl = 0;
        self.cmd_ring_ctrl = 0;
        self.dcbaap = 0;
        self.config = 0;
    }
}

/// XHCI Interrupter
#[derive(Clone)]
pub struct XhciInterrupter {
    mem: Arc<AddressSpace>,
    /// Interrupter Management
    pub iman: u32,
    /// Interrupter Morderation
    pub imod: u32,
    /// Event Ring Segment Table Size
    pub erstsz: u32,
    /// Event Ring Segment Table Base Address
    pub erstba: u64,
    /// Event Ring Dequeue Pointer
    pub erdp: u64,
    /// Event Ring Producer Cycle State
    pub er_pcs: bool,
    pub er_start: u64,
    pub er_size: u32,
    pub er_ep_idx: u32,
}

impl XhciInterrupter {
    pub fn new(mem: &Arc<AddressSpace>) -> Self {
        Self {
            mem: mem.clone(),
            iman: 0,
            imod: 0,
            erstsz: 0,
            erstba: 0,
            erdp: 0,
            er_pcs: false,
            er_start: 0,
            er_size: 0,
            er_ep_idx: 0,
        }
    }

    pub fn reset(&mut self) {
        self.iman = 0;
        self.imod = 0;
        self.erstsz = 0;
        self.erstba = 0;
        self.erdp = 0;
        self.er_pcs = false;
        self.er_start = 0;
        self.er_size = 0;
        self.er_ep_idx = 0;
    }
}

/// XHCI port used to notify device.
pub struct XhciPort {
    xhci: Weak<Mutex<XhciDevice>>,
    /// Port Status and Control
    pub portsc: u32,
    /// Port ID
    pub port_idx: u32,
    pub usb_port: Option<Weak<Mutex<UsbPort>>>,
    pub speed_mask: u32,
    pub name: String,
}

impl XhciPort {
    pub fn new(xhci: &Weak<Mutex<XhciDevice>>, name: String, i: u32) -> Self {
        Self {
            xhci: xhci.clone(),
            portsc: 0,
            port_idx: i,
            speed_mask: 0,
            usb_port: None,
            name,
        }
    }
}
