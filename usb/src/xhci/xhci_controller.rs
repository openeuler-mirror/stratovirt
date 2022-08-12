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

use std::sync::{Arc, Mutex, Weak};

use address_space::AddressSpace;

use crate::bus::UsbBus;
use crate::config::*;
use crate::usb::{UsbPacket, UsbPort};
use crate::xhci::xhci_regs::{XchiOperReg, XhciInterrupter, XhciPort};
use crate::xhci::xhci_ring::{TRBCCode, TRBType, XhciRing, XhciTRB};

pub const MAX_INTRS: u16 = 16;
pub const MAX_SLOTS: u32 = 64;

type DmaAddr = u64;

/// Transfer data between controller and device.
#[derive(Clone)]
pub struct XhciTransfer {
    packet: UsbPacket,
    status: TRBCCode,
    trbs: Vec<XhciTRB>,
    complete: bool,
    slotid: u32,
    epid: u32,
    in_xfer: bool,
    int_req: bool,
    running_retry: bool,
}

impl XhciTransfer {
    fn new(len: u32) -> Self {
        XhciTransfer {
            packet: UsbPacket::default(),
            status: TRBCCode::Invalid,
            trbs: vec![XhciTRB::new(); len as usize],
            complete: false,
            slotid: 0,
            epid: 0,
            in_xfer: false,
            int_req: false,
            running_retry: false,
        }
    }
}

/// Endpoint context which use the ring to transfer data.
#[derive(Clone)]
pub struct XhciEpContext {
    epid: u32,
    enabled: bool,
    ring: XhciRing,
    ep_type: EpType,
    pctx: DmaAddr,
    max_psize: u32,
    state: u32,
    /// Line Stream Array
    lsa: bool,
    interval: u32,
    transfers: Vec<XhciTransfer>,
    retry: Option<XhciTransfer>,
}

impl XhciEpContext {
    pub fn new(mem: &Arc<AddressSpace>, epid: u32) -> Self {
        Self {
            epid,
            enabled: false,
            ring: XhciRing::new(mem),
            ep_type: EpType::Invalid,
            pctx: 0,
            max_psize: 0,
            state: 0,
            lsa: false,
            interval: 0,
            transfers: Vec::new(),
            retry: None,
        }
    }
}

/// Endpoint type, including control, bulk, interrupt and isochronous.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EpType {
    Invalid = 0,
    IsoOut,
    BulkOut,
    IntrOut,
    Control,
    IsoIn,
    BulkIn,
    IntrIn,
}

impl From<u32> for EpType {
    fn from(t: u32) -> EpType {
        match t {
            0 => EpType::Invalid,
            1 => EpType::IsoOut,
            2 => EpType::BulkOut,
            3 => EpType::IntrOut,
            4 => EpType::Control,
            5 => EpType::IsoIn,
            6 => EpType::BulkIn,
            7 => EpType::IntrIn,
            _ => EpType::Invalid,
        }
    }
}

/// Device slot, mainly including some endpoint.
#[derive(Clone)]
pub struct XhciSlot {
    pub enabled: bool,
    pub addressed: bool,
    pub intr: u16,
    pub ctx: u64,
    pub usb_port: Option<Weak<Mutex<UsbPort>>>,
    pub endpoints: Vec<XhciEpContext>,
}

impl XhciSlot {
    pub fn new(mem: &Arc<AddressSpace>) -> Self {
        XhciSlot {
            enabled: false,
            addressed: false,
            intr: 0,
            ctx: 0,
            usb_port: None,
            endpoints: vec![XhciEpContext::new(mem, 0); 31],
        }
    }
}

/// Event usually send to drivers.
#[derive(Debug)]
pub struct XhciEvent {
    pub trb_type: TRBType,
    pub ccode: TRBCCode,
    pub ptr: u64,
    pub length: u32,
    flags: u32,
    slot_id: u8,
    ep_id: u8,
}

impl XhciEvent {
    pub fn new(trb_type: TRBType, ccode: TRBCCode) -> Self {
        Self {
            trb_type,
            ccode,
            ptr: 0,
            length: 0,
            slot_id: 0,
            flags: 0,
            ep_id: 0,
        }
    }
}

/// Controller ops registered in XhciDevice. Such as PCI device send MSIX.
pub trait XhciOps: Send + Sync {
    fn trigger_intr(&mut self, n: u32, level: bool) -> bool;

    fn update_intr(&mut self, n: u32, enable: bool);
}

/// Xhci controller device.
pub struct XhciDevice {
    pub numports_2: u32,
    pub numports_3: u32,
    pub oper: XchiOperReg,
    pub usb_ports: Vec<Arc<Mutex<UsbPort>>>,
    pub ports: Vec<Arc<Mutex<XhciPort>>>,
    pub port_num: u32,
    pub slots: Vec<XhciSlot>,
    pub intrs: Vec<XhciInterrupter>,
    pub cmd_ring: XhciRing,
    mem_space: Arc<AddressSpace>,
    pub bus: Arc<Mutex<UsbBus>>,
    pub ctrl_ops: Option<Weak<Mutex<dyn XhciOps>>>,
}

impl XhciDevice {
    pub fn new(mem_space: &Arc<AddressSpace>) -> Arc<Mutex<Self>> {
        let xhci = XhciDevice {
            oper: XchiOperReg::new(),
            ctrl_ops: None,
            usb_ports: Vec::new(),
            numports_2: 2,
            numports_3: 2,
            port_num: 4,
            ports: Vec::new(),
            slots: vec![XhciSlot::new(mem_space); MAX_SLOTS as usize],
            intrs: vec![XhciInterrupter::new(mem_space); 1],
            cmd_ring: XhciRing::new(mem_space),
            mem_space: mem_space.clone(),
            bus: Arc::new(Mutex::new(UsbBus::new())),
        };
        let xhci = Arc::new(Mutex::new(xhci));
        let clone_xhci = xhci.clone();
        let mut locked_xhci = clone_xhci.lock().unwrap();
        locked_xhci.oper.usb_status = USB_STS_HCH;
        xhci
    }
}
