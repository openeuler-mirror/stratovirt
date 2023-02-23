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

use std::collections::LinkedList;
use std::mem::size_of;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, bail, Context, Result};

use address_space::{AddressSpace, GuestAddress};
use byteorder::{ByteOrder, LittleEndian};
use log::{debug, error, info, warn};
use machine_manager::config::XhciConfig;
use util::num_ops::{read_u32, write_u64_low};

use crate::config::*;
use crate::usb::{Iovec, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus};
use crate::xhci::xhci_regs::{XchiOperReg, XhciInterrupter};
use crate::UsbError;

use super::xhci_ring::XhciEventRingSeg;
use super::xhci_ring::XhciRing;
use super::xhci_ring::XhciTRB;
use super::{
    TRBCCode, TRBType, SETUP_TRB_TR_LEN, TRB_EV_ED, TRB_SIZE, TRB_TR_DIR, TRB_TR_IDT, TRB_TR_IOC,
    TRB_TR_ISP, TRB_TR_LEN_MASK, TRB_TYPE_SHIFT,
};

pub const MAX_INTRS: u16 = 16;
pub const MAX_SLOTS: u32 = 64;
/// Endpoint state
pub const EP_STATE_MASK: u32 = 0x7;
pub const EP_DISABLED: u32 = 0;
pub const EP_RUNNING: u32 = 1;
pub const EP_HALTED: u32 = 2;
pub const EP_STOPPED: u32 = 3;
pub const EP_ERROR: u32 = 4;
/// Endpoint type
const EP_TYPE_SHIFT: u32 = 3;
const EP_TYPE_MASK: u32 = 0x7;
/// Slot state
const SLOT_STATE_MASK: u32 = 0x1f;
const SLOT_STATE_SHIFT: u32 = 27;
/// 6.2.3 Slot Context. Table 6-7.
/// The values of both enabled and disabled are 0.
pub const SLOT_DISABLED_ENABLED: u32 = 0;
pub const SLOT_DEFAULT: u32 = 1;
pub const SLOT_ADDRESSED: u32 = 2;
pub const SLOT_CONFIGURED: u32 = 3;
/// TRB flags
const TRB_CR_BSR: u32 = 1 << 9;
const TRB_CR_EPID_SHIFT: u32 = 16;
const TRB_CR_EPID_MASK: u32 = 0x1f;
const TRB_INTR_SHIFT: u32 = 22;
const TRB_INTR_MASK: u32 = 0x3ff;
const TRB_CR_DC: u32 = 1 << 9;
const TRB_CR_SLOTID_SHIFT: u32 = 24;
const TRB_CR_SLOTID_MASK: u32 = 0xff;
const COMMAND_LIMIT: u32 = 256;
const EP_CTX_INTERVAL_SHIFT: u32 = 16;
const EP_CTX_INTERVAL_MASK: u32 = 0xff;
const EVENT_TRB_CCODE_SHIFT: u32 = 24;
const EVENT_TRB_SLOT_ID_SHIFT: u32 = 24;
const EVENT_TRB_EP_ID_SHIFT: u32 = 16;
const PORT_EVENT_ID_SHIFT: u32 = 24;
const SLOT_CTX_PORT_NUMBER_SHIFT: u32 = 16;
const ENDPOINT_ID_START: u32 = 1;
const MAX_ENDPOINTS: u32 = 31;
const TRANSFER_LEN_MASK: u32 = 0xffffff;
/// XHCI config
const XHCI_MAX_PORT2: u8 = 15;
const XHCI_MAX_PORT3: u8 = 15;
const XHCI_DEFAULT_PORT: u8 = 4;
/// Input Context.
const INPUT_CONTEXT_SIZE: u64 = 0x420;
/// Device Context.
const DEVICE_CONTEXT_SIZE: u64 = 0x400;
/// Slot Context.
const SLOT_INPUT_CTX_OFFSET: u64 = 0x20;
const SLOT_CONTEXT_MAX_EXIT_LATENCY_MASK: u32 = 0xffff;
const SLOT_CONTEXT_MAX_EXIT_LATENCY_SHIFT: u32 = 0;
const SLOT_CONTEXT_INTERRUPTER_TARGET_MASK: u32 = 0x3ff;
const SLOT_CONTEXT_INTERRUPTER_TARGET_SHIFT: u32 = 22;
const SLOT_CONTEXT_PORT_NUMBER_MASK: u32 = 0xff;
const SLOT_CONTEXT_PORT_NUMBER_SHIFT: u32 = 16;
const SLOT_CONTEXT_ENTRIES_MASK: u32 = 0x1f;
const SLOT_CONTEXT_ENTRIES_SHIFT: u32 = 27;
const SLOT_CONTEXT_DEVICE_ADDRESS_MASK: u32 = 0xff;
const SLOT_CONTEXT_DEVICE_ADDRESS_SHIFT: u32 = 0;
/// Endpoint Context.
const EP_INPUT_CTX_ENTRY_SIZE: u64 = 0x20;
const EP_INPUT_CTX_OFFSET: u64 = 0x40;
const EP_CTX_OFFSET: u64 = 0x20;
const EP_CTX_TR_DEQUEUE_POINTER_MASK: u64 = !0xf;
const EP_CTX_DCS: u64 = 1;
const EP_CONTEXT_MAX_PACKET_SIZE_MASK: u32 = 0xffff;
const EP_CONTEXT_MAX_PACKET_SIZE_SHIFT: u32 = 16;
const EP_CONTEXT_INTERVAL_MASK: u32 = 0xff;
const EP_CONTEXT_INTERVAL_SHIFT: u32 = 16;
const EP_CONTEXT_EP_STATE_MASK: u32 = 0x7;
const EP_CONTEXT_EP_STATE_SHIFT: u32 = 0;
const EP_CONTEXT_EP_TYPE_MASK: u32 = 0x7;
const EP_CONTEXT_EP_TYPE_SHIFT: u32 = 3;

type DmaAddr = u64;

/// Transfer data between controller and device.
#[derive(Clone)]
pub struct XhciTransfer {
    packet: UsbPacket,
    status: TRBCCode,
    td: Vec<XhciTRB>,
    complete: Arc<AtomicBool>,
    slotid: u32,
    epid: u32,
    in_xfer: bool,
    running_retry: bool,
}

impl XhciTransfer {
    fn new() -> Self {
        XhciTransfer {
            packet: UsbPacket::default(),
            status: TRBCCode::Invalid,
            td: Vec::new(),
            complete: Arc::new(AtomicBool::new(false)),
            slotid: 0,
            epid: 0,
            in_xfer: false,
            running_retry: false,
        }
    }

    fn is_completed(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    fn set_comleted(&mut self, v: bool) {
        self.complete.store(v, Ordering::SeqCst)
    }
}

/// Endpoint context which use the ring to transfer data.
#[derive(Clone)]
pub struct XhciEpContext {
    epid: u32,
    enabled: bool,
    ring: XhciRing,
    ep_type: EpType,
    output_ctx_addr: DmaAddr,
    state: u32,
    interval: u32,
    transfers: LinkedList<XhciTransfer>,
    retry: Option<XhciTransfer>,
}

impl XhciEpContext {
    pub fn new(mem: &Arc<AddressSpace>) -> Self {
        Self {
            epid: 0,
            enabled: false,
            ring: XhciRing::new(mem),
            ep_type: EpType::Invalid,
            output_ctx_addr: 0,
            state: 0,
            interval: 0,
            transfers: LinkedList::new(),
            retry: None,
        }
    }

    /// Init the endpoint context used the context read from memory.
    fn init_ctx(&mut self, output_ctx: DmaAddr, ctx: &XhciEpCtx) {
        let dequeue: DmaAddr = addr64_from_u32(ctx.deq_lo & !0xf, ctx.deq_hi);
        self.ep_type = ((ctx.ep_info2 >> EP_TYPE_SHIFT) & EP_TYPE_MASK).into();
        self.output_ctx_addr = output_ctx;
        self.ring.init(dequeue);
        self.ring.ccs = (ctx.deq_lo & 1) == 1;
        self.interval = 1 << ((ctx.ep_info >> EP_CTX_INTERVAL_SHIFT) & EP_CTX_INTERVAL_MASK);
    }

    /// Update the endpoint state and write the state to memory.
    fn set_state(&mut self, mem: &Arc<AddressSpace>, state: u32) -> Result<()> {
        let mut ep_ctx = XhciEpCtx::default();
        dma_read_u32(
            mem,
            GuestAddress(self.output_ctx_addr),
            ep_ctx.as_mut_dwords(),
        )?;
        ep_ctx.ep_info &= !EP_STATE_MASK;
        ep_ctx.ep_info |= state;
        ep_ctx.deq_lo = self.ring.dequeue as u32 | self.ring.ccs as u32;
        ep_ctx.deq_hi = (self.ring.dequeue >> 32) as u32;
        dma_write_u32(mem, GuestAddress(self.output_ctx_addr), ep_ctx.as_dwords())?;
        self.state = state;
        Ok(())
    }

    /// Update the dequeue pointer in endpoint context.
    /// If dequeue is None, only flush the dequeue pointer to memory.
    fn update_dequeue(&mut self, mem: &Arc<AddressSpace>, dequeue: Option<u64>) -> Result<()> {
        let mut ep_ctx = XhciEpCtx::default();
        dma_read_u32(
            mem,
            GuestAddress(self.output_ctx_addr),
            ep_ctx.as_mut_dwords(),
        )?;
        if let Some(dequeue) = dequeue {
            self.ring.init(dequeue & EP_CTX_TR_DEQUEUE_POINTER_MASK);
            self.ring.ccs = (dequeue & EP_CTX_DCS) == EP_CTX_DCS;
        }
        ep_ctx.deq_lo = self.ring.dequeue as u32 | self.ring.ccs as u32;
        ep_ctx.deq_hi = (self.ring.dequeue >> 32) as u32;
        dma_write_u32(mem, GuestAddress(self.output_ctx_addr), ep_ctx.as_dwords())?;
        Ok(())
    }

    /// Flush the transfer list, remove the transfer which is completed.
    fn flush_transfer(&mut self) {
        let mut undo = LinkedList::new();
        while let Some(head) = self.transfers.pop_front() {
            if !head.is_completed() {
                undo.push_back(head);
            }
        }
        self.transfers = undo;
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
    pub slot_ctx_addr: u64,
    pub usb_port: Option<Arc<Mutex<UsbPort>>>,
    pub endpoints: Vec<XhciEpContext>,
}

impl XhciSlot {
    fn new(mem: &Arc<AddressSpace>) -> Self {
        XhciSlot {
            enabled: false,
            addressed: false,
            slot_ctx_addr: 0,
            usb_port: None,
            endpoints: vec![XhciEpContext::new(mem); MAX_ENDPOINTS as usize],
        }
    }

    /// Get the slot context from the memory.
    fn get_slot_ctx(&self, mem: &Arc<AddressSpace>) -> Result<XhciSlotCtx> {
        let mut slot_ctx = XhciSlotCtx::default();
        dma_read_u32(
            mem,
            GuestAddress(self.slot_ctx_addr),
            slot_ctx.as_mut_dwords(),
        )?;
        Ok(slot_ctx)
    }

    /// Get the slot state in slot context.
    fn get_slot_state_in_context(&self, mem: &Arc<AddressSpace>) -> Result<u32> {
        // Table 4-1: Device Slot State Code Definitions.
        if self.slot_ctx_addr == 0 {
            return Ok(SLOT_DISABLED_ENABLED);
        }
        let slot_ctx = self.get_slot_ctx(mem)?;
        let slot_state = (slot_ctx.dev_state >> SLOT_STATE_SHIFT) & SLOT_STATE_MASK;
        Ok(slot_state)
    }

    fn slot_state_is_valid(&self, mem: &Arc<AddressSpace>) -> Result<bool> {
        let slot_state = self.get_slot_state_in_context(mem)?;
        let valid = slot_state == SLOT_DEFAULT
            || slot_state == SLOT_ADDRESSED
            || slot_state == SLOT_CONFIGURED;
        Ok(valid)
    }
}

/// USB port which can attached device.
pub struct UsbPort {
    pub xhci: Weak<Mutex<XhciDevice>>,
    /// Port Status and Control
    pub portsc: u32,
    /// Port ID
    pub port_id: u8,
    pub speed_mask: u32,
    pub dev: Option<Arc<Mutex<dyn UsbDeviceOps>>>,
    pub used: bool,
}

impl UsbPort {
    pub fn new(xhci: &Weak<Mutex<XhciDevice>>, i: u8) -> Self {
        Self {
            xhci: xhci.clone(),
            portsc: 0,
            port_id: i,
            speed_mask: 0,
            dev: None,
            used: false,
        }
    }

    /// Get port link state from port status and control register.
    pub fn get_port_link_state(&self) -> u32 {
        self.portsc >> PORTSC_PLS_SHIFT & PORTSC_PLS_MASK
    }

    /// Set port link state in port status and control register.
    pub fn set_port_link_state(&mut self, pls: u32) {
        self.portsc &= !(PORTSC_PLS_MASK << PORTSC_PLS_SHIFT);
        self.portsc |= (pls & PORTSC_PLS_MASK) << PORTSC_PLS_SHIFT;
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

    /// Convert event to trb.
    pub fn to_trb(&self) -> XhciTRB {
        XhciTRB {
            parameter: self.ptr,
            status: self.length | (self.ccode as u32) << EVENT_TRB_CCODE_SHIFT,
            control: (self.slot_id as u32) << EVENT_TRB_SLOT_ID_SHIFT
                | (self.ep_id as u32) << EVENT_TRB_EP_ID_SHIFT
                | self.flags
                | (self.trb_type as u32) << TRB_TYPE_SHIFT,
            addr: 0,
            ccs: false,
        }
    }
}

/// Input Control Context. See the spec 6.2.5 Input Control Context.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XhciInputCtrlCtx {
    pub drop_flags: u32,
    pub add_flags: u32,
}

impl DwordOrder for XhciInputCtrlCtx {}

/// Slot Context. See the spec 6.2.2 Slot Context.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XhciSlotCtx {
    pub dev_info: u32,
    pub dev_info2: u32,
    pub tt_info: u32,
    pub dev_state: u32,
}

impl XhciSlotCtx {
    pub fn set_slot_state(&mut self, state: u32) {
        self.dev_state &= !(SLOT_STATE_MASK << SLOT_STATE_SHIFT);
        self.dev_state |= (state & SLOT_STATE_MASK) << SLOT_STATE_SHIFT;
    }

    pub fn get_slot_state(&self) -> u32 {
        self.dev_state >> SLOT_STATE_SHIFT & SLOT_STATE_MASK
    }

    pub fn set_context_entry(&mut self, num: u32) {
        self.dev_info &= !(SLOT_CONTEXT_ENTRIES_MASK << SLOT_CONTEXT_ENTRIES_SHIFT);
        self.dev_info |= (num & SLOT_CONTEXT_ENTRIES_MASK) << SLOT_CONTEXT_ENTRIES_SHIFT;
    }

    pub fn set_port_number(&mut self, port_number: u32) {
        self.dev_info &= !(SLOT_CONTEXT_PORT_NUMBER_MASK << SLOT_CONTEXT_PORT_NUMBER_SHIFT);
        self.dev_info2 |=
            (port_number & SLOT_CONTEXT_PORT_NUMBER_MASK) << SLOT_CONTEXT_PORT_NUMBER_SHIFT;
    }

    pub fn get_max_exit_latency(&self) -> u32 {
        self.dev_info2 >> SLOT_CONTEXT_MAX_EXIT_LATENCY_SHIFT & SLOT_CONTEXT_MAX_EXIT_LATENCY_MASK
    }

    pub fn set_max_exit_latency(&mut self, state: u32) {
        self.dev_info2 &=
            !(SLOT_CONTEXT_MAX_EXIT_LATENCY_MASK << SLOT_CONTEXT_MAX_EXIT_LATENCY_SHIFT);
        self.dev_info2 |=
            (state & SLOT_CONTEXT_MAX_EXIT_LATENCY_MASK) << SLOT_CONTEXT_MAX_EXIT_LATENCY_SHIFT;
    }

    pub fn get_interrupter_target(&self) -> u32 {
        self.tt_info >> SLOT_CONTEXT_INTERRUPTER_TARGET_SHIFT & SLOT_CONTEXT_INTERRUPTER_TARGET_MASK
    }

    pub fn set_interrupter_target(&mut self, state: u32) {
        self.tt_info &=
            !(SLOT_CONTEXT_INTERRUPTER_TARGET_MASK << SLOT_CONTEXT_INTERRUPTER_TARGET_SHIFT);
        self.tt_info |=
            (state & SLOT_CONTEXT_INTERRUPTER_TARGET_MASK) << SLOT_CONTEXT_INTERRUPTER_TARGET_SHIFT;
    }

    pub fn get_usb_device_address(&self) -> u32 {
        self.dev_state >> SLOT_CONTEXT_DEVICE_ADDRESS_SHIFT & SLOT_CONTEXT_DEVICE_ADDRESS_MASK
    }

    pub fn set_usb_device_address(&mut self, state: u32) {
        self.dev_state &= !(SLOT_CONTEXT_DEVICE_ADDRESS_MASK << SLOT_CONTEXT_DEVICE_ADDRESS_SHIFT);
        self.dev_state |=
            (state & SLOT_CONTEXT_DEVICE_ADDRESS_MASK) << SLOT_CONTEXT_DEVICE_ADDRESS_SHIFT;
    }
}

impl DwordOrder for XhciSlotCtx {}

/// Endpoint Context. See the spec 6.2.3 Endpoint Context.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct XhciEpCtx {
    pub ep_info: u32,
    pub ep_info2: u32,
    pub deq_lo: u32,
    pub deq_hi: u32,
    pub tx_info: u32,
}

impl XhciEpCtx {
    pub fn set_tr_dequeue_pointer(&mut self, dequeue: u64) {
        self.deq_lo = dequeue as u32;
        self.deq_hi = (dequeue >> 32) as u32;
    }

    pub fn get_max_packet_size(&self) -> u32 {
        self.ep_info2 >> EP_CONTEXT_MAX_PACKET_SIZE_SHIFT & EP_CONTEXT_MAX_PACKET_SIZE_MASK
    }

    pub fn set_max_packet_size(&mut self, size: u32) {
        self.ep_info2 &= !(EP_CONTEXT_MAX_PACKET_SIZE_MASK << EP_CONTEXT_MAX_PACKET_SIZE_SHIFT);
        self.ep_info2 |=
            (size & EP_CONTEXT_MAX_PACKET_SIZE_MASK) << EP_CONTEXT_MAX_PACKET_SIZE_SHIFT;
    }

    pub fn set_interval(&mut self, inter: u32) {
        self.ep_info &= !(EP_CONTEXT_INTERVAL_MASK << EP_CONTEXT_INTERVAL_SHIFT);
        self.ep_info |= (inter & EP_CONTEXT_INTERVAL_MASK) << EP_CONTEXT_INTERVAL_SHIFT;
    }

    pub fn get_ep_state(&self) -> u32 {
        self.ep_info >> EP_CONTEXT_EP_STATE_SHIFT & EP_CONTEXT_EP_STATE_MASK
    }

    pub fn set_ep_state(&mut self, state: u32) {
        self.ep_info &= !(EP_CONTEXT_EP_STATE_MASK << EP_CONTEXT_EP_STATE_SHIFT);
        self.ep_info |= (state & EP_CONTEXT_EP_STATE_MASK) << EP_CONTEXT_EP_STATE_SHIFT;
    }

    pub fn set_ep_type(&mut self, state: u32) {
        self.ep_info2 &= !(EP_CONTEXT_EP_TYPE_MASK << EP_CONTEXT_EP_TYPE_SHIFT);
        self.ep_info2 |= (state & EP_CONTEXT_EP_TYPE_MASK) << EP_CONTEXT_EP_TYPE_SHIFT;
    }
}

impl DwordOrder for XhciEpCtx {}

pub trait DwordOrder: Default + Copy + Send + Sync {
    fn as_dwords(&self) -> &[u32] {
        unsafe { from_raw_parts(self as *const Self as *const u32, size_of::<Self>() / 4) }
    }

    fn as_mut_dwords(&mut self) -> &mut [u32] {
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u32, size_of::<Self>() / 4) }
    }
}

/// Xhci controller device.
pub struct XhciDevice {
    pub numports_2: u8,
    pub numports_3: u8,
    pub oper: XchiOperReg,
    pub usb_ports: Vec<Arc<Mutex<UsbPort>>>,
    pub slots: Vec<XhciSlot>,
    pub intrs: Vec<XhciInterrupter>,
    pub cmd_ring: XhciRing,
    mem_space: Arc<AddressSpace>,
    pub send_interrupt_ops: Option<Box<dyn Fn(u32) + Send + Sync>>,
}

impl XhciDevice {
    pub fn new(mem_space: &Arc<AddressSpace>, config: &XhciConfig) -> Arc<Mutex<Self>> {
        let mut p2 = XHCI_DEFAULT_PORT;
        let mut p3 = XHCI_DEFAULT_PORT;
        if config.p2.is_some() {
            p2 = config.p2.unwrap();
            if p2 > XHCI_MAX_PORT2 {
                p2 = XHCI_MAX_PORT2
            }
        }
        if config.p3.is_some() {
            p3 = config.p3.unwrap();
            if p3 > XHCI_MAX_PORT3 {
                p3 = XHCI_MAX_PORT3;
            }
        }
        let xhci = XhciDevice {
            oper: XchiOperReg::new(),
            send_interrupt_ops: None,
            usb_ports: Vec::new(),
            numports_3: p3,
            numports_2: p2,
            slots: vec![XhciSlot::new(mem_space); MAX_SLOTS as usize],
            intrs: vec![XhciInterrupter::new(mem_space); MAX_INTRS as usize],
            cmd_ring: XhciRing::new(mem_space),
            mem_space: mem_space.clone(),
        };
        let xhci = Arc::new(Mutex::new(xhci));
        let clone_xhci = xhci.clone();
        let mut locked_xhci = clone_xhci.lock().unwrap();
        locked_xhci.oper.usb_status = USB_STS_HCH;
        for i in 0..locked_xhci.numports_2 {
            let usb_port = Arc::new(Mutex::new(UsbPort::new(
                &Arc::downgrade(&clone_xhci),
                i + 1,
            )));
            locked_xhci.usb_ports.push(usb_port.clone());
            let mut locked_port = usb_port.lock().unwrap();
            locked_port.speed_mask = USB_SPEED_LOW | USB_SPEED_HIGH | USB_SPEED_FULL;
        }
        for i in 0..locked_xhci.numports_3 {
            let idx = i + locked_xhci.numports_2 + 1;
            let usb_port = Arc::new(Mutex::new(UsbPort::new(&Arc::downgrade(&clone_xhci), idx)));
            locked_xhci.usb_ports.push(usb_port.clone());
            let mut locked_port = usb_port.lock().unwrap();
            locked_port.speed_mask = USB_SPEED_SUPER;
        }
        xhci
    }

    pub fn run(&mut self) {
        self.oper.usb_status &= !USB_STS_HCH;
    }

    pub fn stop(&mut self) {
        self.oper.usb_status |= USB_STS_HCH;
        self.oper.cmd_ring_ctrl &= !(CMD_RING_CTRL_CRR as u64);
    }

    pub fn running(&self) -> bool {
        self.oper.usb_status & USB_STS_HCH != USB_STS_HCH
    }

    pub fn host_controller_error(&mut self) {
        error!("Xhci host controller error!");
        self.oper.usb_status |= USB_STS_HCE;
    }

    pub fn reset(&mut self) {
        info!("xhci reset");
        self.oper.reset();
        for i in 0..self.slots.len() as u32 {
            if let Err(e) = self.disable_slot(i + 1) {
                error!("Failed to disable slot {:?}", e);
            }
        }
        for i in 0..self.usb_ports.len() {
            let port = self.usb_ports[i].clone();
            if let Err(e) = self.port_update(&port) {
                error!("Failed to update port: {:?}", e);
            }
        }
        for i in 0..self.intrs.len() {
            self.intrs[i].reset();
        }
        self.cmd_ring.init(0);
    }

    /// Reset xhci port.
    pub fn reset_port(&mut self, xhci_port: &Arc<Mutex<UsbPort>>, warm_reset: bool) -> Result<()> {
        let mut locked_port = xhci_port.lock().unwrap();
        let usb_dev = if let Some(dev) = locked_port.dev.as_ref() {
            dev
        } else {
            // No device, no need to reset.
            return Ok(());
        };
        usb_dev.lock().unwrap().reset();
        let speed = usb_dev.lock().unwrap().speed();
        if speed == USB_SPEED_SUPER && warm_reset {
            locked_port.portsc |= PORTSC_WRC;
        }
        match speed {
            USB_SPEED_LOW | USB_SPEED_FULL | USB_SPEED_HIGH | USB_SPEED_SUPER => {
                locked_port.set_port_link_state(PLS_U0);
                locked_port.portsc |= PORTSC_PED;
            }
            _ => {
                error!("Invalid speed {}", speed);
            }
        }
        locked_port.portsc &= !PORTSC_PR;
        drop(locked_port);
        self.port_notify(xhci_port, PORTSC_PRC)?;
        Ok(())
    }

    /// Send PortStatusChange event to notify drivers.
    pub fn port_notify(&mut self, port: &Arc<Mutex<UsbPort>>, flag: u32) -> Result<()> {
        let mut locked_port = port.lock().unwrap();
        if locked_port.portsc & flag == flag {
            return Ok(());
        }
        locked_port.portsc |= flag;
        if !self.running() {
            return Ok(());
        }
        let mut evt = XhciEvent::new(TRBType::ErPortStatusChange, TRBCCode::Success);
        evt.ptr = ((locked_port.port_id as u32) << PORT_EVENT_ID_SHIFT) as u64;
        self.send_event(&evt, 0)?;
        Ok(())
    }

    /// Update the xhci port status and then notify the driver.
    pub fn port_update(&mut self, port: &Arc<Mutex<UsbPort>>) -> Result<()> {
        let mut locked_port = port.lock().unwrap();
        locked_port.portsc = PORTSC_PP;
        let mut pls = PLS_RX_DETECT;
        if let Some(dev) = &locked_port.dev {
            let speed = dev.lock().unwrap().speed();
            locked_port.portsc |= PORTSC_CCS;
            if speed == USB_SPEED_SUPER {
                locked_port.portsc |= PORTSC_SPEED_SUPER;
                locked_port.portsc |= PORTSC_PED;
                pls = PLS_U0;
            } else if speed == USB_SPEED_FULL {
                locked_port.portsc |= PORTSC_SPEED_FULL;
                pls = PLS_POLLING;
            } else if speed == USB_SPEED_HIGH {
                locked_port.portsc |= PORTSC_SPEED_HIGH;
                pls = PLS_POLLING;
            } else if speed == USB_SPEED_LOW {
                locked_port.portsc |= PORTSC_SPEED_LOW;
                pls = PLS_POLLING;
            }
        }
        locked_port.set_port_link_state(pls);
        debug!(
            "xhci port update portsc {:x} pls {:x}",
            locked_port.portsc, pls
        );
        drop(locked_port);
        self.oper.usb_status |= USB_STS_PCD;
        self.port_notify(port, PORTSC_CSC)?;
        Ok(())
    }

    fn get_slot_id(&self, evt: &mut XhciEvent, trb: &XhciTRB) -> u32 {
        let slot_id = (trb.control >> TRB_CR_SLOTID_SHIFT) & TRB_CR_SLOTID_MASK;
        if slot_id < 1 || slot_id > self.slots.len() as u32 {
            error!("Failed to get slot id, slot {} out of range", slot_id);
            evt.ccode = TRBCCode::TrbError;
            return 0;
        } else if !self.slots[(slot_id - 1) as usize].enabled {
            error!("Failed to get slot id, slot {} is disabled", slot_id);
            evt.ccode = TRBCCode::SlotNotEnabledError;
            return 0;
        }
        slot_id
    }

    fn lookup_usb_port(&mut self, slot_ctx: &XhciSlotCtx) -> Option<Arc<Mutex<UsbPort>>> {
        let port = (slot_ctx.dev_info2 >> SLOT_CTX_PORT_NUMBER_SHIFT & 0xff) as u8;
        if port < 1 || port > self.usb_ports.len() as u8 {
            error!("Invalid port: {}", port);
            return None;
        }
        let usb_port = &self.usb_ports[(port - 1) as usize];
        let locked_port = usb_port.lock().unwrap();
        if locked_port.used {
            Some(usb_port.clone())
        } else {
            None
        }
    }

    /// Control plane
    pub fn handle_command(&mut self) -> Result<()> {
        self.oper.start_cmd_ring();
        let mut slot_id: u32 = 0;
        let mut event = XhciEvent::new(TRBType::ErCommandComplete, TRBCCode::Success);
        for _ in 0..COMMAND_LIMIT {
            match self.cmd_ring.fetch_trb()? {
                Some(trb) => {
                    let trb_type = trb.get_type();
                    event.ptr = trb.addr;
                    info!("handle_command {:?} {:?}", trb_type, trb);
                    match trb_type {
                        TRBType::CrEnableSlot => {
                            let mut found = 0;
                            for i in 0..self.slots.len() as u32 {
                                if !self.slots[i as usize].enabled {
                                    found = i + 1;
                                    break;
                                }
                            }
                            if found == 0 {
                                event.ccode = TRBCCode::NoSlotsError;
                            } else {
                                slot_id = found;
                                event.ccode = self.enable_slot(slot_id);
                            }
                        }
                        TRBType::CrDisableSlot => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                event.ccode = self.disable_slot(slot_id)?;
                            }
                        }
                        TRBType::CrAddressDevice => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                event.ccode = self.address_device(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrConfigureEndpoint => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                event.ccode = self.configure_endpoint(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrEvaluateContext => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                event.ccode = self.evaluate_context(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrStopEndpoint => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                                event.ccode = self.stop_endpoint(slot_id, ep_id)?;
                            }
                        }
                        TRBType::CrResetEndpoint => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                                event.ccode = self.reset_endpoint(slot_id, ep_id)?;
                            }
                        }
                        TRBType::CrSetTrDequeue => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                                event.ccode = self.set_tr_dequeue_pointer(slot_id, ep_id, &trb)?;
                            }
                        }
                        TRBType::CrResetDevice => {
                            slot_id = self.get_slot_id(&mut event, &trb);
                            if slot_id != 0 {
                                event.ccode = self.reset_device(slot_id)?;
                            }
                        }
                        TRBType::CrNoop => {
                            event.ccode = TRBCCode::Success;
                        }
                        _ => {
                            error!("Invalid Command: type {:?}", trb_type);
                            event.ccode = TRBCCode::TrbError;
                        }
                    }
                    event.slot_id = slot_id as u8;
                    self.send_event(&event, 0)?;
                }
                None => {
                    debug!("No TRB in the cmd ring.");
                    break;
                }
            }
        }
        Ok(())
    }

    fn enable_slot(&mut self, slot_id: u32) -> TRBCCode {
        self.slots[(slot_id - 1) as usize].enabled = true;
        TRBCCode::Success
    }

    fn disable_slot(&mut self, slot_id: u32) -> Result<TRBCCode> {
        for i in 1..=self.slots[(slot_id - 1) as usize].endpoints.len() as u32 {
            self.disable_endpoint(slot_id, i)?;
        }
        self.slots[(slot_id - 1) as usize].enabled = false;
        self.slots[(slot_id - 1) as usize].addressed = false;
        self.slots[(slot_id - 1) as usize].usb_port = None;
        self.slots[(slot_id - 1) as usize].slot_ctx_addr = 0;
        Ok(TRBCCode::Success)
    }

    fn address_device(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        let ictx = trb.parameter;
        if ictx.checked_add(INPUT_CONTEXT_SIZE).is_none() {
            bail!(
                "Input Context access overflow, addr {:x} size {:x}",
                ictx,
                INPUT_CONTEXT_SIZE
            );
        }
        let ccode = self.check_input_ctx(ictx)?;
        if ccode != TRBCCode::Success {
            return Ok(ccode);
        }
        let mut slot_ctx = XhciSlotCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(
                // It is safe to plus here becuase we previously verify the address.
                ictx + SLOT_INPUT_CTX_OFFSET,
            ),
            slot_ctx.as_mut_dwords(),
        )?;
        let bsr = trb.control & TRB_CR_BSR == TRB_CR_BSR;
        let ccode = self.check_slot_state(&slot_ctx, bsr)?;
        if ccode != TRBCCode::Success {
            return Ok(ccode);
        }
        let usb_port = if let Some(usb_port) = self.lookup_usb_port(&slot_ctx) {
            usb_port
        } else {
            error!("Failed to found usb port");
            return Ok(TRBCCode::TrbError);
        };
        let lock_port = usb_port.lock().unwrap();
        let dev = if let Some(dev) = lock_port.dev.as_ref() {
            dev
        } else {
            error!("No device found in usb port.");
            return Ok(TRBCCode::UsbTransactionError);
        };
        let ctx_addr = self.get_device_context_addr(slot_id)?;
        let mut octx = 0;
        dma_read_u64(&self.mem_space, GuestAddress(ctx_addr), &mut octx)?;
        if octx.checked_add(DEVICE_CONTEXT_SIZE).is_none() {
            bail!(
                "Device Context access overflow, addr {:x} size {:x}",
                octx,
                DEVICE_CONTEXT_SIZE
            );
        }
        self.slots[(slot_id - 1) as usize].usb_port = Some(usb_port.clone());
        self.slots[(slot_id - 1) as usize].slot_ctx_addr = octx;
        dev.lock().unwrap().reset();
        if bsr {
            slot_ctx.dev_state = SLOT_DEFAULT << SLOT_STATE_SHIFT;
        } else {
            slot_ctx.dev_state = (SLOT_ADDRESSED << SLOT_STATE_SHIFT) | slot_id;
            self.set_device_address(dev, slot_id);
        }
        // Enable control endpoint.
        self.enable_endpoint(slot_id, 1, ictx, octx)?;
        dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        self.slots[(slot_id - 1) as usize].addressed = true;
        Ok(TRBCCode::Success)
    }

    fn check_input_ctx(&self, ictx: u64) -> Result<TRBCCode> {
        let mut ictl_ctx = XhciInputCtrlCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx),
            ictl_ctx.as_mut_dwords(),
        )?;
        if ictl_ctx.add_flags & 0x3 != 0x3 {
            // The Slot Context(Add Context flag0 (A0)) and Default Endpoint Control
            // (Add Context flag1 (A1)) shall be valid. Others shall be ignored.
            error!("Invalid input context: {:?}", ictl_ctx);
            return Ok(TRBCCode::ParameterError);
        }
        Ok(TRBCCode::Success)
    }

    fn check_slot_state(&self, slot_ctx: &XhciSlotCtx, bsr: bool) -> Result<TRBCCode> {
        let slot_state = (slot_ctx.dev_state >> SLOT_STATE_SHIFT) & SLOT_STATE_MASK;
        if !(slot_state == SLOT_DISABLED_ENABLED || !bsr && slot_state == SLOT_DEFAULT) {
            error!("Invalid slot state: {:?}", slot_state);
            return Ok(TRBCCode::ContextStateError);
        }
        Ok(TRBCCode::Success)
    }

    /// Send SET_ADDRESS request to usb device.
    fn set_device_address(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>, addr: u32) {
        let mut p = UsbPacket::default();
        let mut locked_dev = dev.lock().unwrap();
        p.init(USB_TOKEN_OUT as u32, 0);
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_ADDRESS,
            value: addr as u16,
            index: 0,
            length: 0,
        };
        locked_dev.handle_control(&mut p, &device_req);
    }

    fn get_device_context_addr(&self, slot_id: u32) -> Result<u64> {
        self.oper
            .dcbaap
            .checked_add((8 * slot_id) as u64)
            .ok_or_else(|| {
                anyhow!(UsbError::MemoryAccessOverflow(
                    self.oper.dcbaap,
                    (8 * slot_id) as u64
                ))
            })
    }

    fn configure_endpoint(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        let slot_state =
            self.slots[(slot_id - 1) as usize].get_slot_state_in_context(&self.mem_space)?;
        if trb.control & TRB_CR_DC == TRB_CR_DC {
            if slot_state != SLOT_CONFIGURED {
                error!("Invalid slot state: {:?}", slot_state);
                return Ok(TRBCCode::ContextStateError);
            }
            return self.deconfigure_endpoint(slot_id);
        }
        if slot_state != SLOT_CONFIGURED && slot_state != SLOT_ADDRESSED {
            error!("Invalid slot state: {:?}", slot_state);
            return Ok(TRBCCode::ContextStateError);
        }
        self.config_slot_ep(slot_id, trb.parameter)
    }

    fn deconfigure_endpoint(&mut self, slot_id: u32) -> Result<TRBCCode> {
        for i in 2..32 {
            self.disable_endpoint(slot_id, i)?;
        }
        let mut slot_ctx = self.slots[(slot_id - 1) as usize].get_slot_ctx(&self.mem_space)?;
        slot_ctx.set_slot_state(SLOT_ADDRESSED);
        dma_write_u32(
            &self.mem_space,
            GuestAddress(self.slots[(slot_id - 1) as usize].slot_ctx_addr),
            slot_ctx.as_dwords(),
        )?;
        Ok(TRBCCode::Success)
    }

    fn config_slot_ep(&mut self, slot_id: u32, ictx: u64) -> Result<TRBCCode> {
        if ictx.checked_add(INPUT_CONTEXT_SIZE).is_none() {
            bail!(
                "Input Context access overflow, addr {:x} size {:x}",
                ictx,
                INPUT_CONTEXT_SIZE
            );
        }
        let mut ictl_ctx = XhciInputCtrlCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx),
            ictl_ctx.as_mut_dwords(),
        )?;
        if ictl_ctx.drop_flags & 0x3 != 0x0 || ictl_ctx.add_flags & 0x3 != 0x1 {
            error!("Invalid control context {:?}", ictl_ctx);
            return Ok(TRBCCode::TrbError);
        }
        let octx = self.slots[(slot_id - 1) as usize].slot_ctx_addr;
        for i in 2..32 {
            if ictl_ctx.drop_flags & (1 << i) == 1 << i {
                self.disable_endpoint(slot_id, i)?;
            }
            if ictl_ctx.add_flags & (1 << i) == 1 << i {
                self.disable_endpoint(slot_id, i)?;
                self.enable_endpoint(slot_id, i, ictx, octx)?;
            }
        }
        // From section 4.6.6 Configure Endpoint of the spec:
        // If all Endpoints are Disabled:
        // Set the Slot State in the Output Slot Context to Addresed.
        // else (An Endpoint is Enabled):
        // Set the Slot State in the Output Slot Context to Configured.
        // Set the Context Entries field in the Output Slot Context to the index of
        // the last valid Endpoint Context in its Output Device Context structure.
        let mut enabled_ep_idx = 0;
        for i in (2..32).rev() {
            if self.slots[(slot_id - 1) as usize].endpoints[(i - 1) as usize].enabled {
                enabled_ep_idx = i;
                break;
            }
        }
        let mut slot_ctx = self.slots[(slot_id - 1) as usize].get_slot_ctx(&self.mem_space)?;
        if enabled_ep_idx == 0 {
            slot_ctx.set_slot_state(SLOT_ADDRESSED);
            slot_ctx.set_context_entry(1);
        } else {
            slot_ctx.set_slot_state(SLOT_CONFIGURED);
            slot_ctx.set_context_entry(enabled_ep_idx);
        }
        dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        Ok(TRBCCode::Success)
    }

    fn evaluate_context(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        if !self.slots[(slot_id - 1) as usize].slot_state_is_valid(&self.mem_space)? {
            error!("Invalid slot state, slot id {}", slot_id);
            return Ok(TRBCCode::ContextStateError);
        }
        let ictx = trb.parameter;
        if ictx.checked_add(INPUT_CONTEXT_SIZE).is_none() {
            bail!(
                "Input Context access overflow, addr {:x} size {:x}",
                ictx,
                INPUT_CONTEXT_SIZE
            );
        }
        let octx = self.slots[(slot_id - 1) as usize].slot_ctx_addr;
        let mut ictl_ctx = XhciInputCtrlCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx),
            ictl_ctx.as_mut_dwords(),
        )?;
        if ictl_ctx.drop_flags != 0x0 || ictl_ctx.add_flags & !0x3 == !0x3 {
            error!("Invalid input control");
            return Ok(TRBCCode::TrbError);
        }
        if ictl_ctx.add_flags & 0x1 == 0x1 {
            let mut islot_ctx = XhciSlotCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(
                    // It is safe to plus here becuase we previously verify the address.
                    ictx + SLOT_INPUT_CTX_OFFSET,
                ),
                islot_ctx.as_mut_dwords(),
            )?;
            let mut slot_ctx = XhciSlotCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(octx),
                slot_ctx.as_mut_dwords(),
            )?;
            slot_ctx.set_max_exit_latency(islot_ctx.get_max_exit_latency());
            slot_ctx.set_interrupter_target(islot_ctx.get_interrupter_target());
            dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        }
        if ictl_ctx.add_flags & 0x2 == 0x2 {
            // Default control endpoint context.
            let mut iep_ctx = XhciEpCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(
                    // It is safe to use plus here becuase we previously verify the address.
                    ictx + EP_INPUT_CTX_OFFSET,
                ),
                iep_ctx.as_mut_dwords(),
            )?;
            let mut ep_ctx = XhciEpCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(
                    // It is safe to use plus here becuase we previously verify the address.
                    octx + EP_CTX_OFFSET,
                ),
                ep_ctx.as_mut_dwords(),
            )?;
            ep_ctx.set_max_packet_size(iep_ctx.get_max_packet_size());
            dma_write_u32(
                &self.mem_space,
                // It is safe to use plus here becuase we previously verify the address.
                GuestAddress(octx + EP_CTX_OFFSET),
                ep_ctx.as_dwords(),
            )?;
        }
        Ok(TRBCCode::Success)
    }

    fn reset_device(&mut self, slot_id: u32) -> Result<TRBCCode> {
        let mut slot_ctx = XhciSlotCtx::default();
        let octx = self.slots[(slot_id - 1) as usize].slot_ctx_addr;
        dma_read_u32(
            &self.mem_space,
            GuestAddress(octx),
            slot_ctx.as_mut_dwords(),
        )?;
        let slot_state = (slot_ctx.dev_state >> SLOT_STATE_SHIFT) & SLOT_STATE_MASK;
        if slot_state != SLOT_ADDRESSED
            && slot_state != SLOT_CONFIGURED
            && slot_state != SLOT_DEFAULT
        {
            error!("Invalid slot state: {:?}", slot_state);
            return Ok(TRBCCode::ContextStateError);
        }
        for i in 2..32 {
            self.disable_endpoint(slot_id, i)?;
        }
        slot_ctx.set_slot_state(SLOT_DEFAULT);
        slot_ctx.set_context_entry(1);
        slot_ctx.set_usb_device_address(0);
        dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        Ok(TRBCCode::Success)
    }

    fn enable_endpoint(
        &mut self,
        slot_id: u32,
        ep_id: u32,
        input_ctx: DmaAddr,
        output_ctx: DmaAddr,
    ) -> Result<TRBCCode> {
        let entry_offset = (ep_id - 1) as u64 * EP_INPUT_CTX_ENTRY_SIZE;
        let mut ep_ctx = XhciEpCtx::default();
        dma_read_u32(
            &self.mem_space,
            // It is safe to use plus here becuase we previously verify the address on the outer layer.
            GuestAddress(input_ctx + EP_INPUT_CTX_OFFSET + entry_offset),
            ep_ctx.as_mut_dwords(),
        )?;
        self.disable_endpoint(slot_id, ep_id)?;
        let mut epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        epctx.epid = ep_id;
        epctx.enabled = true;
        // It is safe to use plus here becuase we previously verify the address on the outer layer.
        epctx.init_ctx(output_ctx + EP_CTX_OFFSET + entry_offset, &ep_ctx);
        epctx.state = EP_RUNNING;
        ep_ctx.ep_info &= !EP_STATE_MASK;
        ep_ctx.ep_info |= EP_RUNNING;
        dma_write_u32(
            &self.mem_space,
            // It is safe to use plus here becuase we previously verify the address on the outer layer.
            GuestAddress(output_ctx + EP_CTX_OFFSET + entry_offset),
            ep_ctx.as_dwords(),
        )?;
        Ok(TRBCCode::Success)
    }

    fn disable_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<TRBCCode> {
        let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if !epctx.enabled {
            debug!("Endpoint already disabled");
            return Ok(TRBCCode::Success);
        }
        self.flush_ep_transfer(slot_id, ep_id, TRBCCode::Invalid)?;
        let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if self.oper.dcbaap != 0 {
            epctx.set_state(&self.mem_space, EP_DISABLED)?;
        }
        epctx.enabled = false;
        Ok(TRBCCode::Success)
    }

    fn stop_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<TRBCCode> {
        if !(ENDPOINT_ID_START..=MAX_ENDPOINTS).contains(&ep_id) {
            error!("Invalid endpoint id");
            return Ok(TRBCCode::TrbError);
        }
        if !self.slots[(slot_id - 1) as usize].slot_state_is_valid(&self.mem_space)? {
            error!("Invalid slot state, slotid {}", slot_id);
            return Ok(TRBCCode::ContextStateError);
        }
        let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if !epctx.enabled {
            error!(" Endpoint is disabled, slotid {} epid {}", slot_id, ep_id);
            return Ok(TRBCCode::EpNotEnabledError);
        }
        if epctx.state != EP_RUNNING {
            error!(
                "Endpoint invalid state, slotid {} epid {} state {}",
                slot_id, ep_id, epctx.state
            );
            return Ok(TRBCCode::ContextStateError);
        }
        if self.flush_ep_transfer(slot_id, ep_id, TRBCCode::Stopped)? > 0 {
            warn!("endpoint stop when xfers running!");
        }
        self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize]
            .set_state(&self.mem_space, EP_STOPPED)?;
        Ok(TRBCCode::Success)
    }

    fn reset_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<TRBCCode> {
        if !(ENDPOINT_ID_START..=MAX_ENDPOINTS).contains(&ep_id) {
            error!("Invalid endpoint id {}", ep_id);
            return Ok(TRBCCode::TrbError);
        }
        if !self.slots[(slot_id - 1) as usize].slot_state_is_valid(&self.mem_space)? {
            error!("Invalid slot state, slotid {}", slot_id);
            return Ok(TRBCCode::ContextStateError);
        }
        let slot = &mut self.slots[(slot_id - 1) as usize];
        let epctx = &mut slot.endpoints[(ep_id - 1) as usize];
        if !epctx.enabled {
            error!("reset_endpoint ep is disabled");
            return Ok(TRBCCode::EpNotEnabledError);
        }
        if epctx.state != EP_HALTED {
            error!("Endpoint is not halted");
            return Ok(TRBCCode::ContextStateError);
        }
        if self.flush_ep_transfer(slot_id, ep_id, TRBCCode::Invalid)? > 0 {
            warn!("endpoint reset when xfers running!");
        }
        let slot = &mut self.slots[(slot_id - 1) as usize];
        let epctx = &mut slot.endpoints[(ep_id - 1) as usize];
        if let Some(port) = &slot.usb_port {
            if port.lock().unwrap().dev.is_some() {
                epctx.set_state(&self.mem_space, EP_STOPPED)?;
            } else {
                error!("Failed to found usb device");
                return Ok(TRBCCode::UsbTransactionError);
            }
        } else {
            error!("Failed to found port");
            return Ok(TRBCCode::UsbTransactionError);
        }
        Ok(TRBCCode::Success)
    }

    fn set_tr_dequeue_pointer(
        &mut self,
        slotid: u32,
        epid: u32,
        trb: &XhciTRB,
    ) -> Result<TRBCCode> {
        if !(ENDPOINT_ID_START..=MAX_ENDPOINTS).contains(&epid) {
            error!("Invalid endpoint id {}", epid);
            return Ok(TRBCCode::TrbError);
        }
        if !self.slots[(slotid - 1) as usize].slot_state_is_valid(&self.mem_space)? {
            error!("Invalid slot state, slotid {}", slotid);
            return Ok(TRBCCode::ContextStateError);
        }
        let epctx = &mut self.slots[(slotid - 1) as usize].endpoints[(epid - 1) as usize];
        if !epctx.enabled {
            error!("Endpoint is disabled, slotid {} epid {}", slotid, epid);
            return Ok(TRBCCode::EpNotEnabledError);
        }
        if epctx.state != EP_STOPPED && epctx.state != EP_ERROR {
            error!(
                "Endpoint invalid state, slotid {} epid {} state {}",
                slotid, epid, epctx.state
            );
            return Ok(TRBCCode::ContextStateError);
        }
        epctx.update_dequeue(&self.mem_space, Some(trb.parameter))?;
        Ok(TRBCCode::Success)
    }

    /// Data plane
    pub(crate) fn kick_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<()> {
        let epctx = match self.get_endpoint_ctx(slot_id, ep_id) {
            Ok(epctx) => epctx,
            Err(e) => {
                error!("Kick endpoint error: {}", e);
                // No need to return the error, just ignore it.
                return Ok(());
            }
        };
        debug!(
            "kick_endpoint slotid {} epid {} dequeue {:x}",
            slot_id, ep_id, epctx.ring.dequeue
        );
        if self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize]
            .retry
            .is_some()
            && !self.endpoint_retry_transfer(slot_id, ep_id)?
        {
            // Return directly to retry again at the next kick.
            return Ok(());
        }

        let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if epctx.state == EP_HALTED {
            info!("xhci: endpoint halted");
            return Ok(());
        }
        epctx.set_state(&self.mem_space, EP_RUNNING)?;
        const KICK_LIMIT: u32 = 32;
        let mut count = 0;
        loop {
            let mut xfer: XhciTransfer = XhciTransfer::new();
            xfer.slotid = slot_id;
            xfer.epid = ep_id;
            let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
            match epctx.ring.fetch_td()? {
                Some(td) => {
                    debug!(
                        "fetch transfer trb {:?} ring dequeue {:?}",
                        td, epctx.ring.dequeue,
                    );
                    xfer.td = td;
                }
                None => {
                    debug!("No TD in the transfer ring.");
                    break;
                }
            }
            self.endpoint_do_transfer(&mut xfer)?;
            let mut epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
            if xfer.is_completed() {
                epctx.update_dequeue(&self.mem_space, None)?;
                epctx.flush_transfer();
            } else {
                epctx.transfers.push_back(xfer.clone());
            }
            if epctx.state == EP_HALTED {
                break;
            }
            // retry
            if !xfer.is_completed() && xfer.running_retry {
                epctx.retry = Some(xfer);
                break;
            }
            count += 1;
            if count > KICK_LIMIT {
                warn!("kick endpoint over limit");
                break;
            }
        }
        Ok(())
    }

    fn check_slot_enabled(&self, slot_id: u32) -> Result<()> {
        if slot_id == 0 || slot_id > self.slots.len() as u32 {
            bail!("Invalid slot id {}", slot_id);
        }
        if !self.slots[(slot_id - 1) as usize].enabled {
            bail!("Slot {} is disabled", slot_id);
        }
        Ok(())
    }

    fn get_endpoint_ctx(&self, slot_id: u32, ep_id: u32) -> Result<&XhciEpContext> {
        self.check_slot_enabled(slot_id)?;
        if !(ENDPOINT_ID_START..=MAX_ENDPOINTS).contains(&ep_id) {
            bail!("Invalid endpoint id {}", ep_id);
        }
        let ep_ctx = &self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if !ep_ctx.enabled {
            bail!("Endpoint is disabled, slot id {} ep id {}", slot_id, ep_id);
        }
        Ok(ep_ctx)
    }

    /// Return Ok(true) if retry is done.
    /// Return Ok(false) if packet is need to retry again.
    /// Return Err() if retry failed.
    fn endpoint_retry_transfer(&mut self, slot_id: u32, ep_id: u32) -> Result<bool> {
        let slot = &mut self.slots[(slot_id - 1) as usize];
        // Safe because the retry is checked in the outer function call.
        let xfer = &mut slot.endpoints[(ep_id - 1) as usize]
            .retry
            .as_ref()
            .unwrap()
            .clone();
        self.device_handle_packet(xfer);
        if xfer.packet.status == UsbPacketStatus::Nak {
            debug!("USB packet status is NAK");
            // NAK need to retry again.
            return Ok(false);
        }
        self.complete_packet(xfer)?;
        let epctx = &mut self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize];
        if xfer.is_completed() {
            epctx.update_dequeue(&self.mem_space, None)?;
            epctx.flush_transfer();
        }
        epctx.retry = None;
        Ok(true)
    }

    fn device_handle_packet(&mut self, xfer: &mut XhciTransfer) {
        if let Ok(usb_dev) = self.get_usb_dev(xfer.slotid, xfer.epid) {
            let mut locked_dev = usb_dev.lock().unwrap();
            locked_dev.handle_packet(&mut xfer.packet);
        } else {
            xfer.packet.status = UsbPacketStatus::NoDev;
            error!("Failed to handle packet, No endpoint found");
        }
    }

    fn endpoint_do_transfer(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        if xfer.epid == 1 {
            self.do_ctrl_transfer(xfer)?;
        } else {
            self.do_data_transfer(xfer)?;
        }
        Ok(())
    }

    /// Control Transfer, TRBs include Setup, Data(option), Status.
    fn do_ctrl_transfer(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        if let Err(e) = self.check_ctrl_transfer(xfer) {
            error!("Failed to check control transfer {}", e);
            xfer.status = TRBCCode::TrbError;
            return self.report_transfer_error(xfer);
        }
        let trb_setup = xfer.td[0];
        let bm_request_type = trb_setup.parameter as u8;
        xfer.in_xfer =
            bm_request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
        if let Err(e) = self.setup_usb_packet(xfer) {
            error!("Failed to setup packet when transfer control {}", e);
            xfer.status = TRBCCode::TrbError;
            return self.report_transfer_error(xfer);
        }
        xfer.packet.parameter = trb_setup.parameter;
        self.device_handle_packet(xfer);
        self.complete_packet(xfer)?;
        Ok(())
    }

    fn check_ctrl_transfer(&self, xfer: &mut XhciTransfer) -> Result<()> {
        let trb_setup = xfer.td[0];
        let mut trb_status = xfer.td[xfer.td.len() - 1];
        let status_type = trb_status.get_type();

        if status_type == TRBType::TrEvdata && xfer.td.len() > 2 {
            trb_status = xfer.td[xfer.td.len() - 2];
        }

        let setup_type = trb_setup.get_type();
        if setup_type != TRBType::TrSetup {
            bail!("The first TRB is not Setup");
        }
        if trb_status.get_type() != TRBType::TrStatus {
            bail!("The last TRB is not Status");
        }
        if trb_setup.control & TRB_TR_IDT != TRB_TR_IDT {
            bail!("no IDT bit");
        }
        if trb_setup.status & TRB_TR_LEN_MASK != SETUP_TRB_TR_LEN {
            bail!(
                "Bad Setup TRB length {}",
                trb_setup.status & TRB_TR_LEN_MASK
            );
        }
        Ok(())
    }

    fn do_data_transfer(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        let epctx = &mut self.slots[(xfer.slotid - 1) as usize].endpoints[(xfer.epid - 1) as usize];
        xfer.in_xfer = epctx.ep_type == EpType::Control
            || epctx.ep_type == EpType::IsoIn
            || epctx.ep_type == EpType::BulkIn
            || epctx.ep_type == EpType::IntrIn;
        if epctx.ep_type != EpType::IntrOut && epctx.ep_type != EpType::IntrIn {
            warn!("Unhandled ep_type {:?}", epctx.ep_type);
        }
        if let Err(e) = self.setup_usb_packet(xfer) {
            error!("Failed to setup packet when transfer data {}", e);
            xfer.status = TRBCCode::TrbError;
            return self.report_transfer_error(xfer);
        }
        self.device_handle_packet(xfer);
        self.complete_packet(xfer)?;
        Ok(())
    }

    // Setup USB packet, include mapping dma address to iovector.
    fn setup_usb_packet(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        let dir = if xfer.in_xfer {
            USB_TOKEN_IN
        } else {
            USB_TOKEN_OUT
        };
        let in_xfer = dir == USB_TOKEN_IN;

        // Map dma address to iovec.
        let mut vec = Vec::new();
        for trb in &xfer.td {
            let trb_type = trb.get_type();
            if trb_type == TRBType::TrData && (trb.control & TRB_TR_DIR == 0) == in_xfer {
                bail!("Direction of data transfer is mismatch");
            }

            if trb_type == TRBType::TrData
                || trb_type == TRBType::TrNormal
                || trb_type == TRBType::TrIsoch
            {
                let chunk = trb.status & TRB_TR_LEN_MASK;
                let dma_addr = if trb.control & TRB_TR_IDT == TRB_TR_IDT {
                    if chunk > 8 && in_xfer {
                        bail!("Invalid immediate data TRB");
                    }
                    trb.addr
                } else {
                    trb.parameter
                };
                if let Some(hva) = self.mem_space.get_host_address(GuestAddress(dma_addr)) {
                    vec.push(Iovec::new(hva, chunk as usize));
                } else {
                    bail!("HVA not existed {:x}", dma_addr);
                }
            }
        }
        let (_, ep_number) = endpoint_id_to_number(xfer.epid as u8);
        xfer.packet.init(dir as u32, ep_number);
        xfer.packet.iovecs = vec;
        Ok(())
    }

    fn get_usb_dev(&self, slotid: u32, epid: u32) -> Result<Arc<Mutex<dyn UsbDeviceOps>>> {
        let port = if let Some(port) = &self.slots[(slotid - 1) as usize].usb_port {
            port
        } else {
            bail!("USB port not found slotid {} epid {}", slotid, epid);
        };
        let locked_port = port.lock().unwrap();
        let dev = if let Some(dev) = locked_port.dev.as_ref() {
            dev
        } else {
            bail!("No device found in USB port.");
        };
        Ok(dev.clone())
    }

    /// Update packet status and then submit transfer.
    fn complete_packet(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        if xfer.packet.status == UsbPacketStatus::Async {
            xfer.set_comleted(false);
            xfer.running_retry = false;
            return Ok(());
        } else if xfer.packet.status == UsbPacketStatus::Nak {
            xfer.set_comleted(false);
            xfer.running_retry = true;
            return Ok(());
        } else {
            xfer.set_comleted(true);
            xfer.running_retry = false;
        }
        if xfer.packet.status == UsbPacketStatus::Success {
            xfer.status = TRBCCode::Success;
            self.submit_transfer(xfer)?;
            return Ok(());
        }
        // Handle packet error status
        match xfer.packet.status {
            v if v == UsbPacketStatus::NoDev || v == UsbPacketStatus::IoError => {
                xfer.status = TRBCCode::UsbTransactionError;
            }
            UsbPacketStatus::Stall => {
                xfer.status = TRBCCode::StallError;
            }
            UsbPacketStatus::Babble => {
                xfer.status = TRBCCode::BabbleDetected;
            }
            _ => {
                error!("Unhandle status {:?}", xfer.packet.status);
            }
        }
        self.report_transfer_error(xfer)?;
        // Set the endpoint state to halted if an error occurs in the packet.
        let epctx = &mut self.slots[(xfer.slotid - 1) as usize].endpoints[(xfer.epid - 1) as usize];
        epctx.set_state(&self.mem_space, EP_HALTED)?;
        Ok(())
    }

    /// Submit the succeed transfer TRBs.
    fn submit_transfer(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        // Event Data Transfer Length Accumulator
        let mut edtla: u32 = 0;
        let mut left = xfer.packet.actual_length;
        for i in 0..xfer.td.len() {
            let trb = &xfer.td[i];
            let trb_type = trb.get_type();
            let mut chunk = trb.status & TRB_TR_LEN_MASK;
            match trb_type {
                TRBType::TrSetup => {}
                TRBType::TrData | TRBType::TrNormal | TRBType::TrIsoch => {
                    if chunk > left {
                        chunk = left;
                        xfer.status = TRBCCode::ShortPacket;
                    }
                    left -= chunk;
                    if let Some(v) = edtla.checked_add(chunk) {
                        edtla = v;
                    } else {
                        bail!("Event Data Transfer Length Accumulator overflow, edtla {:x} offset {:x}", edtla, chunk);
                    }
                }
                TRBType::TrStatus => {}
                _ => {
                    debug!("Ignore the TRB, unhandled trb type {:?}", trb.get_type());
                }
            }
            if (trb.control & TRB_TR_IOC == TRB_TR_IOC)
                || (xfer.status == TRBCCode::ShortPacket
                    && (trb.control & TRB_TR_ISP == TRB_TR_ISP))
            {
                self.send_transfer_event(xfer, trb, chunk, &mut edtla)?;
            }
        }
        Ok(())
    }

    fn report_transfer_error(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        // An error occurs in the transfer. The transfer is set to the completed and will not be retried.
        xfer.set_comleted(true);
        let mut evt = XhciEvent::new(TRBType::ErTransfer, TRBCCode::TrbError);
        evt.slot_id = xfer.slotid as u8;
        evt.ep_id = xfer.epid as u8;
        evt.ccode = xfer.status;
        let mut idx = 0;
        // According to 4.10.1 Transfer TRBs, the TRB pointer field in a Transfer TRB not
        // only references the TRB that generated the event, but it also provides system software
        // with the latest value of the xHC Dequeue Pointer for the Transfer Ring.
        if let Some(trb) = xfer.td.last() {
            evt.ptr = trb.addr;
            idx = (trb.status >> TRB_INTR_SHIFT) & TRB_INTR_MASK;
        }
        self.send_event(&evt, idx)
    }

    fn send_transfer_event(
        &mut self,
        xfer: &XhciTransfer,
        trb: &XhciTRB,
        transfered: u32,
        edtla: &mut u32,
    ) -> Result<()> {
        let trb_type = trb.get_type();
        let mut evt = XhciEvent::new(TRBType::ErTransfer, TRBCCode::Success);
        evt.slot_id = xfer.slotid as u8;
        evt.ep_id = xfer.epid as u8;
        evt.length = (trb.status & TRB_TR_LEN_MASK) - transfered;
        evt.flags = 0;
        evt.ptr = trb.addr;
        evt.ccode = xfer.status;
        if trb_type == TRBType::TrEvdata {
            evt.ptr = trb.parameter;
            evt.flags |= TRB_EV_ED;
            evt.length = *edtla & TRANSFER_LEN_MASK;
            *edtla = 0;
        }
        let idx = (trb.status >> TRB_INTR_SHIFT) & TRB_INTR_MASK;
        self.send_event(&evt, idx)?;
        Ok(())
    }

    /// Flush transfer in endpoint in some case such as stop endpoint.
    fn flush_ep_transfer(&mut self, slotid: u32, epid: u32, report: TRBCCode) -> Result<u32> {
        debug!("flush_ep_transfer slotid {} epid {}", slotid, epid);
        let mut cnt = 0;
        let mut report = report;
        while let Some(mut xfer) = self.slots[(slotid - 1) as usize].endpoints[(epid - 1) as usize]
            .transfers
            .pop_front()
        {
            cnt += self.do_ep_transfer(slotid, epid, &mut xfer, report)?;
            if cnt != 0 {
                // Only report once.
                report = TRBCCode::Invalid;
            }
        }
        self.slots[(slotid - 1) as usize].endpoints[(epid - 1) as usize]
            .transfers
            .clear();
        Ok(cnt)
    }

    fn do_ep_transfer(
        &mut self,
        slotid: u32,
        ep_id: u32,
        xfer: &mut XhciTransfer,
        report: TRBCCode,
    ) -> Result<u32> {
        let mut killed = 0;
        if xfer.running_retry {
            if report != TRBCCode::Invalid {
                xfer.status = report;
                self.submit_transfer(xfer)?;
            }
            let epctx = &mut self.slots[(slotid - 1) as usize].endpoints[(ep_id - 1) as usize];
            epctx.retry = None;
            xfer.running_retry = false;
            killed = 1;
        }
        xfer.td.clear();
        Ok(killed)
    }

    /// Used for device to wakeup endpoint
    pub fn wakeup_endpoint(&mut self, slot_id: u32, ep: &UsbEndpoint) -> Result<()> {
        let ep_id = endpoint_number_to_id(ep.in_direction, ep.ep_number);
        self.kick_endpoint(slot_id, ep_id as u32)?;
        Ok(())
    }

    /// Get microframe index
    pub fn get_mf_index(&self) -> u64 {
        0
    }

    pub(crate) fn reset_event_ring(&mut self, idx: u32) -> Result<()> {
        let intr = &mut self.intrs[idx as usize];
        if intr.erstsz == 0 || intr.erstba == 0 {
            intr.er_start = 0;
            intr.er_size = 0;
            return Ok(());
        }
        let mut seg = XhciEventRingSeg::new(&self.mem_space);
        seg.fetch_event_ring_seg(intr.erstba)?;
        if seg.size < 16 || seg.size > 4096 {
            bail!("Invalid segment size {}", seg.size);
        }
        intr.er_start = addr64_from_u32(seg.addr_lo, seg.addr_hi);
        intr.er_size = seg.size;
        intr.er_ep_idx = 0;
        intr.er_pcs = true;
        Ok(())
    }

    /// Send event TRB to driver, first write TRB and then send interrupt.
    pub fn send_event(&mut self, evt: &XhciEvent, idx: u32) -> Result<()> {
        if idx > self.intrs.len() as u32 {
            bail!("Invalid index, out of range {}", idx);
        }
        let intr = &self.intrs[idx as usize];
        let er_end = intr
            .er_start
            .checked_add((TRB_SIZE * intr.er_size) as u64)
            .ok_or(UsbError::MemoryAccessOverflow(
                intr.er_start,
                (TRB_SIZE * intr.er_size) as u64,
            ))?;
        if intr.erdp < intr.er_start || intr.erdp >= er_end {
            bail!(
                "DMA out of range, erdp {} er_start {:x} er_size {}",
                intr.erdp,
                intr.er_start,
                intr.er_size
            );
        }
        let dp_idx = (intr.erdp - intr.er_start) / TRB_SIZE as u64;
        if ((intr.er_ep_idx + 2) % intr.er_size) as u64 == dp_idx {
            error!("Event ring full error, idx {}", idx);
            let event = XhciEvent::new(TRBType::ErHostController, TRBCCode::EventRingFullError);
            self.write_event(&event, idx)?;
        } else if ((intr.er_ep_idx + 1) % intr.er_size) as u64 == dp_idx {
            bail!("Event Ring full, drop Event.");
        } else {
            self.write_event(evt, idx)?;
        }
        self.send_intr(idx);
        Ok(())
    }

    fn write_event(&mut self, evt: &XhciEvent, idx: u32) -> Result<()> {
        let intr = &mut self.intrs[idx as usize];
        intr.write_event(evt)?;
        Ok(())
    }

    pub fn send_intr(&mut self, idx: u32) {
        let pending = read_u32(self.intrs[idx as usize].erdp, 0) & ERDP_EHB == ERDP_EHB;
        let mut erdp_low = read_u32(self.intrs[idx as usize].erdp, 0);
        erdp_low |= ERDP_EHB;
        self.intrs[idx as usize].erdp = write_u64_low(self.intrs[idx as usize].erdp, erdp_low);
        self.intrs[idx as usize].iman |= IMAN_IP;
        self.oper.usb_status |= USB_STS_EINT;
        if pending {
            return;
        }
        if self.intrs[idx as usize].iman & IMAN_IE != IMAN_IE {
            return;
        }
        if self.oper.usb_cmd & USB_CMD_INTE != USB_CMD_INTE {
            return;
        }

        if let Some(intr_ops) = self.send_interrupt_ops.as_ref() {
            intr_ops(idx);
            self.intrs[idx as usize].iman &= !IMAN_IP;
        }
    }

    pub fn update_intr(&mut self, v: u32) {
        if self.intrs[v as usize].iman & IMAN_IP == IMAN_IP
            && self.intrs[v as usize].iman & IMAN_IE == IMAN_IE
            && self.oper.usb_cmd & USB_CMD_INTE == USB_CMD_INTE
        {
            if let Some(intr_ops) = &self.send_interrupt_ops {
                intr_ops(v);
                self.intrs[v as usize].iman &= !IMAN_IP;
            }
        }
    }

    /// Assign USB port and attach the device.
    pub fn assign_usb_port(
        &mut self,
        dev: &Arc<Mutex<dyn UsbDeviceOps>>,
    ) -> Option<Arc<Mutex<UsbPort>>> {
        for port in &self.usb_ports {
            let mut locked_port = port.lock().unwrap();
            if !locked_port.used {
                locked_port.used = true;
                locked_port.dev = Some(dev.clone());
                let mut locked_dev = dev.lock().unwrap();
                locked_dev.set_usb_port(Some(Arc::downgrade(port)));
                return Some(port.clone());
            }
        }
        None
    }
}

// DMA read/write helpers.
pub fn dma_read_bytes(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    mut buf: &mut [u8],
    len: u64,
) -> Result<()> {
    addr_space.read(&mut buf, addr, len).with_context(|| {
        format!(
            "Failed to read dma memory at gpa=0x{:x} len=0x{:x}",
            addr.0, len
        )
    })?;
    Ok(())
}

pub fn dma_write_bytes(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    mut buf: &[u8],
    len: u64,
) -> Result<()> {
    addr_space.write(&mut buf, addr, len).with_context(|| {
        format!(
            "Failed to write dma memory at gpa=0x{:x} len=0x{:x}",
            addr.0, len
        )
    })?;
    Ok(())
}

fn dma_read_u64(addr_space: &Arc<AddressSpace>, addr: GuestAddress, data: &mut u64) -> Result<()> {
    let mut tmp = [0_u8; 8];
    dma_read_bytes(addr_space, addr, &mut tmp, 8)?;
    *data = LittleEndian::read_u64(&tmp);
    Ok(())
}

fn dma_read_u32(addr_space: &Arc<AddressSpace>, addr: GuestAddress, buf: &mut [u32]) -> Result<()> {
    let vec_len = size_of::<u32>() * buf.len();
    let mut vec = vec![0_u8; vec_len];
    let tmp = vec.as_mut_slice();
    dma_read_bytes(addr_space, addr, tmp, vec_len as u64)?;
    for i in 0..buf.len() {
        buf[i] = LittleEndian::read_u32(&tmp[(size_of::<u32>() * i)..]);
    }
    Ok(())
}

fn dma_write_u32(addr_space: &Arc<AddressSpace>, addr: GuestAddress, buf: &[u32]) -> Result<()> {
    let vec_len = size_of::<u32>() * buf.len();
    let mut vec = vec![0_u8; vec_len];
    let tmp = vec.as_mut_slice();
    for i in 0..buf.len() {
        LittleEndian::write_u32(&mut tmp[(size_of::<u32>() * i)..], buf[i]);
    }
    dma_write_bytes(addr_space, addr, tmp, vec_len as u64)?;
    Ok(())
}

fn addr64_from_u32(low: u32, high: u32) -> u64 {
    (((high << 16) as u64) << 16) | low as u64
}

// | ep id | < = > | ep direction | ep number |
// |     1 |       |              |         0 |
// |     2 |       |          OUT |         1 |
// |     3 |       |           IN |         1 |
fn endpoint_id_to_number(ep_id: u8) -> (bool, u8) {
    (ep_id & 1 == 1, ep_id >> 1)
}

fn endpoint_number_to_id(in_direction: bool, ep_number: u8) -> u8 {
    if ep_number == 0 {
        // Control endpoint.
        1
    } else if in_direction {
        ep_number * 2 + 1
    } else {
        ep_number * 2
    }
}
