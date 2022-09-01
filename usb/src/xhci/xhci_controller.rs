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

use std::mem::size_of;
use std::slice::from_raw_parts;
use std::slice::from_raw_parts_mut;
use std::sync::{Arc, Mutex, Weak};

use address_space::{AddressSpace, GuestAddress};
use byteorder::{ByteOrder, LittleEndian};
use util::num_ops::{read_u32, write_u64_low};

use crate::bus::UsbBus;
use crate::config::*;
use crate::errors::{Result, ResultExt};
use crate::usb::{
    Iovec, UsbDeviceOps, UsbDeviceRequest, UsbEndpoint, UsbPacket, UsbPacketStatus, UsbPort,
};
use crate::xhci::xhci_regs::{XchiOperReg, XhciInterrupter, XhciPort};
use crate::xhci::xhci_ring::{
    TRBCCode, TRBType, XhciEventRingSeg, XhciRing, XhciTRB, TRB_EV_ED, TRB_SIZE, TRB_TR_IDT,
    TRB_TR_IOC, TRB_TR_ISP, TRB_TYPE_SHIFT,
};

pub const MAX_INTRS: u16 = 16;
pub const MAX_SLOTS: u32 = 64;
/// Endpoint state
const EP_STATE_MASK: u32 = 0x7;
const EP_DISABLED: u32 = 0;
const EP_RUNNING: u32 = 1;
const EP_HALTED: u32 = 2;
const EP_STOPPED: u32 = 3;
/// Endpoint type
const EP_TYPE_SHIFT: u32 = 3;
const EP_TYPE_MASK: u32 = 0x7;
#[allow(unused)]
const EP_ERROR: u32 = 4;
/// Slot state
const SLOT_STATE_MASK: u32 = 0x1f;
const SLOT_STATE_SHIFT: u32 = 27;
#[allow(unused)]
const SLOT_ENABLED: u32 = 0;
const SLOT_DEFAULT: u32 = 1;
const SLOT_ADDRESSED: u32 = 2;
const SLOT_CONFIGURED: u32 = 3;
const SLOT_CONTEXT_ENTRIES_MASK: u32 = 0x1f;
const SLOT_CONTEXT_ENTRIES_SHIFT: u32 = 27;
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
const EP_CTX_MAX_PACKET_SIZE_SHIFT: u32 = 16;
const EP_CTX_LSA_SHIFT: u32 = 15;
const EP_CTX_INTERVAL_SHIFT: u32 = 16;
const EP_CTX_INTERVAL_MASK: u32 = 0xff;
const EVENT_TRB_CCODE_SHIFT: u32 = 24;
const EVENT_TRB_SLOT_ID_SHIFT: u32 = 24;
const EVENT_TRB_EP_ID_SHIFT: u32 = 16;
const PORT_EVENT_ID_SHIFT: u32 = 24;
const SLOT_CTX_PORT_NUMBER_SHIFT: u32 = 16;
const ENDPOINT_ID_START: u32 = 1;
const MAX_ENDPOINTS: u32 = 31;

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
    fn new(len: usize) -> Self {
        XhciTransfer {
            packet: UsbPacket::default(),
            status: TRBCCode::Invalid,
            trbs: vec![XhciTRB::new(); len],
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

    pub fn init(&mut self, pctx: DmaAddr, ctx: &XhciEpCtx) {
        let dequeue: DmaAddr = addr64_from_u32(ctx.deq_lo & !0xf, ctx.deq_hi);
        self.ep_type = ((ctx.ep_info2 >> EP_TYPE_SHIFT) & EP_TYPE_MASK).into();
        self.pctx = pctx;
        self.max_psize = ctx.ep_info2 >> EP_CTX_MAX_PACKET_SIZE_SHIFT;
        self.max_psize *= 1 + ((ctx.ep_info2 >> 8) & 0xff);
        self.lsa = (ctx.ep_info >> EP_CTX_LSA_SHIFT) & 1 == 1;
        self.ring.init(dequeue);
        self.ring.ccs = (ctx.deq_lo & 1) == 1;
        self.interval = 1 << ((ctx.ep_info >> EP_CTX_INTERVAL_SHIFT) & EP_CTX_INTERVAL_MASK);
    }

    pub fn set_state(&mut self, mem: &Arc<AddressSpace>, state: u32) -> Result<()> {
        let mut ep_ctx = XhciEpCtx::default();
        dma_read_u32(mem, GuestAddress(self.pctx), ep_ctx.as_mut_dwords())?;
        ep_ctx.ep_info &= !EP_STATE_MASK;
        ep_ctx.ep_info |= state;
        ep_ctx.deq_lo = self.ring.dequeue as u32 | self.ring.ccs as u32;
        ep_ctx.deq_hi = (self.ring.dequeue >> 32) as u32;
        dma_write_u32(mem, GuestAddress(self.pctx), ep_ctx.as_dwords())?;
        self.state = state;
        Ok(())
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
            endpoints: vec![XhciEpContext::new(mem, 0); MAX_ENDPOINTS as usize],
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

    /// Convert event to trb.
    pub fn to_trb(&self) -> XhciTRB {
        XhciTRB {
            parameter: self.ptr,
            status: self.length | (self.ccode as u32) << EVENT_TRB_CCODE_SHIFT,
            control: (self.slot_id as u32) << EVENT_TRB_SLOT_ID_SHIFT
                | (self.ep_id as u32) << EVENT_TRB_EP_ID_SHIFT
                | self.flags as u32
                | (self.trb_type as u32) << TRB_TYPE_SHIFT,
            addr: 0,
            ccs: false,
        }
    }
}

/// Controller ops registered in XhciDevice. Such as PCI device send MSIX.
pub trait XhciOps: Send + Sync {
    fn trigger_intr(&mut self, n: u32, level: bool) -> bool;

    fn update_intr(&mut self, n: u32, enable: bool);
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

impl DwordOrder for XhciEpCtx {}

trait DwordOrder: Default + Copy + Send + Sync {
    fn as_dwords(&self) -> &[u32] {
        unsafe { from_raw_parts(self as *const Self as *const u32, size_of::<Self>() / 4) }
    }

    fn as_mut_dwords(&mut self) -> &mut [u32] {
        unsafe { from_raw_parts_mut(self as *mut Self as *mut u32, size_of::<Self>() / 4) }
    }
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
        for i in 0..locked_xhci.port_num {
            locked_xhci.ports.push(Arc::new(Mutex::new(XhciPort::new(
                &Arc::downgrade(&clone_xhci),
                format!("xhci-port-{}", i),
                i + 1,
            ))));
        }
        for i in 0..locked_xhci.numports_2 {
            let usb_port = Arc::new(Mutex::new(UsbPort::new(i)));
            locked_xhci.usb_ports.push(usb_port.clone());
            locked_xhci.bus.lock().unwrap().register_usb_port(&usb_port);
            let mut locked_port = locked_xhci.ports[i as usize].lock().unwrap();
            locked_port.name = format!("{}-usb2-{}", locked_port.name, i);
            locked_port.speed_mask = USB_SPEED_LOW | USB_SPEED_HIGH | USB_SPEED_FULL;
            locked_port.usb_port = Some(Arc::downgrade(&usb_port));
        }
        for i in 0..locked_xhci.numports_3 {
            let idx = i + locked_xhci.numports_2;
            let usb_port = Arc::new(Mutex::new(UsbPort::new(idx)));
            locked_xhci.usb_ports.push(usb_port.clone());
            locked_xhci.bus.lock().unwrap().register_usb_port(&usb_port);
            let mut locked_port = locked_xhci.ports[idx as usize].lock().unwrap();
            locked_port.name = format!("{}-usb3-{}", locked_port.name, idx);
            locked_port.speed_mask = USB_SPEED_SUPER;
            locked_port.usb_port = Some(Arc::downgrade(&usb_port));
        }
        xhci
    }

    pub fn run(&mut self) {
        self.oper.usb_status &= !USB_STS_HCH;
    }

    pub fn stop(&mut self) {
        self.oper.usb_status |= USB_STS_HCH;
        let mut lo = read_u32(self.oper.cmd_ring_ctrl, 0);
        lo &= !CMD_RING_CTRL_CRR;
        write_u64_low(self.oper.cmd_ring_ctrl, lo);
    }

    pub fn running(&self) -> bool {
        self.oper.usb_status & USB_STS_HCH != USB_STS_HCH
    }

    pub fn reset(&mut self) {
        info!("xhci reset");
        self.oper.reset();
        for i in 0..self.slots.len() as u32 {
            if let Err(e) = self.disable_slot(i + 1) {
                error!("Failed to disable slot {}", e);
            }
        }
        for i in 0..self.ports.len() {
            let port = self.ports[i].clone();
            if let Err(e) = self.port_update(&port) {
                error!("Failed to update port: {}", e);
            }
        }
        for i in 0..self.intrs.len() {
            self.intrs[i].reset();
        }
    }

    /// Find xhci port by usb port.
    pub fn lookup_xhci_port(&self, dev: &Arc<Mutex<UsbPort>>) -> Option<Arc<Mutex<XhciPort>>> {
        let index = dev.lock().unwrap().index;
        Some(self.ports[index as usize].clone())
    }

    /// Send PortStatusChange event to notify drivers.
    pub fn port_notify(&mut self, port: &Arc<Mutex<XhciPort>>, flag: u32) -> Result<()> {
        let mut locked_port = port.lock().unwrap();
        if locked_port.portsc & flag == flag {
            return Ok(());
        }
        locked_port.portsc |= flag;
        if !self.running() {
            return Ok(());
        }
        let mut evt = XhciEvent::new(TRBType::ErPortStatusChange, TRBCCode::Success);
        evt.ptr = (locked_port.port_idx << PORT_EVENT_ID_SHIFT) as u64;
        self.send_event(&evt, 0)?;
        Ok(())
    }

    /// Update the xhci port status and then
    pub fn port_update(&mut self, port: &Arc<Mutex<XhciPort>>) -> Result<()> {
        let mut locked_port = port.lock().unwrap();
        locked_port.portsc = PORTSC_PP;
        let mut pls = PLS_RX_DETECT;
        if let Some(usb_port) = &locked_port.usb_port {
            let usb_port = usb_port.upgrade().unwrap();
            let locked_usb_port = usb_port.lock().unwrap();
            if let Some(dev) = &locked_usb_port.dev {
                let speed = dev.lock().unwrap().speed();
                locked_port.portsc |= PORTSC_CCS;
                if speed == PORTSC_SPEED_SUPER {
                    locked_port.portsc |= PORTSC_SPEED_SUPER;
                    locked_port.portsc |= PORTSC_PED;
                    pls = PLS_U0;
                } else {
                    locked_port.portsc |= speed;
                    pls = PLS_POLLING;
                }
            }
        }
        locked_port.portsc = set_field(locked_port.portsc, pls, PORTSC_PLS_MASK, PORTSC_PLS_SHIFT);
        debug!(
            "xhci port update portsc {:x} pls {:x}",
            locked_port.portsc, pls
        );
        drop(locked_port);
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
        let mut path = String::new();
        let mut port = slot_ctx.dev_info2 >> SLOT_CTX_PORT_NUMBER_SHIFT & 0xff;
        if port < 1 || port > self.port_num {
            error!("Invalid port: {}", port);
            return None;
        }
        let usb_port = &self.usb_ports[(port - 1) as usize];
        port = usb_port.lock().unwrap().index + 1;
        path += &format!("{}", port);
        for i in 0..5 {
            port = (slot_ctx.dev_info >> (4 * i)) & 0x0f;
            if port == 0 {
                break;
            }
            path += &format!(".{}", port);
        }
        let locked_bus = self.bus.lock().unwrap();
        locked_bus.find_usb_port(path)
    }

    /// Control plane
    pub fn handle_command(&mut self) -> Result<()> {
        if !self.running() {
            bail!("Failed to process command: xhci is not running");
        }
        let mut lo = read_u32(self.oper.cmd_ring_ctrl, 0);
        lo |= CMD_RING_CTRL_CRR;
        self.oper.cmd_ring_ctrl = write_u64_low(self.oper.cmd_ring_ctrl, lo);
        let mut slot_id: u32;
        let mut event = XhciEvent::new(TRBType::ErCommandComplete, TRBCCode::Success);
        for _ in 0..COMMAND_LIMIT {
            match self.cmd_ring.fetch_trb() {
                Ok(trb) => {
                    let trb_type = trb.get_type();
                    event.ptr = trb.addr;
                    slot_id = self.get_slot_id(&mut event, &trb);
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
                            if slot_id != 0 {
                                event.ccode = self.disable_slot(slot_id)?;
                            }
                        }
                        TRBType::CrAddressDevice => {
                            if slot_id != 0 {
                                event.ccode = self.address_slot(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrConfigureEndpoint => {
                            if slot_id != 0 {
                                event.ccode = self.config_slot(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrEvaluateContext => {
                            if slot_id != 0 {
                                event.ccode = self.evaluate_slot(slot_id, &trb)?;
                            }
                        }
                        TRBType::CrStopEndpoint => {
                            let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                            event.ccode = self.stop_endpoint(slot_id, ep_id)?;
                        }
                        TRBType::CrResetEndpoint => {
                            let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                            event.ccode = self.reset_endpoint(slot_id, ep_id)?;
                        }
                        TRBType::CrSetTrDequeue => {
                            let ep_id = trb.control >> TRB_CR_EPID_SHIFT & TRB_CR_EPID_MASK;
                            event.ccode = self.set_endpoint_dequeue(slot_id, ep_id, &trb)?;
                        }
                        TRBType::CrResetDevice => {
                            event.ccode = self.reset_slot(slot_id)?;
                        }
                        _ => {
                            error!("Invalid Command: type {:?}", trb_type);
                            event.ccode = TRBCCode::TrbError;
                        }
                    }
                    event.slot_id = slot_id as u8;
                    self.send_event(&event, 0)?;
                }
                Err(e) => {
                    error!("Failed to fetch ring: {}", e);
                    event.ccode = TRBCCode::TrbError;
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
        self.slots[(slot_id - 1) as usize].intr = 0;
        Ok(TRBCCode::Success)
    }

    fn address_slot(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        let bsr = trb.control & TRB_CR_BSR == TRB_CR_BSR;
        let dcbaap = self.oper.dcbaap;
        let ictx = trb.parameter;
        let mut octx = 0;
        dma_read_u64(
            &self.mem_space,
            GuestAddress(dcbaap + (8 * slot_id) as u64),
            &mut octx,
        )?;
        let mut ictl_ctx = XhciInputCtrlCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx),
            ictl_ctx.as_mut_dwords(),
        )?;
        if ictl_ctx.drop_flags != 0x0 || ictl_ctx.add_flags != 0x3 {
            error!("Invalid input: {:?}", ictl_ctx);
            return Ok(TRBCCode::TrbError);
        }
        let mut slot_ctx = XhciSlotCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx + 32),
            slot_ctx.as_mut_dwords(),
        )?;
        if let Some(usb_port) = self.lookup_usb_port(&slot_ctx) {
            let lock_port = usb_port.lock().unwrap();
            let dev = lock_port.dev.as_ref().unwrap();
            let mut locked_dev = dev.lock().unwrap();
            if !locked_dev.attached() {
                error!("Failed to connect device");
                return Ok(TRBCCode::UsbTransactionError);
            }
            self.slots[(slot_id - 1) as usize].usb_port = Some(Arc::downgrade(&usb_port));
            self.slots[(slot_id - 1) as usize].ctx = octx;
            self.slots[(slot_id - 1) as usize].intr =
                ((slot_ctx.tt_info >> TRB_INTR_SHIFT) & TRB_INTR_MASK) as u16;
            locked_dev.reset();
            drop(locked_dev);
            if bsr {
                slot_ctx.dev_state = SLOT_DEFAULT << SLOT_STATE_SHIFT;
            } else {
                slot_ctx.dev_state = (SLOT_ADDRESSED << SLOT_STATE_SHIFT) | slot_id;
                self.address_device(dev, slot_id);
            }
            let mut ep0_ctx = XhciEpCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(ictx + 64),
                ep0_ctx.as_mut_dwords(),
            )?;
            self.enable_endpoint(slot_id, 1, octx + 32, &mut ep0_ctx)?;
            dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
            dma_write_u32(
                &self.mem_space,
                GuestAddress(octx + 32),
                ep0_ctx.as_dwords(),
            )?;
            self.slots[(slot_id - 1) as usize].addressed = true;
        } else {
            error!("Failed to found usb port");
            return Ok(TRBCCode::TrbError);
        }
        Ok(TRBCCode::Success)
    }

    fn address_device(&mut self, dev: &Arc<Mutex<dyn UsbDeviceOps>>, slot_id: u32) {
        let mut p = UsbPacket::default();
        let mut locked_dev = dev.lock().unwrap();
        let usb_dev = locked_dev.get_mut_usb_device();
        let locked_usb = usb_dev.lock().unwrap();
        let ep = Arc::downgrade(&locked_usb.get_endpoint(USB_TOKEN_OUT as u32, 0));
        p.init(USB_TOKEN_OUT as u32, ep, 0, false, false);
        drop(locked_usb);
        let device_req = UsbDeviceRequest {
            request_type: USB_DEVICE_OUT_REQUEST,
            request: USB_REQUEST_SET_ADDRESS,
            value: slot_id as u16,
            index: 0,
            length: 0,
        };
        locked_dev.handle_control(&mut p, &device_req, &mut []);
    }

    fn config_slot(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        let ictx = trb.parameter;
        let octx = self.slots[(slot_id - 1) as usize].ctx;
        let mut slot_ctx = XhciSlotCtx::default();
        if trb.control & TRB_CR_DC == TRB_CR_DC {
            for i in 2..32 {
                self.disable_endpoint(slot_id, i)?;
            }
            dma_read_u32(
                &self.mem_space,
                GuestAddress(octx),
                slot_ctx.as_mut_dwords(),
            )?;
            slot_ctx.dev_state &= !(SLOT_STATE_MASK << SLOT_STATE_SHIFT);
            slot_ctx.dev_state |= SLOT_ADDRESSED << SLOT_STATE_SHIFT;
            dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
            return Ok(TRBCCode::Success);
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
        let mut islot_ctx = XhciSlotCtx::default();
        dma_read_u32(
            &self.mem_space,
            GuestAddress(ictx + 32),
            islot_ctx.as_mut_dwords(),
        )?;
        dma_read_u32(
            &self.mem_space,
            GuestAddress(octx),
            slot_ctx.as_mut_dwords(),
        )?;
        if (slot_ctx.dev_state >> SLOT_STATE_SHIFT) & SLOT_STATE_MASK < SLOT_ADDRESSED {
            error!("Invalid slot state");
            return Ok(TRBCCode::TrbError);
        }
        self.config_slot_ep(slot_id, ictx, octx, ictl_ctx)?;
        slot_ctx.dev_state &= !(SLOT_STATE_MASK << SLOT_STATE_SHIFT);
        slot_ctx.dev_state |= SLOT_CONFIGURED << SLOT_STATE_SHIFT;
        slot_ctx.dev_info &= !(SLOT_CONTEXT_ENTRIES_MASK << SLOT_CONTEXT_ENTRIES_SHIFT);
        slot_ctx.dev_info |=
            islot_ctx.dev_info & (SLOT_CONTEXT_ENTRIES_MASK << SLOT_CONTEXT_ENTRIES_SHIFT);
        dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        Ok(TRBCCode::Success)
    }

    fn config_slot_ep(
        &mut self,
        slot_id: u32,
        ictx: u64,
        octx: u64,
        ictl_ctx: XhciInputCtrlCtx,
    ) -> Result<TRBCCode> {
        for i in 2..32 {
            if ictl_ctx.drop_flags & (1 << i) == 1 << i {
                self.disable_endpoint(slot_id, i)?;
            }
            if ictl_ctx.add_flags & (1 << i) == 1 << i {
                let offset = 32 + 32 * i as u64;
                let mut ep_ctx = XhciEpCtx::default();
                dma_read_u32(
                    &self.mem_space,
                    GuestAddress(ictx + offset),
                    ep_ctx.as_mut_dwords(),
                )?;
                self.disable_endpoint(slot_id, i)?;
                let offset = 32 * i as u64;
                let ret = self.enable_endpoint(slot_id, i, octx + offset, &mut ep_ctx)?;
                if ret != TRBCCode::Success {
                    return Ok(ret);
                }
                dma_write_u32(
                    &self.mem_space,
                    GuestAddress(octx + offset),
                    ep_ctx.as_dwords(),
                )?;
            }
        }
        Ok(TRBCCode::Success)
    }

    fn evaluate_slot(&mut self, slot_id: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        let ictx = trb.parameter;
        let octx = self.slots[(slot_id - 1) as usize].ctx;
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
                GuestAddress(ictx + 0x20),
                islot_ctx.as_mut_dwords(),
            )?;
            let mut slot_ctx = XhciSlotCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(octx),
                slot_ctx.as_mut_dwords(),
            )?;
            slot_ctx.dev_info2 &= !0xffff;
            slot_ctx.dev_info2 |= islot_ctx.dev_info2 & 0xffff;
            slot_ctx.tt_info &= !0xff00000;
            slot_ctx.tt_info |= islot_ctx.tt_info & 0xff000000;
            dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        }
        if ictl_ctx.add_flags & 0x2 == 0x2 {
            let mut iep_ctx = XhciEpCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(ictx + 0x40),
                iep_ctx.as_mut_dwords(),
            )?;
            let mut ep_ctx = XhciEpCtx::default();
            dma_read_u32(
                &self.mem_space,
                GuestAddress(octx + 0x20),
                ep_ctx.as_mut_dwords(),
            )?;
            ep_ctx.ep_info2 &= !0xffff0000;
            ep_ctx.ep_info2 |= iep_ctx.ep_info2 & 0xffff0000;
            dma_write_u32(
                &self.mem_space,
                GuestAddress(octx + 0x20),
                ep_ctx.as_dwords(),
            )?;
        }
        Ok(TRBCCode::Success)
    }

    fn reset_slot(&mut self, slot_id: u32) -> Result<TRBCCode> {
        let mut slot_ctx = XhciSlotCtx::default();
        let octx = self.slots[(slot_id - 1) as usize].ctx;
        for i in 2..32 {
            self.disable_endpoint(slot_id, i)?;
        }
        dma_read_u32(
            &self.mem_space,
            GuestAddress(octx),
            slot_ctx.as_mut_dwords(),
        )?;
        slot_ctx.dev_state &= !(SLOT_STATE_MASK << SLOT_STATE_SHIFT);
        slot_ctx.dev_state |= SLOT_DEFAULT << SLOT_STATE_SHIFT;
        dma_write_u32(&self.mem_space, GuestAddress(octx), slot_ctx.as_dwords())?;
        Ok(TRBCCode::Success)
    }

    fn enable_endpoint(
        &mut self,
        slot_id: u32,
        ep_id: u32,
        pctx: DmaAddr,
        ctx: &mut XhciEpCtx,
    ) -> Result<TRBCCode> {
        self.disable_endpoint(slot_id, ep_id)?;
        let mut epctx = XhciEpContext::new(&self.mem_space, ep_id);
        epctx.enabled = true;
        epctx.init(pctx, ctx);
        epctx.state = EP_RUNNING;
        ctx.ep_info &= !EP_STATE_MASK;
        ctx.ep_info |= EP_RUNNING;
        self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize] = epctx;
        Ok(TRBCCode::Success)
    }

    fn disable_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<TRBCCode> {
        let slot = &mut self.slots[(slot_id - 1) as usize];
        let epctx = &mut slot.endpoints[(ep_id - 1) as usize];
        if !epctx.enabled {
            debug!("Endpoint already disabled");
            return Ok(TRBCCode::Success);
        }
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
        if !self.slots[(slot_id - 1) as usize].enabled {
            return Ok(TRBCCode::EpNotEnabledError);
        }
        if self.flush_ep_transfer(slot_id, ep_id, TRBCCode::Stopped)? > 0 {
            warn!("endpoint stop when xfers running!");
        }
        if !self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize].enabled {
            error!("stop_endpoint ep is disabled");
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
        if let Some(port) = &slot.usb_port {
            if port.upgrade().unwrap().lock().unwrap().dev.is_some() {
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

    fn set_endpoint_dequeue(&mut self, slotid: u32, epid: u32, trb: &XhciTRB) -> Result<TRBCCode> {
        if !(ENDPOINT_ID_START..=MAX_ENDPOINTS).contains(&epid) {
            error!("Invalid endpoint id {}", epid);
            return Ok(TRBCCode::TrbError);
        }
        let dequeue = trb.parameter;
        let mut epctx = &mut self.slots[(slotid - 1) as usize].endpoints[(epid - 1) as usize];
        if !epctx.enabled {
            error!(" Endpoint is disabled slotid {} epid {}", slotid, epid);
            return Ok(TRBCCode::EpNotEnabledError);
        }
        if epctx.state != EP_STOPPED {
            error!("Endpoint is not stopped slotid {} epid {}", slotid, epid);
            return Ok(TRBCCode::ContextStateError);
        }
        epctx.ring.init(dequeue & !0xf);
        epctx.ring.ccs = (dequeue & 1) == 1;
        epctx.set_state(&self.mem_space, EP_STOPPED)?;
        Ok(TRBCCode::Success)
    }

    /// Data plane
    pub(crate) fn kick_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<()> {
        let ep_ctx = self.get_endpoint(slot_id, ep_id)?;
        debug!(
            "kick_endpoint slotid {} epid {} dequeue {:x}",
            slot_id, ep_id, ep_ctx.ring.dequeue
        );
        let mut epctx = ep_ctx.clone();
        if let Err(e) = self.endpoint_retry_transfer(&mut epctx) {
            // Update the endpoint context in slot.
            self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize] = epctx;
            bail!("Failed to retry transfer {}", e);
        }
        if epctx.state == EP_HALTED {
            info!("xhci: endpoint halted");
            return Ok(());
        }
        epctx.set_state(&self.mem_space, EP_RUNNING)?;
        const KICK_LIMIT: u32 = 32;
        let mut count = 0;
        loop {
            let len = match epctx.ring.get_transfer_len() {
                Ok(len) => len,
                Err(e) => {
                    error!("Failed to get transfer len: {}", e);
                    break;
                }
            };
            if len == 0 {
                break;
            }
            let mut xfer: XhciTransfer = XhciTransfer::new(len);
            xfer.slotid = slot_id;
            xfer.epid = ep_id;
            for i in 0..len {
                match epctx.ring.fetch_trb() {
                    Ok(trb) => {
                        debug!(
                            "fetch transfer trb {:?} ring dequeue {:x}",
                            trb, epctx.ring.dequeue,
                        );
                        xfer.trbs[i] = trb;
                    }
                    Err(e) => {
                        self.oper.usb_status |= USB_STS_HCE;
                        // update the endpoint in slot
                        self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize] = epctx;
                        bail!("fetch ring failed {}", e);
                    }
                }
            }
            if let Err(e) = self.endpoint_do_transfer(&mut xfer, &mut epctx) {
                error!("Failed to transfer {}", e);
            }
            if xfer.complete {
                epctx.set_state(&self.mem_space, epctx.state)?;
            } else {
                epctx.transfers.push(xfer.clone());
            }
            if epctx.state == EP_HALTED {
                break;
            }
            // retry
            if !xfer.complete && xfer.running_retry {
                epctx.retry = Some(xfer.clone());
                break;
            }
            count += 1;
            if count > KICK_LIMIT {
                warn!("kick endpoint over limit");
                break;
            }
        }
        // Update the endpoint context in slot.
        self.slots[(slot_id - 1) as usize].endpoints[(ep_id - 1) as usize] = epctx;
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

    fn get_endpoint(&self, slot_id: u32, ep_id: u32) -> Result<&XhciEpContext> {
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

    fn endpoint_retry_transfer(&mut self, epctx: &mut XhciEpContext) -> Result<()> {
        if let Some(xfer) = &mut epctx.retry {
            self.setup_usb_packet(xfer, epctx.epid)?;
            self.device_handle_packet(&mut xfer.packet)?;
            if xfer.packet.status == UsbPacketStatus::Nak {
                bail!("USB packet status is NAK");
            }
            self.complete_packet(xfer)?;
            if xfer.complete {
                epctx.set_state(&self.mem_space, epctx.state)?;
            }
            epctx.retry = None;
        }
        Ok(())
    }

    fn device_handle_packet(&mut self, packet: &mut UsbPacket) -> Result<()> {
        if let Some(ep) = &packet.ep {
            let ep = ep.upgrade().unwrap();
            let locked_ep = ep.lock().unwrap();
            let dev = if let Some(usb_dev) = &locked_ep.dev {
                usb_dev.upgrade().unwrap()
            } else {
                bail!("No device found in endpoint");
            };
            drop(locked_ep);
            let mut locked_dev = dev.lock().unwrap();
            locked_dev.handle_packet(packet);
        } else {
            bail!("No endpoint found");
        }
        Ok(())
    }

    fn endpoint_do_transfer(
        &mut self,
        xfer: &mut XhciTransfer,
        epctx: &mut XhciEpContext,
    ) -> Result<()> {
        if xfer.epid == 1 {
            self.do_ctrl_transfer(xfer, epctx)?;
        } else {
            self.do_data_transfer(xfer, epctx)?;
        }
        Ok(())
    }

    /// Control Transfer, TRBs include Setup, Data(option), Status.
    fn do_ctrl_transfer(
        &mut self,
        xfer: &mut XhciTransfer,
        epctx: &mut XhciEpContext,
    ) -> Result<()> {
        let trb_setup = xfer.trbs[0];
        let mut trb_status = xfer.trbs[xfer.trbs.len() - 1];
        let setup_type = trb_setup.get_type();
        let status_type = trb_status.get_type();
        if status_type == TRBType::TrEvdata && xfer.trbs.len() > 2 {
            trb_status = xfer.trbs[xfer.trbs.len() - 2];
        }
        if setup_type != TRBType::TrSetup {
            bail!("The first TRB is not Setup");
        }
        if trb_status.get_type() != TRBType::TrStatus {
            bail!("The last TRB is not Status");
        }
        if trb_setup.control & TRB_TR_IDT != TRB_TR_IDT {
            bail!("no IDT bit");
        }
        if trb_setup.status & 0x1ffff != 8 {
            bail!("Bad Setup TRB length {}", trb_setup.status & 0x1ffff);
        }

        let bm_request_type = trb_setup.parameter as u8;
        xfer.in_xfer =
            bm_request_type & USB_DIRECTION_DEVICE_TO_HOST == USB_DIRECTION_DEVICE_TO_HOST;
        self.setup_usb_packet(xfer, epctx.epid)?;
        xfer.packet.parameter = trb_setup.parameter;
        self.device_handle_packet(&mut xfer.packet)?;
        self.complete_packet(xfer)?;
        Ok(())
    }

    fn do_data_transfer(
        &mut self,
        xfer: &mut XhciTransfer,
        epctx: &mut XhciEpContext,
    ) -> Result<()> {
        xfer.in_xfer = epctx.ep_type == EpType::Control
            || epctx.ep_type == EpType::IsoIn
            || epctx.ep_type == EpType::BulkIn
            || epctx.ep_type == EpType::IntrIn;
        if epctx.ep_type != EpType::IntrOut && epctx.ep_type != EpType::IntrIn {
            bail!("Unhandled ep_type {:?}", epctx.ep_type);
        }
        self.setup_usb_packet(xfer, epctx.epid)?;
        self.device_handle_packet(&mut xfer.packet)?;
        self.complete_packet(xfer)?;
        Ok(())
    }

    // Setup USB packet, include mapping dma address to iovector.
    fn setup_usb_packet(&mut self, xfer: &mut XhciTransfer, epid: u32) -> Result<()> {
        let ep = if let Some(ep) = &xfer.packet.ep {
            ep.clone()
        } else {
            let ep = self.get_usb_ep(xfer.slotid, epid)?;
            Arc::downgrade(&ep)
        };
        let dir = if xfer.in_xfer {
            USB_TOKEN_IN
        } else {
            USB_TOKEN_OUT
        };
        // Map dma address to iovec.
        let mut vec = Vec::new();
        for trb in &xfer.trbs {
            let trb_type = trb.get_type();
            if trb.control & TRB_TR_IOC == TRB_TR_IOC {
                xfer.int_req = true;
            }
            if trb_type == TRBType::TrData
                || trb_type == TRBType::TrNormal
                || trb_type == TRBType::TrIsoch
            {
                let chunk = trb.status & 0x1ffff;
                let dma_addr = if trb.control & TRB_TR_IDT == TRB_TR_IDT {
                    trb.addr
                } else {
                    trb.parameter
                };
                if let Some(hva) = self.mem_space.get_host_address(GuestAddress(dma_addr)) {
                    vec.push(Iovec::new(hva, chunk as usize));
                } else {
                    error!("HVA not existed {:x}", dma_addr);
                }
            }
        }
        xfer.packet.init(dir as u32, ep, 0, false, xfer.int_req);
        for v in vec {
            xfer.packet.iovecs.push(v);
        }
        Ok(())
    }

    fn get_usb_ep(&self, slotid: u32, epid: u32) -> Result<Arc<Mutex<UsbEndpoint>>> {
        let port = if let Some(port) = &self.slots[(slotid - 1) as usize].usb_port {
            port.upgrade().unwrap()
        } else {
            bail!("USB port not found slotid {} epid {}", slotid, epid);
        };
        let locked_port = port.lock().unwrap();
        let dev = locked_port.dev.as_ref().unwrap();
        let mut locked_dev = dev.lock().unwrap();
        let pid = if epid & 1 == 1 {
            USB_TOKEN_IN
        } else {
            USB_TOKEN_OUT
        };
        let usb_dev = locked_dev.get_mut_usb_device();
        let locked_usb = usb_dev.lock().unwrap();
        let ep = locked_usb.get_endpoint(pid as u32, epid >> 1);
        Ok(ep)
    }

    /// Update packet status and then submit transfer.
    fn complete_packet(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        if xfer.packet.status == UsbPacketStatus::Async {
            xfer.complete = false;
            xfer.running_retry = false;
            return Ok(());
        } else if xfer.packet.status == UsbPacketStatus::Nak {
            xfer.complete = false;
            xfer.running_retry = true;
            return Ok(());
        } else {
            xfer.complete = true;
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
                self.submit_transfer(xfer)?;
            }
            UsbPacketStatus::Stall => {
                xfer.status = TRBCCode::StallError;
                self.submit_transfer(xfer)?;
            }
            UsbPacketStatus::Babble => {
                xfer.status = TRBCCode::BabbleDetected;
                self.submit_transfer(xfer)?;
            }
            _ => {
                bail!("Unhandle status {:?}", xfer.packet.status);
            }
        }
        Ok(())
    }

    /// Submit transfer TRBs.
    fn submit_transfer(&mut self, xfer: &mut XhciTransfer) -> Result<()> {
        // Event Data Transfer Length Accumulator
        let mut edtla = 0;
        let mut left = xfer.packet.actual_length;
        let mut reported = false;
        let mut short_pkt = false;
        for i in 0..xfer.trbs.len() {
            let trb = &xfer.trbs[i];
            let trb_type = trb.get_type();
            let mut chunk = trb.status & 0x1ffff;
            match trb_type {
                TRBType::TrSetup => {
                    if chunk > 8 {
                        chunk = 8;
                    }
                }
                TRBType::TrData | TRBType::TrNormal | TRBType::TrIsoch => {
                    if chunk > left {
                        chunk = left;
                        if xfer.status == TRBCCode::Success {
                            short_pkt = true;
                        }
                    }
                    left -= chunk;
                    edtla += chunk;
                }
                TRBType::TrStatus => {
                    reported = false;
                    short_pkt = false;
                }
                _ => {
                    debug!("Ignore the TRB, unhandled trb type {:?}", trb.get_type());
                }
            }
            if !reported
                && ((trb.control & TRB_TR_IOC == TRB_TR_IOC)
                    || (short_pkt && (trb.control & TRB_TR_ISP == TRB_TR_ISP))
                    || (xfer.status != TRBCCode::Success && left == 0))
            {
                self.send_transfer_event(xfer, trb, chunk, short_pkt, &mut edtla)?;
                reported = true;
                if xfer.status != TRBCCode::Success {
                    // Send unSuccess event succeed,return directly.
                    info!("submit_transfer xfer status {:?}", xfer.status);
                    return Ok(());
                }
            }
            if trb_type == TRBType::TrSetup {
                reported = false;
                short_pkt = false;
            }
        }
        Ok(())
    }

    fn send_transfer_event(
        &mut self,
        xfer: &XhciTransfer,
        trb: &XhciTRB,
        chunk: u32,
        short_pkt: bool,
        edtla: &mut u32,
    ) -> Result<()> {
        let trb_type = trb.get_type();
        let mut evt = XhciEvent::new(TRBType::ErTransfer, TRBCCode::Success);
        evt.slot_id = xfer.slotid as u8;
        evt.ep_id = xfer.epid as u8;
        evt.length = (trb.status & 0x1ffff) - chunk;
        evt.flags = 0;
        evt.ptr = trb.addr;
        evt.ccode = if xfer.status == TRBCCode::Success {
            if short_pkt {
                TRBCCode::ShortPacket
            } else {
                TRBCCode::Success
            }
        } else {
            xfer.status
        };
        if trb_type == TRBType::TrEvdata {
            evt.ptr = trb.parameter;
            evt.flags |= TRB_EV_ED;
            evt.length = *edtla & 0xffffff;
            *edtla = 0;
        }
        self.send_event(&evt, 0)?;
        Ok(())
    }

    /// Flush transfer in endpoint in some case such as stop endpoint.
    fn flush_ep_transfer(&mut self, slotid: u32, epid: u32, report: TRBCCode) -> Result<u32> {
        info!("flush_ep_transfer slotid {} epid {}", slotid, epid);
        let mut cnt = 0;
        let mut report = report;
        let xfers = self.slots[(slotid - 1) as usize].endpoints[(epid - 1) as usize]
            .transfers
            .clone();
        for mut xfer in xfers {
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
            if !epctx.enabled {
                bail!("Endpoint is disabled");
            }
            epctx.retry = None;
            xfer.running_retry = false;
            killed = 1;
        }
        xfer.trbs.clear();
        Ok(killed)
    }

    /// Used for device to wakeup endpoint
    pub fn wakeup_endpoint(&mut self, slot_id: u32, ep: &Arc<Mutex<UsbEndpoint>>) -> Result<()> {
        let locked_ep = ep.lock().unwrap();
        let ep_id = locked_ep.get_ep_id();
        // Kick endpoint may hold the lock, drop it.
        drop(locked_ep);
        self.kick_endpoint(slot_id as u32, ep_id as u32)?;
        Ok(())
    }

    /// Get microframe index
    pub fn get_mf_index(&self) -> u64 {
        0
    }

    pub fn update_mf(&self) {}

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
        if intr.erdp < intr.er_start
            || intr.erdp >= (intr.er_start + (TRB_SIZE * intr.er_size) as u64)
        {
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

        if let Some(ops) = self.ctrl_ops.as_ref() {
            ops.upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .trigger_intr(idx, true);
            self.intrs[idx as usize].iman &= !IMAN_IP;
        }
    }

    pub fn update_intr(&mut self, v: u32) {
        let mut level = false;
        if v == 0 {
            if self.intrs[0].iman & IMAN_IP == IMAN_IP
                && self.intrs[0].iman & IMAN_IE == IMAN_IE
                && self.oper.usb_cmd & USB_CMD_INTE == USB_CMD_INTE
            {
                level = true;
            }
            if let Some(ops) = &self.ctrl_ops {
                if ops
                    .upgrade()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .trigger_intr(0, level)
                {
                    self.intrs[0].iman &= !IMAN_IP;
                }
            }
        }

        if let Some(ops) = &self.ctrl_ops {
            ops.upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .update_intr(v, self.intrs[0].iman & IMAN_IE == IMAN_IE);
        }
    }
}

// DMA read/write helpers.
pub fn dma_read_bytes(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    mut buf: &mut [u8],
    len: u64,
) -> Result<()> {
    addr_space.read(&mut buf, addr, len).chain_err(|| {
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
    addr_space.write(&mut buf, addr, len).chain_err(|| {
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

pub fn get_field(val: u32, mask: u32, shift: u32) -> u32 {
    val >> shift & mask
}

pub fn set_field(val: u32, new_val: u32, mask: u32, shift: u32) -> u32 {
    let mut tmp = val;
    tmp &= !(mask << shift);
    tmp |= (new_val & mask) << shift;
    tmp
}
