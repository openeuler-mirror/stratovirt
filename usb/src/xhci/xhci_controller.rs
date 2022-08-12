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

use crate::xhci::xhci_ring::XhciEventRingSeg;
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
use crate::usb::{UsbPacket, UsbPort};
use crate::xhci::xhci_regs::{XchiOperReg, XhciInterrupter, XhciPort};
use crate::xhci::xhci_ring::{TRBCCode, TRBType, XhciRing, XhciTRB, TRB_SIZE, TRB_TYPE_SHIFT};

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
const EP_CTX_MAX_PACKET_SIZE_SHIFT: u32 = 16;
const EP_CTX_LSA_SHIFT: u32 = 15;
const EP_CTX_INTERVAL_SHIFT: u32 = 16;
const EP_CTX_INTERVAL_MASK: u32 = 0xff;
const EVENT_TRB_CCODE_SHIFT: u32 = 24;
const EVENT_TRB_SLOT_ID_SHIFT: u32 = 24;
const EVENT_TRB_EP_ID_SHIFT: u32 = 16;
const PORT_EVENT_ID_SHIFT: u32 = 24;

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

    /// Control plane
    pub fn handle_command(&mut self) -> Result<()> {
        Ok(())
    }

    /// Data plane
    pub(crate) fn kick_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<()> {
        Ok(())
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

    fn disable_endpoint(&mut self, slot_id: u32, ep_id: u32) -> Result<TRBCCode> {
        let slot = &mut self.slots[(slot_id - 1) as usize];
        let epctx = &mut slot.endpoints[(ep_id - 1) as usize];
        if !epctx.enabled {
            info!("Endpoint already disabled");
            return Ok(TRBCCode::Success);
        }
        if self.oper.dcbaap != 0 {
            epctx.set_state(&self.mem_space, EP_DISABLED)?;
        }
        epctx.enabled = false;
        Ok(TRBCCode::Success)
    }

    /// Get microframe index
    pub fn get_mf_index(&self) -> u64 {
        warn!("get_mf_index not implemented");
        0
    }

    pub fn update_mf(&self) {
        warn!("update_mf not implemented");
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

pub fn dma_read_u64(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    data: &mut u64,
) -> Result<()> {
    let mut tmp = [0_u8; 8];
    dma_read_bytes(addr_space, addr, &mut tmp, 8)?;
    *data = LittleEndian::read_u64(&tmp);
    Ok(())
}

pub fn dma_read_u32(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    buf: &mut [u32],
) -> Result<()> {
    let vec_len = size_of::<u32>() * buf.len();
    let mut vec = vec![0_u8; vec_len];
    let tmp = vec.as_mut_slice();
    dma_read_bytes(addr_space, addr, tmp, vec_len as u64)?;
    for i in 0..buf.len() {
        buf[i] = LittleEndian::read_u32(&tmp[(size_of::<u32>() * i)..]);
    }
    Ok(())
}

pub fn dma_write_u32(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    buf: &[u32],
) -> Result<()> {
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
