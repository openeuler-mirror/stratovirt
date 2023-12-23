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

use std::sync::atomic::{fence, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};
use log::{debug, error};

use super::xhci_controller::dma_write_bytes;
use super::xhci_controller::{UsbPort, XhciDevice, XhciEvent};
use super::xhci_ring::XhciTRB;
use super::xhci_trb::{TRBCCode, TRBType, TRB_C, TRB_SIZE};
use crate::usb::{config::*, UsbError};
use address_space::{AddressSpace, GuestAddress, RegionOps};
use util::num_ops::{read_data_u32, read_u32, write_data_u32, write_u64_high, write_u64_low};

/// Capability offset or size.
pub(crate) const XHCI_CAP_LENGTH: u32 = 0x40;
pub(crate) const XHCI_OFF_DOORBELL: u32 = 0x2000;
pub(crate) const XHCI_OFF_RUNTIME: u32 = 0x1000;
/// Capability Registers.
/// Capability Register Length.
const XHCI_CAP_REG_CAPLENGTH: u64 = 0x00;
/// Interface Version Number.
const XHCI_CAP_REG_HCIVERSION: u64 = 0x02;
/// Structural Parameters 1.
const XHCI_CAP_REG_HCSPARAMS1: u64 = 0x04;
/// Structural Parameters 2.
const XHCI_CAP_REG_HCSPARAMS2: u64 = 0x08;
/// Structural Parameters 3.
const XHCI_CAP_REG_HCSPARAMS3: u64 = 0x0c;
/// Capability Parameters 1.
const XHCI_CAP_REG_HCCPARAMS1: u64 = 0x10;
/// Doorbell Offset.
const XHCI_CAP_REG_DBOFF: u64 = 0x14;
/// Runtime Register Space Offset.
const XHCI_CAP_REG_RTSOFF: u64 = 0x18;
/// Capability Parameters 2.
const XHCI_CAP_REG_HCCPARAMS2: u64 = 0x1c;
const XHCI_VERSION: u32 = 0x100;
/// Number of Device Slots(MaxSlots).
const CAP_HCSP_NDS_SHIFT: u32 = 0;
/// Number of Interrupters(MaxIntrs).
const CAP_HCSP_NI_SHIFT: u32 = 8;
/// Number of Ports(MaxPorts).
const CAP_HCSP_NP_SHIFT: u32 = 24;
/// 64-bit Addressing Capability.
const CAP_HCCP_AC64: u32 = 0x1;
/// xHCI Extended Capabilities Pointer.
const CAP_HCCP_EXCP_SHIFT: u32 = 16;
/// Maximum Primary Stream Array Size.
const CAP_HCCP_MPSAS_SHIFT: u32 = 12;
/// Extended Capability Code (Supported Protocol).
const CAP_EXT_CAP_ID_SUPPORT_PROTOCOL: u8 = 2;
/// xHCI Supported Protocol Capability (Name String).
const CAP_EXT_USB_NAME_STRING: u32 = 0x20425355;
/// Supported Protocol Capability (Major Revision and Minor Revision).
const CAP_EXT_REVISION_SHIFT: u32 = 16;
/// Next xHCI Extended Capability Pointer.
const CAP_EXT_NEXT_CAP_POINTER_SHIFT: u32 = 8;
/// USB 2.0.
const CAP_EXT_USB_REVISION_2_0: u32 = 0x0200;
/// USB 3.0.
const CAP_EXT_USB_REVISION_3_0: u32 = 0x0300;
/// Operational Registers.
pub const XHCI_OPER_REG_USBCMD: u64 = 0x00;
pub const XHCI_OPER_REG_USBSTS: u64 = 0x04;
pub const XHCI_OPER_REG_PAGESIZE: u64 = 0x08;
pub const XHCI_OPER_REG_DNCTRL: u64 = 0x14;
const XHCI_OPER_REG_CMD_RING_CTRL_LO: u64 = 0x18;
const XHCI_OPER_REG_CMD_RING_CTRL_HI: u64 = 0x1c;
const XHCI_OPER_REG_DCBAAP_LO: u64 = 0x30;
const XHCI_OPER_REG_DCBAAP_HI: u64 = 0x34;
pub const XHCI_OPER_REG_CONFIG: u64 = 0x38;
const XHCI_OPER_PAGESIZE: u32 = 1;
/// Command Ring Control Register RCS/CS/CA mask.
const XHCI_CRCR_CTRL_LO_MASK: u32 = 0xffffffc7;
/// Command Ring Pointer Mask.
const XHCI_CRCR_CRP_MASK: u64 = !0x3f;
/// Notification Enable.
pub const XHCI_OPER_NE_MASK: u32 = 0xffff;
/// Interrupter Registers.
pub const XHCI_INTR_REG_IMAN: u64 = 0x00;
pub const XHCI_INTR_REG_IMOD: u64 = 0x04;
pub const XHCI_INTR_REG_ERSTSZ: u64 = 0x08;
pub const XHCI_INTR_REG_ERSTBA_LO: u64 = 0x10;
pub const XHCI_INTR_REG_ERSTBA_HI: u64 = 0x14;
pub const XHCI_INTR_REG_ERDP_LO: u64 = 0x18;
pub const XHCI_INTR_REG_ERDP_HI: u64 = 0x1c;
pub const XHCI_INTR_REG_SIZE: u64 = 0x20;
const XHCI_INTR_REG_SHIFT: u64 = 5;
/// Doorbell Register Bit Field.
/// DB Target.
const DB_TARGET_MASK: u32 = 0xff;
/// Port Registers.
const XHCI_PORTSC: u64 = 0x0;
const XHCI_PORTPMSC: u64 = 0x4;
const XHCI_PORTLI: u64 = 0x8;
const XHCI_PORTHLPMC: u64 = 0xc;

/// XHCI Operation Registers
#[derive(Default)]
pub struct XhciOperReg {
    /// USB Command
    pub usb_cmd: Arc<AtomicU32>,
    /// USB Status
    pub usb_status: Arc<AtomicU32>,
    /// Device Notify Control
    pub dev_notify_ctrl: u32,
    /// Command Ring Control
    pub cmd_ring_ctrl: u64,
    /// Device Context Base Address Array Pointer
    pub dcbaap: u64,
    /// Configure
    pub config: u32,
}

impl XhciOperReg {
    pub fn reset(&mut self) {
        self.set_usb_cmd(0);
        self.set_usb_status(USB_STS_HCH);
        self.dev_notify_ctrl = 0;
        self.cmd_ring_ctrl = 0;
        self.dcbaap = 0;
        self.config = 0;
    }

    /// Run the command ring.
    pub fn start_cmd_ring(&mut self) {
        self.cmd_ring_ctrl |= CMD_RING_CTRL_CRR as u64;
    }

    pub fn set_usb_cmd(&mut self, value: u32) {
        self.usb_cmd.store(value, Ordering::SeqCst)
    }

    pub fn get_usb_cmd(&self) -> u32 {
        self.usb_cmd.load(Ordering::Acquire)
    }

    pub fn set_usb_status(&mut self, value: u32) {
        self.usb_status.store(value, Ordering::SeqCst)
    }

    pub fn get_usb_status(&self) -> u32 {
        self.usb_status.load(Ordering::Acquire)
    }

    pub fn set_usb_status_flag(&mut self, value: u32) {
        self.usb_status.fetch_or(value, Ordering::SeqCst);
    }

    pub fn unset_usb_status_flag(&mut self, value: u32) {
        self.usb_status.fetch_and(!value, Ordering::SeqCst);
    }
}

/// XHCI Interrupter
pub struct XhciInterrupter {
    mem: Arc<AddressSpace>,
    oper_usb_cmd: Arc<AtomicU32>,
    oper_usb_status: Arc<AtomicU32>,
    id: u32,
    interrupt_cb: Option<Arc<dyn Fn(u32, u8) -> bool + Send + Sync>>,
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
    pub fn new(
        mem: &Arc<AddressSpace>,
        oper_usb_cmd: &Arc<AtomicU32>,
        oper_usb_status: &Arc<AtomicU32>,
        id: u32,
    ) -> Self {
        Self {
            mem: mem.clone(),
            oper_usb_cmd: oper_usb_cmd.clone(),
            oper_usb_status: oper_usb_status.clone(),
            id,
            interrupt_cb: None,
            iman: 0,
            imod: 0,
            erstsz: 0,
            erstba: 0,
            erdp: 0,
            er_pcs: true,
            er_start: 0,
            er_size: 0,
            er_ep_idx: 0,
        }
    }

    pub fn set_interrupter(&mut self, cb: Arc<dyn Fn(u32, u8) -> bool + Send + Sync>) {
        self.interrupt_cb = Some(cb);
    }

    pub fn oper_intr_enabled(&self) -> bool {
        self.oper_usb_cmd.load(Ordering::Acquire) & USB_CMD_INTE == USB_CMD_INTE
    }

    pub fn enable_intr(&mut self) {
        self.oper_usb_status
            .fetch_or(USB_STS_EINT, Ordering::SeqCst);
    }

    pub fn reset(&mut self) {
        self.iman = 0;
        self.imod = 0;
        self.erstsz = 0;
        self.erstba = 0;
        self.erdp = 0;
        self.er_pcs = true;
        self.er_start = 0;
        self.er_size = 0;
        self.er_ep_idx = 0;
    }

    /// Send event TRB to driver, first write TRB and then send interrupt.
    pub fn send_event(&mut self, evt: &XhciEvent) -> Result<()> {
        let er_end = self
            .er_start
            .checked_add((TRB_SIZE * self.er_size) as u64)
            .ok_or(UsbError::MemoryAccessOverflow(
                self.er_start,
                (TRB_SIZE * self.er_size) as u64,
            ))?;
        if self.erdp < self.er_start || self.erdp >= er_end {
            bail!(
                "DMA out of range, erdp {} er_start {:x} er_size {}",
                self.erdp,
                self.er_start,
                self.er_size
            );
        }
        let dp_idx = (self.erdp - self.er_start) / TRB_SIZE as u64;
        if ((self.er_ep_idx + 2) % self.er_size) as u64 == dp_idx {
            debug!("Event ring full error, idx {}", dp_idx);
            let event = XhciEvent::new(TRBType::ErHostController, TRBCCode::EventRingFullError);
            self.write_event(&event)?;
        } else if ((self.er_ep_idx + 1) % self.er_size) as u64 == dp_idx {
            debug!("Event Ring full, drop Event.");
        } else {
            self.write_event(evt)?;
        }
        self.send_intr();
        Ok(())
    }

    fn send_intr(&mut self) {
        let pending = read_u32(self.erdp, 0) & ERDP_EHB == ERDP_EHB;
        let mut erdp_low = read_u32(self.erdp, 0);
        erdp_low |= ERDP_EHB;
        self.erdp = write_u64_low(self.erdp, erdp_low);
        self.iman |= IMAN_IP;
        self.enable_intr();
        if pending {
            return;
        }
        if self.iman & IMAN_IE != IMAN_IE {
            return;
        }
        if !self.oper_intr_enabled() {
            return;
        }

        if let Some(intr_ops) = self.interrupt_cb.as_ref() {
            if intr_ops(self.id, 1) {
                self.iman &= !IMAN_IP;
            }
        }
    }

    fn update_intr(&mut self) {
        if self.id == 0 {
            let mut level = 0;
            if self.iman & IMAN_IP == IMAN_IP
                && self.iman & IMAN_IE == IMAN_IE
                && self.oper_intr_enabled()
            {
                level = 1;
            }
            if let Some(intr_ops) = &self.interrupt_cb {
                if intr_ops(0, level) {
                    self.iman &= !IMAN_IP;
                }
            }
        }
    }

    /// Write event to the ring and update index.
    pub fn write_event(&mut self, evt: &XhciEvent) -> Result<()> {
        let mut ev_trb = evt.to_trb();
        if self.er_pcs {
            ev_trb.control |= TRB_C;
        }
        self.write_trb(&ev_trb)?;
        // Update index
        self.er_ep_idx += 1;
        if self.er_ep_idx >= self.er_size {
            self.er_ep_idx = 0;
            self.er_pcs = !self.er_pcs;
        }
        Ok(())
    }

    fn write_trb(&mut self, trb: &XhciTRB) -> Result<()> {
        let addr = self
            .er_start
            .checked_add((TRB_SIZE * self.er_ep_idx) as u64)
            .ok_or(UsbError::MemoryAccessOverflow(
                self.er_start,
                (TRB_SIZE * self.er_ep_idx) as u64,
            ))?;
        let cycle = trb.control as u8;
        // Toggle the cycle bit to avoid driver read it.
        let control = if trb.control & TRB_C == TRB_C {
            trb.control & !TRB_C
        } else {
            trb.control | TRB_C
        };
        let mut buf = [0_u8; TRB_SIZE as usize];
        LittleEndian::write_u64(&mut buf, trb.parameter);
        LittleEndian::write_u32(&mut buf[8..], trb.status);
        LittleEndian::write_u32(&mut buf[12..], control);
        dma_write_bytes(&self.mem, GuestAddress(addr), &buf)?;
        // Write the cycle bit at last.
        fence(Ordering::SeqCst);
        dma_write_bytes(&self.mem, GuestAddress(addr + 12), &[cycle])?;
        Ok(())
    }
}

/// Build capability region ops.
pub fn build_cap_ops(xhci_dev: &Arc<Mutex<XhciDevice>>) -> RegionOps {
    let xhci_dev = xhci_dev.clone();
    let cap_read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
        let locked_dev = xhci_dev.lock().unwrap();
        let max_ports = locked_dev.numports_2 + locked_dev.numports_3;
        let max_intrs = locked_dev.intrs.len() as u32;
        let value = match offset {
            XHCI_CAP_REG_CAPLENGTH => {
                let hci_version_offset = XHCI_CAP_REG_HCIVERSION * 8;
                XHCI_VERSION << hci_version_offset | XHCI_CAP_LENGTH
            }
            XHCI_CAP_REG_HCSPARAMS1 => {
                (max_ports as u32) << CAP_HCSP_NP_SHIFT
                    | max_intrs << CAP_HCSP_NI_SHIFT
                    | (locked_dev.slots.len() as u32) << CAP_HCSP_NDS_SHIFT
            }
            XHCI_CAP_REG_HCSPARAMS2 => {
                // IST
                0xf
            }
            XHCI_CAP_REG_HCSPARAMS3 => 0x0,
            XHCI_CAP_REG_HCCPARAMS1 => {
                0x8 << CAP_HCCP_EXCP_SHIFT | (0 << CAP_HCCP_MPSAS_SHIFT) | CAP_HCCP_AC64
            }
            XHCI_CAP_REG_DBOFF => XHCI_OFF_DOORBELL,
            XHCI_CAP_REG_RTSOFF => XHCI_OFF_RUNTIME,
            XHCI_CAP_REG_HCCPARAMS2 => 0,
            // Extended capabilities (USB 2.0)
            0x20 => {
                CAP_EXT_USB_REVISION_2_0 << CAP_EXT_REVISION_SHIFT
                    | 0x4 << CAP_EXT_NEXT_CAP_POINTER_SHIFT
                    | CAP_EXT_CAP_ID_SUPPORT_PROTOCOL as u32
            }
            0x24 => CAP_EXT_USB_NAME_STRING,
            0x28 => ((locked_dev.numports_2 as u32) << 8) | 1,
            0x2c => 0x0,
            // Extended capabilities (USB 3.0)
            0x30 => {
                CAP_EXT_USB_REVISION_3_0 << CAP_EXT_REVISION_SHIFT
                    | CAP_EXT_CAP_ID_SUPPORT_PROTOCOL as u32
            }
            0x34 => CAP_EXT_USB_NAME_STRING,
            0x38 => ((locked_dev.numports_3 as u32) << 8) | (locked_dev.numports_2 + 1) as u32,
            0x3c => 0x0,
            _ => {
                error!("Failed to read xhci cap: not implemented");
                0
            }
        };
        trace::usb_xhci_cap_read(&addr.0, &offset, &value);
        write_data_u32(data, value)
    };

    let cap_write = move |_data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
        error!(
            "Failed to write cap register: addr {:?} offset {}",
            _addr, offset
        );
        true
    };

    RegionOps {
        read: Arc::new(cap_read),
        write: Arc::new(cap_write),
    }
}

/// Build operational region ops.
pub fn build_oper_ops(xhci_dev: &Arc<Mutex<XhciDevice>>) -> RegionOps {
    let xhci = xhci_dev.clone();
    let oper_read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
        let locked_xhci = xhci.lock().unwrap();
        let value = match offset {
            XHCI_OPER_REG_USBCMD => locked_xhci.oper.get_usb_cmd(),
            XHCI_OPER_REG_USBSTS => locked_xhci.oper.get_usb_status(),
            XHCI_OPER_REG_PAGESIZE => XHCI_OPER_PAGESIZE,
            XHCI_OPER_REG_DNCTRL => locked_xhci.oper.dev_notify_ctrl,
            XHCI_OPER_REG_CMD_RING_CTRL_LO => {
                // 5.4.5 Command Ring Control Register
                // Table 5-24 shows read RCS CS CA always returns 0.
                read_u32(locked_xhci.oper.cmd_ring_ctrl, 0) & CMD_RING_CTRL_CRR
            }
            XHCI_OPER_REG_CMD_RING_CTRL_HI => {
                // 5.4.5 Command Ring Control Register
                // Table 5-24 shows read CRP always returns 0.
                0
            }
            XHCI_OPER_REG_DCBAAP_LO => read_u32(locked_xhci.oper.dcbaap, 0),
            XHCI_OPER_REG_DCBAAP_HI => read_u32(locked_xhci.oper.dcbaap, 1),
            XHCI_OPER_REG_CONFIG => locked_xhci.oper.config,
            _ => {
                error!(
                    "Invalid offset {:x} for reading operational registers.",
                    offset
                );
                0
            }
        };
        trace::usb_xhci_oper_read(&addr.0, &offset, &value);
        write_data_u32(data, value)
    };

    let xhci = xhci_dev.clone();
    let oper_write = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
        let mut value = 0;
        if !read_data_u32(data, &mut value) {
            return false;
        }
        let mut locked_xhci = xhci.lock().unwrap();
        match offset {
            XHCI_OPER_REG_USBCMD => {
                if (value & USB_CMD_RUN) == USB_CMD_RUN
                    && (locked_xhci.oper.get_usb_cmd() & USB_CMD_RUN) != USB_CMD_RUN
                {
                    locked_xhci.run();
                } else if (value & USB_CMD_RUN) != USB_CMD_RUN
                    && (locked_xhci.oper.get_usb_cmd() & USB_CMD_RUN) == USB_CMD_RUN
                {
                    locked_xhci.stop();
                }
                if value & USB_CMD_CSS == USB_CMD_CSS {
                    locked_xhci.oper.unset_usb_status_flag(USB_STS_SRE);
                }
                // When the restore command is issued, an error is reported and then
                // guest OS performs a complete initialization.
                if value & USB_CMD_CRS == USB_CMD_CRS {
                    locked_xhci.oper.set_usb_status_flag(USB_STS_SRE);
                }
                locked_xhci.oper.set_usb_cmd(value & 0xc0f);
                locked_xhci.mfwrap_update();
                if value & USB_CMD_HCRST == USB_CMD_HCRST {
                    locked_xhci.reset();
                }
                locked_xhci.intrs[0].lock().unwrap().update_intr();
            }
            XHCI_OPER_REG_USBSTS => {
                // Write 1 to clear.
                locked_xhci.oper.unset_usb_status_flag(
                    value & (USB_STS_HSE | USB_STS_EINT | USB_STS_PCD | USB_STS_SRE),
                );
                locked_xhci.intrs[0].lock().unwrap().update_intr();
            }
            XHCI_OPER_REG_DNCTRL => locked_xhci.oper.dev_notify_ctrl = value & XHCI_OPER_NE_MASK,
            XHCI_OPER_REG_CMD_RING_CTRL_LO => {
                let mut crc_lo = read_u32(locked_xhci.oper.cmd_ring_ctrl, 0);
                crc_lo = (value & XHCI_CRCR_CTRL_LO_MASK) | (crc_lo & CMD_RING_CTRL_CRR);
                locked_xhci.oper.cmd_ring_ctrl =
                    write_u64_low(locked_xhci.oper.cmd_ring_ctrl, crc_lo);
            }
            XHCI_OPER_REG_CMD_RING_CTRL_HI => {
                let crc_hi = (value as u64) << 32;
                let mut crc_lo = read_u32(locked_xhci.oper.cmd_ring_ctrl, 0);
                if crc_lo & (CMD_RING_CTRL_CA | CMD_RING_CTRL_CS) != 0
                    && (crc_lo & CMD_RING_CTRL_CRR) == CMD_RING_CTRL_CRR
                {
                    let event =
                        XhciEvent::new(TRBType::ErCommandComplete, TRBCCode::CommandRingStopped);
                    crc_lo &= !CMD_RING_CTRL_CRR;
                    if let Err(e) = locked_xhci.intrs[0].lock().unwrap().send_event(&event) {
                        error!("Failed to send event: {:?}", e);
                    }
                } else {
                    let addr = (crc_hi | crc_lo as u64) & XHCI_CRCR_CRP_MASK;
                    locked_xhci.cmd_ring.init(addr);
                }
                crc_lo &= !(CMD_RING_CTRL_CA | CMD_RING_CTRL_CS);
                locked_xhci.oper.cmd_ring_ctrl = write_u64_low(crc_hi, crc_lo);
            }
            XHCI_OPER_REG_DCBAAP_LO => {
                locked_xhci.oper.dcbaap = write_u64_low(locked_xhci.oper.dcbaap, value & 0xffffffc0)
            }
            XHCI_OPER_REG_DCBAAP_HI => {
                locked_xhci.oper.dcbaap = write_u64_high(locked_xhci.oper.dcbaap, value)
            }
            XHCI_OPER_REG_CONFIG => locked_xhci.oper.config = value & 0xff,
            _ => {
                error!(
                    "Invalid offset {:x} for writing operational registers.",
                    offset
                );
                return false;
            }
        };
        trace::usb_xhci_oper_write(&addr.0, &offset, &value);
        true
    };

    RegionOps {
        read: Arc::new(oper_read),
        write: Arc::new(oper_write),
    }
}

/// Build runtime region ops.
pub fn build_runtime_ops(xhci_dev: &Arc<Mutex<XhciDevice>>) -> RegionOps {
    let xhci = xhci_dev.clone();
    let runtime_read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
        let mut value = 0;
        if offset < 0x20 {
            if offset == 0x0 {
                value = (xhci.lock().unwrap().mfindex() & 0x3fff) as u32;
            } else {
                error!("Failed to read runtime registers, offset is {:x}", offset);
            }
        } else {
            let idx = ((offset - XHCI_INTR_REG_SIZE) >> XHCI_INTR_REG_SHIFT) as usize;
            let xhci = xhci.lock().unwrap();
            if idx >= xhci.intrs.len() {
                error!("Invalid interrupter index: {} idx {}", offset, idx);
                return false;
            }
            let locked_intr = xhci.intrs[idx].lock().unwrap();
            value = match offset & 0x1f {
                XHCI_INTR_REG_IMAN => locked_intr.iman,
                XHCI_INTR_REG_IMOD => locked_intr.imod,
                XHCI_INTR_REG_ERSTSZ => locked_intr.erstsz,
                XHCI_INTR_REG_ERSTBA_LO => read_u32(locked_intr.erstba, 0),
                XHCI_INTR_REG_ERSTBA_HI => read_u32(locked_intr.erstba, 1),
                XHCI_INTR_REG_ERDP_LO => read_u32(locked_intr.erdp, 0),
                XHCI_INTR_REG_ERDP_HI => read_u32(locked_intr.erdp, 1),
                _ => {
                    error!(
                        "Invalid offset {:x} for reading interrupter registers.",
                        offset
                    );
                    return false;
                }
            };
        }
        trace::usb_xhci_runtime_read(&addr.0, &offset, &value);
        write_data_u32(data, value)
    };

    let xhci = xhci_dev.clone();
    let runtime_write = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
        let mut value = 0;
        if !read_data_u32(data, &mut value) {
            return false;
        }
        if offset < 0x20 {
            error!("Runtime write not implemented: offset {}", offset);
            return false;
        }
        let mut xhci = xhci.lock().unwrap();
        let idx = ((offset - XHCI_INTR_REG_SIZE) >> XHCI_INTR_REG_SHIFT) as u32;
        if idx >= xhci.intrs.len() as u32 {
            error!("Invalid interrupter index: {} idx {}", offset, idx);
            return false;
        }
        let mut locked_intr = xhci.intrs[idx as usize].lock().unwrap();
        match offset & 0x1f {
            XHCI_INTR_REG_IMAN => {
                if value & IMAN_IP == IMAN_IP {
                    locked_intr.iman &= !IMAN_IP;
                }
                locked_intr.iman &= !IMAN_IE;
                locked_intr.iman |= value & IMAN_IE;
                locked_intr.update_intr();
            }
            XHCI_INTR_REG_IMOD => locked_intr.imod = value,
            XHCI_INTR_REG_ERSTSZ => locked_intr.erstsz = value & 0xffff,
            XHCI_INTR_REG_ERSTBA_LO => {
                locked_intr.erstba = write_u64_low(locked_intr.erstba, value & 0xffffffc0);
            }
            XHCI_INTR_REG_ERSTBA_HI => {
                locked_intr.erstba = write_u64_high(locked_intr.erstba, value);
                drop(locked_intr);
                if let Err(e) = xhci.reset_event_ring(idx) {
                    error!("Failed to reset event ring: {:?}", e);
                }
            }
            XHCI_INTR_REG_ERDP_LO => {
                // ERDP_EHB is write 1 clear.
                let mut erdp_lo = value & !ERDP_EHB;
                if value & ERDP_EHB != ERDP_EHB {
                    let erdp_old = read_u32(locked_intr.erdp, 0);
                    erdp_lo |= erdp_old & ERDP_EHB;
                }
                locked_intr.erdp = write_u64_low(locked_intr.erdp, erdp_lo);
                if value & ERDP_EHB == ERDP_EHB {
                    let erdp = locked_intr.erdp;
                    let er_end = if let Some(addr) = locked_intr
                        .er_start
                        .checked_add((TRB_SIZE * locked_intr.er_size) as u64)
                    {
                        addr
                    } else {
                        error!(
                            "Memory access overflow, addr {:x} offset {:x}",
                            locked_intr.er_start,
                            (TRB_SIZE * locked_intr.er_size) as u64
                        );
                        return false;
                    };
                    if erdp >= locked_intr.er_start
                        && erdp < er_end
                        && (erdp - locked_intr.er_start) / TRB_SIZE as u64
                            != locked_intr.er_ep_idx as u64
                    {
                        drop(locked_intr);
                        xhci.intrs[idx as usize].lock().unwrap().send_intr();
                    }
                }
            }
            XHCI_INTR_REG_ERDP_HI => {
                locked_intr.erdp = write_u64_high(locked_intr.erdp, value);
            }
            _ => {
                error!(
                    "Invalid offset {:x} for writing interrupter registers.",
                    offset
                );
            }
        };
        trace::usb_xhci_runtime_write(&addr.0, &offset, &value);
        true
    };

    RegionOps {
        read: Arc::new(runtime_read),
        write: Arc::new(runtime_write),
    }
}

/// Build doorbell region ops.
pub fn build_doorbell_ops(xhci_dev: &Arc<Mutex<XhciDevice>>) -> RegionOps {
    let doorbell_read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
        trace::usb_xhci_doorbell_read(&addr.0, &offset, &0);
        write_data_u32(data, 0)
    };
    let xhci = xhci_dev.clone();
    let doorbell_write = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
        let mut value = 0;
        if !read_data_u32(data, &mut value) {
            return false;
        }
        if !xhci.lock().unwrap().running() {
            error!("Failed to write doorbell, XHCI is not running");
            return false;
        }
        let mut xhci = xhci.lock().unwrap();
        let slot_id = (offset >> 2) as u32;
        if slot_id == 0 {
            error!("Invalid slot id 0 !");
            return false;
        } else {
            let ep_id = value & DB_TARGET_MASK;
            if let Err(e) = xhci.kick_endpoint(slot_id, ep_id) {
                error!("Failed to kick endpoint: {:?}", e);
                xhci.host_controller_error();
                return false;
            }
        }
        trace::usb_xhci_doorbell_write(&addr.0, &offset, &value);
        true
    };

    RegionOps {
        read: Arc::new(doorbell_read),
        write: Arc::new(doorbell_write),
    }
}

/// Build port region ops.
pub fn build_port_ops(xhci_port: &Arc<Mutex<UsbPort>>) -> RegionOps {
    let port = xhci_port.clone();
    let port_read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
        let locked_port = port.lock().unwrap();
        let value = match offset {
            XHCI_PORTSC => locked_port.portsc,
            XHCI_PORTPMSC => 0,
            XHCI_PORTLI => 0,
            XHCI_PORTHLPMC => 0,
            _ => {
                error!("Failed to read port register: offset {:x}", offset);
                return false;
            }
        };
        trace::usb_xhci_port_read(&addr.0, &offset, &value);
        write_data_u32(data, value)
    };

    let port = xhci_port.clone();
    let port_write = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
        let mut value = 0;
        if !read_data_u32(data, &mut value) {
            return false;
        }
        match offset {
            XHCI_PORTSC => {
                if let Err(e) = xhci_portsc_write(&port, value) {
                    error!("Failed to write portsc register, {:?}", e);
                    return false;
                }
            }
            XHCI_PORTPMSC => (),
            XHCI_PORTLI => (),
            XHCI_PORTHLPMC => (),
            _ => {
                error!("Invalid port link state offset {}", offset);
                return false;
            }
        }
        trace::usb_xhci_port_write(&addr.0, &offset, &value);
        true
    };

    RegionOps {
        read: Arc::new(port_read),
        write: Arc::new(port_write),
    }
}

fn xhci_portsc_write(port: &Arc<Mutex<UsbPort>>, value: u32) -> Result<()> {
    let locked_port = port.lock().unwrap();
    let xhci = locked_port.xhci.upgrade().unwrap();
    drop(locked_port);
    // Lock controller first.
    let mut locked_xhci = xhci.lock().unwrap();
    if value & PORTSC_WPR == PORTSC_WPR {
        return locked_xhci.reset_port(port, true);
    }
    if value & PORTSC_PR == PORTSC_PR {
        return locked_xhci.reset_port(port, false);
    }
    let mut locked_port = port.lock().unwrap();
    let old_portsc = locked_port.portsc;
    let mut notify = 0;
    // Write 1 to clear.
    locked_port.portsc &= !(value
        & (PORTSC_CSC
            | PORTSC_PEC
            | PORTSC_WRC
            | PORTSC_OCC
            | PORTSC_PRC
            | PORTSC_PLC
            | PORTSC_CEC));
    if value & PORTSC_LWS == PORTSC_LWS {
        let old_pls = (old_portsc >> PORTSC_PLS_SHIFT) & PORTSC_PLS_MASK;
        let new_pls = (value >> PORTSC_PLS_SHIFT) & PORTSC_PLS_MASK;
        notify = xhci_portsc_ls_write(&mut locked_port, old_pls, new_pls);
    }
    locked_port.portsc &= !(PORTSC_PP | PORTSC_WCE | PORTSC_WDE | PORTSC_WOE);
    locked_port.portsc |= value & (PORTSC_PP | PORTSC_WCE | PORTSC_WDE | PORTSC_WOE);
    drop(locked_port);
    if notify != 0 {
        locked_xhci.port_notify(port, notify)?;
    }
    Ok(())
}

fn xhci_portsc_ls_write(port: &mut UsbPort, old_pls: u32, new_pls: u32) -> u32 {
    match new_pls {
        PLS_U0 => {
            if old_pls != PLS_U0 {
                port.set_port_link_state(new_pls);
                trace::usb_xhci_port_link(&port.port_id, &new_pls);
                return PORTSC_PLC;
            }
        }
        PLS_U3 => {
            if old_pls < PLS_U3 {
                port.set_port_link_state(new_pls);
                trace::usb_xhci_port_link(&port.port_id, &new_pls);
            }
        }
        PLS_RESUME => {}
        _ => {
            error!(
                "Unhandled port link state, ignore the write. old {:x} new {:x}",
                old_pls, new_pls
            );
        }
    }
    0
}
