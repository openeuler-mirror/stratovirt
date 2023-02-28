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

use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;

use anyhow::{bail, Result};

use address_space::{AddressSpace, GuestAddress};
use byteorder::{ByteOrder, LittleEndian};
use log::debug;

use super::{TRBType, TRB_C, TRB_LK_TC, TRB_SIZE, TRB_TR_CH, TRB_TYPE_MASK, TRB_TYPE_SHIFT};
use crate::xhci::xhci_controller::dma_read_bytes;
use crate::UsbError;

const TRB_LINK_LIMIT: u32 = 32;
/// The max size of a ring segment in bytes is 64k.
const RING_SEGMENT_LIMIT: u32 = 0x1_0000;
/// The max size of ring.
const RING_LEN_LIMIT: u32 = TRB_LINK_LIMIT * RING_SEGMENT_LIMIT / TRB_SIZE;

type DmaAddr = u64;

/// XHCI Transfer Request Block
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub struct XhciTRB {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
    pub addr: DmaAddr,
    pub ccs: bool,
}

impl XhciTRB {
    pub fn new() -> Self {
        Self {
            parameter: 0,
            status: 0,
            control: 0,
            addr: 0,
            ccs: true,
        }
    }

    /// Get TRB type
    pub fn get_type(&self) -> TRBType {
        ((self.control >> TRB_TYPE_SHIFT) & TRB_TYPE_MASK).into()
    }

    // Get Cycle bit
    pub fn get_cycle_bit(&self) -> bool {
        self.control & TRB_C == TRB_C
    }
}

/// XHCI Ring
#[derive(Clone)]
pub struct XhciRing {
    mem: Arc<AddressSpace>,
    pub dequeue: u64,
    /// Consumer Cycle State
    pub ccs: bool,
}

impl XhciRing {
    pub fn new(mem: &Arc<AddressSpace>) -> Self {
        Self {
            mem: mem.clone(),
            dequeue: 0,
            ccs: true,
        }
    }

    pub fn init(&mut self, addr: u64) {
        self.dequeue = addr;
        self.ccs = true;
    }

    pub fn set_cycle_bit(&mut self, v: bool) {
        self.ccs = v;
    }

    /// Fetch TRB from the ring.
    pub fn fetch_trb(&mut self) -> Result<Option<XhciTRB>> {
        let mut link_cnt = 0;
        loop {
            let mut trb = self.read_trb(self.dequeue)?;
            trb.addr = self.dequeue;
            trb.ccs = self.ccs;
            if trb.get_cycle_bit() != self.ccs {
                debug!("TRB cycle bit not matched");
                return Ok(None);
            }
            let trb_type = trb.get_type();
            debug!("Fetch TRB: type {:?} trb {:?}", trb_type, trb);
            if trb_type == TRBType::TrLink {
                link_cnt += 1;
                if link_cnt > TRB_LINK_LIMIT {
                    bail!("TRB reach link limit");
                }
                self.dequeue = trb.parameter;
                if trb.control & TRB_LK_TC == TRB_LK_TC {
                    self.ccs = !self.ccs;
                }
            } else {
                self.dequeue = self.dequeue.checked_add(TRB_SIZE as u64).ok_or(
                    UsbError::MemoryAccessOverflow(self.dequeue, TRB_SIZE as u64),
                )?;
                return Ok(Some(trb));
            }
        }
    }

    fn read_trb(&self, addr: u64) -> Result<XhciTRB> {
        let mut buf = [0; TRB_SIZE as usize];
        dma_read_bytes(&self.mem, GuestAddress(addr), &mut buf, TRB_SIZE as u64)?;
        let trb = XhciTRB {
            parameter: LittleEndian::read_u64(&buf),
            status: LittleEndian::read_u32(&buf[8..]),
            control: LittleEndian::read_u32(&buf[12..]),
            addr: 0,
            ccs: true,
        };
        Ok(trb)
    }

    /// Get the transfer descriptor which includes one or more TRBs.
    /// Return None if the td is not ready.
    /// Return Vec if the td is ok.
    /// Return Error if read trb failed.
    pub fn fetch_td(&mut self) -> Result<Option<Vec<XhciTRB>>> {
        let mut dequeue = self.dequeue;
        let mut ccs = self.ccs;
        let mut ctrl_td = false;
        let mut link_cnt = 0;
        let mut td = Vec::new();
        for _ in 0..RING_LEN_LIMIT {
            let mut trb = self.read_trb(dequeue)?;
            trb.addr = dequeue;
            trb.ccs = ccs;
            if trb.get_cycle_bit() != ccs {
                // TRB is not ready.
                debug!("TRB cycle bit not matched");
                return Ok(None);
            }
            let trb_type = trb.get_type();
            if trb_type == TRBType::TrLink {
                link_cnt += 1;
                if link_cnt > TRB_LINK_LIMIT {
                    bail!("TRB link over limit");
                }
                dequeue = trb.parameter;
                if trb.control & TRB_LK_TC == TRB_LK_TC {
                    ccs = !ccs;
                }
            } else {
                td.push(trb);
                dequeue = dequeue
                    .checked_add(TRB_SIZE as u64)
                    .ok_or(UsbError::MemoryAccessOverflow(dequeue, TRB_SIZE as u64))?;
                if trb_type == TRBType::TrSetup {
                    ctrl_td = true;
                } else if trb_type == TRBType::TrStatus {
                    ctrl_td = false;
                }
                if !ctrl_td && (trb.control & TRB_TR_CH != TRB_TR_CH) {
                    // Update the dequeue pointer and ccs flag.
                    self.dequeue = dequeue;
                    self.ccs = ccs;
                    return Ok(Some(td));
                }
            }
        }
        bail!("Transfer TRB length over limit");
    }
}

impl Display for XhciRing {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "XhciRing dequeue {:x} ccs {}", self.dequeue, self.ccs)
    }
}

/// Event Ring Segment Table Entry. See in the specs 6.5 Event Ring Segment Table.
#[derive(Clone)]
pub struct XhciEventRingSeg {
    mem: Arc<AddressSpace>,
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub size: u32,
    pub rsvd: u32,
}

impl Display for XhciEventRingSeg {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "XhciEventRingSeg addr_lo {:x} addr_hi {:x} size {} rsvd {}",
            self.addr_lo, self.addr_hi, self.size, self.rsvd
        )
    }
}

impl XhciEventRingSeg {
    pub fn new(mem: &Arc<AddressSpace>) -> Self {
        Self {
            mem: mem.clone(),
            addr_lo: 0,
            addr_hi: 0,
            size: 0,
            rsvd: 0,
        }
    }

    /// Fetch the event ring segment.
    pub fn fetch_event_ring_seg(&mut self, addr: u64) -> Result<()> {
        let mut buf = [0_u8; TRB_SIZE as usize];
        dma_read_bytes(&self.mem, GuestAddress(addr), &mut buf, TRB_SIZE as u64)?;
        self.addr_lo = LittleEndian::read_u32(&buf);
        self.addr_hi = LittleEndian::read_u32(&buf[4..]);
        self.size = LittleEndian::read_u32(&buf[8..]);
        self.rsvd = LittleEndian::read_u32(&buf[12..]);
        Ok(())
    }
}
