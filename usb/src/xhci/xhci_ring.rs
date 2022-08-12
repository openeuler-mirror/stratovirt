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

use address_space::AddressSpace;

/// TRB Type Definitions. See the spec 6.4.6 TRB types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TRBType {
    TrbReserved = 0,
    TrNormal,
    TrSetup,
    TrData,
    TrStatus,
    TrIsoch,
    TrLink,
    TrEvdata,
    TrNoop,
    CrEnableSlot,
    CrDisableSlot,
    CrAddressDevice,
    CrConfigureEndpoint,
    CrEvaluateContext,
    CrResetEndpoint,
    CrStopEndpoint,
    CrSetTrDequeue,
    CrResetDevice,
    CrForceEvent,
    CrNegotiateBw,
    CrSetLatencyTolerance,
    CrGetPortBandwidth,
    CrForceHeader,
    CrNoop,
    ErTransfer = 32,
    ErCommandComplete,
    ErPortStatusChange,
    ErBandwidthRequest,
    ErDoorbell,
    ErHostController,
    ErDeviceNotification,
    ErMfindexWrap,
    /* vendor specific bits */
    CrVendorNecFirmwareRevision = 49,
    CrVendorNecChallengeResponse = 50,
    Unknown,
}

impl From<u32> for TRBType {
    fn from(t: u32) -> TRBType {
        match t {
            0 => TRBType::TrbReserved,
            1 => TRBType::TrNormal,
            2 => TRBType::TrSetup,
            3 => TRBType::TrData,
            4 => TRBType::TrStatus,
            5 => TRBType::TrIsoch,
            6 => TRBType::TrLink,
            7 => TRBType::TrEvdata,
            8 => TRBType::TrNoop,
            9 => TRBType::CrEnableSlot,
            10 => TRBType::CrDisableSlot,
            11 => TRBType::CrAddressDevice,
            12 => TRBType::CrConfigureEndpoint,
            13 => TRBType::CrEvaluateContext,
            14 => TRBType::CrResetEndpoint,
            15 => TRBType::CrStopEndpoint,
            16 => TRBType::CrSetTrDequeue,
            17 => TRBType::CrResetDevice,
            18 => TRBType::CrForceEvent,
            19 => TRBType::CrNegotiateBw,
            20 => TRBType::CrSetLatencyTolerance,
            21 => TRBType::CrGetPortBandwidth,
            22 => TRBType::CrForceHeader,
            23 => TRBType::CrNoop,
            32 => TRBType::ErTransfer,
            33 => TRBType::ErCommandComplete,
            34 => TRBType::ErPortStatusChange,
            35 => TRBType::ErBandwidthRequest,
            36 => TRBType::ErDoorbell,
            37 => TRBType::ErHostController,
            38 => TRBType::ErDeviceNotification,
            39 => TRBType::ErMfindexWrap,
            49 => TRBType::CrVendorNecFirmwareRevision,
            50 => TRBType::CrVendorNecChallengeResponse,
            _ => TRBType::Unknown,
        }
    }
}

/// TRB Completion Code. See the spec 6.4.5 TRB Completion Codes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TRBCCode {
    Invalid = 0,
    Success,
    DataBufferError,
    BabbleDetected,
    UsbTransactionError,
    TrbError,
    StallError,
    ResourceError,
    BandwidthError,
    NoSlotsError,
    InvalidStreamTypeError,
    SlotNotEnabledError,
    EpNotEnabledError,
    ShortPacket,
    RingUnderrun,
    RingOverrun,
    VfErFull,
    ParameterError,
    BandwidthOverrun,
    ContextStateError,
    NoPingResponseError,
    EventRingFullError,
    IncompatibleDeviceError,
    MissedServiceError,
    CommandRingStopped,
    CommandAborted,
    Stopped,
    StoppedLengthInvalid,
    MaxExitLatencyTooLargeError = 29,
    IsochBufferOverrun = 31,
    EventLostError,
    UndefinedError,
    InvalidStreamIdError,
    SecondaryBandwidthError,
    SplitTransactionError,
}

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
}

impl Display for XhciRing {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "XhciRing dequeue {:x} ccs {}", self.dequeue, self.ccs)
    }
}

/// XHCI event ring segment
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
