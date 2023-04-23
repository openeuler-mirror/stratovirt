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

pub mod xhci_controller;
pub mod xhci_pci;
pub mod xhci_regs;
mod xhci_ring;

/// Transfer Request Block
pub const TRB_SIZE: u32 = 16;
pub const TRB_TYPE_SHIFT: u32 = 10;
pub const TRB_TYPE_MASK: u32 = 0x3f;
/// Cycle bit
pub const TRB_C: u32 = 1;
/// Event Data
pub const TRB_EV_ED: u32 = 1 << 2;
/// Toggle Cycle
pub const TRB_LK_TC: u32 = 1 << 1;
/// Interrupt-on Short Packet
pub const TRB_TR_ISP: u32 = 1 << 2;
/// Chain bit
pub const TRB_TR_CH: u32 = 1 << 4;
/// Interrupt On Completion
pub const TRB_TR_IOC: u32 = 1 << 5;
/// Immediate Data.
pub const TRB_TR_IDT: u32 = 1 << 6;
/// Direction of the data transfer.
pub const TRB_TR_DIR: u32 = 1 << 16;
/// TRB Transfer Length Mask
pub const TRB_TR_LEN_MASK: u32 = 0x1ffff;
/// Setup Stage TRB Length always 8
pub const SETUP_TRB_TR_LEN: u32 = 8;

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
