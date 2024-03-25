// Copyright (c) 2021 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Result};

/// The version of the protocol StratoVirt support.
pub const VHOST_USER_VERSION: u32 = 0x1;
pub const VHOST_USER_MSG_MAX_SIZE: usize = 0x1000;
pub const MAX_ATTACHED_FD_ENTRIES: usize = 32;
pub const VHOST_USER_F_PROTOCOL_FEATURES: u32 = 30;
pub const VHOST_USER_MAX_CONFIG_SIZE: u32 = 256;

/// Type of requests sending from vhost user device to the userspace process.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VhostUserMsgReq {
    None = 0,
    GetFeatures = 1,
    SetFeatures = 2,
    SetOwner = 3,
    ResetOwner = 4,
    SetMemTable = 5,
    SetLogBase = 6,
    SetLogFd = 7,
    SetVringNum = 8,
    SetVringAddr = 9,
    SetVringBase = 10,
    GetVringBase = 11,
    SetVringKick = 12,
    SetVringCall = 13,
    SetVringErr = 14,
    GetProtocolFeatures = 15,
    SetProtocolFeatures = 16,
    GetQueueNum = 17,
    SetVringEnable = 18,
    SendRarp = 19,
    NetSetMtu = 20,
    SetSlaveReqFd = 21,
    IotlbMsg = 22,
    SetVringEndian = 23,
    GetConfig = 24,
    SetConfig = 25,
    CreateCryptoSession = 26,
    CloseCryptoSession = 27,
    PostcopyAdvise = 28,
    PostcopyListen = 29,
    PostcopyEnd = 30,
    GetInflightFd = 31,
    SetInflightFd = 32,
    MaxCmd = 33,
}

impl From<u32> for VhostUserMsgReq {
    fn from(t: u32) -> Self {
        match t {
            0 => VhostUserMsgReq::None,
            1 => VhostUserMsgReq::GetFeatures,
            2 => VhostUserMsgReq::SetFeatures,
            3 => VhostUserMsgReq::SetOwner,
            4 => VhostUserMsgReq::ResetOwner,
            5 => VhostUserMsgReq::SetMemTable,
            6 => VhostUserMsgReq::SetLogBase,
            7 => VhostUserMsgReq::SetLogFd,
            8 => VhostUserMsgReq::SetVringNum,
            9 => VhostUserMsgReq::SetVringAddr,
            10 => VhostUserMsgReq::SetVringBase,
            11 => VhostUserMsgReq::GetVringBase,
            12 => VhostUserMsgReq::SetVringKick,
            13 => VhostUserMsgReq::SetVringCall,
            14 => VhostUserMsgReq::SetVringErr,
            15 => VhostUserMsgReq::GetProtocolFeatures,
            16 => VhostUserMsgReq::SetProtocolFeatures,
            17 => VhostUserMsgReq::GetQueueNum,
            18 => VhostUserMsgReq::SetVringEnable,
            19 => VhostUserMsgReq::SendRarp,
            20 => VhostUserMsgReq::NetSetMtu,
            21 => VhostUserMsgReq::SetSlaveReqFd,
            22 => VhostUserMsgReq::IotlbMsg,
            23 => VhostUserMsgReq::SetVringEndian,
            24 => VhostUserMsgReq::GetConfig,
            25 => VhostUserMsgReq::SetConfig,
            26 => VhostUserMsgReq::CreateCryptoSession,
            27 => VhostUserMsgReq::CloseCryptoSession,
            28 => VhostUserMsgReq::PostcopyAdvise,
            29 => VhostUserMsgReq::PostcopyListen,
            30 => VhostUserMsgReq::PostcopyEnd,
            31 => VhostUserMsgReq::GetInflightFd,
            32 => VhostUserMsgReq::SetInflightFd,
            _ => VhostUserMsgReq::MaxCmd,
        }
    }
}

/// The meaning of flag bits for header of vhost user message.
pub enum VhostUserHdrFlag {
    /// Bits[0..1] is message version number.
    Version = 0x3,
    /// Bits`\[`2`]` Mark message as reply.
    Reply = 0x4,
    /// Bits`\[`3`\]` Sender anticipates a reply message from the peer.
    NeedReply = 0x8,
    /// All valid bits.
    AllFlags = 0xc,
    /// All reserved bits.
    ReservedBits = !0xf,
}

/// the struct for the header of vhost user message.
#[repr(C)]
pub struct VhostUserMsgHdr {
    /// The request id for vhost-user message
    pub request: u32,
    /// The flags for property setting
    pub flags: u32,
    /// The total length of vhost user message
    pub size: u32,
}

impl VhostUserMsgHdr {
    /// Create a new instance of `VhostUserMsgHeader`.
    pub fn new(request: u32, flags: u32, size: u32) -> Self {
        // Default to protocol version 1
        let flag = (flags & VhostUserHdrFlag::AllFlags as u32) | VHOST_USER_VERSION;
        VhostUserMsgHdr {
            request,
            flags: flag,
            size,
        }
    }

    /// Get message version number.
    fn get_version(&self) -> u32 {
        self.flags & VhostUserHdrFlag::Version as u32
    }

    /// Check whether reply for this message is requested.
    pub fn need_reply(&self) -> bool {
        (self.flags & VhostUserHdrFlag::NeedReply as u32) != 0
    }

    /// Check whether reply for message.
    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserHdrFlag::Reply as u32) != 0
    }

    /// Check the header of vhost user message is invalid.
    pub fn is_invalid(&self) -> bool {
        self.request >= VhostUserMsgReq::MaxCmd as u32
            || self.size > VHOST_USER_MSG_MAX_SIZE as u32
            || self.flags & (VhostUserHdrFlag::ReservedBits as u32) != 0
            || self.get_version() != VHOST_USER_VERSION
    }
}

impl Default for VhostUserMsgHdr {
    fn default() -> Self {
        VhostUserMsgHdr {
            request: 0,
            flags: VHOST_USER_VERSION,
            size: 0,
        }
    }
}

/// Struct for get and set config to vhost user.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VhostUserConfig<T: Default + Sized> {
    offset: u32,
    size: u32,
    flags: u32,
    pub config: T,
}

impl<T: Default + Sized> VhostUserConfig<T> {
    /// Create a new instance of `VhostUserConfig`.
    pub fn new(offset: u32, flags: u32, config: T) -> Result<Self> {
        let size = size_of::<T>() as u32;
        if size > VHOST_USER_MAX_CONFIG_SIZE {
            bail!("Failed to create VhostUserConfig: exceed max config size.")
        }
        Ok(VhostUserConfig {
            offset,
            size,
            flags,
            config,
        })
    }
}

/// Memory region information for the message of memory table.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegionMemInfo {
    /// Guest physical address of the memory region.
    pub guest_phys_addr: u64,
    /// Size of the memory region.
    pub memory_size: u64,
    /// Virtual address in the current process.
    pub userspace_addr: u64,
    /// Offset where region starts in the mapped memory.
    pub mmap_offset: u64,
}

/// The header for the message of memory table.
#[repr(C)]
pub struct VhostUserMemHdr {
    /// Number of memory regions in the payload.
    pub nregions: u32,
    /// Padding for alignment.
    pub padding: u32,
}

impl VhostUserMemHdr {
    pub fn new(nregions: u32, padding: u32) -> Self {
        VhostUserMemHdr { nregions, padding }
    }
}

/// The context for the message of memory table.
#[repr(C)]
pub struct VhostUserMemContext {
    /// The vector of memory region information.
    pub regions: Vec<RegionMemInfo>,
}

impl VhostUserMemContext {
    fn new() -> Self {
        VhostUserMemContext {
            regions: Vec::new(),
        }
    }

    pub fn region_add(&mut self, region: RegionMemInfo) {
        self.regions.push(region);
    }
}

impl Default for VhostUserMemContext {
    fn default() -> Self {
        Self::new()
    }
}

/// The configuration for the state of virtual ring.
#[repr(C)]
#[derive(Default)]
pub struct VhostUserVringState {
    /// Index for virtual ring.
    pub index: u32,
    /// A common 32bit value to encapsulate vring state etc.
    pub value: u32,
}

impl VhostUserVringState {
    pub fn new(index: u32, value: u32) -> Self {
        VhostUserVringState { index, value }
    }
}

/// The configuration for the address of virtual ring.
#[repr(C)]
#[derive(Debug)]
pub struct VhostUserVringAddr {
    /// Index for virtual ring.
    pub index: u32,
    /// The option for virtual ring.
    pub flags: u32,
    /// Address of the descriptor table.
    pub desc_user_addr: u64,
    /// Address of the used ring.
    pub used_user_addr: u64,
    /// Address of the available ring.
    pub avail_user_addr: u64,
    /// Guest address for logging.
    pub log_guest_addr: u64,
}
