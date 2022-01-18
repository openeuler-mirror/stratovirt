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

/// The version of the protocol StratoVirt support.
pub const VHOST_USER_VERSION: u32 = 0x1;
pub const VHOST_USER_MSG_MAX_SIZE: usize = 0x1000;
pub const MAX_ATTACHED_FD_ENTRIES: usize = 32;

/// Type of requests sending from vhost user device to the userspace process.
#[repr(u32)]
#[allow(dead_code)]
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

/// The meaning of flag bits for header of vhost user message.
pub enum VhostUserHdrFlag {
    /// Bits[0..1] is message version number.
    Version = 0x3,
    /// Bits[2] Mark message as reply.
    Reply = 0x4,
    /// Bits[3] Sender anticipates a reply message from the peer.
    NeedReply = 0x8,
    /// All valid bits.
    AllFlags = 0xc,
    /// All reserved bits.
    ReservedBits = !0xf,
}

///the struct for the header of vhost user message.
#[repr(C)]
pub struct VhostUserMsgHdr {
    /// The request id for vhost-user message
    pub request: u32,
    /// The flags for property setting
    pub flags: u32,
    /// The total length of vhost user message
    pub size: u32,
}

#[allow(dead_code)]
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
    fn need_reply(&self) -> bool {
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
