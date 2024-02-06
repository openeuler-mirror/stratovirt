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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AddressSpaceError {
    #[error("Util")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Failed to call listener, request type is {0:#?}")]
    ListenerRequest(crate::listener::ListenerReqType),
    #[error("Failed to update topology, base 0x{0:X}, size 0x{1:X}, region type is {2:#?}")]
    UpdateTopology(u64, u64, crate::RegionType),
    #[error("Failed to clone EventFd")]
    IoEventFd,
    #[error("Failed to align-up address, addr 0x{0:X}, align 0x{1:X}")]
    AddrAlignUp(u64, u64),
    #[error("Failed to find matched region, addr 0x{0:X}")]
    RegionNotFound(u64),
    #[error("Address overflows, addr is 0x{0:X}")]
    Overflow(u64),
    #[error("Failed to mmap")]
    Mmap,
    #[error("Failed to access IO-type region, region base 0x{0:X}, offset 0x{1:X}, size 0x{2:X}")]
    IoAccess(u64, u64, u64),
    #[error("Wrong region type, {0:#?}")]
    RegionType(crate::RegionType),
    #[error("Invalid offset: offset 0x{0:X}, data length 0x{1:X}, region size 0x{2:X}")]
    InvalidOffset(u64, u64, u64),
}
