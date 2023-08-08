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
pub enum LegacyError {
    #[error("SysBus")]
    SysBus {
        #[from]
        source: crate::sysbus::error::SysBusError,
    },
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Failed to allocate system bus resource.")]
    SetSysResErr,
    #[error("Failed to add FwCfg entry, key is {0}")]
    AddEntryErr(String),
    #[error("Failed to find FwCfg entry, key is {0}.")]
    EntryNotFound(String),
    #[error("Duplicate FwCfg file-entry, name is {0}")]
    DuplicateFile(String),
    #[error("No available FwCfg file-slot for this file entry with filename {0}")]
    FileSlotsNotAvailable(String),
    #[error("Failed to read DMA request, dma_addr=0x{0:x} size=0x{1:x}")]
    ReadDmaRequest(u64, u64),
    #[error("Invalid FwCfg entry key {0}")]
    InvalidFwCfgEntry(u16),
    #[error("Flash size is 0x{0:x}, offset 0x{1:x} and size 0x{2:x} in write request overflows")]
    PFlashWriteOverflow(u64, u64, u64),
    #[error("Flash size is 0x{0:x}, offset 0x{1:x} and size 0x{2:x} in read request overflows")]
    PFlashReadOverflow(u64, u64, u64),
    #[error("Failed to seek to offset 0x{0:x} of PFlash file")]
    PFlashFileSeekErr(u64),
    #[error("Flash CFI table len is 0x{0:x}, request 0x{1:x} overflows")]
    PFlashIndexOverflow(u64, usize),
    #[error("Unsupported device configuration: device width {0}, bank width {1}")]
    PFlashDevConfigErr(u32, u32),
    #[error("Failed to write to Flash ROM")]
    WritePFlashRomErr,
    #[error("Failed to register event notifier.")]
    RegNotifierErr,
}
