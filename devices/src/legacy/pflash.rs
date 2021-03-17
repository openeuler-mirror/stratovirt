// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::fs::File;
use std::sync::Arc;

use address_space::Region;
use sysbus::SysRes;

use super::errors::Result;

/// PFlash structure
pub struct PFlash {
    /// File to save data in PFlash ROM
    fd_blk: File,
    /// Number of blocks
    blk_num: u32,
    /// Length of sector
    sector_len: u32,
    /// Indicator of byte or bit
    bank_width: u32,
    /// If 0, device width not specified
    device_width: u32,
    /// Max device width in bytes
    max_device_width: u32,
    /// If 0, the flash is read normally
    write_cycle: i32,
    /// Pflash is read only or not
    read_only: i32,
    /// Command to control pflash
    cmd: u8,
    /// Pflash status
    status: u8,
    /// Pflash ID0
    ident0: u32,
    /// Pflash ID1
    ident1: u32,
    /// Pflash ID2
    ident2: u32,
    /// Pflash ID3
    ident3: u32,
    /// Hardcoded information of pflash device
    cfi_table: [u8; 0x52],
    /// Counter of write block
    counter: u32,
    /// Size of write block
    write_blk_size: u32,
    /// ROM region of pflash
    rom: Option<Arc<Region>>,
    /// System Resource of device.
    res: SysRes,
}

impl PFlash {
    pub fn new(
        size: u64,
        fd_blk: File,
        sector_len: u32,
        bank_width: u32,
        device_width: u32,
        read_only: i32,
    ) -> Result<Self> {
        if sector_len == 0 {
            bail!("attribute \"sector-length\" is zero.");
        }
        let nb_blocs: u32 = size as u32 / sector_len;
        if nb_blocs == 0 {
            bail!("attribute \"num-blocks\" is zero.");
        }

        let max_device_width: u32 = device_width;
        let write_cycle: i32 = 0;
        let cmd: u8 = 0;
        let status: u8 = 0x80;
        let mut cfi_table: [u8; 0x52] = [0; 0x52];
        let counter: u32 = 0;
        let mut write_block_size: u32;
        let blk_size = fd_blk.metadata().unwrap().len();
        if blk_size < size {
            bail!(
                "PFlash requires {} bytes, given file provides {} bytes",
                size,
                blk_size
            );
        }

        let num_devices: u32 = if device_width == 0 {
            1
        } else {
            bank_width / device_width
        };

        let blocks_per_device: u32 = nb_blocs;
        let sector_len_per_device: u32 = sector_len / num_devices;
        let device_len: u32 = sector_len_per_device * blocks_per_device;

        // Standard "QRY" string
        cfi_table[0x10] = b'Q';
        cfi_table[0x11] = b'R';
        cfi_table[0x12] = b'Y';
        // Command set (Intel)
        cfi_table[0x13] = 0x01;
        cfi_table[0x14] = 0x00;
        // Primary extended table address (none)
        cfi_table[0x15] = 0x31;
        cfi_table[0x16] = 0x00;
        // Alternate command set (none)
        cfi_table[0x17] = 0x00;
        cfi_table[0x18] = 0x00;
        // Alternate extended table (none)
        cfi_table[0x19] = 0x00;
        cfi_table[0x1A] = 0x00;
        // Vcc min
        cfi_table[0x1B] = 0x45;
        // Vcc max
        cfi_table[0x1C] = 0x55;
        // Vpp min (no Vpp pin)
        cfi_table[0x1D] = 0x00;
        // Vpp max (no Vpp pin)
        cfi_table[0x1E] = 0x00;
        // Reserved
        cfi_table[0x1F] = 0x07;
        // Timeout for min size buffer write
        cfi_table[0x20] = 0x07;
        // Typical timeout for block erase
        cfi_table[0x21] = 0x0a;
        // Typical timeout for full chip erase (4096 ms)
        cfi_table[0x22] = 0x00;
        // Reserved
        cfi_table[0x23] = 0x04;
        // Max timeout for buffer write
        cfi_table[0x24] = 0x04;
        // Max timeout for block erase
        cfi_table[0x25] = 0x04;
        // Max timeout for chip erase
        cfi_table[0x26] = 0x00;
        // Device size
        cfi_table[0x27] = device_len.trailing_zeros() as u8;
        // Flash device interface (8 & 16 bits)
        cfi_table[0x28] = 0x02;
        cfi_table[0x29] = 0x00;
        // Max number of bytes in multi-bytes write
        cfi_table[0x2A] = if bank_width == 1 { 0x08 } else { 0x0B };

        write_block_size = 1 << cfi_table[0x2A];
        if num_devices > 1 {
            write_block_size *= num_devices;
        }

        cfi_table[0x2B] = 0x00;
        // Number of erase block regions (uniform)
        cfi_table[0x2C] = 0x01;
        // Erase block region 1
        cfi_table[0x2D] = (blocks_per_device - 1) as u8;
        cfi_table[0x2E] = ((blocks_per_device - 1) >> 8) as u8;
        cfi_table[0x2F] = (sector_len_per_device >> 8) as u8;
        cfi_table[0x30] = (sector_len_per_device >> 16) as u8;

        // Extended
        cfi_table[0x31] = b'P';
        cfi_table[0x32] = b'R';
        cfi_table[0x33] = b'I';

        cfi_table[0x34] = b'1';
        cfi_table[0x35] = b'0';

        // Number of protection fields
        cfi_table[0x3f] = 0x01;

        Ok(PFlash {
            fd_blk,
            sector_len,
            bank_width,
            ident0: 0x89,
            ident1: 0x18,
            ident2: 0x00,
            ident3: 0x00,
            blk_num: nb_blocs,
            device_width,
            max_device_width,
            write_cycle,
            read_only,
            cmd,
            status,
            cfi_table,
            counter,
            write_blk_size: write_block_size,
            rom: None,
            res: SysRes::default(),
        })
    }
}
