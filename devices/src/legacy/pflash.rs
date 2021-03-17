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
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use address_space::{GuestAddress, Region};
use byteorder::{ByteOrder, LittleEndian};
use error_chain::ChainedError;
use kvm_ioctls::VmFd;
use sysbus::{errors::Result as SysBusResult, SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::num_ops::{deposit_u32, extract_u32};

use super::errors::{ErrorKind, Result};

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

    fn set_mem(&mut self, rom_region: Option<Arc<Region>>) -> Result<bool> {
        let flash_size = self.blk_num * self.sector_len;
        let blk_size = self.fd_blk.metadata().unwrap().len();

        let mut blk_content = vec![0_u8; blk_size as usize];
        self.fd_blk.read_exact(&mut blk_content)?;

        let host_addr = rom_region
            .as_ref()
            .unwrap()
            .get_host_address()
            .ok_or_else(|| "Failed to get host address")?;
        // Safe because host_addr of the region is allocated and flash_size is limited
        let mut dst =
            unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, flash_size as usize) };
        dst.write_all(&blk_content)?;

        self.rom = rom_region;
        Ok(true)
    }

    fn set_read_only_mode(&mut self) {
        if self
            .rom
            .as_ref()
            .unwrap()
            .set_rom_device_romd(true)
            .is_err()
        {
            error!("Failed to set to read only mode.");
        }
        self.write_cycle = 0;
        self.cmd = 0x00;
    }

    fn set_read_only_mode_with_error(&mut self) {
        if self
            .rom
            .as_ref()
            .unwrap()
            .set_rom_device_romd(true)
            .is_err()
        {
            error!("Failed to set pflash device to read only mode.");
        }

        self.write_cycle = 0;
        self.cmd = 0x00;

        error!(
            "Unimplemented flash cmd sequence (write cycle: 0x{:X}, cmd: 0x{:X})",
            self.write_cycle, self.cmd
        );
    }

    // Query device id according to the bank width of flash device
    fn query_devid(&mut self, offset: u64) -> Result<u32> {
        let mut resp: u32;
        let boff: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        // Mask off upper bits which may be used in to query block
        // or sector lock status at other addresses.
        // Offsets 2/3 are block lock status which is not emulated.
        match boff & 0xFF {
            0 => {
                resp = self.ident0;
            }
            1 => {
                resp = self.ident1;
            }
            _ => {
                return Ok(0);
            }
        }
        // Replicate responses for each device in bank.
        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .ok_or_else(|| "Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    // Query CFI according to the bank width of the flash device
    fn query_cfi(&mut self, offset: u64) -> Result<u32> {
        let mut resp: u32;
        // Adjust offset to match expected device-width addressing
        let boff: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        if boff >= self.cfi_table.len() as u64 {
            return Ok(0);
        }

        resp = self.cfi_table[boff as usize].into();
        if self.device_width != self.max_device_width {
            // The only case currently supported is x8 mode for a wider part
            if self.device_width != 1 || self.bank_width > 4 {
                error!("Unsupported device configuration");
                return Ok(0);
            }
            // CFI query data is repeated for wide devices used in x8 mode
            for i in 1..self.max_device_width {
                resp = deposit_u32(resp, 8 * i as u32, 8, self.cfi_table[boff as usize] as u32)
                    .ok_or_else(|| "Failed to deposit bits to u32")?;
            }
        }
        // Replicate responses for each device in bank.
        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .ok_or_else(|| "Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    // Update content of flash device to fd_blk in the disk
    fn content_update(&mut self, offset: u64, size: u32) -> Result<()> {
        if offset + size as u64 >= (self.blk_num * self.sector_len) as u64 {
            return Err(ErrorKind::FlashWriteOverflow.into());
        }

        let host_addr = self
            .rom
            .as_ref()
            .unwrap()
            .get_host_address()
            .ok_or_else(|| "Failed to get host address.")?;
        // Safe because host_addr of the region is allocated and sanity has been checked
        let src = unsafe {
            std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, size as usize)
        };

        self.fd_blk.seek(SeekFrom::Start(offset))?;
        self.fd_blk.write_all(src)?;
        Ok(())
    }

    fn read_data(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> Result<bool> {
        if offset >= data.len() as u64 {
            return Err(ErrorKind::FlashReadOverflow.into());
        }

        match &self.rom {
            Some(mr) => {
                if let Some(host_addr) = mr.get_host_address() {
                    // Safe because host_addr of the region is local allocated and sanity has been checked
                    let src = unsafe {
                        std::slice::from_raw_parts_mut(
                            (host_addr + offset) as *mut u8,
                            data.len() as usize,
                        )
                    };
                    data.as_mut().write_all(&src)?;
                }
            }
            None => {
                error!("No memory region available for read");
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn write_data(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> Result<bool> {
        if offset >= data.len() as u64 {
            return Err(ErrorKind::FlashWriteOverflow.into());
        }

        match &self.rom {
            Some(mr) => {
                if let Some(host_addr) = mr.get_host_address() {
                    // Safe because host_addr of the region is local allocated and sanity has been checked
                    let mut dst = unsafe {
                        std::slice::from_raw_parts_mut(
                            (host_addr + offset) as *mut u8,
                            data.len() as usize,
                        )
                    };
                    dst.write_all(&data)?;
                }
            }
            None => {
                error!("No memory region available for write");
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl SysBusDevOps for PFlash {
    fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool {
        let mut boff: u64;
        let mut ret: u32 = 0;
        let width: u32 = data.len() as u32;

        match self.cmd {
            0x00 => {
                if self.read_data(data, base, offset).is_err() {
                    error!("Faild to read data from pflash.");
                }
            }
            0x10 | 0x20 | 0x28 | 0x40 | 0x50 | 0x60 | 0x70 | 0xe8 => {
                // 0x10: Single byte program
                // 0x20: Block erase
                // 0x28: Block erase
                // 0x40: single byte program
                // 0x50: Clear status register
                // 0x60: Block / unBlock
                // 0x70: Status Register
                // 0xe8: Write block
                ret = self.status as u32;
                if self.device_width != 0 && width > self.device_width {
                    let mut shift: u32 = self.device_width * 8;
                    while shift + self.device_width * 8 <= width * 8 {
                        ret |= (self.status as u32) << shift;
                        shift += self.device_width * 8;
                    }
                } else if self.device_width == 0 && width > 2 {
                    ret |= (self.status as u32) << 16;
                }
            }
            0x90 => {
                if self.device_width == 0 {
                    // Preserve old behavior if device width not specified
                    boff = offset & 0xFF;
                    if self.bank_width == 2 {
                        boff >>= 1;
                    } else if self.bank_width == 4 {
                        boff >>= 2;
                    }

                    match boff {
                        0 => ret = self.ident0 << 8 | self.ident1,
                        1 => ret = self.ident2 << 8 | self.ident3,
                        _ => ret = 0,
                    }
                } else {
                    // If we have a read larger than the bank_width, combine multiple
                    // manufacturer/device ID queries into a single response.
                    let mut i: u32 = 0;
                    while i < width {
                        match self.query_devid(offset + (i * self.bank_width) as u64) {
                            Err(e) => {
                                error!("Failed to query devid {}.", e.display_chain());
                                break;
                            }
                            Ok(fieldval) => {
                                if let Some(v) =
                                    deposit_u32(ret, i * 8, self.bank_width * 8, fieldval)
                                {
                                    ret = v;
                                } else {
                                    error!(
                                        "Failed to fill result of query_cfi to return u32 value"
                                    );
                                    break;
                                }
                            }
                        };

                        i += self.bank_width;
                    }
                }
            }
            0x98 => {
                // Query mode
                if self.device_width == 0 {
                    boff = offset & 0xFF;
                    if self.bank_width == 2 {
                        boff >>= 1;
                    } else if self.bank_width == 4 {
                        boff >>= 2;
                    }

                    if boff < self.cfi_table.len() as u64 {
                        ret = self.cfi_table[boff as usize].into();
                    } else {
                        ret = 0;
                    }
                } else {
                    let mut i: u32 = 0;
                    while i < width {
                        match self.query_cfi(offset + (i * self.bank_width) as u64) {
                            Err(_e) => {
                                error!("Failed to query devid.");
                                break;
                            }
                            Ok(fieldval) => {
                                if let Some(v) =
                                    deposit_u32(ret, i * 8, self.bank_width * 8, fieldval)
                                {
                                    ret = v;
                                } else {
                                    error!(
                                        "Failed to fill result of query_cfi to return u32 value"
                                    );
                                    break;
                                }
                            }
                        };

                        i += self.bank_width;
                    }
                }
            }
            _ => {
                // This should never happen : reset state & treat it as a read
                error!("PFlash read: unknown command state 0x{:X}", self.cmd);
                self.write_cycle = 0;
                self.cmd = 0x00;
                if self.read_data(data, base, offset).is_err() {
                    error!("Faild to read data from pflash.");
                }
            }
        }

        match data.len() {
            1 => data[0] = ret as u8,
            2 => LittleEndian::write_u16(data, ret as u16),
            4 => LittleEndian::write_u32(data, ret),
            n => {
                error!("Invalid data length {}", n);
                return false;
            }
        }

        true
    }

    fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool {
        let mut value: u32 = LittleEndian::read_u32(data);
        let cmd: u8 = data[0];
        let width: u8 = data.len() as u8;

        if self.write_cycle == 0 {
            // Set the device in I/O access mode
            if self
                .rom
                .as_ref()
                .unwrap()
                .set_rom_device_romd(false)
                .is_err()
            {
                error!("Failed flash to set device to read only mode.");
            }
        }

        match self.write_cycle {
            0 => {
                // read mode
                match cmd {
                    0x00 => {
                        // This model reset value for READ_ARRAY (not CFI)
                        self.set_read_only_mode();
                        return true;
                    }
                    0x10 | 0x40 => {
                        debug!("PFlash write: Single Byte Program");
                    }
                    0x20 => {
                        // Block erase
                        let offset_temp = offset & !(self.sector_len as u64 - 1);
                        if self.read_only == 0 {
                            let all_one = vec![0xff_u8; self.sector_len as usize];
                            if self
                                .write_data(all_one.as_slice(), base, offset_temp)
                                .is_err()
                            {
                                error!("Failed to write pflash device.");
                            }

                            if self.content_update(offset_temp, self.sector_len).is_err() {
                                error!("Failed to update content for pflash device.");
                            }
                        } else {
                            // Block erase error
                            self.status |= 0x20;
                        }
                        // Ready!
                        self.status |= 0x80;
                    }
                    0x50 => {
                        // Clear status bits
                        self.status = 0x0;
                        self.set_read_only_mode();
                        return true;
                    }
                    0x60 => {
                        debug!("PFlash write: Block unlock");
                    }
                    0x70 | 0x90 => {
                        // 0x70: Status Register, 0x90: Read Device ID
                        self.cmd = cmd;
                        return true;
                    }
                    0x98 => {
                        debug!("PFlash write: CFI query");
                    }
                    0xe8 => {
                        // Write to buffer
                        self.status |= 0x80;
                    }
                    0xf0 | 0xff => {
                        // 0xf0 cmd is probe for AMD flash
                        self.set_read_only_mode();
                        return true;
                    }
                    _ => {
                        self.set_read_only_mode_with_error();
                        return true;
                    }
                }
                self.write_cycle += 1;
                self.cmd = cmd;
            }
            1 => {
                match self.cmd {
                    0x10 | 0x40 => {
                        // Write single byte program
                        if self.read_only == 0 {
                            if self.write_data(&data, base, offset).is_err() {
                                error!("Failed to write to pflash device.");
                            }

                            if self.content_update(offset, width.into()).is_err() {
                                error!("Failed to update content for pflash device.");
                            }
                        } else {
                            // Programming error
                            self.status |= 0x10;
                        }
                        self.status |= 0x80;
                        self.write_cycle = 0;
                    }
                    0x20 | 0x28 => {
                        // Block erase
                        if cmd == 0xd0 {
                            self.write_cycle = 0;
                            self.status |= 0x80;
                        } else if cmd == 0xff {
                            self.set_read_only_mode();
                            return true;
                        } else {
                            self.set_read_only_mode_with_error();
                            return true;
                        }
                    }
                    0xe8 => {
                        // If device width is not specified, mask writeblock size based on bank width
                        let length: u32 = if self.device_width != 0 {
                            self.device_width * 8
                        } else {
                            self.bank_width * 8
                        };
                        value = if let Some(v) = extract_u32(value, 0, length) {
                            v
                        } else {
                            error!("Failed to extract bits from u32 value");
                            return false;
                        };
                        self.counter = value;
                        self.write_cycle += 1;
                    }
                    0x60 => {
                        if (cmd == 0xd0) || (cmd == 0x01) {
                            self.write_cycle = 0;
                            self.status |= 0x80;
                        } else if cmd == 0xff {
                            self.set_read_only_mode_with_error();
                            return true;
                        } else {
                            debug!("PFlash write: Unknown (un)locking command");
                            self.set_read_only_mode();
                            return true;
                        }
                    }
                    0x98 => {
                        if cmd == 0xff {
                            self.set_read_only_mode();
                            return true;
                        }
                    }
                    _ => {
                        self.set_read_only_mode_with_error();
                        return true;
                    }
                }
            }
            2 => {
                match self.cmd {
                    0xe8 => {
                        // Block write
                        if self.read_only == 0 {
                            if self.write_data(&data, base, offset).is_err() {
                                error!("Failed to write to plfash device.");
                            }
                        } else {
                            self.status |= 0x10;
                        }
                        self.status |= 0x80;
                        if self.counter == 0 {
                            let mut mask: u64 = self.write_blk_size as u64 - 1;
                            mask = !mask;
                            self.write_cycle += 1;
                            if self.read_only == 0 {
                                // Flush the entire write buffer onto backing storage.

                                if self
                                    .content_update(offset & mask, self.write_blk_size)
                                    .is_err()
                                {
                                    error!("Failed to update content for pflash device.");
                                }
                            } else {
                                self.status |= 0x10;
                            }
                        }
                        if self.counter != 0 {
                            self.counter -= 1;
                        }
                    }
                    _ => {
                        self.set_read_only_mode_with_error();
                        return true;
                    }
                }
            }
            3 => {
                // Confirm mode
                match self.cmd {
                    0xe8 => {
                        if cmd == 0xd0 {
                            self.write_cycle = 0;
                            self.status |= 0x80;
                        } else {
                            self.set_read_only_mode();
                            return true;
                        }
                    }
                    _ => {
                        self.set_read_only_mode_with_error();
                        return true;
                    }
                }
            }
            _ => {
                // Should never happen
                error!(
                    "PFlash write: invalid write state: write cycle {}",
                    self.write_cycle
                );
                self.set_read_only_mode();
                return false;
            }
        }
        true
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        _vm_fd: &VmFd,
    ) -> SysBusResult<()> {
        let mut res = self.get_sys_resource().unwrap();
        res.region_base = region_base;
        res.region_size = region_size;
        res.irq = 0;
        Ok(())
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::Flash
    }
}
