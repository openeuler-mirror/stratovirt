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
use std::sync::{Arc, Mutex};

use acpi::AmlBuilder;
use address_space::{GuestAddress, HostMemMapping, Region};
use byteorder::{ByteOrder, LittleEndian};
use error_chain::ChainedError;
use sysbus::{errors::Result as SysBusResult, SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::num_ops::{deposit_u32, extract_u32};

use super::errors::{ErrorKind, Result, ResultExt};

/// PFlash structure
pub struct PFlash {
    /// File to save data in PFlash ROM
    fd_blk: File,
    /// Number of blocks
    blk_num: u32,
    /// Length of block
    block_len: u32,
    /// Indicator of byte or bit
    bank_width: u32,
    /// If 0, device width not specified
    device_width: u32,
    /// Max device width in bytes
    max_device_width: u32,
    /// If 0, the flash is read normally
    write_cycle: i32,
    /// Pflash is read only or not
    read_only: bool,
    /// Command to control pflash
    cmd: u8,
    /// Pflash status
    status: u8,
    /// Pflash ID
    ident: [u32; 0x4],
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
        block_len: u32,
        bank_width: u32,
        device_width: u32,
        read_only: bool,
    ) -> Result<Self> {
        if block_len == 0 {
            bail!("Flash: block-length is zero which is invalid.");
        }
        let blocks_per_device: u32 = size as u32 / block_len;
        if blocks_per_device == 0 {
            bail!("Flash: num-blocks is zero which is invalid.");
        }

        let file_size = fd_blk.metadata().unwrap().len();
        if file_size < size {
            bail!(
                "Flash requires 0x{:X} bytes, given file provides 0x{:X} bytes",
                size,
                file_size
            );
        }

        let num_devices: u32 = if device_width == 0 {
            1
        } else {
            bank_width / device_width
        };
        let block_len_per_device: u32 = block_len / num_devices;
        let device_len: u32 = block_len_per_device * blocks_per_device;

        let mut cfi_table: [u8; 0x52] = [0; 0x52];
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
        // Vcc min
        cfi_table[0x1B] = 0x45;
        // Vcc max
        cfi_table[0x1C] = 0x55;
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
        cfi_table[0x2B] = 0x00;

        let mut write_blk_size: u32 = 1 << cfi_table[0x2A];
        if num_devices > 1 {
            write_blk_size *= num_devices;
        }

        // Number of erase block regions (uniform)
        cfi_table[0x2C] = 0x01;
        // Erase block region 1
        cfi_table[0x2D] = (blocks_per_device - 1) as u8;
        cfi_table[0x2E] = ((blocks_per_device - 1) >> 8) as u8;
        cfi_table[0x2F] = (block_len_per_device >> 8) as u8;
        cfi_table[0x30] = (block_len_per_device >> 16) as u8;

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
            block_len,
            bank_width,
            // device id for Intel flash.
            ident: [0x89, 0x18, 0x00, 0x00],
            blk_num: blocks_per_device,
            device_width,
            max_device_width: device_width,
            write_cycle: 0,
            read_only,
            cmd: 0,
            status: 0x80,
            cfi_table,
            counter: 0,
            write_blk_size,
            rom: None,
            res: SysRes::default(),
        })
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        self.set_sys_resource(sysbus, region_base, region_size)
            .chain_err(|| "Failed to allocate system resource for PFlash.")?;

        let dev = Arc::new(Mutex::new(self));
        let region_ops = sysbus.build_region_ops(&dev);
        let mem_mapping =
            HostMemMapping::new(GuestAddress(region_base), region_size, None, false, false)
                .chain_err(|| "Failed to create HostMemMapping for PFlash {}.")?;

        let mem_mapping = Arc::new(mem_mapping);
        let rom_region = Region::init_rom_device_region(mem_mapping, region_ops);

        sysbus
            .sys_mem
            .root()
            .add_subregion(rom_region.clone(), region_base)
            .chain_err(|| "Failed to attach PFlash to system bus")?;
        dev.lock().unwrap().set_rom_mem(Arc::new(rom_region))?;
        sysbus.devices.push(dev);

        Ok(())
    }

    fn set_rom_mem(&mut self, rom_region: Arc<Region>) -> Result<()> {
        let flash_size = self.blk_num * self.block_len;
        let file_size = self.fd_blk.metadata().unwrap().len();

        let mut file_content = vec![0_u8; file_size as usize];
        self.fd_blk
            .read_exact(&mut file_content)
            .chain_err(|| "Failed to read fd_blk of Flash device")?;

        let host_addr = rom_region.get_host_address().unwrap();

        // Safe because host_addr of the region is allocated and flash_size is limited.
        let mut dst =
            unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, flash_size as usize) };
        dst.write_all(&file_content)
            .chain_err(|| ErrorKind::WritePFlashRomErr)?;
        self.rom = Some(rom_region);

        Ok(())
    }

    fn set_read_array_mode(&mut self, is_illegal_cmd: bool) -> Result<()> {
        self.rom
            .as_ref()
            .unwrap()
            .set_rom_device_romd(true)
            .chain_err(|| "Failed to set to read only mode.")?;
        self.write_cycle = 0;
        self.cmd = 0x00;

        if is_illegal_cmd {
            warn!(
                "Unimplemented flash cmd sequence (write cycle: 0x{:X}, cmd: 0x{:X})",
                self.write_cycle, self.cmd
            );
        }

        Ok(())
    }

    // Query device id according to the bank width of flash device
    fn query_devid(&mut self, offset: u64) -> Result<u32> {
        let mut resp: u32;
        let index: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        // Mask off upper bits which may be used in to query block
        // or sector lock status at other addresses.
        // Offsets 2/3 are block lock status which is not emulated.
        match index & 0xFF {
            0 => {
                resp = self.ident[0];
            }
            1 => {
                resp = self.ident[1];
            }
            _ => {
                bail!("Device ID 2 and 3 are not supported");
            }
        }
        // Replicate responses for each device in bank.
        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .ok_or("Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    // Query CFI according to the bank width of the flash device
    fn query_cfi(&mut self, offset: u64) -> Result<u32> {
        let mut resp: u32;
        // Adjust index for expected device-width addressing.
        let index: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        if index >= self.cfi_table.len() as u64 {
            return Err(ErrorKind::PFlashIndexOverflow(index, self.cfi_table.len()).into());
        }

        resp = self.cfi_table[index as usize].into();
        if self.device_width != self.max_device_width {
            // The only case currently supported is x8 mode for a wider part
            if self.device_width != 1 || self.bank_width > 4 {
                return Err(
                    ErrorKind::PFlashDevConfigErr(self.device_width, self.bank_width).into(),
                );
            }
            // CFI query data is repeated for wide devices used in x8 mode
            for i in 1..self.max_device_width {
                resp = deposit_u32(resp, 8 * i as u32, 8, self.cfi_table[index as usize] as u32)
                    .ok_or("Failed to deposit bits to u32")?;
            }
        }
        // Replicate responses for each device in bank.
        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .ok_or("Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    // Update content of flash device to fd_blk in the disk
    fn update_content(&mut self, offset: u64, size: u32) -> Result<()> {
        // After realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + size as u64 > mr.size() as u64 {
            return Err(
                ErrorKind::PFlashWriteOverflow(mr.size() as u64, offset, size as u64).into(),
            );
        }

        let host_addr = self.rom.as_ref().unwrap().get_host_address().unwrap();
        // Safe because host_addr of the region is allocated and sanity has been checked
        let src = unsafe {
            std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, size as usize)
        };

        self.fd_blk
            .seek(SeekFrom::Start(offset))
            .chain_err(|| ErrorKind::PFlashFileSeekErr(offset))?;
        self.fd_blk
            .write_all(src)
            .chain_err(|| "Failed to update content of Flash Rom to fd_blk")?;
        Ok(())
    }

    fn read_data(&mut self, data: &mut [u8], offset: u64) -> Result<()> {
        // After realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + data.len() as u64 > mr.size() as u64 {
            return Err(ErrorKind::PFlashReadOverflow(mr.size(), offset, data.len() as u64).into());
        }
        let host_addr = mr.get_host_address().unwrap();
        // Safe because host_addr of the region is local allocated and sanity has been checked
        let src = unsafe {
            std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, data.len() as usize)
        };
        data.as_mut()
            .write_all(&src)
            .chain_err(|| "Failed to read data from Flash Rom")?;

        Ok(())
    }

    fn write_data(&mut self, data: &[u8], offset: u64) -> Result<()> {
        // After realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + data.len() as u64 > mr.size() as u64 {
            return Err(
                ErrorKind::PFlashWriteOverflow(mr.size(), offset, data.len() as u64).into(),
            );
        }
        let host_addr = mr.get_host_address().unwrap();
        // Safe because host_addr of the region is local allocated and sanity has been checked
        let mut dst = unsafe {
            std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, data.len() as usize)
        };
        dst.write_all(&data)
            .chain_err(|| "Failed to write data to Flash Rom")?;

        Ok(())
    }

    fn handle_write_first_pass(&mut self, cmd: u8, offset: u64) -> bool {
        match cmd {
            // 0xf0 cmd is match for AMD flash.
            0x00 | 0xf0 | 0xff => {
                if let Err(e) = self.set_read_array_mode(false) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {}",
                        cmd,
                        e.display_chain()
                    );
                    return false;
                }
                return true;
            }
            0x10 | 0x40 => {
                debug!("PFlash write: Single Byte Program");
            }
            0x20 => {
                // Block erase
                let offset_mask = offset & !(self.block_len as u64 - 1);
                if !self.read_only {
                    let all_one = vec![0xff_u8; self.block_len as usize];
                    if let Err(e) = self.write_data(all_one.as_slice(), offset_mask) {
                        error!("Failed to write pflash device: {}.", e.display_chain());
                    }

                    if let Err(e) = self.update_content(offset_mask, self.block_len) {
                        error!(
                            "Failed to update content for pflash device: {}.",
                            e.display_chain()
                        );
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
                if let Err(e) = self.set_read_array_mode(false) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {}",
                        cmd,
                        e.display_chain()
                    );
                    return false;
                }
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
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {}",
                        cmd,
                        e.display_chain()
                    );
                    return false;
                }
                return true;
            }
        }
        self.write_cycle += 1;
        self.cmd = cmd;
        true
    }

    fn handle_write_second_pass(
        &mut self,
        cmd: u8,
        offset: u64,
        data: &[u8],
        data_len: u8,
        mut value: u32,
    ) -> bool {
        match self.cmd {
            0x10 | 0x40 => {
                // Write single byte program
                if !self.read_only {
                    if let Err(e) = self.write_data(&data, offset) {
                        error!("Failed to write to pflash device: {}.", e.display_chain());
                    }

                    if let Err(e) = self.update_content(offset, data_len.into()) {
                        error!(
                            "Failed to update content for pflash device: {}.",
                            e.display_chain()
                        );
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
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            cmd,
                            e.display_chain()
                        );
                        return false;
                    }
                    return true;
                } else {
                    if let Err(e) = self.set_read_array_mode(true) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            self.cmd,
                            e.display_chain()
                        );
                        return false;
                    }
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
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            self.cmd,
                            e.display_chain()
                        );
                        return false;
                    }
                    return true;
                } else {
                    if let Err(e) = self.set_read_array_mode(true) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            self.cmd,
                            e.display_chain()
                        );
                        return false;
                    }
                    return true;
                }
            }
            0x98 => {
                if cmd == 0xff {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            self.cmd,
                            e.display_chain()
                        );
                        return false;
                    }
                    return true;
                }
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                        self.cmd,
                        e.display_chain()
                    );
                    return false;
                }
                return true;
            }
        }
        true
    }

    fn handle_write_third_pass(&mut self, offset: u64, data: &[u8]) -> bool {
        match self.cmd {
            0xe8 => {
                // Block write
                if !self.read_only {
                    if let Err(e) = self.write_data(&data, offset) {
                        error!("Failed to write to pflash device: {}.", e.display_chain());
                    }
                } else {
                    self.status |= 0x10;
                }
                self.status |= 0x80;
                if self.counter == 0 {
                    let mask: u64 = !(self.write_blk_size as u64 - 1);
                    self.write_cycle += 1;
                    if !self.read_only {
                        // Flush the entire write buffer onto backing storage.
                        if let Err(e) = self.update_content(offset & mask, self.write_blk_size) {
                            error!(
                                "Failed to update content for pflash device: {}.",
                                e.display_chain()
                            );
                        }
                    } else {
                        self.status |= 0x10;
                    }
                } else {
                    self.counter -= 1;
                }
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 2, cmd 0x{:x}, error is {}",
                        self.cmd,
                        e.display_chain()
                    );
                    return false;
                }
                return true;
            }
        }
        true
    }

    fn handle_write_fourth_pass(&mut self, cmd: u8) -> bool {
        match self.cmd {
            // Confirm mode
            0xe8 => {
                if cmd == 0xd0 {
                    self.write_cycle = 0;
                    self.status |= 0x80;
                } else {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!(
                            "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                            self.cmd,
                            e.display_chain()
                        );
                        return false;
                    }
                    return true;
                }
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {}",
                        self.cmd,
                        e.display_chain()
                    );
                    return false;
                }
                return true;
            }
        }
        true
    }
}

impl SysBusDevOps for PFlash {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let mut index: u64;
        let mut ret: u32 = 0;
        let data_len: u32 = data.len() as u32;

        match self.cmd {
            0x00 => {
                if self.read_data(data, offset).is_err() {
                    error!("Failed to read data from pflash.");
                }
                return true;
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
                if self.device_width != 0 && data_len > self.device_width {
                    let mut shift: u32 = self.device_width * 8;
                    while shift + self.device_width * 8 <= data_len * 8 {
                        ret |= (self.status as u32) << shift;
                        shift += self.device_width * 8;
                    }
                } else if self.device_width == 0 && data_len > 2 {
                    ret |= (self.status as u32) << 16;
                }
            }
            0x90 => {
                if self.device_width == 0 {
                    // Preserve old behavior if device width not specified
                    index = offset & 0xFF;
                    if self.bank_width == 2 {
                        index >>= 1;
                    } else if self.bank_width == 4 {
                        index >>= 2;
                    }

                    match index {
                        0 => ret = self.ident[0] << 8 | self.ident[1],
                        1 => ret = self.ident[2] << 8 | self.ident[3],
                        _ => ret = 0,
                    }
                } else {
                    // If we have a read larger than the bank_width, combine multiple
                    // manufacturer/device ID queries into a single response.
                    let mut i: u32 = 0;
                    while i < data_len {
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
                                        "Failed to fill result of query_devid to return u32 value"
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
                    index = offset & 0xFF;
                    if self.bank_width == 2 {
                        index >>= 1;
                    } else if self.bank_width == 4 {
                        index >>= 2;
                    }

                    if index < self.cfi_table.len() as u64 {
                        ret = self.cfi_table[index as usize].into();
                    } else {
                        ret = 0;
                    }
                } else {
                    let mut i: u32 = 0;
                    while i < data_len {
                        match self.query_cfi(offset + (i * self.bank_width) as u64) {
                            Err(e) => {
                                error!("Failed to query devid, {}.", e);
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
                if let Err(e) = self.read_data(data, offset) {
                    error!("Failed to read data from pflash: {}.", e.display_chain());
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

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let value: u32 = match data.len() {
            1 => data[0] as u32,
            2 => LittleEndian::read_u16(data).into(),
            4 => LittleEndian::read_u32(data),
            n => {
                error!("Invalid data length {}", n);
                return false;
            }
        };
        let cmd: u8 = data[0];
        let data_len: u8 = data.len() as u8;

        if self.write_cycle == 0
            && self
                .rom
                .as_ref()
                .unwrap()
                .set_rom_device_romd(false)
                .is_err()
        {
            error!("Failed flash to set device to read only mode.");
        }

        match self.write_cycle {
            0 => self.handle_write_first_pass(cmd, offset),
            1 => self.handle_write_second_pass(cmd, offset, data, data_len, value),
            2 => self.handle_write_third_pass(offset, data),
            3 => self.handle_write_fourth_pass(cmd),
            _ => {
                // Should never happen
                error!(
                    "PFlash write: invalid write state: write cycle {}",
                    self.write_cycle
                );
                if let Err(e) = self.set_read_array_mode(false) {
                    error!(
                        "Failed to set pflash to read array mode, error is {}",
                        e.display_chain()
                    );
                }
                false
            }
        }
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
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

impl AmlBuilder for PFlash {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}
