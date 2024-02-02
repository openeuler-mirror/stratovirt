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
use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use log::{error, warn};

use super::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType, SysRes};
use crate::{Device, DeviceBase};
use acpi::AmlBuilder;
use address_space::{FileBackend, GuestAddress, HostMemMapping, Region};
use util::num_ops::{deposit_u32, extract_u32, read_data_u32, write_data_u32};

pub struct PFlash {
    base: SysBusDevBase,
    /// Has backend file or not.
    has_backend: bool,
    /// Length of block.
    block_len: u32,
    /// The width of PFlash array for vm.
    bank_width: u32,
    /// The width of single PFlash device.
    /// If 0, device width is not specified.
    device_width: u32,
    /// Max device width of single PFlash device.
    /// This is used to support x16 wide PFlash run in x8 mode.
    max_device_width: u32,
    /// If 0, the PFlash is read normally.
    write_cycle: u32,
    /// PFlash is read only or not.
    read_only: bool,
    /// Command to control PFlash.
    cmd: u8,
    /// PFlash status.
    status: u8,
    /// PFlash IDs.
    ident: [u32; 0x4],
    /// Hardcoded information of PFlash device.
    cfi_table: [u8; 0x52],
    /// Counter for writing block.
    counter: u32,
    /// Width of write block request.
    write_blk_size: u32,
    /// ROM region of PFlash.
    rom: Option<Region>,
}

impl PFlash {
    /// Construct function of PFlash device.
    ///
    /// # Arguments
    ///
    /// * `size` - PFlash device size.
    /// * `backend` - Backend file.
    /// * `block_len` - The length of block in PFlash device.
    /// * `bank_width` - The width of PFlash array which contains this PFlash device.
    /// * `device_width` - The width of this PFlash device.
    /// * `read_only` - This PFlash device is read only or not.
    ///
    /// # Errors
    ///
    /// Return Error when
    /// * block-length is zero.
    /// * PFlash size is zero.
    /// * file size is smaller than PFlash size.
    pub fn new(
        size: u64,
        backend: &Option<File>,
        block_len: u32,
        bank_width: u32,
        device_width: u32,
        read_only: bool,
    ) -> Result<Self> {
        if block_len == 0 {
            bail!("PFlash: block-length is zero which is invalid.");
        }
        let blocks_per_device: u32 = size as u32 / block_len;
        if blocks_per_device == 0 {
            bail!("PFlash: num-blocks is zero which is invalid.");
        }
        if let Some(fd) = backend.as_ref() {
            let len = fd.metadata().unwrap().len();
            if len > size || len == 0 || (!read_only && len != size) {
                bail!(
                    "Invalid flash file: Region size 0x{size:X}, file size 0x{len:X}; read_only {read_only}"
                );
            }
        }
        let num_devices: u32 = if device_width == 0 {
            1
        } else {
            bank_width / device_width
        };
        let block_len_per_device: u32 = block_len / num_devices;
        let device_len: u32 = block_len_per_device * blocks_per_device;

        let mut cfi_table: [u8; 0x52] = [0; 0x52];
        // Standard "QRY" string for CFI query.
        cfi_table[0x10] = b'Q';
        cfi_table[0x11] = b'R';
        cfi_table[0x12] = b'Y';
        // Primary vendor command set and control interface ID code (Intel).
        cfi_table[0x13] = 0x01;
        cfi_table[0x14] = 0x00;
        // Table address of primary algorithm for extended query.
        cfi_table[0x15] = 0x31;
        cfi_table[0x16] = 0x00;
        // Vcc logic supplies minimum program/erase voltage.
        cfi_table[0x1B] = 0x45;
        // Vcc logic supplies maximum program/erase voltage.
        cfi_table[0x1C] = 0x55;
        // Typical timeout per single byte/word write (buffer write count = 1), 2^n μs.
        cfi_table[0x1F] = 0x07;
        // Typical timeout for maximum-size buffer write, 2^n μs.
        cfi_table[0x20] = 0x07;
        // Typical timeout per individual block erase, 2^n ms.
        cfi_table[0x21] = 0x0a;
        // Typical timeout for full chip erase (not supported).
        cfi_table[0x22] = 0x00;
        // Maximum timeout for byte/word write, 2^n times typically.
        cfi_table[0x23] = 0x04;
        // Maximum timeout for buffer write, 2^n times typically.
        cfi_table[0x24] = 0x04;
        // Maximum timeout per individual block erase, 2^n times typically.
        cfi_table[0x25] = 0x04;
        // Maximum timeout for chip erase, 2n times typically (not supported).
        cfi_table[0x26] = 0x00;
        // Device size, 2^n in number of bytes.
        cfi_table[0x27] = device_len.trailing_zeros() as u8;
        // PFlash device interface description (8 & 16 bits).
        cfi_table[0x28] = 0x02;
        cfi_table[0x29] = 0x00;
        // Max number of bytes (2^n) in multi-bytes write.
        cfi_table[0x2A] = if bank_width == 1 { 0x08 } else { 0x0B };
        cfi_table[0x2B] = 0x00;

        let mut write_blk_size: u32 = 1 << cfi_table[0x2A];
        if num_devices > 1 {
            write_blk_size *= num_devices;
        }

        // Number of erase block regions within device (uniform).
        cfi_table[0x2C] = 0x01;
        // Information about block region erase.
        cfi_table[0x2D] = (blocks_per_device - 1) as u8;
        cfi_table[0x2E] = ((blocks_per_device - 1) >> 8) as u8;
        cfi_table[0x2F] = (block_len_per_device >> 8) as u8;
        cfi_table[0x30] = (block_len_per_device >> 16) as u8;

        // Primary extended query table, SCS not supported.
        cfi_table[0x31] = b'P';
        cfi_table[0x32] = b'R';
        cfi_table[0x33] = b'I';
        // Major version number.
        cfi_table[0x34] = b'1';
        // Minor version number.
        cfi_table[0x35] = b'0';
        // Number of protection fields.
        cfi_table[0x3f] = 0x01;

        Ok(PFlash {
            base: SysBusDevBase::new(SysBusDevType::Flash),
            has_backend: backend.is_some(),
            block_len,
            bank_width,
            // device id for Intel PFlash.
            ident: [0x89, 0x18, 0x00, 0x00],
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
        })
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        backend: Option<File>,
    ) -> Result<()> {
        self.set_sys_resource(sysbus, region_base, region_size)
            .with_context(|| "Failed to allocate system resource for PFlash.")?;

        let host_mmap = Arc::new(HostMemMapping::new(
            GuestAddress(region_base),
            None,
            region_size,
            backend.map(FileBackend::new_common),
            false,
            true,
            self.read_only,
        )?);

        let dev = Arc::new(Mutex::new(self));
        let region_ops = sysbus.build_region_ops(&dev);

        let rom_region = Region::init_rom_device_region(host_mmap, region_ops, "PflashRom");
        dev.lock().unwrap().rom = Some(rom_region.clone());
        sysbus
            .sys_mem
            .root()
            .add_subregion(rom_region, region_base)
            .with_context(|| "Failed to attach PFlash to system bus")?;
        sysbus.devices.push(dev);

        Ok(())
    }

    fn set_read_array_mode(&mut self, is_illegal_cmd: bool) -> Result<()> {
        if is_illegal_cmd {
            warn!(
                "Unimplemented PFlash cmd sequence (write cycle: 0x{:X}, cmd: 0x{:X})",
                self.write_cycle, self.cmd
            );
        }

        trace::pflash_mode_read_array();
        self.rom
            .as_ref()
            .unwrap()
            .set_rom_device_romd(true)
            .with_context(|| "Failed to set to read array mode.")?;
        self.write_cycle = 0;
        self.cmd = 0x00;

        Ok(())
    }

    fn query_devid(&mut self, offset: u64) -> Result<u32> {
        let index: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        // Mask off upper bits, the rest (ident[2] and ident[3]) is not emulated.
        let mut resp: u32 = match index & 0xFF {
            0 => {
                trace::pflash_manufacturer_id(self.ident[0]);
                self.ident[0]
            }
            1 => {
                trace::pflash_device_id(self.ident[1]);
                self.ident[1]
            }
            _ => {
                trace::pflash_device_info(index);
                return Ok(0);
            }
        };

        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .with_context(|| "Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    fn query_cfi(&mut self, offset: u64) -> Result<u32> {
        // Adjust index for expected device-width addressing.
        let index: u64 = offset
            >> (self.bank_width.trailing_zeros() + self.max_device_width.trailing_zeros()
                - self.device_width.trailing_zeros());

        if index >= self.cfi_table.len() as u64 {
            return Err(anyhow!(LegacyError::PFlashIndexOverflow(
                index,
                self.cfi_table.len()
            )));
        }

        let mut resp: u32 = self.cfi_table[index as usize].into();
        if self.device_width != self.max_device_width {
            if self.device_width != 1 || self.bank_width > 4 {
                return Err(anyhow!(LegacyError::PFlashDevConfigErr(
                    self.device_width,
                    self.bank_width
                )));
            }
            // Repeat data for PFlash device which supports x16-mode but works in x8-mode.
            for i in 1..self.max_device_width {
                resp = deposit_u32(resp, 8 * i, 8, self.cfi_table[index as usize] as u32)
                    .with_context(|| "Failed to deposit bits to u32")?;
            }
        }
        // Responses are repeated for every device in bank.
        if self.device_width < self.bank_width {
            let mut i: u32 = self.device_width;
            while i < self.bank_width {
                resp = deposit_u32(resp, 8 * i, 8 * self.device_width, resp)
                    .with_context(|| "Failed to deposit bits to u32")?;
                i += self.device_width;
            }
        }

        Ok(resp)
    }

    fn update_content(&mut self, offset: u64, size: u32) -> Result<()> {
        if !self.has_backend {
            return Ok(());
        }
        // Unwrap is safe, because after realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + size as u64 > mr.size() {
            return Err(anyhow!(LegacyError::PFlashWriteOverflow(
                mr.size(),
                offset,
                size as u64
            )));
        }

        let addr: u64 = mr
            .get_host_address()
            .with_context(|| "Failed to get host address.")?;
        let ret =
        // SAFETY: addr and size are valid.
        unsafe {
            libc::msync(
                addr as *mut libc::c_void,
                size as libc::size_t,
                libc::MS_SYNC,
            )
        };
        if ret != 0 {
            bail!("{}", std::io::Error::last_os_error());
        }

        Ok(())
    }

    fn read_data(&mut self, data: &mut [u8], offset: u64) -> Result<()> {
        // Unwrap is safe, because after realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + data.len() as u64 > mr.size() {
            return Err(anyhow!(LegacyError::PFlashReadOverflow(
                mr.size(),
                offset,
                data.len() as u64
            )));
        }
        let host_addr = mr.get_host_address().unwrap();
        let src =
            // SAFETY: host_addr of the region is local allocated and sanity has been checked.
            unsafe { std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, data.len()) };
        data.as_mut()
            .write_all(src)
            .with_context(|| "Failed to read data from PFlash Rom")?;
        trace::pflash_read_data(offset, data.len(), &data[..std::cmp::min(4, data.len())]);

        Ok(())
    }

    fn write_data(&mut self, data: &[u8], offset: u64) -> Result<()> {
        trace::pflash_write_data(
            offset,
            data.len(),
            &data[..std::cmp::min(4, data.len())],
            self.counter,
        );
        // Unwrap is safe, because after realize function, rom isn't none.
        let mr = self.rom.as_ref().unwrap();
        if offset + data.len() as u64 > mr.size() {
            return Err(anyhow!(LegacyError::PFlashWriteOverflow(
                mr.size(),
                offset,
                data.len() as u64
            )));
        }
        let host_addr = mr.get_host_address().unwrap();
        let mut dst =
            // SAFETY: host_addr of the region is local allocated and sanity has been checked.
            unsafe { std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, data.len()) };
        dst.write_all(data)
            .with_context(|| "Failed to write data to PFlash Rom")?;

        Ok(())
    }

    fn handle_write_first_pass(&mut self, cmd: u8, offset: u64) -> bool {
        match cmd {
            // cmd 0xf0 is for AMD PFlash.
            0x00 | 0xf0 | 0xff => {
                trace::pflash_write("read array mode".to_string(), cmd);
                if let Err(e) = self.set_read_array_mode(false) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {:?}",
                        cmd, e
                    );
                    return false;
                }
                return true;
            }
            0x10 | 0x40 => {
                trace::pflash_write("single byte program (0)".to_string(), cmd);
            }
            0x20 => {
                let offset_mask = offset & !(self.block_len as u64 - 1);
                trace::pflash_write_block_erase(offset, self.block_len);
                if !self.read_only {
                    let all_one = vec![0xff_u8; self.block_len as usize];
                    if let Err(e) = self.write_data(all_one.as_slice(), offset_mask) {
                        error!("Failed to write PFlash device: {:?}", e);
                    }

                    if let Err(e) = self.update_content(offset_mask, self.block_len) {
                        error!("Failed to update content for PFlash device: {:?}", e);
                    }
                } else {
                    // Block erase error.
                    self.status |= 0x20;
                }
                // Ready!
                self.status |= 0x80;
            }
            0x50 => {
                trace::pflash_write("clear status bits".to_string(), cmd);
                self.status = 0x0;
                if let Err(e) = self.set_read_array_mode(false) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {:?}",
                        cmd, e
                    );
                    return false;
                }
                return true;
            }
            0x60 => {
                trace::pflash_write("block unlock".to_string(), cmd);
            }
            0x70 => {
                trace::pflash_write("read status register".to_string(), cmd);
                self.cmd = cmd;
                return true;
            }
            0x90 => {
                trace::pflash_write("read device information".to_string(), cmd);
                self.cmd = cmd;
                return true;
            }
            0x98 => {
                trace::pflash_write("CFI query".to_string(), cmd);
            }
            0xe8 => {
                trace::pflash_write("write to buffer".to_string(), cmd);
                self.status |= 0x80;
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 0, cmd 0x{:x}, error is {:?}",
                        cmd, e
                    );
                    return false;
                }
                return true;
            }
        }
        self.write_cycle = self.write_cycle.wrapping_add(1);
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
                trace::pflash_write("single byte program (1)".to_string(), self.cmd);
                if !self.read_only {
                    if let Err(e) = self.write_data(data, offset) {
                        error!("Failed to write to PFlash device: {:?}.", e);
                    }
                    if let Err(e) = self.update_content(offset, data_len.into()) {
                        error!("Failed to update content for PFlash device: {:?}", e);
                    }
                } else {
                    self.status |= 0x10;
                }
                self.status |= 0x80;
                self.write_cycle = 0;
            }
            0x20 | 0x28 => {
                if cmd == 0xd0 {
                    self.write_cycle = 0;
                    self.status |= 0x80;
                } else if cmd == 0xff {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!("Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                            cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                } else {
                    if let Err(e) = self.set_read_array_mode(true) {
                        error!("Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                            self.cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                }
            }
            0xe8 => {
                // If device width is not specified,
                // use bank width to mask write block size.
                let length: u32 = if self.device_width != 0 {
                    self.device_width * 8
                } else {
                    self.bank_width * 8
                };
                if let Some(v) = extract_u32(value, 0, length) {
                    value = v;
                } else {
                    error!("Failed to extract bits from u32 value");
                    return false;
                };
                trace::pflash_write_block(value);
                self.write_cycle = self.write_cycle.wrapping_add(1);
                self.counter = value;
            }
            0x60 => {
                if (cmd == 0xd0) || (cmd == 0x01) {
                    self.write_cycle = 0;
                    self.status |= 0x80;
                } else if cmd == 0xff {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!("Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                            self.cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                } else {
                    trace::pflash_write("unknown (un)blocking command".to_string(), cmd);
                    if let Err(e) = self.set_read_array_mode(true) {
                        error!("Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                            self.cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                }
            }
            0x98 => {
                if cmd == 0xff {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!("Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                            self.cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                }
                trace::pflash_write("leaving query mode".to_string(), cmd);
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 1, cmd 0x{:x}, error is {:?}",
                        self.cmd, e
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
                if !self.read_only {
                    if let Err(e) = self.write_data(data, offset) {
                        error!("Failed to write to PFlash device: {:?}", e);
                    }
                } else {
                    self.status |= 0x10;
                }
                self.status |= 0x80;
                if self.counter == 0 {
                    let mask: u64 = !(self.write_blk_size as u64 - 1);
                    trace::pflash_write("block write finished".to_string(), self.cmd);
                    self.write_cycle = self.write_cycle.wrapping_add(1);
                    if !self.read_only {
                        if let Err(e) = self.update_content(offset & mask, self.write_blk_size) {
                            error!("Failed to update content for PFlash device: {:?}", e);
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
                        "Failed to set read array mode, write cycle 2, cmd 0x{:x}, error is {:?}",
                        self.cmd, e
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
            0xe8 => {
                if cmd == 0xd0 {
                    self.write_cycle = 0;
                    self.status |= 0x80;
                } else {
                    if let Err(e) = self.set_read_array_mode(false) {
                        error!("Failed to set read array mode, write cycle 3, cmd 0x{:x}, error is {:?}",
                            self.cmd,
                            e
                        );
                        return false;
                    }
                    return true;
                }
            }
            _ => {
                if let Err(e) = self.set_read_array_mode(true) {
                    error!(
                        "Failed to set read array mode, write cycle 3, cmd 0x{:x}, error is {:?}",
                        self.cmd, e
                    );
                    return false;
                }
                return true;
            }
        }
        true
    }
}

impl Device for PFlash {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for PFlash {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let mut index: u64;
        let mut ret: u32 = 0;
        let data_len: u32 = data.len() as u32;

        // Read:
        // - cmd 0x00 represents PFlash read.
        // - cmd 0x90 represents PFlash ID query.
        // - cmd 0x98 represents PFlash CFI query.
        match self.cmd {
            0x00 => {
                if self.read_data(data, offset).is_err() {
                    error!("Failed to read data from PFlash.");
                }
                return true;
            }
            0x10 | 0x20 | 0x28 | 0x40 | 0x50 | 0x60 | 0x70 | 0xe8 => {
                // 0x10 | 0x40: Single byte program.
                // 0x20 | 0x28: Block erase.
                // 0x50: Clear status register.
                // 0x60: Block / unBlock.
                // 0x70: Status Register.
                // 0xe8: Write block.
                // Just read status register, return every device status in bank.
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
                trace::pflash_read_status(ret);
            }
            0x90 => {
                if self.device_width == 0 {
                    // If device width is not specified, just return device ID.
                    index = offset & 0xFF;
                    if self.bank_width == 2 {
                        index >>= 1;
                    } else if self.bank_width == 4 {
                        index >>= 2;
                    }

                    match index {
                        0 => {
                            ret = self.ident[0] << 8 | self.ident[1];
                            trace::pflash_manufacturer_id(ret);
                        }
                        1 => {
                            ret = self.ident[2] << 8 | self.ident[3];
                            trace::pflash_device_id(ret);
                        }
                        _ => {
                            ret = 0;
                            trace::pflash_device_info(index);
                        }
                    }
                } else {
                    // If a read request is larger than bank_width of PFlash device,
                    // (eg.read data len is 4, bank_width is 2, device_width is 1)
                    // combine serval queries into one response.
                    let mut i: u32 = 0;
                    while i < data_len {
                        match self.query_devid(offset + (i * self.bank_width) as u64) {
                            Err(e) => {
                                error!("Failed to query devid {:?}", e);
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
                                error!("Failed to query devid, {:?}", e);
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
                // This should never happen : reset state & treat it as a read.
                trace::pflash_read_unknown_state(self.cmd);
                self.write_cycle = 0;
                self.cmd = 0x00;
                if let Err(e) = self.read_data(data, offset) {
                    error!("Failed to read data from PFlash: {:?}", e);
                }
            }
        }

        trace::pflash_io_read(offset, data_len, ret, self.cmd, self.write_cycle);
        write_data_u32(data, ret)
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let mut value = 0;
        if !read_data_u32(data, &mut value) {
            return false;
        }
        let cmd: u8 = data[0];
        let data_len: u8 = data.len() as u8;
        trace::pflash_io_write(offset, data_len, value, self.write_cycle);

        if self.write_cycle == 0
            && self
                .rom
                .as_ref()
                .unwrap()
                .set_rom_device_romd(false)
                .is_err()
        {
            error!("Failed PFlash to set device to read array mode.");
        }

        // Write:
        // - PFlash write
        //   * cmd 0x10 | 0x40 represents single Byte Program.
        //   * cmd 0xe8 represents write to buffer.
        //   * cmd 0x20 | 0x28 represents PFlash erase (write all 1).
        match self.write_cycle {
            0 => self.handle_write_first_pass(cmd, offset),
            1 => self.handle_write_second_pass(cmd, offset, data, data_len, value),
            2 => self.handle_write_third_pass(offset, data),
            3 => self.handle_write_fourth_pass(cmd),
            _ => {
                trace::pflash_write("invalid write state".to_string(), cmd);
                if let Err(e) = self.set_read_array_mode(false) {
                    error!("Failed to set PFlash to read array mode, error is {:?}", e);
                }
                false
            }
        }
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
    ) -> Result<()> {
        let res = self.get_sys_resource_mut().unwrap();
        res.region_base = region_base;
        res.region_size = region_size;
        res.irq = 0;
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.rom
            .as_ref()
            .unwrap()
            .set_rom_device_romd(true)
            .with_context(|| "Fail to set PFlash rom region read only")?;
        self.cmd = 0x00;
        self.write_cycle = 0;
        self.status = 0x80;
        Ok(())
    }
}

impl AmlBuilder for PFlash {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::fs::File;

    use super::*;
    use crate::sysbus::{IRQ_BASE, IRQ_MAX};
    use address_space::AddressSpace;

    fn sysbus_init() -> SysBus {
        let sys_mem = AddressSpace::new(
            Region::init_container_region(u64::max_value(), "sys_mem"),
            "sys_mem",
            None,
        )
        .unwrap();
        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(
            Region::init_container_region(1 << 16, "sys_io"),
            "sys_io",
            None,
        )
        .unwrap();
        let free_irqs: (i32, i32) = (IRQ_BASE, IRQ_MAX);
        let mmio_region: (u64, u64) = (0x0A00_0000, 0x1000_0000);
        SysBus::new(
            #[cfg(target_arch = "x86_64")]
            &sys_io,
            &sys_mem,
            free_irqs,
            mmio_region,
        )
    }

    fn pflash_dev_init(file_name: &str) -> Arc<Mutex<PFlash>> {
        let sector_len: u32 = 0x40_000;
        let flash_size: u64 = 0x400_0000;
        let read_only: bool = false;
        let flash_base: u64 = 0;

        let fd = File::create(file_name).unwrap();
        fd.set_len(flash_size).unwrap();
        drop(fd);

        let fd = Some(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(file_name)
                .unwrap(),
        );
        let pflash = PFlash::new(flash_size, &fd, sector_len, 4, 2, read_only).unwrap();
        let sysbus = sysbus_init();
        let dev = Arc::new(Mutex::new(pflash));
        let region_ops = sysbus.build_region_ops(&dev);
        let host_mmap = Arc::new(
            HostMemMapping::new(
                GuestAddress(flash_base),
                None,
                flash_size,
                fd.map(FileBackend::new_common),
                false,
                true,
                false,
            )
            .unwrap(),
        );

        let rom_region = Region::init_rom_device_region(host_mmap, region_ops, "pflash-dev");
        dev.lock().unwrap().rom = Some(rom_region);
        dev
    }

    #[test]
    fn test_cfi_query() {
        let file_name = "flash_vars_for_read_1.fd";
        let dev = pflash_dev_init(file_name);

        let base = GuestAddress(0x0000);
        let mut read_data = vec![0, 0, 0, 0];
        let offset = 0x40;
        dev.lock().unwrap().cmd = 0x98;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let cfi_data = vec![0x51, 0x00, 0x51, 0x00];
        assert_eq!(cfi_data, read_data);

        let mut read_data = vec![0, 0, 0, 0];
        let offset = 0x44;
        dev.lock().unwrap().cmd = 0x98;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let cfi_data = vec![0x52, 0x00, 0x52, 0x00];
        assert_eq!(cfi_data, read_data);

        let mut read_data = vec![0, 0, 0, 0];
        let offset = 0x48;
        dev.lock().unwrap().cmd = 0x98;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let cfi_data = vec![0x59, 0x00, 0x59, 0x00];
        assert_eq!(cfi_data, read_data);

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_id_query() {
        let file_name = "flash_vars_for_read_2.fd";
        let dev = pflash_dev_init(file_name);

        let base = GuestAddress(0x0000);
        let mut read_data = vec![0, 0, 0, 0];
        let offset = 0x00;
        dev.lock().unwrap().cmd = 0x90;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let id_data = vec![0x89, 0x00, 0x89, 0x00];
        assert_eq!(read_data, id_data);

        let mut read_data = vec![0, 0, 0, 0];
        let offset = 0x04;
        dev.lock().unwrap().cmd = 0x90;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let id_data = vec![0x18, 0x00, 0x18, 0x00];
        assert_eq!(read_data, id_data);

        let mut read_data = vec![0xff, 0xff, 0xff, 0xff];
        let offset = 0x08;
        dev.lock().unwrap().cmd = 0x90;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        let id_data = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_data, id_data);

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_block_erase() {
        let file_name = "flash_vars_for_write_1.fd";
        let dev = pflash_dev_init(file_name);

        let base = GuestAddress(0x0000);
        let offset = 0_u64;

        let data = vec![0x20, 0, 0, 0];
        dev.lock().unwrap().write_cycle = 0;
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));

        let mut read_data = vec![0, 0, 0, 0];
        let erase_data = vec![0xFF_u8, 0xFF, 0xFF, 0xFF];
        dev.lock().unwrap().cmd = 0x00;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        assert_eq!(erase_data, read_data);

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_write_single_byte() {
        use std::io::Read;

        let file_name = "flash_vars_for_write_2.fd";
        let dev = pflash_dev_init(file_name);
        let base = GuestAddress(0x0000);
        let offset = 0_u64;
        let data = vec![0x10, 0, 0, 0];
        dev.lock().unwrap().write_cycle = 0;
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));
        let data = vec![0x70, 0, 0x70, 0];
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));

        let mut read_data = vec![0, 0, 0, 0];
        dev.lock().unwrap().cmd = 0x00;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        assert_eq!(data, read_data);

        let mut file_buf = vec![0_u8, 0, 0, 0];
        let mut fd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_name)
            .unwrap();
        fd.read_exact(&mut file_buf).unwrap();
        assert_eq!(data, file_buf);

        fs::remove_file(file_name).unwrap();
    }

    #[test]
    fn test_write_to_buffer() {
        let file_name = "flash_vars_for_write_3.fd";
        let dev = pflash_dev_init(file_name);

        let base = GuestAddress(0x0000);
        let offset = 0_u64;
        let data = vec![0xe8, 0, 0, 0];
        dev.lock().unwrap().write_cycle = 0;
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));
        let data = vec![0x12, 0x34, 0x56, 0x78];
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));
        assert!(dev.lock().unwrap().write(data.as_ref(), base, offset));

        let mut read_data = vec![0, 0, 0, 0];
        dev.lock().unwrap().cmd = 0x00;
        assert!(dev.lock().unwrap().read(&mut read_data, base, offset));
        assert_eq!(data, read_data);

        fs::remove_file(file_name).unwrap();
    }
}
