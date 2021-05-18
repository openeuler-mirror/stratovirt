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

use std::sync::Arc;

use address_space::{AddressSpace, GuestAddress};
use byteorder::{BigEndian, ByteOrder};
use util::byte_code::ByteCode;
use util::{__offset_of, offset_of};

use crate::legacy::errors::{ErrorKind, Result, ResultExt};

// FwCfg Signature
const FW_CFG_DMA_SIGNATURE: u128 = 0x51454d5520434647;
/// FwCfg version bits
const FW_CFG_VERSION: u16 = 0x01;
const FW_CFG_VERSION_DMA: u16 = 0x02;
// FwCfg related constants
const FW_CFG_FILE_SLOTS_DFLT: u16 = 0x20;
const FW_CFG_FILE_FIRST: u16 = 0x20;
const FW_CFG_WRITE_CHANNEL: u16 = 0x4000;
const FW_CFG_ARCH_LOCAL: u16 = 0x8000;
const FW_CFG_ENTRY_MASK: u16 = !(FW_CFG_WRITE_CHANNEL | FW_CFG_ARCH_LOCAL);
const FW_CFG_INVALID: u16 = 0xffff;
/// FwCfg DMA control bits
const FW_CFG_DMA_CTL_ERROR: u32 = 0x01;
const FW_CFG_DMA_CTL_READ: u32 = 0x02;
const FW_CFG_DMA_CTL_SKIP: u32 = 0x04;
const FW_CFG_DMA_CTL_SELECT: u32 = 0x08;
const FW_CFG_DMA_CTL_WRITE: u32 = 0x10;

/// Define the Firmware Configuration Entry Type
#[repr(u16)]
pub enum FwCfgEntryType {
    Signature = 0x00,
    Id,
    Uuid,
    RamSize,
    NoGraphic,
    NbCpus,
    MachineId,
    KernelAddr,
    KernelSize,
    KernelCmdline,
    InitrdAddr,
    InitrdSize,
    BootDevice,
    Numa,
    BootMenu,
    MaxCpus,
    KernelEntry,
    KernelData,
    InitrdData,
    CmdlineAddr,
    CmdlineSize,
    CmdlineData,
    SetupAddr,
    SetupSize,
    SetupData,
    FileDir,
    #[cfg(target_arch = "x86_64")]
    Irq0Override = 0x8002,
    #[cfg(target_arch = "x86_64")]
    E820Table = 0x8003,
}
/// Get the FwCfg entry name of a given key
fn get_key_name(key: usize) -> &'static str {
    static FW_CFG_KEYS: [&str; 26] = [
        "signature",
        "id",
        "uuid",
        "ram_size",
        "nographic",
        "nb_cpus",
        "machine_id",
        "kernel_addr",
        "kernel_size",
        "kernel_cmdline",
        "initrd_addr",
        "initrd_size",
        "boot_device",
        "numa",
        "boot_menu",
        "max_cpus",
        "kernel_entry",
        "kernel_data",
        "initrd_data",
        "cmdline_addr",
        "cmdline_size",
        "cmdline_data",
        "setup_addr",
        "setup_size",
        "setup_data",
        "file_dir",
    ];

    if key < FW_CFG_FILE_FIRST as usize {
        FW_CFG_KEYS[key]
    } else {
        "unknown"
    }
}

/// FwCfg select callback and write callback type definition
type FwCfgCallbackType = Arc<dyn FwCfgCallback + Send + Sync>;
type FwCfgWriteCallbackType = Arc<dyn FwCfgWriteCallback + Send + Sync>;

/// FwCfg select callback
pub trait FwCfgCallback {
    fn select_callback(&self);
}

/// FwCfg write callback
pub trait FwCfgWriteCallback {
    fn write_callback(&self, start: u64, len: usize);
}

/// The FwCfgEntry type which holds the firmware item
#[derive(Clone, Default)]
struct FwCfgEntry {
    data: Vec<u8>,
    select_cb: Option<FwCfgCallbackType>,
    write_cb: Option<FwCfgWriteCallbackType>,
    allow_write: bool,
}

impl FwCfgEntry {
    fn new(
        data: Vec<u8>,
        select_cb: Option<FwCfgCallbackType>,
        write_cb: Option<FwCfgWriteCallbackType>,
        allow_write: bool,
    ) -> Self {
        FwCfgEntry {
            data,
            select_cb,
            write_cb,
            allow_write,
        }
    }
}

/// The FwCfgFile entry used to retrieve firwmware files by os loader
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct FwCfgFile {
    size: u32,
    select: u16,
    reserved: u16,
    name: [u8; 56],
}

impl Eq for FwCfgFile {}

impl PartialEq for FwCfgFile {
    fn eq(&self, other: &Self) -> bool {
        self.name.to_vec() == other.name.to_vec()
    }
}

impl Default for FwCfgFile {
    fn default() -> Self {
        FwCfgFile {
            size: 0_u32,
            select: 0_u16,
            reserved: 0_u16,
            name: [0_u8; 56],
        }
    }
}

impl FwCfgFile {
    fn new(size: u32, select: u16, name: &str) -> Self {
        let len = std::cmp::min(56, name.len());
        let mut bytes = [0; 56];
        bytes[..len].copy_from_slice(&name.as_bytes()[..len]);

        FwCfgFile {
            size,
            select,
            reserved: 0_u16,
            name: bytes,
        }
    }

    /// Convert FwCfgFile item into a big endian format data array
    fn as_be_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0; 64_usize];

        let mut curr_offset = 0_usize;
        let mut next_size = std::mem::size_of::<u32>();
        BigEndian::write_u32(
            &mut bytes[curr_offset..(curr_offset + next_size)],
            self.size,
        );

        curr_offset += next_size;
        next_size = std::mem::size_of::<u16>();
        BigEndian::write_u16(
            &mut bytes[curr_offset..(curr_offset + next_size)],
            self.select,
        );

        curr_offset += next_size;
        next_size = std::mem::size_of::<u16>();
        BigEndian::write_u16(
            &mut bytes[curr_offset..(curr_offset + next_size)],
            self.reserved,
        );

        curr_offset += next_size;
        bytes[curr_offset..].copy_from_slice(&self.name);

        bytes
    }
}

/// The FwCfgDmaAccess entry used as DMA descriptor in memory for operation
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct FwCfgDmaAccess {
    control: u32,
    length: u32,
    address: u64,
}

impl ByteCode for FwCfgDmaAccess {}

/// set DMA memory zone with char
fn set_dma_memory(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    char: u8,
    len: u64,
) -> Result<()> {
    const FILLBUF_SIZE: usize = 512;
    let fill_buf: &[u8; FILLBUF_SIZE] = &[char; FILLBUF_SIZE];

    addr_space
        .write(&mut fill_buf.as_ref(), addr, len)
        .chain_err(|| {
            format!(
                "Failed to set dma memory for fwcfg at gpa=0x{:x} len=0x{:x}",
                addr.0, len
            )
        })?;

    Ok(())
}

/// write data to DMA memory zone
fn write_dma_memory(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    mut buf: &[u8],
    len: u64,
) -> Result<()> {
    addr_space.write(&mut buf, addr, len).chain_err(|| {
        format!(
            "Failed to write dma memory of fwcfg at gpa=0x{:x} len=0x{:x}",
            addr.0, len
        )
    })?;

    Ok(())
}

/// read data form DMA memory zone
fn read_dma_memory(
    addr_space: &Arc<AddressSpace>,
    addr: GuestAddress,
    mut buf: &mut [u8],
    len: u64,
) -> Result<()> {
    addr_space.read(&mut buf, addr, len).chain_err(|| {
        format!(
            "Failed to read dma memory of fwcfg at gpa=0x{:x} len=0x{:x}",
            addr.0, len
        )
    })?;
    Ok(())
}

/// Write DMA result to DMA response zone
fn write_dma_result(addr_space: &Arc<AddressSpace>, addr: GuestAddress, value: u32) -> Result<()> {
    let mut dma_buf: [u8; 4] = [0; 4];
    BigEndian::write_u32(&mut dma_buf, value);
    write_dma_memory(
        addr_space,
        addr.unchecked_add(offset_of!(FwCfgDmaAccess, control) as u64),
        &dma_buf,
        dma_buf.len() as u64,
    )
    .chain_err(|| {
        format!(
            "Failed to write dma result of fwcfg at gpa=0x{:x} value=0x{:x}",
            addr.0, value
        )
    })?;
    Ok(())
}

pub struct FwCfgCommon {
    // Firmware file slot count
    file_slots: u16,
    // Arch related firmware entry
    arch_entries: Vec<FwCfgEntry>,
    // Arch independent firmware entry
    entries: Vec<FwCfgEntry>,
    // Firmware configuration files
    files: Vec<FwCfgFile>,
    // The current entry index selected
    cur_entry: u16,
    // The current entry data offset of the entry selected
    cur_offset: u32,
    // DMA enable flag
    dma_enabled: bool,
    // DMA guest address
    dma_addr: GuestAddress,
    // System memory address space
    mem_space: Arc<AddressSpace>,
}

impl FwCfgCommon {
    fn new(sys_mem: Arc<AddressSpace>) -> Self {
        FwCfgCommon {
            file_slots: FW_CFG_FILE_SLOTS_DFLT as u16,
            arch_entries: vec![
                FwCfgEntry::default();
                (FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT) as usize
            ],
            entries: vec![
                FwCfgEntry::default();
                (FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT) as usize
            ],
            files: Vec::new(),
            cur_entry: 0,
            cur_offset: 0,
            dma_enabled: true,
            dma_addr: GuestAddress(0),
            mem_space: sys_mem,
        }
    }

    /// Check whether the selected entry has a arch_local flag
    fn is_arch_local(&self) -> bool {
        (self.cur_entry & FW_CFG_ARCH_LOCAL) > 0
    }

    /// Get the max entry size
    fn max_entry(&self) -> u16 {
        FW_CFG_FILE_FIRST + self.file_slots
    }

    /// Get a mutable reference of the current selected entry
    fn get_entry_mut(&mut self) -> Result<&mut FwCfgEntry> {
        let key = self.cur_entry & FW_CFG_ENTRY_MASK;
        if key >= self.max_entry() || self.cur_entry == FW_CFG_INVALID {
            return Err(
                ErrorKind::EntryNotFound(get_key_name(self.cur_entry as usize).to_owned()).into(),
            );
        };

        // unwrap is safe bacause the count of arch_entries and entries is initialized
        // as `FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT`, which is equal to the return
        // value of `max_entry` function.
        if self.is_arch_local() {
            Ok(self.arch_entries.get_mut(key as usize).unwrap())
        } else {
            Ok(self.entries.get_mut(key as usize).unwrap())
        }
    }

    /// Select the entry by the key specified
    fn select_entry(&mut self, key: u16) {
        self.cur_offset = 0;
        if (key & FW_CFG_ENTRY_MASK) >= self.max_entry() {
            self.cur_entry = FW_CFG_INVALID;
        } else {
            self.cur_entry = key;

            // unwrap() is safe because we have checked the range of `key`.
            let selected_entry = self.get_entry_mut().unwrap();
            if let Some(ref mut cb) = selected_entry.select_cb {
                cb.select_callback();
            }
        }
    }

    fn add_entry(
        &mut self,
        key: FwCfgEntryType,
        select_cb: Option<FwCfgCallbackType>,
        write_cb: Option<FwCfgWriteCallbackType>,
        data: Vec<u8>,
        allow_write: bool,
    ) -> Result<()> {
        let key = (key as u16) & FW_CFG_ENTRY_MASK;

        if key >= self.max_entry() || data.len() >= std::u32::MAX as usize {
            return Err(ErrorKind::InvalidFwCfgEntry(key).into());
        }

        let entry = if self.is_arch_local() {
            self.arch_entries.get_mut(key as usize)
        } else {
            self.entries.get_mut(key as usize)
        };

        if entry.is_none() {
            warn!("entry not initialized in construction function");
        }

        let entry = entry.unwrap();
        if !entry.data.is_empty() {
            warn!("Entry not empty, will override");
        }

        entry.data = data;
        entry.select_cb = select_cb;
        entry.allow_write = allow_write;
        entry.write_cb = write_cb;

        Ok(())
    }

    // Update a FwCfgEntry
    fn update_entry_data(&mut self, key: u16, mut data: Vec<u8>) -> Result<()> {
        if key >= self.max_entry() || data.len() >= std::u32::MAX as usize {
            return Err(ErrorKind::InvalidFwCfgEntry(key).into());
        }

        let entry = if self.is_arch_local() {
            self.arch_entries.get_mut(key as usize)
        } else {
            self.entries.get_mut(key as usize)
        };

        if let Some(e) = entry {
            e.data.clear();
            e.data.append(&mut data);
            Ok(())
        } else {
            Err(ErrorKind::EntryNotFound(get_key_name(key as usize).to_owned()).into())
        }
    }

    fn add_file_callback(
        &mut self,
        filename: &str,
        data: Vec<u8>,
        select_cb: Option<FwCfgCallbackType>,
        write_cb: Option<FwCfgWriteCallbackType>,
        allow_write: bool,
    ) -> Result<()> {
        if self.files.len() >= self.file_slots as usize {
            return Err(ErrorKind::FileSlotsNotAvailable(filename.to_owned()).into());
        }

        let file_name_bytes = filename.to_string().as_bytes().to_vec();
        // Check against duplicate file here
        if self
            .files
            .iter()
            .any(|f| f.name[0..file_name_bytes.len()].to_vec() == file_name_bytes)
        {
            return Err(ErrorKind::DuplicateFile(filename.to_owned()).into());
        }

        let mut index = self.files.len();
        for (i, file_entry) in self.files.iter().enumerate() {
            if file_name_bytes < file_entry.name.to_vec() {
                index = i;
                break;
            }
        }

        let file = FwCfgFile::new(
            data.len() as u32,
            FW_CFG_FILE_FIRST + index as u16,
            filename,
        );
        self.files.insert(index, file);
        self.files.iter_mut().skip(index + 1).for_each(|f| {
            f.select += 1;
        });

        let mut bytes = Vec::new();
        let file_length_be = BigEndian::read_u32((self.files.len() as u32).as_bytes());
        bytes.append(&mut file_length_be.as_bytes().to_vec());
        for value in self.files.iter() {
            bytes.append(&mut value.as_be_bytes());
        }
        self.update_entry_data(FwCfgEntryType::FileDir as u16, bytes)?;

        self.entries.insert(
            FW_CFG_FILE_FIRST as usize + index,
            FwCfgEntry::new(data, select_cb, write_cb, allow_write),
        );
        Ok(())
    }

    // Fetch FwCfgDma request from guest and handle it
    fn handle_dma_request(&mut self) -> Result<()> {
        let dma_addr = self.dma_addr;
        let mem_space = self.mem_space.clone();
        let cur_entry = self.cur_entry;

        // Reset dma_addr address before next dma access
        self.dma_addr = GuestAddress(0);

        // Read DMA request from guest
        let mut dma_deafult = FwCfgDmaAccess::default();
        let dma_request = dma_deafult.as_mut_bytes();
        let size = std::mem::size_of::<FwCfgDmaAccess>() as u64;
        if let Err(_e) = read_dma_memory(&self.mem_space, dma_addr, dma_request, size) {
            write_dma_result(&self.mem_space, dma_addr, FW_CFG_DMA_CTL_ERROR)?;
            return Err(ErrorKind::ReadDMARequest(dma_addr.0, size).into());
        }

        // Build `FwCfgDmaAccess` object from dma_request here
        let mut dma = FwCfgDmaAccess {
            control: BigEndian::read_u32(&dma_request[0..4]),
            length: BigEndian::read_u32(&dma_request[4..8]),
            address: BigEndian::read_u64(&dma_request[8..]),
        };
        if dma.control & FW_CFG_DMA_CTL_SELECT > 0 {
            self.select_entry((dma.control >> 16) as u16);
        }

        let mut offset = self.cur_offset;

        let mut is_read = false;
        let mut is_write = false;
        if dma.control & FW_CFG_DMA_CTL_READ != 0 {
            is_read = true;
        }
        if dma.control & FW_CFG_DMA_CTL_WRITE != 0 {
            is_write = true;
        }
        if dma.control & FW_CFG_DMA_CTL_SKIP != 0 {
            dma.length = 0;
        }

        // clear dma.control here
        dma.control = 0;

        let entry = self.get_entry_mut()?;

        let mut len: u32;
        while dma.length > 0 && (dma.control & FW_CFG_DMA_CTL_ERROR) == 0 {
            if cur_entry == FW_CFG_INVALID
                || entry.data.is_empty()
                || offset >= entry.data.len() as u32
            {
                len = dma.length;

                if is_read
                    && set_dma_memory(&mem_space, GuestAddress(dma.address), 0, len as u64).is_err()
                {
                    dma.control |= FW_CFG_DMA_CTL_ERROR;
                }

                if is_write {
                    dma.control |= FW_CFG_DMA_CTL_ERROR;
                }
            } else {
                if dma.length <= entry.data.len() as u32 - offset {
                    len = dma.length;
                } else {
                    len = entry.data.len() as u32 - offset;
                }

                // If it is a DMA read request
                if is_read
                    && write_dma_memory(
                        &mem_space,
                        GuestAddress(dma.address),
                        &entry.data[offset as usize..],
                        len as u64,
                    )
                    .is_err()
                {
                    dma.control |= FW_CFG_DMA_CTL_ERROR;
                }

                if is_write {
                    let mut dma_read_error = false;
                    let data = &mut entry.data[offset as usize..];
                    if read_dma_memory(&mem_space, GuestAddress(dma.address), data, len as u64)
                        .is_err()
                    {
                        dma_read_error = true;
                    }

                    if dma_read_error || !entry.allow_write || len != dma.length {
                        dma.control |= FW_CFG_DMA_CTL_ERROR;
                    } else if true {
                        if let Some(cb) = &entry.write_cb {
                            cb.write_callback(offset as u64, len as usize);
                        }
                    }
                }
                offset += len;
            }
            dma.length -= len;
            dma.address += len as u64
        }

        self.cur_offset = offset;
        write_dma_result(&self.mem_space, dma_addr, dma.control)?;
        Ok(())
    }
}
