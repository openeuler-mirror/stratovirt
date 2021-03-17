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

use std::sync::{Arc, Mutex};

use address_space::{AddressSpace, GuestAddress};
#[cfg(target_arch = "x86_64")]
use byteorder::LittleEndian;
use byteorder::{BigEndian, ByteOrder};
use error_chain::ChainedError;
use kvm_ioctls::VmFd;
use sysbus::{SysBus, SysBusDevOps, SysBusDevType, SysRes};
use util::byte_code::ByteCode;
use util::num_ops::extract_u64;
use util::{__offset_of, offset_of};

use crate::legacy::errors::{ErrorKind, Result, ResultExt};

#[cfg(target_arch = "x86_64")]
const FW_CFG_IO_BASE: u64 = 0x510;
// Size of ioports including control/data registers and DMA.
#[cfg(target_arch = "x86_64")]
const FW_CFG_IO_SIZE: u64 = 0x12;

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

    /// Write DMA mem register
    ///
    /// # Arguments
    ///
    /// * `addr`    - The address to write to
    /// * `value`   - Value to write
    /// * `size`    - Length of raw bytes to write
    ///
    /// # Errors
    ///
    /// Return Error if fail to add the file entry.
    ///
    fn dma_mem_write(&mut self, addr: u64, value: u64, size: u32) -> Result<()> {
        if size == 4 {
            if addr == 0 {
                self.dma_addr = GuestAddress(value << 32);
            } else if addr == 4 {
                self.dma_addr = GuestAddress(self.dma_addr.raw_value() | value as u64);
                self.handle_dma_request()?;
            }
        } else if size == 8 && addr == 0 {
            self.dma_addr = GuestAddress(value);
            self.handle_dma_request()?;
        } else {
            bail!(
                "Failed to set DMA address, offset is 0x{:x}, size is 0x{:x}",
                addr,
                size
            );
        }
        Ok(())
    }

    /// Read DMA mem register
    ///
    /// # Arguments
    ///
    /// * `addr`    - The address to read to
    /// * `size`    - Length of raw bytes to read
    ///
    /// # Return
    ///
    /// Return the value of the register
    ///
    fn dma_mem_read(&self, addr: u64, size: u32) -> Result<u64> {
        extract_u64(
            FW_CFG_DMA_SIGNATURE as u64,
            ((8 - addr - size as u64) * 8) as u32,
            (size * 8) as u32,
        )
        .ok_or_else(|| ErrorKind::Msg("Failed to extract bits from u64".to_string()).into())
    }

    /// Read data register
    ///
    /// # Arguments
    ///
    /// * `_addr`    - The address to read to
    /// * `size`    - Length of raw bytes to read
    ///
    /// # Return
    ///
    /// Return the value of the register
    ///
    fn read_data_reg(&mut self, _addr: u64, mut size: u32) -> Result<u64> {
        if size == 0 || size >= std::mem::size_of::<u64>() as u32 {
            bail!(
                "Failed to read from FWcfg data register, size {} overflows",
                size
            );
        }

        let cur_entry = self.cur_entry;
        let mut cur_offset = self.cur_offset;
        let entry = self.get_entry_mut()?;
        let mut value: u64 = 0;

        if cur_entry != FW_CFG_INVALID
            && !entry.data.is_empty()
            && cur_offset < entry.data.len() as u32
        {
            loop {
                value = (value << 8) | entry.data[cur_offset as usize] as u64;
                cur_offset += 1;
                size -= 1;

                if size == 0 || cur_offset >= entry.data.len() as u32 {
                    break;
                }
            }
            value <<= 8 * size as u64;
        }
        self.cur_offset = cur_offset;
        Ok(value)
    }

    fn common_realize(&mut self) -> Result<()> {
        // Firmware configurations add Signature item
        let sig = &[b'Q', b'E', b'M', b'U'];
        self.add_entry(FwCfgEntryType::Signature, None, None, sig.to_vec(), false)?;

        self.add_entry(
            FwCfgEntryType::NoGraphic,
            None,
            None,
            (0_u16).as_bytes().to_vec(),
            false,
        )?;

        self.add_entry(
            FwCfgEntryType::BootMenu,
            None,
            None,
            (0_u16).as_bytes().to_vec(),
            false,
        )?;

        // Add FileDir item
        self.add_entry(FwCfgEntryType::FileDir, None, None, Vec::new(), false)?;

        // Add boot-fail-wait file item, default to 5s
        self.add_file_callback(
            "etc/boot-fail-wait",
            (5_u32).as_bytes().to_vec(),
            None,
            None,
            false,
        )?;

        // Firmware version
        let mut version = FW_CFG_VERSION;
        if self.dma_enabled {
            version |= FW_CFG_VERSION_DMA;
        }
        self.add_entry(
            FwCfgEntryType::Id,
            None,
            None,
            version.as_bytes().to_vec(),
            false,
        )?;
        Ok(())
    }
}

/// FwCfg MMIO Device use for AArch64 platform
#[cfg(target_arch = "aarch64")]
pub struct FwCfgMem {
    fwcfg: FwCfgCommon,
    /// System Resource of device.
    res: SysRes,
}

#[cfg(target_arch = "aarch64")]
impl FwCfgMem {
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        FwCfgMem {
            fwcfg: FwCfgCommon::new(sys_mem),
            res: SysRes::default(),
        }
    }

    pub fn realize(
        mut self,
        sysbus: &mut SysBus,
        region_base: u64,
        region_size: u64,
        vm_fd: &VmFd,
    ) -> Result<Arc<Mutex<Self>>> {
        self.fwcfg.common_realize()?;
        self.set_sys_resource(sysbus, region_base, region_size, vm_fd)
            .chain_err(|| "Failed to allocate system resource for FwCfg.")?;

        let dev = Arc::new(Mutex::new(self));
        sysbus
            .attach_device(&dev, region_base, region_size)
            .chain_err(|| "Failed to attach FwCfg device to system bus.")?;
        Ok(dev)
    }
}

#[cfg(target_arch = "aarch64")]
impl SysBusDevOps for FwCfgMem {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let value = match offset {
            0..=7 => match self.fwcfg.read_data_reg(offset, data.len() as u32) {
                Ok(val) => val,
                Err(e) => {
                    error!(
                        "Failed to read from FwCfg data register, error is {}",
                        e.display_chain()
                    );
                    return false;
                }
            },
            8..=15 => {
                error!("Read from FwCfg control register is not supported.");
                0
            }
            16..=23 => match self.fwcfg.dma_mem_read(offset - 0x10, data.len() as u32) {
                Ok(val) => val,
                Err(e) => {
                    error!("Failed to handle FWCFg DMA-read, error is {}", e);
                    return false;
                }
            },
            _ => {
                error!("Failed to read FWCFg, offset 0x{:x} is invalid", offset);
                return false;
            }
        };

        match data.len() {
            1 => data[0] = value as u8,
            2 => BigEndian::write_u16(data, value as u16),
            4 => BigEndian::write_u32(data, value as u32),
            8 => BigEndian::write_u64(data, value as u64),
            _ => {}
        }
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let size = data.len() as u32;
        let value = match size {
            1 => data[0] as u64,
            2 => BigEndian::read_u16(data) as u64,
            4 => BigEndian::read_u32(data) as u64,
            8 => BigEndian::read_u64(data) as u64,
            _ => 0,
        };
        match offset {
            0..=7 => {
                error!("Write to FwCfg data register is not supported.");
            }
            8..=15 => {
                // Write to FwCfg control register
                self.fwcfg.select_entry(value as u16);
            }
            16..=23 => {
                if self
                    .fwcfg
                    .dma_mem_write(offset - 0x10, value, size)
                    .is_err()
                {
                    error!("Failed to write dma at offset=0x{:x}.", offset);
                    return false;
                }
            }
            _ => {
                error!("Failed to write FWCFg, offset 0x{:x} is invalid", offset);
                return false;
            }
        }
        true
    }

    fn get_sys_resource(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.res)
    }

    /// Get device type.
    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::FwCfg
    }
}

#[cfg(target_arch = "x86_64")]
pub struct FwCfgIO {
    fwcfg: FwCfgCommon,
    /// System Resource of device.
    res: SysRes,
}

#[cfg(target_arch = "x86_64")]
impl FwCfgIO {
    pub fn new(sys_mem: Arc<AddressSpace>) -> Self {
        FwCfgIO {
            fwcfg: FwCfgCommon::new(sys_mem),
            res: SysRes {
                region_base: FW_CFG_IO_BASE,
                region_size: FW_CFG_IO_SIZE,
                irq: 0,
            },
        }
    }

    pub fn realize(mut self, sysbus: &mut SysBus, vm_fd: &VmFd) -> Result<Arc<Mutex<Self>>> {
        self.fwcfg.common_realize()?;
        let region_base = self.res.region_base;
        let region_size = self.res.region_size;
        self.set_sys_resource(sysbus, region_base, region_size, vm_fd)
            .chain_err(|| "Failed to allocate system resource for FwCfg.")?;

        let dev = Arc::new(Mutex::new(self));
        sysbus
            .attach_device(&dev, region_base, region_size)
            .chain_err(|| "Failed to attach FwCfg device to system bus.")?;
        Ok(dev)
    }
}

#[cfg(target_arch = "x86_64")]
impl SysBusDevOps for FwCfgIO {
    fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool {
        let value: u64 = match offset {
            0..=1 => match self.fwcfg.read_data_reg(offset, data.len() as u32) {
                Err(e) => {
                    error!(
                        "Failed to read from FwCfg data register, error is {}",
                        e.display_chain()
                    );
                    return false;
                }
                Ok(val) => val,
            },
            4..=11 => match self.fwcfg.dma_mem_read(offset - 4, data.len() as u32) {
                Err(e) => {
                    error!("Failed to handle FwCfg DMA-read, error is {}", e);
                    return false;
                }
                Ok(val) => val,
            },
            _ => {
                // This should never happen
                error!(
                    "Failed to read FwCfg, ioport 0x{:x} is invalid",
                    base.0 + offset
                );
                return false;
            }
        };

        match data.len() {
            1 => data[0] = value as u8,
            2 => BigEndian::write_u16(data, value as u16),
            4 => BigEndian::write_u32(data, value as u32),
            8 => BigEndian::write_u64(data, value as u64),
            _ => {
                warn!(
                    "Failed to read from FwCfg data register, data length {} is invalid",
                    data.len()
                );
                return false;
            }
        }
        true
    }

    fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool {
        let size = data.len() as u32;
        match offset {
            0..=1 => {
                if size != 2 {
                    error!(
                        "Failed to write FwCfg control register, data length {} is invalid",
                        data.len()
                    );
                    return false;
                }
                self.fwcfg.select_entry(LittleEndian::read_u16(data));
            }
            4..=11 => {
                let value = match size {
                    1 => data[0] as u64,
                    2 => BigEndian::read_u16(data) as u64,
                    4 => BigEndian::read_u32(data) as u64,
                    8 => BigEndian::read_u64(data) as u64,
                    _ => 0,
                };
                if let Err(e) = self.fwcfg.dma_mem_write(offset - 4, value, size) {
                    error!(
                        "Failed to handle FWCFg DMA-write, error is {}",
                        e.display_chain()
                    );
                    return false;
                }
            }
            _ => {
                // This should never happen
                error!(
                    "Failed to write FwCfg, ioport 0x{:x} is invalid",
                    base.0 + offset
                );
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
    ) -> sysbus::errors::Result<()> {
        let mut res = self.get_sys_resource().unwrap();
        res.region_base = region_base;
        res.region_size = region_size;
        res.irq = 0;
        Ok(())
    }

    fn get_type(&self) -> SysBusDevType {
        SysBusDevType::FwCfg
    }
}
