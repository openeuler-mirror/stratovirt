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

use crate::legacy::errors::{Result, ResultExt};

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
