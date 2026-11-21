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

use anyhow::{anyhow, bail, Context, Result};
#[cfg(target_arch = "x86_64")]
use byteorder::LittleEndian;
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, warn};
use serde::{Deserialize, Serialize};

use crate::legacy::error::LegacyError;
use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType};
use crate::{convert_bus_mut, Device, DeviceBase, MUT_SYS_BUS};
use acpi::{
    AmlBuilder, AmlDevice, AmlInteger, AmlNameDecl, AmlResTemplate, AmlScopeBuilder, AmlString,
};
#[cfg(target_arch = "x86_64")]
use acpi::{AmlIoDecode, AmlIoResource};
#[cfg(target_arch = "aarch64")]
use acpi::{AmlMemory32Fixed, AmlReadAndWrite};
use address_space::{AddressAttr, AddressSpace, GuestAddress};
use migration::snapshot::FWCFG_SNAPSHOT_ID;
use migration::{DeviceStateDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use util::byte_code::ByteCode;
use util::gen_base_func;

#[cfg(target_arch = "x86_64")]
const FW_CFG_IO_BASE: u64 = 0x510;
// Size of ioports including control/data registers and DMA.
#[cfg(target_arch = "x86_64")]
const FW_CFG_IO_SIZE: u64 = 0x12;

// FwCfg Signature
const FW_CFG_DMA_SIGNATURE: &[u8; 8] = b"QEMU CFG";
/// FwCfg version bits
const FW_CFG_VERSION: u32 = 0x01;
const FW_CFG_VERSION_DMA: u32 = 0x02;
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

    FW_CFG_KEYS.get(key).copied().unwrap_or("unknown")
}

/// FwCfg select callback and write callback type definition
type FwCfgCallbackType = Arc<dyn FwCfgCallback + Send + Sync>;
type FwCfgWriteCallbackType = Arc<Mutex<dyn FwCfgWriteCallback + Send + Sync>>;

/// FwCfg select callback
pub trait FwCfgCallback {
    fn select_callback(&self);
}

/// FwCfg write callback
pub trait FwCfgWriteCallback {
    /// Receives the bytes written and their offset within the item.
    fn write_callback(&mut self, data: Vec<u8>, start: u64, len: usize);
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

/// A file directory record.
struct FwCfgFile {
    size: u32,
    select: u16,
    name: [u8; 56],
}

impl FwCfgFile {
    fn encode_name(name: &str) -> Result<[u8; 56]> {
        if name.is_empty() || name.len() >= 56 || !name.is_ascii() || name.as_bytes().contains(&0) {
            bail!("invalid fwcfg file name {:?}", name);
        }
        let mut bytes = [0; 56];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(bytes)
    }

    fn append_to(&self, directory: &mut Vec<u8>) {
        directory.extend_from_slice(&self.size.to_be_bytes());
        directory.extend_from_slice(&self.select.to_be_bytes());
        directory.extend_from_slice(&[0; 2]);
        directory.extend_from_slice(&self.name);
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

#[derive(Clone, Copy, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
struct FwCfgState {
    cur_entry: u16,
    cur_offset: u32,
    dma_enabled: u8,
    dma_addr: u64,
}

pub struct FwCfgCommon {
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
            arch_entries: vec![
                FwCfgEntry::default();
                (FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT) as usize
            ],
            entries: vec![
                FwCfgEntry::default();
                (FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT) as usize
            ],
            files: Vec::with_capacity(usize::from(FW_CFG_FILE_SLOTS_DFLT)),
            cur_entry: 0,
            cur_offset: 0,
            dma_enabled: true,
            dma_addr: GuestAddress(0),
            mem_space: sys_mem,
        }
    }

    fn entry(&self, key: u16) -> Option<&FwCfgEntry> {
        let entries = if key & FW_CFG_ARCH_LOCAL != 0 {
            &self.arch_entries
        } else {
            &self.entries
        };
        entries.get(usize::from(key & FW_CFG_ENTRY_MASK))
    }

    fn entry_mut(&mut self, key: u16) -> Option<&mut FwCfgEntry> {
        let entries = if key & FW_CFG_ARCH_LOCAL != 0 {
            &mut self.arch_entries
        } else {
            &mut self.entries
        };
        entries.get_mut(usize::from(key & FW_CFG_ENTRY_MASK))
    }

    fn select_entry(&mut self, key: u16) {
        self.cur_offset = 0;
        let valid = self.entry(key).is_some();
        self.cur_entry = if valid { key } else { FW_CFG_INVALID };
        if let Some(callback) = self.entry(key).and_then(|entry| entry.select_cb.as_ref()) {
            callback.select_callback();
        }
        trace::fwcfg_select_entry(key, get_key_name(key as usize), i32::from(valid));
    }

    fn add_entry(&mut self, key: FwCfgEntryType, data: Vec<u8>) -> Result<()> {
        let key = key as u16;
        if u32::try_from(data.len()).is_err() {
            return Err(anyhow!(LegacyError::InvalidFwCfgEntry(key)));
        }
        let entry = self
            .entry_mut(key)
            .with_context(|| LegacyError::InvalidFwCfgEntry(key))?;
        if !entry.data.is_empty() {
            warn!("overriding fwcfg entry {:#x}", key);
        }
        trace::fwcfg_add_entry(key, get_key_name(key as usize), data.len());
        *entry = FwCfgEntry::new(data, None, None, false);
        Ok(())
    }

    fn rebuild_file_directory(&mut self) {
        let directory = &mut self.entries[FwCfgEntryType::FileDir as usize].data;
        directory.clear();
        directory.reserve(4 + self.files.len() * 64);
        directory.extend_from_slice(&(self.files.len() as u32).to_be_bytes());
        for file in &self.files {
            file.append_to(directory);
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
        if self.files.len() >= usize::from(FW_CFG_FILE_SLOTS_DFLT) {
            return Err(anyhow!(LegacyError::FileSlotsNotAvailable(
                filename.to_owned()
            )));
        }

        let name = FwCfgFile::encode_name(filename)?;
        let index = match self.files.binary_search_by_key(&name, |file| file.name) {
            Ok(_) => return Err(anyhow!(LegacyError::DuplicateFile(filename.to_owned()))),
            Err(index) => index,
        };
        let size = u32::try_from(data.len()).context("fwcfg file is too large")?;
        let first = usize::from(FW_CFG_FILE_FIRST);
        self.entries[first + index..=first + self.files.len()].rotate_right(1);
        self.entries[first + index] = FwCfgEntry::new(data, select_cb, write_cb, allow_write);
        self.files.insert(
            index,
            FwCfgFile {
                size,
                select: FW_CFG_FILE_FIRST + index as u16,
                name,
            },
        );
        for file in &mut self.files[index + 1..] {
            file.select += 1;
        }
        self.rebuild_file_directory();

        trace::fwcfg_add_file(index, filename, size as usize);
        Ok(())
    }

    fn modify_file(&mut self, filename: &str, data: Vec<u8>) -> Result<()> {
        let name = FwCfgFile::encode_name(filename)?;
        let index = self
            .files
            .binary_search_by_key(&name, |file| file.name)
            .ok()
            .with_context(|| LegacyError::EntryNotFound(filename.to_owned()))?;
        let file = &mut self.files[index];
        file.size = u32::try_from(data.len()).context("fwcfg file is too large")?;
        self.entries[usize::from(file.select)] = FwCfgEntry::new(data, None, None, true);
        self.rebuild_file_directory();
        Ok(())
    }

    fn handle_dma_request(&mut self) -> Result<()> {
        let addr = std::mem::replace(&mut self.dma_addr, GuestAddress(0));
        let size = std::mem::size_of::<FwCfgDmaAccess>() as u64;
        let result = addr
            .0
            .checked_add(size - 1)
            .context("fwcfg DMA descriptor address overflows")
            .and_then(|_| {
                self.mem_space
                    .read_object::<FwCfgDmaAccess>(addr, AddressAttr::Ram)
                    .with_context(|| LegacyError::ReadDmaRequest(addr.0, size))
            })
            .and_then(|request| self.transfer_dma(request));
        let status = if let Err(err) = result {
            debug!("fwcfg DMA request at {:#x} failed: {:#}", addr.0, err);
            FW_CFG_DMA_CTL_ERROR
        } else {
            0
        };
        trace::fwcfg_read_data(0);

        self.mem_space
            .write_object(&status.to_be(), addr, AddressAttr::Ram)
            .with_context(|| format!("failed to write fwcfg DMA status at {:#x}", addr.0))
    }

    fn transfer_dma(&mut self, request: FwCfgDmaAccess) -> Result<()> {
        let control = u32::from_be(request.control);
        if control & FW_CFG_DMA_CTL_SELECT != 0 {
            self.select_entry((control >> 16) as u16);
        }
        let length = u32::from_be(request.length) as usize;
        if length == 0 {
            return Ok(());
        }

        let address = u64::from_be(request.address);
        let offset = self.cur_offset as usize;
        let remaining = self
            .entry(self.cur_entry)
            .and_then(|entry| entry.data.get(offset..))
            .unwrap_or_default();
        let count = length.min(remaining.len());

        // READ takes precedence over WRITE, then SKIP.
        if control & (FW_CFG_DMA_CTL_READ | FW_CFG_DMA_CTL_WRITE) != 0 {
            address
                .checked_add(length as u64 - 1)
                .context("fwcfg DMA buffer address overflows")?;
        }
        let next_offset = self
            .cur_offset
            .checked_add(count as u32)
            .context("fwcfg cur_offset overflow")?;
        let transfer_result = if control & FW_CFG_DMA_CTL_READ != 0 {
            (|| -> Result<()> {
                if count != 0 {
                    self.mem_space.write_bytes(
                        &remaining[..count],
                        GuestAddress(address),
                        AddressAttr::Ram,
                    )?;
                }
                // AddressSpace::write consumes the entire reader into a buffer.
                static ZEROES: [u8; 64 * 1024] = [0; 64 * 1024];
                for start in (count..length).step_by(ZEROES.len()) {
                    let size = (length - start).min(ZEROES.len());
                    self.mem_space.write_bytes(
                        &ZEROES[..size],
                        GuestAddress(address + start as u64),
                        AddressAttr::Ram,
                    )?;
                }
                Ok(())
            })()
        } else if control & FW_CFG_DMA_CTL_WRITE != 0 {
            self.write_dma_entry(GuestAddress(address), offset, length, count)
        } else if control & FW_CFG_DMA_CTL_SKIP != 0 {
            Ok(())
        } else {
            return Ok(());
        };

        self.cur_offset = next_offset;
        transfer_result?;
        Ok(())
    }

    fn write_dma_entry(
        &mut self,
        address: GuestAddress,
        offset: usize,
        length: usize,
        count: usize,
    ) -> Result<()> {
        let key = self.cur_entry;
        let entry = self.entry(key).context("missing fwcfg entry")?;
        if !entry.allow_write || count != length {
            bail!("fwcfg DMA write to read-only item or past end of item");
        }
        let callback = entry.write_cb.clone();
        let mut callback = callback
            .as_ref()
            .map(|cb| {
                cb.lock()
                    .map_err(|_| anyhow!("fwcfg write callback lock is poisoned"))
            })
            .transpose()?;

        // A guest memory read can fail after copying part of the request.
        let mut data = Vec::new();
        data.try_reserve_exact(length)?;
        self.mem_space
            .read(&mut data, address, length as u64, AddressAttr::Ram)?;
        let entry = self.entry_mut(key).context("missing fwcfg entry")?;
        entry.data[offset..offset + length].copy_from_slice(&data);
        if let Some(cb) = callback.as_mut() {
            cb.write_callback(data, offset as u64, length);
        }
        Ok(())
    }

    fn dma_mem_write(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        if !self.dma_enabled {
            bail!("fwcfg DMA is disabled");
        }
        match (addr, data.len()) {
            (0, 4) => self.dma_addr = GuestAddress(u64::from(BigEndian::read_u32(data)) << 32),
            (4, 4) => {
                self.dma_addr.0 |= u64::from(BigEndian::read_u32(data));
                self.handle_dma_request()?;
            }
            (0, 8) => {
                self.dma_addr = GuestAddress(BigEndian::read_u64(data));
                self.handle_dma_request()?;
            }
            _ => bail!(
                "invalid fwcfg DMA register write at offset {:#x}, size {}",
                addr,
                data.len()
            ),
        }
        Ok(())
    }

    fn dma_mem_read(&self, offset: usize, data: &mut [u8]) -> bool {
        let signature = FW_CFG_DMA_SIGNATURE.get(offset..).unwrap_or_default();
        if !self.dma_enabled || data.len() > signature.len() {
            return false;
        }
        data.copy_from_slice(&signature[..data.len()]);
        true
    }

    fn read_data_reg(&mut self, data: &mut [u8]) {
        let offset = self.cur_offset as usize;
        let remaining = self
            .entry(self.cur_entry)
            .and_then(|entry| entry.data.get(offset..))
            .unwrap_or_default();
        let count = data.len().min(remaining.len());
        data[..count].copy_from_slice(&remaining[..count]);
        data[count..].fill(0);
        self.cur_offset += count as u32;

        for chunk in data.chunks(8) {
            let mut value = [0; 8];
            value[8 - chunk.len()..].copy_from_slice(chunk);
            trace::fwcfg_read_data(u64::from_be_bytes(value));
        }
    }

    fn common_realize(&mut self) -> Result<()> {
        // Firmware configurations add Signature item
        let sig = b"QEMU";
        self.add_entry(FwCfgEntryType::Signature, sig.to_vec())?;

        self.add_entry(FwCfgEntryType::NoGraphic, (0_u16).as_bytes().to_vec())?;

        self.add_entry(FwCfgEntryType::BootMenu, (0_u16).as_bytes().to_vec())?;

        // Add FileDir item
        self.add_entry(FwCfgEntryType::FileDir, Vec::new())?;

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
        self.add_entry(FwCfgEntryType::Id, version.to_le_bytes().to_vec())?;
        Ok(())
    }

    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let fwcfg_state = FwCfgState {
            cur_entry: self.cur_entry,
            cur_offset: self.cur_offset,
            dma_enabled: u8::from(self.dma_enabled),
            dma_addr: self.dma_addr.0,
        };

        Ok(serde_json::to_vec(&fwcfg_state)?)
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let fwcfg_state: FwCfgState = serde_json::from_slice(state)
            .with_context(|| MigrationError::FromBytesError("FwCfgState"))?;
        if fwcfg_state.dma_enabled != 0 && fwcfg_state.dma_enabled != 1 {
            bail!(
                "fwcfg dma_enabled state is error: {}",
                fwcfg_state.dma_enabled
            );
        }
        self.cur_entry = fwcfg_state.cur_entry;
        self.cur_offset = fwcfg_state.cur_offset;
        self.dma_enabled = fwcfg_state.dma_enabled == 1;
        self.dma_addr = GuestAddress(fwcfg_state.dma_addr);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&FwCfgState::descriptor().name).unwrap_or(!0)
    }
}

/// FwCfg MMIO Device use for AArch64 platform
#[cfg(target_arch = "aarch64")]
pub struct FwCfgMem {
    base: SysBusDevBase,
    fwcfg: FwCfgCommon,
}

#[cfg(target_arch = "aarch64")]
impl FwCfgMem {
    pub fn new(
        sys_mem: Arc<AddressSpace>,
        sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
    ) -> Result<Self> {
        let mut fwcfgmem = FwCfgMem {
            base: SysBusDevBase::new(SysBusDevType::FwCfg),
            fwcfg: FwCfgCommon::new(sys_mem),
        };
        fwcfgmem
            .set_sys_resource(sysbus, region_base, region_size, "FwCfgMem")
            .with_context(|| "Failed to allocate system resource for FwCfg.")?;
        fwcfgmem.set_parent_bus(sysbus.clone());

        Ok(fwcfgmem)
    }
}

#[cfg(target_arch = "aarch64")]
impl FwCfgOps for FwCfgMem {
    fn fw_cfg_common(&mut self) -> &mut FwCfgCommon {
        &mut self.fwcfg
    }
}

#[cfg(target_arch = "aarch64")]
impl Device for FwCfgMem {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        Ok(())
    }

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self
            .parent_bus()
            .and_then(|bus| bus.upgrade())
            .context("fwcfg system bus is unavailable")?;
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        self.fwcfg.common_realize()?;
        let dev = Arc::new(Mutex::new(self));
        sysbus
            .attach_device(&dev)
            .with_context(|| "Failed to attach FwCfg device to system bus.")?;

        MigrationManager::register_device_instance(
            FwCfgState::descriptor(),
            dev.clone(),
            FWCFG_SNAPSHOT_ID,
        );
        Ok(dev)
    }
}

#[cfg(target_arch = "aarch64")]
impl SysBusDevOps for FwCfgMem {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0..=7 => self.fwcfg.read_data_reg(data),
            8..=15 => data.fill(0),
            16..=23 => return self.fwcfg.dma_mem_read((offset - 16) as usize, data),
            _ => return false,
        }
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0..=7 => {
                error!("Write to FwCfg data register is not supported.");
            }
            8..=15 => {
                // Write to FwCfg control register
                let key = match data.len() {
                    1 => u16::from(data[0]),
                    2 | 4 | 8 => BigEndian::read_u16(&data[data.len() - 2..]),
                    _ => return false,
                };
                self.fwcfg.select_entry(key);
            }
            16..=23 => {
                if let Err(e) = self.fwcfg.dma_mem_write(offset - 0x10, data) {
                    error!("Failed to write dma at offset=0x{:x} {:?}.", offset, e);
                    return false;
                }
            }
            _ => {
                error!("Failed to write FwCfg, offset 0x{:x} is invalid", offset);
                return false;
            }
        }
        true
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        region_name: &str,
    ) -> Result<()> {
        self.sysbusdev_base_mut()
            .set_sys(-1, region_base, region_size, region_name);
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl StateTransfer for FwCfgMem {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.fwcfg.get_state_vec()
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        self.fwcfg.set_state_mut(state)
    }

    fn get_device_alias(&self) -> u64 {
        self.fwcfg.get_device_alias()
    }
}

#[cfg(target_arch = "aarch64")]
impl MigrationHook for FwCfgMem {}

#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "x86_64")]
pub struct FwCfgIO {
    base: SysBusDevBase,
    fwcfg: FwCfgCommon,
}

#[cfg(target_arch = "x86_64")]
impl FwCfgIO {
    pub fn new(sys_mem: Arc<AddressSpace>, sysbus: &Arc<Mutex<SysBus>>) -> Result<Self> {
        let mut fwcfg = FwCfgIO {
            base: SysBusDevBase::new(SysBusDevType::FwCfg),
            fwcfg: FwCfgCommon::new(sys_mem),
        };
        fwcfg
            .set_sys_resource(sysbus, FW_CFG_IO_BASE, FW_CFG_IO_SIZE, "FwCfgIO")
            .with_context(|| "Failed to allocate system resource for FwCfg.")?;
        fwcfg.set_parent_bus(sysbus.clone());

        Ok(fwcfg)
    }
}

#[cfg(target_arch = "x86_64")]
impl FwCfgOps for FwCfgIO {
    fn fw_cfg_common(&mut self) -> &mut FwCfgCommon {
        &mut self.fwcfg
    }
}

#[cfg(target_arch = "x86_64")]
impl Device for FwCfgIO {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        Ok(())
    }

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self
            .parent_bus()
            .and_then(|bus| bus.upgrade())
            .context("fwcfg system bus is unavailable")?;
        MUT_SYS_BUS!(parent_bus, locked_bus, sysbus);
        self.fwcfg.common_realize()?;
        let dev = Arc::new(Mutex::new(self));
        sysbus
            .attach_device(&dev)
            .with_context(|| "Failed to attach FwCfg device to system bus.")?;

        MigrationManager::register_device_instance(
            FwCfgState::descriptor(),
            dev.clone(),
            FWCFG_SNAPSHOT_ID,
        );

        Ok(dev)
    }
}

#[cfg(target_arch = "x86_64")]
impl SysBusDevOps for FwCfgIO {
    gen_base_func!(sysbusdev_base, sysbusdev_base_mut, SysBusDevBase, base);

    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0..=1 => self.fwcfg.read_data_reg(data),
            4..=11 => return self.fwcfg.dma_mem_read((offset - 4) as usize, data),
            _ => return false,
        }
        true
    }

    fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool {
        let size = data.len();
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
                if let Err(e) = self.fwcfg.dma_mem_write(offset - 4, data) {
                    error!("Failed to handle FwCfg DMA-write, error is {:?}", e);
                    return false;
                }
            }
            _ => {
                // This should never happen
                error!(
                    "Failed to write FwCfg, ioport 0x{:x} is invalid",
                    base.0.saturating_add(offset)
                );
                return false;
            }
        }
        true
    }

    fn set_sys_resource(
        &mut self,
        _sysbus: &Arc<Mutex<SysBus>>,
        region_base: u64,
        region_size: u64,
        region_name: &str,
    ) -> Result<()> {
        self.sysbusdev_base_mut()
            .set_sys(-1, region_base, region_size, region_name);
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
impl StateTransfer for FwCfgIO {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.fwcfg.get_state_vec()
    }

    fn set_state_mut(&mut self, state: &[u8], _version: u32) -> Result<()> {
        self.fwcfg.set_state_mut(state)
    }

    fn get_device_alias(&self) -> u64 {
        self.fwcfg.get_device_alias()
    }
}

#[cfg(target_arch = "x86_64")]
impl MigrationHook for FwCfgIO {}

pub trait FwCfgOps: Send + Sync {
    fn fw_cfg_common(&mut self) -> &mut FwCfgCommon;

    /// Add an entry to FwCfg device, with Vector content.
    ///
    /// # Arguments
    ///
    /// * `key` - FwCfgEntryType
    /// * `data` - Raw data bytes of the entry to be added
    fn add_data_entry(&mut self, key: FwCfgEntryType, data: Vec<u8>) -> Result<()> {
        self.fw_cfg_common().add_entry(key, data)
    }

    /// Add an entry to FwCfg device, with String content.
    ///
    /// # Arguments
    ///
    /// * `key` - FwCfgEntryType
    /// * `value` - string data entry to be added
    fn add_string_entry(&mut self, key: FwCfgEntryType, value: &str) -> Result<()> {
        let mut bytes = Vec::with_capacity(value.len() + 1);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0_u8);
        self.fw_cfg_common().add_entry(key, bytes)
    }

    /// Add a file entry to FwCfg device, with select callback function and
    /// write callback function.
    ///
    /// # Arguments
    ///
    /// * `filename`    - Name of the file
    /// * `data`        - Raw data bytes of the file to be added
    /// * `select_cb`   - Select callback
    /// * `write_cb`    - Write callback
    /// * `allow_write` - Does the file allow write
    fn add_file_callback_entry(
        &mut self,
        filename: &str,
        data: Vec<u8>,
        select_cb: Option<FwCfgCallbackType>,
        write_cb: Option<FwCfgWriteCallbackType>,
        allow_write: bool,
    ) -> Result<()> {
        self.fw_cfg_common()
            .add_file_callback(filename, data, select_cb, write_cb, allow_write)
    }

    /// Add a file entry to FwCfg device, without callbacks, write-allow.
    ///
    /// # Arguments
    ///
    /// * `filename` - Name of the file
    /// * `data` - Raw data bytes of the file to be added
    fn add_file_entry(&mut self, filename: &str, data: Vec<u8>) -> Result<()> {
        self.fw_cfg_common()
            .add_file_callback(filename, data, None, None, true)
    }

    /// Modify a file entry to FwCfg device, without callbacks, write-allow.
    ///
    /// # Arguments
    ///
    /// * `filename` - Name of the file
    /// * `data` - Raw data bytes of the file to be modified
    fn modify_file_entry(&mut self, filename: &str, data: Vec<u8>) -> Result<()> {
        self.fw_cfg_common().modify_file(filename, data)
    }
}

#[cfg(target_arch = "aarch64")]
impl AmlBuilder for FwCfgMem {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("FWCF");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlString("QEMU0002".to_string())));
        acpi_dev.append_child(AmlNameDecl::new("_STA", AmlInteger(0xB)));
        acpi_dev.append_child(AmlNameDecl::new("_CCA", AmlInteger(0x1)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlMemory32Fixed::new(
            AmlReadAndWrite::ReadWrite,
            self.base.res.region_base as u32,
            self.base.res.region_size as u32,
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.aml_bytes()
    }
}

#[cfg(target_arch = "x86_64")]
impl AmlBuilder for FwCfgIO {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("FWCF");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlString("QEMU0002".to_string())));
        acpi_dev.append_child(AmlNameDecl::new("_STA", AmlInteger(0xB)));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlIoResource::new(
            AmlIoDecode::Decode16,
            self.base.res.region_base as u16,
            self.base.res.region_base as u16,
            0x01,
            self.base.res.region_size as u8,
        ));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.aml_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sysbus::sysbus_init;
    use crate::test::address_space_init;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn arch_entry_registration_uses_the_entry_key() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        fwcfg
            .add_entry(FwCfgEntryType::E820Table, vec![1, 2])
            .unwrap();
        assert!(fwcfg
            .entry(FwCfgEntryType::RamSize as u16)
            .unwrap()
            .data
            .is_empty());
        fwcfg.select_entry(FwCfgEntryType::E820Table as u16);
        let mut data = [0; 2];
        fwcfg.read_data_reg(&mut data);
        assert_eq!(data, [1, 2]);
    }

    #[test]
    fn file_directory_matches_full_names_and_updates_when_full() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        fwcfg.select_entry(FW_CFG_ARCH_LOCAL);
        fwcfg
            .add_file_callback("aa", vec![2], None, None, false)
            .unwrap();
        fwcfg
            .add_file_callback("a", vec![1], None, None, false)
            .unwrap();
        assert!(fwcfg
            .add_file_callback("a", vec![], None, None, false)
            .is_err());
        assert!(fwcfg
            .add_file_callback(&"x".repeat(56), vec![], None, None, false)
            .is_err());
        assert!(fwcfg.modify_file("a\0", vec![]).is_err());
        assert_eq!(fwcfg.entry(FW_CFG_FILE_FIRST + 1).unwrap().data, [2]);
        for index in 2..FW_CFG_FILE_SLOTS_DFLT {
            fwcfg
                .add_file_callback(&format!("other/{index:02}"), vec![], None, None, false)
                .unwrap();
        }
        fwcfg.modify_file("a", vec![3, 4]).unwrap();

        let dir = &fwcfg.entry(FwCfgEntryType::FileDir as u16).unwrap().data;
        assert_eq!(&dir[..4], &u32::from(FW_CFG_FILE_SLOTS_DFLT).to_be_bytes());
        assert_eq!(&dir[4..12], &[0, 0, 0, 2, 0, 0x20, 0, 0]);
        assert_eq!(&dir[12..14], b"a\0");
        assert_eq!(&dir[76..79], b"aa\0");
        assert_eq!(
            fwcfg.entries.len(),
            usize::from(FW_CFG_FILE_FIRST + FW_CFG_FILE_SLOTS_DFLT)
        );
    }

    fn submit_dma(fwcfg: &mut FwCfgCommon, control: u32, length: u32, address: u64) -> u32 {
        let addr = GuestAddress(0);
        let request = FwCfgDmaAccess {
            control: control.to_be(),
            length: length.to_be(),
            address: address.to_be(),
        };
        fwcfg
            .mem_space
            .write_object(&request, addr, AddressAttr::Ram)
            .unwrap();
        fwcfg.dma_addr = addr;
        fwcfg.handle_dma_request().unwrap();
        u32::from_be(
            fwcfg
                .mem_space
                .read_object::<u32>(addr, AddressAttr::Ram)
                .unwrap(),
        )
    }

    #[test]
    fn dma_skip_and_select_preserve_stream_position() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        fwcfg.common_realize().unwrap();
        fwcfg.select_entry(FW_CFG_INVALID);
        let mut data = [0xff; 4];
        fwcfg.read_data_reg(&mut data);
        assert_eq!(data, [0; 4]);
        assert_eq!(
            submit_dma(
                &mut fwcfg,
                FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_SKIP,
                2,
                0
            ),
            0
        );
        assert_eq!(fwcfg.cur_offset, 2);
        let control = FW_CFG_DMA_CTL_READ | FW_CFG_DMA_CTL_WRITE | FW_CFG_DMA_CTL_SKIP;
        assert_eq!(submit_dma(&mut fwcfg, control, 4, 0x1000), 0);
        let value = fwcfg
            .mem_space
            .read_object::<u32>(GuestAddress(0x1000), AddressAttr::Ram)
            .unwrap();
        assert_eq!(value.to_ne_bytes(), *b"MU\0\0");
        assert_eq!(fwcfg.cur_offset, 4);

        let control =
            FW_CFG_DMA_CTL_READ | FW_CFG_DMA_CTL_SELECT | (u32::from(FW_CFG_INVALID) << 16);
        assert_eq!(submit_dma(&mut fwcfg, control, 4, 0x1000), 0);
        assert_eq!(
            fwcfg
                .mem_space
                .read_object::<u32>(GuestAddress(0x1000), AddressAttr::Ram)
                .unwrap(),
            0
        );
        assert_eq!(
            submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_READ, 4, u64::MAX),
            FW_CFG_DMA_CTL_ERROR
        );
    }

    #[test]
    fn rejected_dma_writes_leave_the_item_unchanged() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        fwcfg
            .add_entry(FwCfgEntryType::Signature, b"QEMU".to_vec())
            .unwrap();
        fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        assert_eq!(
            submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_WRITE, 4, 0x1000),
            FW_CFG_DMA_CTL_ERROR
        );
        assert_eq!(fwcfg.entry(0).unwrap().data, b"QEMU");
        assert_eq!(fwcfg.cur_offset, 4);

        fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        fwcfg
            .add_entry(FwCfgEntryType::Signature, b"QEMU".to_vec())
            .unwrap();
        fwcfg
            .entry_mut(FwCfgEntryType::Signature as u16)
            .unwrap()
            .allow_write = true;
        // The first two bytes are in RAM and the remaining two are unmapped.
        assert_eq!(
            submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_WRITE, 4, 0x0fff_fffe),
            FW_CFG_DMA_CTL_ERROR
        );
        assert_eq!(
            submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_WRITE, 5, 0x1000),
            FW_CFG_DMA_CTL_ERROR
        );
        assert_eq!(fwcfg.cur_offset, 4);
        assert_eq!(fwcfg.entry(0).unwrap().data, b"QEMU");
        fwcfg.select_entry(FwCfgEntryType::Signature as u16);
        assert_eq!(submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_WRITE, 2, 0x1000), 0);
        assert_eq!(fwcfg.entry(0).unwrap().data, b"\0\0MU");
        assert_eq!(fwcfg.cur_offset, 2);
    }

    #[test]
    fn failed_dma_read_advances_entry_offset() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        fwcfg
            .add_entry(FwCfgEntryType::Signature, b"QEMU".to_vec())
            .unwrap();
        fwcfg.select_entry(FwCfgEntryType::Signature as u16);

        assert_eq!(
            submit_dma(&mut fwcfg, FW_CFG_DMA_CTL_READ, 4, 0x0fff_fffe),
            FW_CFG_DMA_CTL_ERROR
        );
        assert_eq!(fwcfg.cur_offset, 4);
    }

    #[test]
    fn dma_register_rejects_out_of_range_accesses() {
        let mut fwcfg = FwCfgCommon::new(address_space_init());
        assert!(!fwcfg.dma_mem_read(7, &mut [0; 2]));
        assert!(fwcfg.dma_mem_write(1, &[0; 4]).is_err());
        let mut data = [0];
        assert!(fwcfg.dma_mem_read(7, &mut data));
        assert_eq!(data, *b"G");
    }

    #[test]
    fn test_entry_functions() {
        let sys_mem = address_space_init();
        let mut fwcfg_common = FwCfgCommon::new(sys_mem);

        let ncpus: usize = 1;
        fwcfg_common
            .add_entry(FwCfgEntryType::NbCpus, ncpus.as_bytes().to_vec())
            .unwrap();
        assert_eq!(
            fwcfg_common.entries[FwCfgEntryType::NbCpus as usize].data,
            ncpus.as_bytes().to_vec()
        );

        let cmdline =
            "console=ttyAMA0 reboot=t panic=1 tsc=reliable ipv6.disable=1 root=/dev/vda rw"
                .to_string();
        fwcfg_common
            .add_entry(
                FwCfgEntryType::CmdlineSize,
                (cmdline.len() + 1).as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(
            fwcfg_common.entries[FwCfgEntryType::CmdlineSize as usize].data,
            (cmdline.len() + 1).as_bytes().to_vec()
        );

        fwcfg_common
            .add_entry(FwCfgEntryType::CmdlineData, cmdline.as_bytes().to_vec())
            .unwrap();
        assert_eq!(
            fwcfg_common.entries[FwCfgEntryType::CmdlineData as usize].data,
            cmdline.as_bytes().to_vec()
        );

        let boot_order = Vec::<u8>::new();
        fwcfg_common
            .add_entry(FwCfgEntryType::FileDir, boot_order)
            .unwrap();
        assert_eq!(
            fwcfg_common.entries[FwCfgEntryType::FileDir as usize].data,
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_file_entry() {
        let sys_mem = address_space_init();
        let mut fwcfg_common = FwCfgCommon::new(sys_mem);
        assert!(fwcfg_common.common_realize().is_ok());

        let file_data = vec![0xcc; 200];
        assert!(fwcfg_common
            .add_file_callback("xyz", file_data.clone(), None, None, false)
            .is_ok());
        let id = fwcfg_common.files.last().unwrap().select;
        fwcfg_common.select_entry(id);
        let entry = fwcfg_common.entry(fwcfg_common.cur_entry).unwrap();
        assert_eq!(entry.data, file_data);

        let file_data = vec![0x8b; 200];
        assert!(fwcfg_common
            .add_file_callback("def", file_data.clone(), None, None, false)
            .is_ok());
        let id = fwcfg_common.files[0].select;
        fwcfg_common.select_entry(id);
        let entry = fwcfg_common.entry(fwcfg_common.cur_entry).unwrap();
        assert_eq!(entry.data, file_data);

        let file_data = Vec::new();
        assert!(fwcfg_common
            .add_file_callback("bootorder", file_data.clone(), None, None, false)
            .is_ok());
        let id = fwcfg_common.files[0].select;
        fwcfg_common.select_entry(id);
        let entry = fwcfg_common.entry(fwcfg_common.cur_entry).unwrap();
        assert_eq!(entry.data, file_data);

        let modify_file_data = "/pci@ffffffffffffffff/pci-bridge@3/scsi@0,1/disk@0,0"
            .as_bytes()
            .to_vec();
        assert!(fwcfg_common
            .modify_file("bootorder", modify_file_data.clone())
            .is_ok());
        let id = fwcfg_common.files[0].select;
        fwcfg_common.select_entry(id);
        let entry = fwcfg_common.entry(fwcfg_common.cur_entry).unwrap();
        assert_eq!(entry.data, modify_file_data);

        assert!(fwcfg_common
            .modify_file("abc", modify_file_data.clone())
            .is_err());
        let file_data = vec![0x33; 500];
        assert!(fwcfg_common
            .add_file_callback("abc", file_data.clone(), None, None, false)
            .is_ok());
        let id = fwcfg_common.files[0].select;
        fwcfg_common.select_entry(id);
        let entry = fwcfg_common.entry(fwcfg_common.cur_entry).unwrap();
        assert_eq!(entry.data, file_data);
    }

    #[test]
    fn test_dma_functions() {
        let sys_mem = address_space_init();
        let mut fwcfg_common = FwCfgCommon::new(sys_mem);
        assert!(fwcfg_common.common_realize().is_ok());

        // [1]write dma request.
        let mut dma_req = FwCfgDmaAccess::default();
        dma_req.length = u32::from_bytes(&4_u32.to_be_bytes()).unwrap();
        dma_req.address = u64::from_bytes(&0xffff_u64.to_be_bytes()).unwrap();
        dma_req.control = u32::from_bytes(&FW_CFG_DMA_CTL_READ.to_be_bytes()).unwrap();
        let dma_request = dma_req.as_mut_bytes();
        let addr = GuestAddress(0x0000);
        fwcfg_common
            .mem_space
            .write(
                &mut dma_request.as_ref(),
                addr,
                dma_request.len() as u64,
                AddressAttr::Ram,
            )
            .unwrap();

        // [2]set dma addr.
        fwcfg_common.dma_addr = addr;

        // [3]handle dma request.
        assert!(fwcfg_common.handle_dma_request().is_ok());

        // [4]check dma response.
        assert_eq!(
            fwcfg_common
                .mem_space
                .read_object::<u32>(addr, AddressAttr::Ram)
                .unwrap(),
            0
        );

        // [5]check dma write result.
        let mut read_dma_buf = Vec::new();
        let sig_entry_data = [b'Q', b'E', b'M', b'U'];
        let len = sig_entry_data.len();
        fwcfg_common
            .mem_space
            .read(
                &mut read_dma_buf,
                GuestAddress(0xffff),
                len as u64,
                AddressAttr::Ram,
            )
            .unwrap();
        assert_eq!(read_dma_buf, sig_entry_data);

        // Read uninitialized entry.
        let mut dma_req = FwCfgDmaAccess::default();
        dma_req.length = u32::from_bytes(&8_u32.to_be_bytes()).unwrap();
        dma_req.address = u64::from_bytes(&0xffff_u64.to_be_bytes()).unwrap();
        dma_req.control = u32::from_bytes(&FW_CFG_DMA_CTL_READ.to_be_bytes()).unwrap();
        let dma_request = dma_req.as_mut_bytes();
        let addr = GuestAddress(0x0000);
        fwcfg_common
            .mem_space
            .write(
                &mut dma_request.as_ref(),
                addr,
                dma_request.len() as u64,
                AddressAttr::Ram,
            )
            .unwrap();

        fwcfg_common.dma_addr = addr;

        assert!(fwcfg_common.handle_dma_request().is_ok());

        // Result should be all zero.
        assert_eq!(
            fwcfg_common
                .mem_space
                .read_object::<u32>(addr, AddressAttr::Ram)
                .unwrap(),
            0
        );

        let mut read_dma_buf = Vec::new();
        let all_zero = vec![0x0_u8; 4];
        let len = all_zero.len();
        fwcfg_common
            .mem_space
            .read(
                &mut read_dma_buf,
                GuestAddress(0xffff),
                len as u64,
                AddressAttr::Ram,
            )
            .unwrap();
        assert_eq!(read_dma_buf, all_zero);
    }

    #[test]
    fn test_large_entry_dma_read_in_one_mb_chunks() {
        const CHUNK_SIZE: usize = 1024 * 1024;
        const CHUNK_COUNT: usize = 128;
        const DMA_BUFFER_START: u64 = 0x0800_0000;

        let sys_mem = address_space_init();
        let mut fwcfg_common = FwCfgCommon::new(sys_mem);
        fwcfg_common.common_realize().unwrap();

        let mut initrd_data = vec![0_u8; CHUNK_SIZE * CHUNK_COUNT];
        for (index, chunk) in initrd_data.chunks_exact_mut(CHUNK_SIZE).enumerate() {
            chunk.fill(index as u8);
        }
        fwcfg_common
            .add_entry(FwCfgEntryType::InitrdData, initrd_data)
            .unwrap();

        for index in 0..CHUNK_COUNT {
            let mut control = FW_CFG_DMA_CTL_READ;
            if index == 0 {
                control |=
                    FW_CFG_DMA_CTL_SELECT | (u32::from(FwCfgEntryType::InitrdData as u16) << 16);
            }
            let mut dma_req = FwCfgDmaAccess {
                control: control.to_be(),
                length: (CHUNK_SIZE as u32).to_be(),
                address: (DMA_BUFFER_START + (index * CHUNK_SIZE) as u64).to_be(),
            };
            let dma_request = dma_req.as_mut_bytes();
            let descriptor_addr = GuestAddress(0);
            fwcfg_common
                .mem_space
                .write(
                    &mut dma_request.as_ref(),
                    descriptor_addr,
                    dma_request.len() as u64,
                    AddressAttr::Ram,
                )
                .unwrap();
            fwcfg_common.dma_addr = descriptor_addr;
            fwcfg_common.handle_dma_request().unwrap();

            let first = fwcfg_common
                .mem_space
                .read_object::<u8>(
                    GuestAddress(DMA_BUFFER_START + (index * CHUNK_SIZE) as u64),
                    AddressAttr::Ram,
                )
                .unwrap();
            let last = fwcfg_common
                .mem_space
                .read_object::<u8>(
                    GuestAddress(DMA_BUFFER_START + ((index + 1) * CHUNK_SIZE - 1) as u64),
                    AddressAttr::Ram,
                )
                .unwrap();
            assert_eq!(first, index as u8);
            assert_eq!(last, index as u8);
        }

        assert_eq!(fwcfg_common.cur_offset, (CHUNK_SIZE * CHUNK_COUNT) as u32);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_read_write_aarch64() {
        let mut sys_bus = sysbus_init();
        let sys_mem = address_space_init();
        let fwcfg = FwCfgMem::new(sys_mem, &mut sys_bus, 0x0902_0000, 0x0000_0018).unwrap();

        let fwcfg_dev = fwcfg.realize().unwrap();
        // Read FW_CFG_DMA_SIGNATURE entry.
        let base = GuestAddress(0x0000);
        let mut read_data = vec![0xff_u8, 0xff, 0xff, 0xff];
        let offset = 0x10;
        let target_data = vec![0x51_u8, 0x45, 0x4d, 0x55];
        fwcfg_dev.lock().unwrap().read(&mut read_data, base, offset);
        assert_eq!(read_data, target_data);

        // Select entry and read it.
        let write_data = vec![0x0_u8];
        let offset = 0x8;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, true);
        let mut read_data = vec![0xff_u8, 0xff, 0xff, 0xff];
        let offset = 0x4;
        let sig_entry_data = [b'Q', b'E', b'M', b'U'];
        fwcfg_dev.lock().unwrap().read(&mut read_data, base, offset);
        assert_eq!(read_data, sig_entry_data);

        // Failed to write because of offset overflow.
        let write_data = vec![0x0_u8];
        let offset = 0x18;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, false);

        // Illegal write_data length.
        let write_data = vec![0x0_u8];
        let offset = 0x10;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, false);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_read_write_x86_64() {
        let mut sys_bus = sysbus_init();
        let sys_mem = address_space_init();
        let fwcfg = FwCfgIO::new(sys_mem, &mut sys_bus).unwrap();

        let fwcfg_dev = fwcfg.realize().unwrap();
        // Read FW_CFG_DMA_SIGNATURE entry.
        let base = GuestAddress(0x0000);
        let mut read_data = vec![0xff_u8, 0xff, 0xff, 0xff];
        let offset = 0x4;
        let target_data = vec![0x51_u8, 0x45, 0x4d, 0x55];
        fwcfg_dev.lock().unwrap().read(&mut read_data, base, offset);
        assert_eq!(read_data, target_data);

        // Select entry and read it.
        let write_data = vec![0x0_u8, 0x0];
        let offset = 0x0;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, true);
        let mut read_data = vec![0xff_u8, 0xff, 0xff, 0xff];
        let offset = 0x0;
        let sig_entry_data = [b'Q', b'E', b'M', b'U'];
        fwcfg_dev.lock().unwrap().read(&mut read_data, base, offset);
        assert_eq!(read_data, sig_entry_data);

        // Failed to write because of offset overflow.
        let write_data = vec![0x0_u8];
        let offset = 0x0c;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, false);

        // Illegal write_data length.
        let write_data = vec![0x0_u8];
        let offset = 0x0;
        let f_back = fwcfg_dev.lock().unwrap().write(&write_data, base, offset);
        assert_eq!(f_back, false);
    }
}
