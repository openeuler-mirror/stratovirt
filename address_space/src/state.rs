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
use std::mem::size_of;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::{AddressAttr, AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};
use migration::{
    DeviceStateDesc, FieldDesc, MemBlock, MigrationError, MigrationHook, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::unix::host_page_size;

const MIGRATION_HEADER_LENGTH: usize = 4096;

const ADDRESS_SPACE_MAX_REGIONS_NUMBER: usize = 16;
const MAX_REGION_NAME_SIZE: usize = 64;

// -------------------------------------------
// |    MIGRATION HEADER (4096 align)        |
// -------------------------------------------
// |    Address Space Header (4096 align)    |
// -------------------------------------------
// |    Address Space Region Data            |
// -------------------------------------------
// |    RamList Region Header                |
// -------------------------------------------
// |    RamList Region Data                  |
// -------------------------------------------

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct RamRegionState {
    // Region name's size.
    pub name_size: u32,
    // Region name.
    pub name: [u8; MAX_REGION_NAME_SIZE],
    // Offset has different meanings in different region.
    // 1) Address space RAM region: representing the offset from the first address space RAM region.
    // 2) Ramlist RAM region: representing the offset from the first ramlist ram region.
    pub offset: u64,
    // Region size.
    pub size: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct AliasRegionState {
    // Region name's size.
    pub name_size: u32,
    // Region name.
    pub name: [u8; MAX_REGION_NAME_SIZE],
    // Alias offset.
    pub alias_offset: u64,
    // Region offset.
    pub offset: u64,
    // Region size.
    pub size: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct AddressSpaceState {
    // Total size of address space memory region.
    total_region_size: u64,
    // The number of ram region.
    nr_ram_region: u64,
    ram_region_state: [RamRegionState; ADDRESS_SPACE_MAX_REGIONS_NUMBER],
    // The number of ram region.
    nr_alias_region: u64,
    alias_region_state: [AliasRegionState; ADDRESS_SPACE_MAX_REGIONS_NUMBER],
}

// To get the offset to memory data in memory snapshot file.
// It would be changed when pagesize changed.
fn memory_offset() -> usize {
    let page_size = host_page_size() as usize;
    if page_size >= MIGRATION_HEADER_LENGTH + size_of::<AddressSpaceState>() {
        page_size
    } else {
        page_size * 2
    }
}

impl StateTransfer for AddressSpace {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = AddressSpaceState::default();
        let mut offset = 0;
        let machine_ram = self
            .get_machine_ram()
            .with_context(|| "This address space does not support migration.")?;
        for region in machine_ram.subregions().iter() {
            let name_size = region.name.len().min(MAX_REGION_NAME_SIZE);
            let mut name = [0u8; MAX_REGION_NAME_SIZE];
            name[..name_size].copy_from_slice(&region.name.as_bytes()[..name_size]);
            state.ram_region_state[state.nr_ram_region as usize] = RamRegionState {
                name_size: name_size as u32,
                name,
                offset,
                size: region.size(),
            };
            offset += region.size();
            state.nr_ram_region += 1;
            state.total_region_size += region.size();
        }

        for region in self.root().subregions().iter() {
            if region.alias_name().is_some() {
                let name_size = region.name.len().min(MAX_REGION_NAME_SIZE);
                let mut name = [0u8; MAX_REGION_NAME_SIZE];
                name[..name_size].copy_from_slice(&region.name.as_bytes()[..name_size]);
                state.alias_region_state[state.nr_alias_region as usize] = AliasRegionState {
                    name_size: name_size as u32,
                    name,
                    alias_offset: region.alias_offset(),
                    offset: region.offset().0,
                    size: region.size(),
                };
                state.nr_alias_region += 1;
            }
        }

        Ok(state.as_bytes().to_vec())
    }

    fn get_device_alias(&self) -> u64 {
        self.root().size()
    }
}

impl MigrationHook for AddressSpace {
    fn save_memory(&self, fd: &mut File) -> Result<()> {
        // Save address space header.
        let ram_state = self.get_state_vec()?;
        fd.write_all(&ram_state)?;
        let padding_buffer =
            [0].repeat(memory_offset() - MIGRATION_HEADER_LENGTH - size_of::<AddressSpaceState>());
        fd.write_all(&padding_buffer)?;

        // Save address space region.
        if let Some(machine_ram) = self.get_machine_ram() {
            for region in machine_ram.subregions().iter() {
                if let Some(base_addr) = region.start_addr() {
                    region
                        .read(fd, base_addr, 0, region.size())
                        .map_err(|e| MigrationError::SaveVmMemoryErr(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    fn restore_memory(&self, memory: &mut File, mapped: bool) -> Result<()> {
        let mut state_bytes = [0u8].repeat(memory_offset() - MIGRATION_HEADER_LENGTH);
        if let Err(e) = memory.read_exact(&mut state_bytes) {
            bail!("Read memory file error: {:?}", e);
        }
        let address_space_state: &AddressSpaceState =
            AddressSpaceState::from_bytes(&state_bytes[0..size_of::<AddressSpaceState>()])
                .with_context(|| MigrationError::FromBytesError("MEMORY"))?;

        if mapped {
            let first_region_offset = memory_offset() as u64;
            let cloned_file = match memory.try_clone() {
                Ok(file) => file,
                Err(e) => bail!("Failed to clone memory file: {:?}", e),
            };
            let memfile_arc = Arc::new(cloned_file);

            if let Some(machine_ram) = self.get_machine_ram() {
                let mut offset = 0_u64;
                for ram_state in address_space_state.ram_region_state
                    [0..address_space_state.nr_ram_region as usize]
                    .iter()
                {
                    let file_backend = FileBackend {
                        file: memfile_arc.clone(),
                        offset: ram_state.offset + first_region_offset,
                        page_size: host_page_size(),
                    };
                    let host_mmap = Arc::new(
                        HostMemMapping::new(
                            GuestAddress(0),
                            None,
                            ram_state.size,
                            Some(file_backend),
                            false,
                            false,
                            false,
                        )
                        .map_err(|e| MigrationError::RestoreVmMemoryErr(e.to_string()))?,
                    );

                    let region_name = &ram_state.name[0..ram_state.name_size as usize];
                    let name = String::from_utf8(region_name.to_vec())?;
                    machine_ram
                        .add_subregion_not_update(
                            Region::init_ram_region(host_mmap.clone(), &name),
                            offset,
                        )
                        .map_err(|e| MigrationError::RestoreVmMemoryErr(e.to_string()))?;
                    offset += ram_state.size;
                }
                for alias_state in address_space_state.alias_region_state
                    [0..address_space_state.nr_alias_region as usize]
                    .iter()
                {
                    let region_name = &alias_state.name[0..alias_state.name_size as usize];
                    let name = String::from_utf8(region_name.to_vec())?;
                    let ram = Region::init_alias_region(
                        machine_ram.clone(),
                        alias_state.alias_offset,
                        alias_state.size,
                        &name,
                    );
                    self.root().add_subregion(ram, alias_state.offset)?;
                }
            }
            let region_data_end = first_region_offset
                .checked_add(address_space_state.total_region_size)
                .with_context(|| {
                    format!(
                        "Restore memory add overflow: {} + {}",
                        first_region_offset, address_space_state.total_region_size
                    )
                })?;
            memory.seek(SeekFrom::Start(region_data_end))?;
        } else if let Some(machine_ram) = self.get_machine_ram() {
            for region in machine_ram.subregions().iter() {
                if let Some(base_addr) = region.start_addr() {
                    region
                        .write(memory, base_addr, 0, region.size())
                        .map_err(|e| MigrationError::RestoreVmMemoryErr(e.to_string()))?;
                }
            }
        }

        Ok(())
    }

    fn send_memory(&self, fd: &mut dyn Write, range: MemBlock) -> Result<()> {
        self.read(fd, GuestAddress(range.gpa), range.len, AddressAttr::Ram)
            .map_err(|e| MigrationError::SendVmMemoryErr(e.to_string()))?;

        Ok(())
    }

    fn recv_memory(&self, fd: &mut dyn Read, range: MemBlock) -> Result<()> {
        self.write(fd, GuestAddress(range.gpa), range.len, AddressAttr::Ram)
            .map_err(|e| MigrationError::RecvVmMemoryErr(e.to_string()))?;

        Ok(())
    }
}
