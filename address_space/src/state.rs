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
use serde::{Deserialize, Serialize};

use crate::{AddressAttr, AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};
use migration::{DeviceStateDesc, MemBlock, MigrationError, MigrationHook, StateTransfer};
use migration_derive::DescSerde;
use util::aio::ALIGNMENT_SIZE;
use util::num_ops::round_up;
use util::unix::host_page_size;

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

#[derive(Clone, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
pub struct RamRegionState {
    // Region name.
    pub name: String,
    // Offset has different meanings in different region.
    // 1) Address space RAM region: representing the offset from the first address space RAM region.
    // 2) Ramlist RAM region: representing the offset from the first ramlist ram region.
    pub offset: u64,
    // Region size.
    pub size: u64,
}

#[derive(Clone, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
pub struct AliasRegionState {
    // Region name.
    pub name: String,
    // Alias offset.
    pub alias_offset: u64,
    // Region offset.
    pub offset: u64,
    // Region size.
    pub size: u64,
}

#[derive(Clone, Default, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
pub struct AddressSpaceState {
    // Total size of address space memory region.
    total_region_size: u64,
    ram_region_state: Vec<RamRegionState>,
    alias_region_state: Vec<AliasRegionState>,
}

impl StateTransfer for AddressSpace {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = AddressSpaceState::default();
        let mut offset = 0;
        let machine_ram = self
            .get_machine_ram()
            .with_context(|| "This address space does not support migration.")?;
        for region in machine_ram.subregions().iter() {
            state.ram_region_state.push(RamRegionState {
                name: region.name.clone(),
                offset,
                size: region.size(),
            });
            offset += region.size();
            state.total_region_size += region.size();
        }

        for region in self.root().subregions().iter() {
            if region.alias_name().is_some() {
                state.alias_region_state.push(AliasRegionState {
                    name: region.name.clone(),
                    alias_offset: region.alias_offset(),
                    offset: region.offset().0,
                    size: region.size(),
                });
            }
        }

        Ok(serde_json::to_vec(&state)?)
    }

    fn get_device_alias(&self) -> u64 {
        self.root().size()
    }
}

impl MigrationHook for AddressSpace {
    fn save_memory(&self, fd: &mut File) -> Result<()> {
        // Save address space header.
        let ram_state = self.get_state_vec()?;
        let data_slice = get_state_slice(&ram_state)
            .with_context(|| "Failed to get state slice while saving state")?;
        fd.write_all(&data_slice)?;

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
        let data_slice = read_state_slice(memory)
            .with_context(|| "Failed to read state slice while restoring state")?;
        let address_space_state: AddressSpaceState = serde_json::from_slice(&data_slice)
            .with_context(|| MigrationError::FromBytesError("MEMORY"))?;

        if mapped {
            // Get the start pos for saved ram region.
            let first_region_offset = memory.stream_position()?;
            let cloned_file = match memory.try_clone() {
                Ok(file) => file,
                Err(e) => bail!("Failed to clone memory file: {:?}", e),
            };
            let memfile_arc = Arc::new(cloned_file);

            if let Some(machine_ram) = self.get_machine_ram() {
                let mut offset = 0_u64;
                for ram_state in address_space_state.ram_region_state.iter() {
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

                    machine_ram
                        .add_subregion_not_update(
                            Region::init_ram_region(host_mmap.clone(), &ram_state.name),
                            offset,
                        )
                        .map_err(|e| MigrationError::RestoreVmMemoryErr(e.to_string()))?;
                    offset += ram_state.size;
                }
                for alias_state in address_space_state.alias_region_state.iter() {
                    let ram = Region::init_alias_region(
                        machine_ram.clone(),
                        alias_state.alias_offset,
                        alias_state.size,
                        &alias_state.name,
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

pub fn get_state_slice(state: &[u8]) -> Result<Vec<u8>> {
    let state_len = state.len();
    let le_bytes = (state_len as u64).to_le_bytes();
    let le_len = le_bytes.len();
    let total_len = le_len + state_len;

    // Aligned up to ALIGNMENT_SIZE.
    let aligned_len = round_up(total_len as u64, ALIGNMENT_SIZE)
        .with_context(|| format!("Failed to round up, total state length {}", total_len))?;
    let mut data_slice = vec![0u8; aligned_len as usize];
    data_slice[0..le_len].copy_from_slice(&le_bytes);
    data_slice[le_len..total_len].copy_from_slice(state);

    Ok(data_slice)
}

pub fn read_state_slice(file: &mut File) -> Result<Vec<u8>> {
    // Read state length.
    let size = size_of::<u64>();
    let mut le_bytes = vec![0u8; size];
    if let Err(e) = file.read_exact(&mut le_bytes) {
        bail!("Read state length error {:?}", e);
    }
    let state_len = u64::from_le_bytes(le_bytes.try_into().unwrap());
    let total_len = size as u64 + state_len;
    let aligned_len = round_up(total_len, ALIGNMENT_SIZE)
        .with_context(|| format!("Failed to round up, total state len {}", total_len))?;

    // Read state content.
    let mut data_slice = vec![0u8; aligned_len as usize - size];
    if let Err(e) = file.read_exact(&mut data_slice) {
        bail!("Read state content error {:?}", e);
    }

    Ok(data_slice[..state_len as usize].to_vec())
}
