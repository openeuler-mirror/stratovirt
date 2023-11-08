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
use std::io::{Read, Write};
use std::mem::size_of;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::{AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};
use migration::{
    error::MigrationError, DeviceStateDesc, FieldDesc, MemBlock, MigrationHook, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::unix::host_page_size;

const MIGRATION_HEADER_LENGTH: usize = 4096;

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct AddressSpaceState {
    nr_alias_region: u64,
    ram_alias_state: [RamRegionState; 16],
    nr_ram_region: u64,
    ram_region_state: [RamRegionState; 16],
}

#[derive(Copy, Clone, ByteCode)]
pub struct RamRegionState {
    alias_offset: u64,
    size: u64,
    // The offset of this memory region in file backend file.
    offset: u64,
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
        let mut offset = memory_offset() as u64;

        if self.get_machine_ram().is_none() {
            bail!("This address space does not support migration.");
        }

        let machine_ram = self.get_machine_ram().unwrap();
        for region in machine_ram.subregions().iter() {
            state.ram_alias_state[state.nr_alias_region as usize] = RamRegionState {
                alias_offset: 0,
                size: region.size(),
                offset,
            };
            offset += region.size();
            state.nr_alias_region += 1;
        }

        for region in self.root().subregions().iter() {
            if region.alias_name().is_some() {
                state.ram_region_state[state.nr_ram_region as usize] = RamRegionState {
                    alias_offset: region.alias_offset(),
                    size: region.size(),
                    offset: region.offset().0,
                };
                state.nr_ram_region += 1;
            }
        }

        Ok(state.as_bytes().to_vec())
    }

    fn get_device_alias(&self) -> u64 {
        self.root().size()
    }
}

impl MigrationHook for AddressSpace {
    fn save_memory(&self, fd: &mut dyn Write) -> Result<()> {
        let ram_state = self.get_state_vec()?;
        fd.write_all(&ram_state)?;
        let padding_buffer =
            [0].repeat(memory_offset() - MIGRATION_HEADER_LENGTH - size_of::<AddressSpaceState>());
        fd.write_all(&padding_buffer)?;
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

    fn restore_memory(&self, memory: Option<&File>, state: &[u8]) -> Result<()> {
        let address_space_state: &AddressSpaceState =
            AddressSpaceState::from_bytes(&state[0..size_of::<AddressSpaceState>()])
                .with_context(|| MigrationError::FromBytesError("MEMORY"))?;
        let memfile_arc = Arc::new(memory.unwrap().try_clone().unwrap());
        if let Some(machine_ram) = self.get_machine_ram() {
            let mut offset = 0_u64;
            for ram_state in address_space_state.ram_alias_state
                [0..address_space_state.nr_alias_region as usize]
                .iter()
            {
                let file_backend = FileBackend {
                    file: memfile_arc.clone(),
                    offset: ram_state.offset,
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
                        Region::init_ram_region(host_mmap.clone(), "HostMem"),
                        offset,
                    )
                    .map_err(|e| MigrationError::RestoreVmMemoryErr(e.to_string()))?;
                offset += ram_state.size;
            }
            for ram_state in address_space_state.ram_region_state
                [0..address_space_state.nr_ram_region as usize]
                .iter()
            {
                let ram = Region::init_alias_region(
                    machine_ram.clone(),
                    ram_state.alias_offset,
                    ram_state.size,
                    "ram",
                );
                self.root().add_subregion(ram, ram_state.offset)?;
            }
        }

        Ok(())
    }

    fn send_memory(&self, fd: &mut dyn Write, range: MemBlock) -> Result<()> {
        self.read(fd, GuestAddress(range.gpa), range.len)
            .map_err(|e| MigrationError::SendVmMemoryErr(e.to_string()))?;

        Ok(())
    }

    fn recv_memory(&self, fd: &mut dyn Read, range: MemBlock) -> Result<()> {
        self.write(fd, GuestAddress(range.gpa), range.len)
            .map_err(|e| MigrationError::RecvVmMemoryErr(e.to_string()))?;

        Ok(())
    }
}
