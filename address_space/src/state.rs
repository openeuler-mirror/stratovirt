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

use anyhow::{anyhow, Result};
use migration::{
    error::MigrationError, DeviceStateDesc, FieldDesc, MemBlock, MigrationHook, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::unix::host_page_size;

use crate::{AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};

const MIGRATION_HEADER_LENGTH: usize = 4096;

#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct AddressSpaceState {
    nr_ram_region: u64,
    ram_region_state: [RamRegionState; 16],
}

#[derive(Copy, Clone, ByteCode)]
pub struct RamRegionState {
    base_address: u64,
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

        for region in self.root().subregions().iter() {
            if let Some(start_addr) = region.start_addr() {
                state.ram_region_state[state.nr_ram_region as usize] = RamRegionState {
                    base_address: start_addr.0,
                    size: region.size(),
                    offset,
                };
                offset += region.size();
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

        for region in self.root().subregions().iter() {
            if let Some(base_addr) = region.start_addr() {
                region
                    .read(fd, base_addr, 0, region.size())
                    .map_err(|e| anyhow!(MigrationError::SaveVmMemoryErr(e.to_string())))?;
            }
        }

        Ok(())
    }

    fn restore_memory(&self, memory: Option<&File>, state: &[u8]) -> Result<()> {
        let address_space_state: &AddressSpaceState =
            AddressSpaceState::from_bytes(&state[0..size_of::<AddressSpaceState>()])
                .ok_or_else(|| anyhow!(MigrationError::FromBytesError("MEMORY")))?;
        let memfile_arc = Arc::new(memory.unwrap().try_clone().unwrap());

        for ram_state in address_space_state.ram_region_state
            [0..address_space_state.nr_ram_region as usize]
            .iter()
        {
            let file_backend = FileBackend {
                file: memfile_arc.clone(),
                offset: ram_state.offset,
                page_size: host_page_size(),
            };
            let host_mmap = Arc::new(
                HostMemMapping::new(
                    GuestAddress(ram_state.base_address),
                    None,
                    ram_state.size,
                    Some(file_backend),
                    false,
                    false,
                    false,
                )
                .map_err(|e| anyhow!(MigrationError::RestoreVmMemoryErr(e.to_string())))?,
            );
            self.root()
                .add_subregion(
                    Region::init_ram_region(host_mmap.clone()),
                    host_mmap.start_address().raw_value(),
                )
                .map_err(|e| anyhow!(MigrationError::RestoreVmMemoryErr(e.to_string())))?;
        }

        Ok(())
    }

    fn send_memory(&self, fd: &mut dyn Write, range: MemBlock) -> Result<()> {
        self.read(fd, GuestAddress(range.gpa), range.len)
            .map_err(|e| anyhow!(MigrationError::SendVmMemoryErr(e.to_string())))?;

        Ok(())
    }

    fn recv_memory(&self, fd: &mut dyn Read, range: MemBlock) -> Result<()> {
        self.write(fd, GuestAddress(range.gpa), range.len)
            .map_err(|e| anyhow!(MigrationError::RecvVmMemoryErr(e.to_string())))?;

        Ok(())
    }
}
