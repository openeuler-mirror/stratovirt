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
use std::mem::size_of;
use std::sync::Arc;

use crate::{AddressSpace, FileBackend, GuestAddress, HostMemMapping, Region};
use migration::errors::{ErrorKind, Result, ResultExt};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use util::byte_code::ByteCode;
use util::unix::host_page_size;

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
    fn pre_save(&self, _id: u64, writer: &mut dyn Write) -> Result<()> {
        let ram_state = self.get_state_vec()?;
        writer.write_all(&ram_state)?;
        let padding_buffer =
            [0].repeat(memory_offset() - MIGRATION_HEADER_LENGTH - size_of::<AddressSpaceState>());
        writer.write_all(&padding_buffer)?;

        for region in self.root().subregions().iter() {
            if let Some(base_addr) = region.start_addr() {
                region
                    .read(writer, base_addr, 0, region.size())
                    .map_err(|e| ErrorKind::SaveVmMemoryErr(e.to_string()))?;
            }
        }

        Ok(())
    }

    fn pre_load(&self, state: &[u8], memory: Option<&File>) -> Result<()> {
        let address_space_state: &AddressSpaceState =
            AddressSpaceState::from_bytes(&state[0..size_of::<AddressSpaceState>()])
                .ok_or(ErrorKind::FromBytesError("MEMORY"))?;
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
                .chain_err(|| ErrorKind::RestoreVmMemoryErr)?,
            );
            self.root()
                .add_subregion(
                    Region::init_ram_region(host_mmap.clone()),
                    host_mmap.start_address().raw_value(),
                )
                .chain_err(|| ErrorKind::RestoreVmMemoryErr)?;
        }

        Ok(())
    }
}
