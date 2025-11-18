// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Context, Result};
use util::byte_code::ByteCode;

use crate::{HostMemMapping, RamRegionState};
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};

struct RamList {
    map_list: HashMap<String, Arc<HostMemMapping>>,
}

impl RamList {
    fn new() -> Self {
        RamList {
            map_list: HashMap::new(),
        }
    }
}

static RAM_LIST: OnceLock<Arc<Mutex<RamList>>> = OnceLock::new();

pub fn register_ram_list() {
    let list = RAM_LIST.get_or_init(|| Arc::new(Mutex::new(RamList::new())));
    MigrationManager::register_ram_region_instance(list.clone());
}

pub fn register_ram_region(region_name: String, mem_mapping: Arc<HostMemMapping>) -> Result<()> {
    let list = RAM_LIST.get_or_init(|| Arc::new(Mutex::new(RamList::new())));
    let mut locked_list = list.lock().unwrap();
    if locked_list.map_list.contains_key(&region_name) {
        bail!("Duplicate region name {}", region_name);
    }
    locked_list
        .map_list
        .insert(region_name.clone(), mem_mapping);

    Ok(())
}

pub fn unregister_ram_region(region_name: String) -> Option<Arc<HostMemMapping>> {
    if let Some(list) = RAM_LIST.get() {
        let mut locked_list = list.lock().unwrap();
        return locked_list.map_list.remove(&region_name);
    }
    None
}

const MAX_REGION_NAME_SIZE: usize = 64;
const RAMLIST_MAX_REGIONS_NUMBER: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct RamRegionStateHeader {
    // Number of ram regions.
    regions_number: u32,
    // States of ram regions.
    region_states: [RamRegionState; RAMLIST_MAX_REGIONS_NUMBER],
}

impl StateTransfer for RamList {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut header = RamRegionStateHeader::default();
        let mut ram_region_offset = 0;
        for (region_name, region) in self.map_list.iter() {
            let name_size = region_name.len().min(MAX_REGION_NAME_SIZE);
            let mut name = [0u8; MAX_REGION_NAME_SIZE];
            name[..name_size].copy_from_slice(&region_name.as_bytes()[..name_size]);
            let state = RamRegionState {
                name_size: name_size as u32,
                name,
                offset: ram_region_offset,
                size: region.size(),
            };
            ram_region_offset += region.size();
            header.region_states[header.regions_number as usize] = state;
            header.regions_number += 1;
        }

        Ok(header.as_bytes().to_vec())
    }

    fn get_device_alias(&self) -> u64 {
        0
    }
}

impl MigrationHook for RamList {
    fn save_memory(&self, file: &mut File) -> Result<()> {
        let state_header = self.get_state_vec()?;
        file.write_all(&state_header)?;

        for (region_name, region_map) in self.map_list.iter() {
            let hva = region_map.host_address();
            let size = region_map.size() as usize;
            log::info!("Save ramlist region {} size {}", region_name, size);

            // SAFETY: host_addr is managed by mem_mapping, it can be guaranteed to be legal,
            // the legality of offset and count has been verified.
            let slice = unsafe { std::slice::from_raw_parts(hva as *const u8, size) };
            file.write_all(slice).with_context(|| {
                MigrationError::SaveVmMemoryErr("Failed to save ramlist memory".to_string())
            })?;
        }

        Ok(())
    }

    fn restore_memory(&self, file: &mut File, _mapped: bool) -> Result<()> {
        let mut header_bytes = [0_u8].repeat(std::mem::size_of::<RamRegionStateHeader>());
        file.read_exact(&mut header_bytes)?;
        let state_header: &RamRegionStateHeader =
            RamRegionStateHeader::from_bytes(&header_bytes)
                .with_context(|| MigrationError::FromBytesError("RamRegionStateHeader"))?;

        // Get the start pos for saved ram region.
        let first_ram_region_offset = file.stream_position()?;
        for (region_name, region_map) in self.map_list.iter() {
            let state = get_ram_region_state(region_name, &state_header.region_states)
                .with_context(|| format!("Can not find ram region {:?}", region_name))?;
            let hva = region_map.host_address();
            let size = region_map.size() as usize;
            if state.size != size as u64 {
                bail!(
                    "Size of ram region {} changed, saved size {}, now {}.",
                    region_name,
                    state.size,
                    size
                );
            }
            let record_offset = first_ram_region_offset
                .checked_add(state.offset)
                .with_context(|| {
                    format!(
                        "Restore memory overflow: {} + {}",
                        first_ram_region_offset, state.offset
                    )
                })?;
            file.seek(SeekFrom::Start(record_offset))?;

            // SAFETY: host_addr is managed by mem_mapping, it can be guaranteed to be legal,
            // the legality of offset and count has been verified.
            let slice = unsafe { std::slice::from_raw_parts_mut(hva as *mut u8, size) };
            file.read_exact(slice)?;
        }

        Ok(())
    }
}

fn get_ram_region_state(name: &String, region_states: &[RamRegionState]) -> Option<RamRegionState> {
    let name_size = name.len().min(MAX_REGION_NAME_SIZE);
    let mut region_name = [0u8; MAX_REGION_NAME_SIZE];
    region_name[..name_size].copy_from_slice(&name.as_bytes()[..name_size]);
    for region in region_states {
        if region_name == region.name {
            return Some(*region);
        }
    }
    None
}
