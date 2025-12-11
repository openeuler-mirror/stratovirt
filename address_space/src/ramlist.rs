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
use serde::{Deserialize, Serialize};

use crate::state::{get_state_slice, read_state_slice};
use crate::{HostMemMapping, RamRegionState};
use migration::{DeviceStateDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;

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

#[derive(Clone, Default, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
pub struct RamRegionStateHeader {
    // States of ram regions.
    region_states: Vec<RamRegionState>,
}

impl StateTransfer for RamList {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut header = RamRegionStateHeader::default();
        let mut ram_region_offset = 0;
        for (region_name, region) in self.map_list.iter() {
            let state = RamRegionState {
                name: region_name.clone(),
                offset: ram_region_offset,
                size: region.size(),
            };
            ram_region_offset += region.size();
            header.region_states.push(state);
        }

        Ok(serde_json::to_vec(&header)?)
    }

    fn get_device_alias(&self) -> u64 {
        0
    }
}

impl MigrationHook for RamList {
    fn save_memory(&self, file: &mut File) -> Result<()> {
        let state_header = self.get_state_vec()?;
        let data_slice = get_state_slice(&state_header)
            .with_context(|| "Failed to get state slice while saving ramlist")?;
        file.write_all(&data_slice)?;

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
        let data_slice = read_state_slice(file)
            .with_context(|| "Failed to read state slice while restoring ramlist")?;
        let state_header: RamRegionStateHeader = serde_json::from_slice(&data_slice)
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
    for region in region_states {
        if *name == region.name {
            return Some(region.clone());
        }
    }
    None
}
