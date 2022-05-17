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

use std::collections::HashMap;
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::PathBuf;

use error_chain::bail;
use log::info;
use util::byte_code::ByteCode;
use util::reader::BufferReader;
use util::unix::host_page_size;

use crate::device_state::{DeviceStateDesc, VersionCheck};
use crate::errors::{ErrorKind, Result, ResultExt};
use crate::header::{FileFormat, MigrationHeader};
use crate::manager::{id_remap, InstanceId, MigrationEntry, MigrationManager, MIGRATION_MANAGER};
use crate::status::MigrationStatus;

/// The length of `MigrationHeader` part occupies bytes in snapshot file.
const HEADER_LENGTH: usize = 4096;
/// The suffix used for snapshot memory storage.
const MEMORY_PATH_SUFFIX: &str = "memory";
/// The suffix used for snapshot device state storage.
const DEVICE_PATH_SUFFIX: &str = "state";

impl MigrationManager {
    /// Do snapshot for `VM`.
    ///
    /// # Notes
    ///
    /// Offers a interface for snapshot functions. This function will make a snapshot dir
    /// for input path. It will create two file in snapshot dir - device state file `state`
    /// and memory file `memory`.
    ///
    /// # Argument
    ///
    /// * `path` - snapshot dir path. If path dir not exists, will create it.
    pub fn save_snapshot(path: &str) -> Result<()> {
        // Set status to `Active`
        MigrationManager::set_status(MigrationStatus::Active)?;

        // Create snapshot dir.
        if let Err(e) = create_dir(path) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                bail!("Failed to create snapshot dir: {}", e);
            }
        }

        // Save device state
        let mut vm_state_path = PathBuf::from(path);
        vm_state_path.push(DEVICE_PATH_SUFFIX);
        match File::create(vm_state_path) {
            Ok(mut state_file) => {
                Self::save_header(FileFormat::Device, &mut state_file)?;
                Self::save_descriptor_db(&mut state_file)?;
                Self::save_device_state(&mut state_file)?;
            }
            Err(e) => {
                bail!("Failed to create snapshot state file: {}", e);
            }
        }

        // Save memory data
        let mut vm_memory_path = PathBuf::from(path);
        vm_memory_path.push(MEMORY_PATH_SUFFIX);
        match File::create(vm_memory_path) {
            Ok(mut memory_file) => {
                Self::save_header(FileFormat::MemoryFull, &mut memory_file)?;
                Self::save_memory(&mut memory_file)?;
            }
            Err(e) => {
                bail!("Failed to create snapshot memory file: {}", e);
            }
        }

        // Set status to `Completed`
        MigrationManager::set_status(MigrationStatus::Completed)?;

        Ok(())
    }

    /// Restore snapshot for `VM`.
    ///
    /// # Notes
    ///
    /// Offers a interface for restore snapshot functions. This function will make VM
    /// back to the state restored in snapshot file including both device and memory.
    ///
    /// # Argument
    ///
    /// * `path` - snapshot dir path.
    pub fn restore_snapshot(path: &str) -> Result<()> {
        // Set status to `Active`
        MigrationManager::set_status(MigrationStatus::Active)?;

        let mut snapshot_path = PathBuf::from(path);
        if !snapshot_path.is_dir() {
            return Err(ErrorKind::InvalidSnapshotPath.into());
        }

        snapshot_path.push(MEMORY_PATH_SUFFIX);
        let mut memory_file =
            File::open(&snapshot_path).chain_err(|| "Failed to open memory snapshot file")?;
        let memory_header = Self::load_header(&mut memory_file)?;
        memory_header.check_header()?;
        if memory_header.format != FileFormat::MemoryFull {
            bail!("Invalid memory snapshot file");
        }
        snapshot_path.pop();
        snapshot_path.push(DEVICE_PATH_SUFFIX);
        let mut device_state_file =
            File::open(&snapshot_path).chain_err(|| "Failed to open device state snapshot file")?;
        let device_state_header = Self::load_header(&mut device_state_file)?;
        device_state_header.check_header()?;
        if device_state_header.format != FileFormat::Device {
            bail!("Invalid device state snapshot file");
        }

        Self::load_memory(&mut memory_file).chain_err(|| "Failed to load snapshot memory")?;
        let snapshot_desc_db =
            Self::load_descriptor_db(&mut device_state_file, device_state_header.desc_len)
                .chain_err(|| "Failed to load device descriptor db")?;
        Self::load_vmstate(snapshot_desc_db, &mut device_state_file)
            .chain_err(|| "Failed to load snapshot device state")?;
        Self::resume()?;

        // Set status to `Completed`
        MigrationManager::set_status(MigrationStatus::Completed)?;

        Ok(())
    }

    /// Write `MigrationHeader` to `Write` trait object as bytes.
    /// `MigrationHeader` will occupy the first 4096 bytes in snapshot file.
    ///
    /// # Arguments
    ///
    /// * `file_format` - confirm snapshot file format.
    /// * `writer` - The `Write` trait object to write header message.
    fn save_header(file_format: FileFormat, writer: &mut dyn Write) -> Result<()> {
        let mut header = MigrationHeader::default();
        header.format = file_format;
        header.desc_len = match file_format {
            FileFormat::Device => Self::get_desc_db_len()?,
            FileFormat::MemoryFull => (host_page_size() as usize) * 2 - HEADER_LENGTH,
        };
        let header_bytes = header.as_bytes();
        let mut input_slice = [0u8; HEADER_LENGTH];

        input_slice[0..size_of::<MigrationHeader>()].copy_from_slice(header_bytes);
        writer
            .write(&input_slice)
            .chain_err(|| "Failed to save migration header")?;

        Ok(())
    }

    /// Load and parse `MigrationHeader` from `Read` object.
    ///
    /// # Arguments
    ///
    /// * `reader` - The `Read` trait object.
    fn load_header(reader: &mut dyn Read) -> Result<MigrationHeader> {
        let mut header_bytes = [0u8; size_of::<MigrationHeader>()];
        reader.read_exact(&mut header_bytes)?;

        let mut place_holder = [0u8; HEADER_LENGTH - size_of::<MigrationHeader>()];
        reader.read_exact(&mut place_holder)?;

        Ok(*MigrationHeader::from_bytes(&header_bytes)
            .ok_or(ErrorKind::FromBytesError("HEADER"))?)
    }

    /// Save memory state and data to `Write` trait object.
    ///
    /// # Arguments
    ///
    /// * `writer` - The `Write` trait object.
    fn save_memory(writer: &mut dyn Write) -> Result<()> {
        let entry = MIGRATION_MANAGER.entry.read().unwrap();
        for item in entry.iter() {
            for (id, entry) in item.iter() {
                if let MigrationEntry::Memory(i) = entry {
                    i.pre_save(id, writer)
                        .chain_err(|| "Failed to save vm memory")?;
                }
            }
        }

        Ok(())
    }

    /// Load and restore memory from snapshot memory file.
    ///
    /// # Arguments
    ///
    /// * `file` - snapshot memory file.
    fn load_memory(file: &mut File) -> Result<()> {
        let mut state_bytes = [0_u8].repeat((host_page_size() as usize) * 2 - HEADER_LENGTH);
        file.read_exact(&mut state_bytes)?;
        let entry = MIGRATION_MANAGER.entry.read().unwrap();
        for item in entry.iter() {
            for (_, entry) in item.iter() {
                if let MigrationEntry::Memory(i) = entry {
                    i.pre_load(&state_bytes, Some(file))
                        .chain_err(|| "Failed to load vm memory")?;
                }
            }
        }

        Ok(())
    }

    /// Save device state to `Write` trait object.
    ///
    /// # Arguments
    ///
    /// * `writer` - The `Write` trait object.
    fn save_device_state(writer: &mut dyn Write) -> Result<()> {
        let entry = MIGRATION_MANAGER.entry.read().unwrap();
        for item in entry.iter() {
            for (id, entry) in item.iter() {
                match entry {
                    MigrationEntry::Safe(i) => i.pre_save(id, writer)?,
                    MigrationEntry::Mutex(i) => i.lock().unwrap().pre_save(id, writer)?,
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Restore vm state from `Read` trait object.
    ///
    /// # Arguments
    ///
    /// * `snap_desc_db` - The snapshot descriptor hashmap read from snapshot file.
    /// * `reader` - The `Read` trait object.
    fn load_vmstate(
        snap_desc_db: HashMap<u64, DeviceStateDesc>,
        reader: &mut dyn Read,
    ) -> Result<()> {
        let desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        let device_entry = MIGRATION_MANAGER.entry.read().unwrap();

        let mut migration_file = BufferReader::new(reader);
        migration_file.read_buffer()?;

        while let Some(data) = &migration_file.read_vectored(size_of::<InstanceId>()) {
            let instance_id = InstanceId::from_bytes(data.as_slice()).unwrap();
            let snap_desc = snap_desc_db.get(&instance_id.object_type).unwrap();
            let current_desc = desc_db.get(&snap_desc.name).unwrap();

            let mut state_data =
                if let Some(data) = migration_file.read_vectored(snap_desc.size as usize) {
                    data
                } else {
                    bail!("Invalid snapshot device state data");
                };
            match current_desc.check_version(snap_desc) {
                VersionCheck::Same => {}
                VersionCheck::Compat => {
                    current_desc
                        .add_padding(snap_desc, &mut state_data)
                        .chain_err(|| "Failed to transform snapshot data version.")?;
                }
                VersionCheck::Mismatch => {
                    return Err(ErrorKind::VersionNotFit(
                        current_desc.compat_version,
                        snap_desc.current_version,
                    )
                    .into())
                }
            }

            for item in device_entry.iter() {
                for (key, state) in item {
                    if id_remap(key) == instance_id.object_id {
                        info!("Load VM state: key {}", key);
                        match state {
                            MigrationEntry::Safe(i) => i.pre_load(&state_data, None)?,
                            MigrationEntry::Mutex(i) => {
                                i.lock().unwrap().pre_load_mut(&state_data, None)?
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Resume recovered device.
    /// This function will be called after restore device state.
    fn resume() -> Result<()> {
        let entry = MIGRATION_MANAGER.entry.read().unwrap();
        for item in entry.iter() {
            for (_, state) in item {
                if let MigrationEntry::Mutex(i) = state {
                    i.lock().unwrap().resume()?
                }
            }
        }
        Ok(())
    }
}
