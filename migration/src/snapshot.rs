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
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;

use crate::device_state::{DeviceStateDesc, VersionCheck};
use crate::errors::{ErrorKind, Result, ResultExt};
use crate::header::{FileFormat, MigrationHeader};
use crate::manager::{InstanceId, MigrationEntry, MigrationManager, MIGRATION_MANAGER};
use util::byte_code::ByteCode;
use util::reader::BufferReader;
use util::unix::host_page_size;

/// The length of `MigrationHeader` part occupies bytes in snapshot file.
const HEADER_LENGTH: usize = 4096;

impl MigrationManager {
    /// Write `MigrationHeader` to `Write` trait object as bytes.
    /// `MigrationHeader` will occupy the first 4096 bytes in snapshot file.
    ///
    /// # Arguments
    ///
    /// * `file_format` - confirm snapshot file / migration stream file format.
    /// * `writer` - The `Write` trait object to write to receive header message.
    fn save_header(file_format: FileFormat, writer: &mut dyn Write) -> Result<()> {
        let mut header = MigrationHeader::default();
        header.format = file_format;
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
        for (id, entry) in MIGRATION_MANAGER.entry.read().unwrap().iter() {
            if let MigrationEntry::Memory(i) = entry {
                i.pre_save(*id, writer)
                    .chain_err(|| "Failed to save vm memory")?;
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
        for (_, entry) in MIGRATION_MANAGER.entry.read().unwrap().iter() {
            if let MigrationEntry::Memory(i) = entry {
                i.pre_load(&state_bytes, Some(file))
                    .chain_err(|| "Failed to load vm memory")?;
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
        for (device_id, entry) in MIGRATION_MANAGER.entry.read().unwrap().iter() {
            match entry {
                MigrationEntry::Safe(i) => i.pre_save(*device_id, writer)?,
                MigrationEntry::Mutex(i) => i.lock().unwrap().pre_save(*device_id, writer)?,
                _ => {}
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

            let mut state_data = migration_file
                .read_vectored(snap_desc.size as usize)
                .unwrap();
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

            match device_entry.get(&instance_id.object_id).unwrap() {
                MigrationEntry::Safe(i) => i.pre_load(&state_data, None)?,
                MigrationEntry::Mutex(i) => i.lock().unwrap().pre_load_mut(&state_data, None)?,
                _ => {}
            }
        }

        Ok(())
    }
}
