// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::mem::size_of;

use anyhow::{anyhow, bail, Context, Result};

use crate::manager::{Instance, MIGRATION_MANAGER};
use crate::protocol::{
    DeviceStateDesc, FileFormat, MigrationHeader, MigrationStatus, VersionCheck, HEADER_LENGTH,
};
use crate::{MigrationError, MigrationManager};
use util::unix::host_page_size;

impl MigrationManager {
    /// Write `MigrationHeader` to `Write` trait object as bytes.
    /// `MigrationHeader` will occupy the first 4096 bytes in snapshot file.
    /// bytes 0-8: the length of the header that's in serde style from struct MigrationHeader.
    /// bytes 8-4096: the header that's in serde style from struct MigrationHeader, and tailing 0s.
    ///
    /// # Arguments
    ///
    /// * `file_format` - confirm snapshot file format.
    /// * `fd` - The `Write` trait object to write header message.
    pub fn save_header(file_format: Option<FileFormat>, fd: &mut dyn Write) -> Result<()> {
        let mut header = MigrationHeader::default();
        if let Some(format) = file_format {
            header.format = format;
            header.desc_len = match format {
                FileFormat::Device => Self::desc_db_len()?,
                FileFormat::MemoryFull => (host_page_size() as usize) * 2 - HEADER_LENGTH,
            };
        } else {
            header.desc_len = Self::desc_db_len()?;
        }

        let header_serde = serde_json::to_vec(&header)?;
        if header_serde.len() > HEADER_LENGTH - 8 {
            return Err(anyhow!(MigrationError::SaveVmMemoryErr(
                "header too long".to_string()
            )));
        }
        let header_len = header_serde.len().to_le_bytes();
        let mut input_slice = [0u8; HEADER_LENGTH];
        input_slice[0..8].copy_from_slice(&header_len);
        input_slice[8..header_serde.len() + 8].copy_from_slice(&header_serde);

        fd.write(&input_slice)
            .with_context(|| "Failed to save migration header")?;

        Ok(())
    }

    /// Restore and parse `MigrationHeader` from `Read` object.
    ///
    /// # Arguments
    ///
    /// * `fd` - The `Read` trait object to read header message.
    pub fn restore_header(fd: &mut dyn Read) -> Result<MigrationHeader> {
        // 1. reader header length
        let mut header_len = [0u8; 8];
        fd.read_exact(&mut header_len)?;
        let header_len = u64::from_le_bytes(header_len);
        if header_len > HEADER_LENGTH as u64 - 8 {
            return Err(anyhow!(MigrationError::FromBytesError(
                "migration header length too large"
            )));
        }

        // 2. read header according to its length
        let mut header_bytes = Vec::new();
        // SAFETY: upper limit of header_len is HEADER_LENGTH - 8.
        header_bytes.resize(header_len as usize, 0);
        fd.read_exact(&mut header_bytes)?;

        // 3. change the binary format header into struct
        let deserializer = serde_json::Deserializer::from_slice(&header_bytes);
        let mut migration_header: Option<MigrationHeader> = None;
        for header in deserializer.into_iter::<MigrationHeader>() {
            migration_header = match header {
                Ok(h) => Some(h),
                Err(_) => {
                    return Err(anyhow!(MigrationError::FromBytesError(
                        "Invalid migration header"
                    )))
                }
            };
        }

        // 4. read the extra bits
        let mut place_holder = vec![0u8; HEADER_LENGTH - 8 - header_len as usize];
        fd.read_exact(&mut place_holder)?;

        // SAFETY: migration_header is Some here.
        Ok(migration_header.unwrap())
    }

    /// Write all `DeviceStateDesc` in `desc_db` hashmap to `Write` trait object.
    pub fn save_desc_db(fd: &mut dyn Write) -> Result<()> {
        let length = Self::desc_db_len()?;
        let mut buffer = Vec::new();
        // SAFETY: desc db length is under control.
        buffer.resize(length, 0);
        let mut start = 0;

        let desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        for (_, desc) in desc_db.iter() {
            let desc_str = serde_json::to_string(desc)?;
            let desc_bytes = desc_str.as_bytes();
            buffer[start..start + desc_bytes.len()].copy_from_slice(desc_bytes);
            start += desc_bytes.len();
        }
        fd.write_all(&buffer)
            .with_context(|| "Failed to write descriptor message.")?;

        Ok(())
    }

    /// Load and parse device state descriptor from `Read` trait object. Save as a Hashmap.
    pub fn restore_desc_db(
        fd: &mut dyn Read,
        desc_length: usize,
    ) -> Result<HashMap<u64, DeviceStateDesc>> {
        let mut desc_buffer = Vec::new();
        // SAFETY: desc_length has been checked in check_header().
        desc_buffer.resize(desc_length, 0);
        fd.read_exact(&mut desc_buffer)?;
        let mut snapshot_desc_db = HashMap::<u64, DeviceStateDesc>::new();

        let deserializer = serde_json::Deserializer::from_slice(&desc_buffer);
        for desc in deserializer.into_iter::<DeviceStateDesc>() {
            let device_desc: DeviceStateDesc = match desc {
                Ok(desc) => desc,
                Err(_) => break,
            };
            if device_desc.size > (1 << 20) {
                bail!("The size field of DeviceStateDesc is too large");
            }
            snapshot_desc_db.insert(device_desc.alias, device_desc);
        }

        Ok(snapshot_desc_db)
    }

    /// Get vm state and check its version can be match.
    ///
    /// # Arguments
    ///
    /// * fd - The `Read` trait object.
    /// * snap_desc_db - snap_desc_db - snapshot state descriptor.
    pub fn check_vm_state(
        fd: &mut dyn Read,
        desc_db: &HashMap<u64, DeviceStateDesc>,
    ) -> Result<(Vec<u8>, u64)> {
        let mut instance = Instance::default();
        fd.read_exact(
            // SAFETY: The pointer of instance can guaranteed not null.
            unsafe {
                std::slice::from_raw_parts_mut(
                    &mut instance as *mut Instance as *mut u8,
                    size_of::<Instance>(),
                )
            },
        )
        .with_context(|| "Failed to read instance of object")?;

        let locked_desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        let snap_desc = desc_db
            .get(&instance.object)
            .with_context(|| "Failed to get instance object")?;
        let current_desc = locked_desc_db
            .get(&snap_desc.name)
            .with_context(|| "Failed to get snap_desc name")?;

        let mut state_data = Vec::new();
        // SAFETY: size has been checked in restore_desc_db().
        state_data.resize(snap_desc.size as usize, 0);
        fd.read_exact(&mut state_data)?;

        match current_desc.check_version(snap_desc) {
            VersionCheck::Same => {}
            VersionCheck::Compat => {
                current_desc
                    .add_padding(snap_desc, &mut state_data)
                    .with_context(|| "Failed to transform snapshot data version")?;
            }
            VersionCheck::Mismatch => {
                return Err(anyhow!(MigrationError::VersionNotFit(
                    current_desc.compat_version,
                    snap_desc.current_version,
                )))
            }
        }

        Ok((state_data, instance.name))
    }

    /// Get `Device`'s alias from device type string.
    ///
    /// # Argument
    ///
    /// * `device_type` - The type string of device instance.
    pub fn get_desc_alias(device_type: &str) -> Option<u64> {
        Some(translate_id(device_type))
    }

    /// Return `desc_db` value len(0 restored as `serde_json`)
    pub fn desc_db_len() -> Result<usize> {
        let mut db_data_len = 0;
        let desc_db = MIGRATION_MANAGER.desc_db.read().unwrap();
        for (_, desc) in desc_db.iter() {
            let desc_str = serde_json::to_string(desc)?;
            db_data_len += desc_str.as_bytes().len();
        }

        Ok(db_data_len)
    }

    /// Get current migration status for migration manager.
    pub fn status() -> MigrationStatus {
        *MIGRATION_MANAGER.status.read().unwrap()
    }

    /// Set a new migration status for migration manager.
    ///
    /// # Arguments
    ///
    /// * `new_status`: new migration status, the transform must be illegal.
    pub fn set_status(new_status: MigrationStatus) -> Result<()> {
        let mut status = MIGRATION_MANAGER.status.write().unwrap();
        *status = status.transfer(new_status)?;

        Ok(())
    }

    /// Check whether current migration status is active.
    pub fn is_active() -> bool {
        Self::status() == MigrationStatus::Active
    }

    /// Check whether current migration status is cancel.
    pub fn is_canceled() -> bool {
        Self::status() == MigrationStatus::Canceled
    }
}

pub trait Lifecycle {
    /// Pause VM during migration.
    fn pause() -> Result<()> {
        if let Some(locked_vm) = &MIGRATION_MANAGER.vmm.read().unwrap().vm {
            locked_vm.lock().unwrap().pause();
        }

        Ok(())
    }

    /// Resume VM during migration.
    fn resume() -> Result<()> {
        let locked_transports = &MIGRATION_MANAGER.vmm.read().unwrap().transports;
        for (_, transport) in locked_transports.iter() {
            transport.lock().unwrap().resume()?;
        }

        let locked_devices = &MIGRATION_MANAGER.vmm.read().unwrap().devices;
        for (_, device) in locked_devices.iter() {
            device.lock().unwrap().resume()?;
        }

        Ok(())
    }
}

impl Lifecycle for MigrationManager {}

/// Converting device instance to unique ID of u64 bit.
/// Because name of String type in `Instance` does not implement Copy trait.
///
/// # Arguments
///
/// * `dev_id` - The device id.
pub fn translate_id(dev_id: &str) -> u64 {
    let mut hash = DefaultHasher::new();
    dev_id.hash(&mut hash);
    hash.finish()
}
