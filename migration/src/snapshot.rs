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

use std::collections::HashMap;
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};

use crate::general::{translate_id, Lifecycle};
use crate::manager::{MigrationManager, MIGRATION_MANAGER};
use crate::protocol::{DeviceStateDesc, FileFormat, MigrationStatus, HEADER_LENGTH};
use crate::MigrationError;
use util::unix::host_page_size;

pub const SERIAL_SNAPSHOT_ID: &str = "serial";
pub const KVM_SNAPSHOT_ID: &str = "kvm";
pub const GICV3_SNAPSHOT_ID: &str = "gicv3";
pub const GICV3_ITS_SNAPSHOT_ID: &str = "gicv3_its";
pub const PL011_SNAPSHOT_ID: &str = "pl011";
pub const PL031_SNAPSHOT_ID: &str = "pl031";

/// The suffix used for snapshot memory storage.
const MEMORY_PATH_SUFFIX: &str = "memory";
/// The suffix used for snapshot device state storage.
const DEVICE_PATH_SUFFIX: &str = "state";

impl MigrationManager {
    /// Save snapshot for `VM`.
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
                Self::save_vmstate(Some(FileFormat::Device), &mut state_file)?;
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
                Self::save_memory(Some(FileFormat::MemoryFull), &mut memory_file)?;
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
            return Err(anyhow!(MigrationError::InvalidSnapshotPath));
        }

        snapshot_path.push(MEMORY_PATH_SUFFIX);
        let mut memory_file =
            File::open(&snapshot_path).with_context(|| "Failed to open memory snapshot file")?;
        let memory_header = Self::restore_header(&mut memory_file)?;
        memory_header.check_header()?;
        if memory_header.format != FileFormat::MemoryFull {
            bail!("Invalid memory snapshot file");
        }
        snapshot_path.pop();
        snapshot_path.push(DEVICE_PATH_SUFFIX);
        let mut device_state_file = File::open(&snapshot_path)
            .with_context(|| "Failed to open device state snapshot file")?;
        let device_state_header = Self::restore_header(&mut device_state_file)?;
        device_state_header.check_header()?;
        if device_state_header.format != FileFormat::Device {
            bail!("Invalid device state snapshot file");
        }

        Self::restore_memory(&mut memory_file).with_context(|| "Failed to load snapshot memory")?;
        let snapshot_desc_db =
            Self::restore_desc_db(&mut device_state_file, device_state_header.desc_len)
                .with_context(|| "Failed to load device descriptor db")?;
        Self::restore_vmstate(snapshot_desc_db, &mut device_state_file)
            .with_context(|| "Failed to load snapshot device state")?;
        Self::resume()?;

        // Set status to `Completed`
        MigrationManager::set_status(MigrationStatus::Completed)?;

        Ok(())
    }

    /// Save memory state and data to `Write` trait object.
    ///
    /// # Arguments
    ///
    /// * `fd` - The `Write` trait object to save memory data.
    fn save_memory(file_format: Option<FileFormat>, fd: &mut dyn Write) -> Result<()> {
        Self::save_header(file_format, fd)?;

        let locked_vmm = MIGRATION_MANAGER.vmm.read().unwrap();
        locked_vmm.memory.as_ref().unwrap().save_memory(fd)?;

        Ok(())
    }

    /// Load and restore memory from snapshot memory file.
    ///
    /// # Arguments
    ///
    /// * `file` - snapshot memory file.
    fn restore_memory(file: &mut File) -> Result<()> {
        let mut state_bytes = [0_u8].repeat((host_page_size() as usize) * 2 - HEADER_LENGTH);
        file.read_exact(&mut state_bytes)?;
        let locked_vmm = MIGRATION_MANAGER.vmm.read().unwrap();
        locked_vmm
            .memory
            .as_ref()
            .unwrap()
            .restore_memory(Some(file), &state_bytes)?;

        Ok(())
    }

    /// Save vm state to `Write` trait object as bytes..
    ///
    /// # Arguments
    ///
    /// * fd - The `Write` trait object to save VM data.
    pub fn save_vmstate(file_format: Option<FileFormat>, fd: &mut dyn Write) -> Result<()> {
        Self::save_header(file_format, fd)?;
        Self::save_desc_db(fd)?;

        let locked_vmm = MIGRATION_MANAGER.vmm.read().unwrap();
        // Save transports state.
        for (id, transport) in locked_vmm.transports.iter() {
            transport
                .lock()
                .unwrap()
                .save_device(*id, fd)
                .with_context(|| "Failed to save transport state")?;
        }

        // Save devices state.
        for (id, device) in locked_vmm.devices.iter() {
            device
                .lock()
                .unwrap()
                .save_device(*id, fd)
                .with_context(|| "Failed to save device state")?;
        }

        // Save CPUs state.
        for (id, cpu) in locked_vmm.cpus.iter() {
            cpu.save_device(*id, fd)
                .with_context(|| "Failed to save cpu state")?;
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Save kvm device state.
            locked_vmm
                .kvm
                .as_ref()
                .unwrap()
                .save_device(translate_id(KVM_SNAPSHOT_ID), fd)
                .with_context(|| "Failed to save kvm state")?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Save GICv3 device state.
            let gic_id = translate_id(GICV3_SNAPSHOT_ID);
            if let Some(gic) = locked_vmm.gic_group.get(&gic_id) {
                gic.save_device(gic_id, fd)
                    .with_context(|| "Failed to save gic state")?;
            }

            // Save GICv3 ITS device state.
            let its_id = translate_id(GICV3_ITS_SNAPSHOT_ID);
            if let Some(its) = locked_vmm.gic_group.get(&its_id) {
                its.save_device(its_id, fd)
                    .with_context(|| "Failed to save gic its state")?;
            }
        }

        Ok(())
    }

    /// Restore vm state from `Read` trait object as bytes..
    ///
    /// # Arguments
    ///
    /// * snap_desc_db - snapshot state descriptor.
    /// * fd - The `Read` trait object to restore VM data.
    pub fn restore_vmstate(
        snap_desc_db: HashMap<u64, DeviceStateDesc>,
        fd: &mut dyn Read,
    ) -> Result<()> {
        let locked_vmm = MIGRATION_MANAGER.vmm.read().unwrap();
        // Restore transports state.
        for _ in 0..locked_vmm.transports.len() {
            let (transport_data, id) = Self::check_vm_state(fd, &snap_desc_db)?;
            if let Some(transport) = locked_vmm.transports.get(&id) {
                transport
                    .lock()
                    .unwrap()
                    .restore_mut_device(&transport_data)
                    .with_context(|| "Failed to restore transport state")?;
            }
        }

        // Restore devices state.
        for _ in 0..locked_vmm.devices.len() {
            let (device_data, id) = Self::check_vm_state(fd, &snap_desc_db)?;
            if let Some(device) = locked_vmm.devices.get(&id) {
                device
                    .lock()
                    .unwrap()
                    .restore_mut_device(&device_data)
                    .with_context(|| "Failed to restore device state")?;
            }
        }

        // Restore CPUs state.
        for _ in 0..locked_vmm.cpus.len() {
            let (cpu_data, id) = Self::check_vm_state(fd, &snap_desc_db)?;
            if let Some(cpu) = locked_vmm.cpus.get(&id) {
                cpu.restore_device(&cpu_data)
                    .with_context(|| "Failed to restore cpu state")?;
            }
        }

        #[cfg(target_arch = "x86_64")]
        {
            // Restore kvm device state.
            if let Some(kvm) = &locked_vmm.kvm {
                let (kvm_data, _) = Self::check_vm_state(fd, &snap_desc_db)?;
                kvm.restore_device(&kvm_data)
                    .with_context(|| "Failed to restore kvm state")?;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // Restore GIC group state.
            for _ in 0..locked_vmm.gic_group.len() {
                let (gic_data, id) = Self::check_vm_state(fd, &snap_desc_db)?;
                if let Some(gic) = locked_vmm.gic_group.get(&id) {
                    gic.restore_device(&gic_data)
                        .with_context(|| "Failed to restore gic state")?;
                }
            }
        }

        Ok(())
    }
}
