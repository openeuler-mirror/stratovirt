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
use std::io::{Read, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use log::{info, warn};

use crate::general::Lifecycle;
use crate::manager::MIGRATION_MANAGER;
use crate::protocol::{MemBlock, MigrationStatus, Request, Response, TransStatus};
use crate::MigrateMemSlot;
use crate::{MigrationError, MigrationManager};
use machine_manager::config::{get_pci_bdf, PciBdf, VmConfig};
use util::unix::host_page_size;

impl MigrationManager {
    /// Start VM live migration at source VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object. it
    /// will send source VM memory data and devices state to destination VM.
    /// And, it will receive confirmation from destination VM.
    pub fn send_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Read + Write,
    {
        // Activate the migration status of source and destination virtual machine.
        Self::active_migration(fd).with_context(|| "Failed to active migration")?;

        // Send source virtual machine configuration.
        Self::send_vm_config(fd).with_context(|| "Failed to send vm config")?;

        // Start logging dirty pages.
        Self::start_dirty_log().with_context(|| "Failed to start logging dirty page")?;

        // Send all memory of virtual machine itself to destination.
        Self::send_vm_memory(fd).with_context(|| "Failed to send VM memory")?;

        // Iteratively send virtual machine dirty memory.
        let iterations = MIGRATION_MANAGER.limit.read().unwrap().max_dirty_iterations;
        for _ in 0..iterations {
            // Check the migration is active.
            if !Self::is_active() {
                break;
            }

            if !Self::iteration_send(fd)? {
                break;
            }
        }

        // Check whether the migration is canceled.
        if Self::is_canceled() {
            // Cancel the migration of source and destination.
            Self::cancel_migration(fd).with_context(|| "Failed to cancel migration")?;
            return Ok(());
        }

        // Pause virtual machine.
        Self::pause()?;

        // Send remaining virtual machine dirty memory.
        Self::send_dirty_memory(fd).with_context(|| "Failed to send dirty memory")?;

        // Stop logging dirty pages.
        Self::stop_dirty_log().with_context(|| "Failed to stop logging dirty page")?;

        // Get virtual machine state and send it to destination VM.
        Self::send_vmstate(fd).with_context(|| "Failed to send vm state")?;

        // Complete the migration.
        Self::complete_migration(fd).with_context(|| "Failed to completing migration")?;

        // Destroy virtual machine.
        Self::clear_migration().with_context(|| "Failed to clear migration")?;

        Ok(())
    }

    /// Start VM live migration at destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object. it
    /// will receive source VM memory data and devices state. And,
    /// it will send confirmation to source VM.
    pub fn recv_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Read + Write,
    {
        // Activate the migration status.
        let request = Request::recv_msg(fd)?;
        if request.status == TransStatus::Active {
            info!("Active the migration");
            Self::set_status(MigrationStatus::Active)?;
            Response::send_msg(fd, TransStatus::Ok)?;
        } else {
            Response::send_msg(fd, TransStatus::Error)?;
            return Err(anyhow!(MigrationError::MigrationStatusErr(
                (request.status as u16).to_string(),
                TransStatus::Active.to_string(),
            )));
        }

        // Check source and destination virtual machine configuration.
        let request = Request::recv_msg(fd)?;
        if request.status == TransStatus::VmConfig {
            info!("Receive VmConfig status");
            Self::check_vm_config(fd, request.length)
                .with_context(|| "Failed to check vm config")?;
        } else {
            Response::send_msg(fd, TransStatus::Error)?;
            return Err(anyhow!(MigrationError::MigrationStatusErr(
                (request.status as u16).to_string(),
                TransStatus::VmConfig.to_string(),
            )));
        }

        loop {
            let request = Request::recv_msg(fd)?;
            match request.status {
                TransStatus::Memory => {
                    info!("Receive Memory status");
                    Self::recv_vm_memory(fd, request.length)?;
                }
                TransStatus::State => {
                    info!("Receive State status");
                    Self::recv_vmstate(fd)?;
                    break;
                }
                TransStatus::Cancel => {
                    info!("Receive Cancel status");
                    Self::set_status(MigrationStatus::Canceled)?;
                    Response::send_msg(fd, TransStatus::Ok)?;

                    bail!("Cancel migration from source");
                }
                _ => {
                    warn!("Unable to distinguish status");
                }
            }
        }

        Ok(())
    }

    /// Send Vm configuration from source virtual machine.
    fn send_vm_config<T>(fd: &mut T) -> Result<()>
    where
        T: Write + Read,
    {
        let vm_config = &MIGRATION_MANAGER
            .vmm
            .read()
            .unwrap()
            .config
            .lock()
            .unwrap()
            .clone();
        let config_data = serde_json::to_vec(vm_config)?;
        Request::send_msg(fd, TransStatus::VmConfig, config_data.len() as u64)?;
        fd.write_all(&config_data)?;

        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    /// Check source and destination virtual machine config.
    fn check_vm_config<T>(fd: &mut T, len: u64) -> Result<()>
    where
        T: Write + Read,
    {
        // Sanity check for len to avoid OOM. Given 1MB is enough.
        if len > (1 << 20) {
            bail!("Source vm_config size is too large");
        }

        let mut data: Vec<u8> = Vec::new();
        data.resize_with(len as usize, Default::default);
        fd.read_exact(&mut data)?;

        let src_config: &VmConfig = &serde_json::from_slice(&data)?;
        let dest_config: &VmConfig = &MIGRATION_MANAGER
            .vmm
            .read()
            .unwrap()
            .config
            .lock()
            .unwrap()
            .clone();
        // Check vCPU number.
        Self::check_vcpu(src_config, dest_config)?;
        Self::check_memory(src_config, dest_config)?;
        Self::check_devices(src_config, dest_config)?;

        Response::send_msg(fd, TransStatus::Ok)?;

        Ok(())
    }

    /// Check vcpu number config.
    fn check_vcpu(src_config: &VmConfig, dest_config: &VmConfig) -> Result<()> {
        let src_cpu = src_config.machine_config.nr_cpus;
        let dest_cpu = dest_config.machine_config.nr_cpus;
        if src_cpu != dest_cpu {
            return Err(anyhow!(MigrationError::MigrationConfigErr(
                "vCPU number".to_string(),
                src_cpu.to_string(),
                dest_cpu.to_string(),
            )));
        }

        Ok(())
    }

    /// Check memory size config.
    fn check_memory(src_config: &VmConfig, dest_config: &VmConfig) -> Result<()> {
        let src_mem = src_config.machine_config.mem_config.mem_size;
        let dest_mem = dest_config.machine_config.mem_config.mem_size;
        if src_mem != dest_mem {
            return Err(anyhow!(MigrationError::MigrationConfigErr(
                "memory size".to_string(),
                src_mem.to_string(),
                dest_mem.to_string(),
            )));
        }

        Ok(())
    }

    /// Check devices type and BDF config.
    fn check_devices(src_config: &VmConfig, dest_config: &VmConfig) -> Result<()> {
        let mut dest_devices: HashMap<PciBdf, String> = HashMap::new();
        for (dev_type, dev_info) in dest_config.devices.iter() {
            if let Ok(dest_bdf) = get_pci_bdf(dev_info) {
                dest_devices.insert(dest_bdf, dev_type.to_string());
            }
        }
        for (src_type, dev_info) in src_config.devices.iter() {
            if let Ok(src_bdf) = get_pci_bdf(dev_info) {
                match dest_devices.get(&src_bdf) {
                    Some(dest_type) => {
                        if !src_type.eq(dest_type) {
                            return Err(anyhow!(MigrationError::MigrationConfigErr(
                                "device type".to_string(),
                                src_type.to_string(),
                                dest_type.to_string(),
                            )));
                        }
                    }
                    None => bail!(
                        "Failed to get destination device bdf {:?}, type {}",
                        src_bdf,
                        src_type
                    ),
                }
            }
        }

        Ok(())
    }

    /// Start to send dirty memory page iteratively. Return true if it should
    /// continue to the next iteration. Otherwise, return false.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn iteration_send<T>(fd: &mut T) -> Result<bool>
    where
        T: Write + Read,
    {
        let mut state =
            Self::send_dirty_memory(fd).with_context(|| "Failed to send dirty memory")?;

        // Check the virtual machine downtime.
        if MIGRATION_MANAGER
            .limit
            .read()
            .unwrap()
            .iteration_start_time
            .elapsed()
            < Duration::from_millis(MIGRATION_MANAGER.limit.read().unwrap().limit_downtime)
        {
            state = false;
        }
        // Update iteration start time.
        MIGRATION_MANAGER
            .limit
            .write()
            .unwrap()
            .iteration_start_time = Instant::now();

        Ok(state)
    }

    /// Receive memory data from source VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    /// * `len` - The length of Block data.
    fn recv_vm_memory<T>(fd: &mut T, len: u64) -> Result<()>
    where
        T: Write + Read,
    {
        // Sanity check for len to avoid OOM. Given 1MB is enough.
        if len > (1 << 20) {
            bail!("Source MemBlock config size is too large");
        }

        let mut blocks = Vec::<MemBlock>::new();
        blocks.resize_with(len as usize / (size_of::<MemBlock>()), Default::default);
        fd.read_exact(
            // SAFETY:
            // 1. The pointer of blocks can be guaranteed not null.
            // 2. The range of len has been limited.
            unsafe {
                std::slice::from_raw_parts_mut(
                    blocks.as_ptr() as *mut MemBlock as *mut u8,
                    len as usize,
                )
            },
        )?;

        if let Some(locked_memory) = &MIGRATION_MANAGER.vmm.read().unwrap().memory {
            for block in blocks.iter() {
                locked_memory.recv_memory(
                    fd,
                    MemBlock {
                        gpa: block.gpa,
                        len: block.len,
                    },
                )?;
            }
        }

        Response::send_msg(fd, TransStatus::Ok)?;

        Ok(())
    }

    /// Send memory data to destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    /// * `blocks` - The memory blocks need to be sent.
    fn send_memory<T>(fd: &mut T, blocks: Vec<MemBlock>) -> Result<()>
    where
        T: Read + Write,
    {
        let len = size_of::<MemBlock>() * blocks.len();
        Request::send_msg(fd, TransStatus::Memory, len as u64)?;
        fd.write_all(
            // SAFETY:
            // 1. The pointer of blocks can be guaranteed not null.
            // 2. The len is constant.
            unsafe {
                std::slice::from_raw_parts(blocks.as_ptr() as *const MemBlock as *const u8, len)
            },
        )?;

        if let Some(locked_memory) = &MIGRATION_MANAGER.vmm.read().unwrap().memory {
            for block in blocks.iter() {
                locked_memory.send_memory(
                    fd,
                    MemBlock {
                        gpa: block.gpa,
                        len: block.len,
                    },
                )?;
            }
        }

        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    /// Send entire VM memory data to destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn send_vm_memory<T>(fd: &mut T) -> Result<()>
    where
        T: Read + Write,
    {
        let mut blocks: Vec<MemBlock> = Vec::new();
        if let Some(mgt_object) = &MIGRATION_MANAGER.vmm.read().unwrap().mgt_object {
            let slots = mgt_object.lock().unwrap().get_mem_slots();
            for (_, slot) in slots.lock().unwrap().iter() {
                blocks.push(MemBlock {
                    gpa: slot.guest_phys_addr,
                    len: slot.memory_size,
                });
            }
        }

        Self::send_memory(fd, blocks)
    }

    /// Send dirty memory data to destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn send_dirty_memory<T>(fd: &mut T) -> Result<bool>
    where
        T: Read + Write,
    {
        let mut blocks: Vec<MemBlock> = Vec::new();
        if let Some(mgt_object) = &MIGRATION_MANAGER.vmm.read().unwrap().mgt_object {
            let mem_slots = mgt_object.lock().unwrap().get_mem_slots();
            for (_, slot) in mem_slots.lock().unwrap().iter() {
                let sub_blocks: Vec<MemBlock> = Self::get_dirty_log(slot)?;
                blocks.extend(sub_blocks);
            }
        }

        if blocks.is_empty() {
            return Ok(false);
        }

        Self::send_memory(fd, blocks)?;

        Ok(true)
    }

    /// Send VM state data to destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn send_vmstate<T>(fd: &mut T) -> Result<()>
    where
        T: Read + Write,
    {
        Request::send_msg(fd, TransStatus::State, 0)?;
        Self::save_vmstate(None, fd)?;

        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    /// Receive VM state data from source VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn recv_vmstate<T>(fd: &mut T) -> Result<()>
    where
        T: Write + Read,
    {
        let header = Self::restore_header(fd)?;
        header.check_header()?;
        let desc_db = Self::restore_desc_db(fd, header.desc_len)
            .with_context(|| "Failed to load device descriptor db")?;
        Self::restore_vmstate(desc_db, fd).with_context(|| "Failed to load snapshot device")?;
        Self::resume()?;

        Response::send_msg(fd, TransStatus::Ok)?;

        Ok(())
    }

    /// Active migration status and synchronize the state of destination VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn active_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Read + Write,
    {
        Self::set_status(MigrationStatus::Active)?;
        Request::send_msg(fd, TransStatus::Active, 0)?;
        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    /// Synchronize the `Completed` status of destination VM
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn complete_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Write + Read,
    {
        Self::set_status(MigrationStatus::Completed)?;
        Request::send_msg(fd, TransStatus::Complete, 0)?;
        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    ///  Finish the migration of destination VM and notify the source VM.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    pub fn finish_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Write + Read,
    {
        // Receive complete status from source vm.
        let request = Request::recv_msg(fd)?;
        if request.status == TransStatus::Complete {
            info!("Receive Complete status");
            Self::set_status(MigrationStatus::Completed)?;
            Response::send_msg(fd, TransStatus::Ok)?;
        } else {
            return Err(anyhow!(MigrationError::MigrationStatusErr(
                (request.status as u16).to_string(),
                TransStatus::Complete.to_string(),
            )));
        }

        Ok(())
    }

    /// Cancel live migration.
    ///
    /// # Arguments
    ///
    /// * `fd` - The fd implements `Read` and `Write` trait object.
    fn cancel_migration<T>(fd: &mut T) -> Result<()>
    where
        T: Write + Read,
    {
        // Stop logging dirty pages.
        Self::stop_dirty_log().with_context(|| "Failed to stop logging dirty page")?;

        Request::send_msg(fd, TransStatus::Cancel, 0)?;
        let result = Response::recv_msg(fd)?;
        if result.is_err() {
            return Err(anyhow!(MigrationError::ResponseErr));
        }

        Ok(())
    }

    /// Clear live migration environment and shut down VM.
    fn clear_migration() -> Result<()> {
        if let Some(locked_vm) = &MIGRATION_MANAGER.vmm.read().unwrap().vm {
            locked_vm.lock().unwrap().destroy();
        }

        Ok(())
    }

    /// Recover the virtual machine if migration is failed.
    pub fn recover_from_migration() -> Result<()> {
        if let Some(locked_vm) = &MIGRATION_MANAGER.vmm.read().unwrap().vm {
            locked_vm.lock().unwrap().resume();
        }

        Ok(())
    }
}

/// Dirty bitmap information of vmm memory slot.
pub struct DirtyBitmap {
    /// Guest address.
    pub gpa: u64,
    /// Host address.
    pub hva: u64,
    /// length of memory.
    pub len: u64,
    /// Bitmap for vmm memory slot.
    pub map: Vec<AtomicU64>,
    /// Host page size.
    pub page_size: u64,
}

impl DirtyBitmap {
    /// Create a new dirty bitmap for vmm.
    ///
    /// # Arguments
    ///
    /// * `gpa` - Guest physical address of memory slot.
    /// * `hva` - Host virtual address of memory slot.
    /// * `len` - Length of memory slot.
    fn new(gpa: u64, hva: u64, len: u64) -> Self {
        let page_size = host_page_size();

        let mut num_pages = len / page_size;
        // Page alignment.
        if len % page_size > 0 {
            num_pages += 1;
        }
        let size = num_pages / 64 + 1;
        let map: Vec<AtomicU64> = (0..size).map(|_| AtomicU64::new(0)).collect();

        DirtyBitmap {
            gpa,
            hva,
            len,
            map,
            page_size,
        }
    }

    /// Mark dirty bitmap for vmm.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest physical address of memory.
    /// * `len` - Length of memory slot.
    fn mark_bitmap(&self, addr: u64, len: u64) {
        // Just return if len is 0.
        if len == 0 {
            return;
        }

        let offset = addr - self.gpa;
        let first_bit = offset / self.page_size;
        let last_bit = (offset + len - 1) / self.page_size;
        for n in first_bit..=last_bit {
            // Ignore bit that is out of range.
            if n >= self.len {
                break;
            }
            self.map[(n as usize) >> 6].fetch_or(1 << (n & 63), Ordering::SeqCst);
        }
    }

    /// Get and clear dirty bitmap for vmm.
    fn get_and_clear_dirty(&self) -> Vec<u64> {
        self.map
            .iter()
            .map(|m| m.fetch_and(0, Ordering::SeqCst))
            .collect()
    }
}

pub trait Migratable {
    /// Start the dirty log in the migration objects and vmm.
    fn start_dirty_log() -> Result<()> {
        // Create dirty bitmaps for vmm.
        let mut bitmaps = HashMap::<u32, DirtyBitmap>::new();
        if let Some(mgt_object) = &MIGRATION_MANAGER.vmm.read().unwrap().mgt_object {
            let mem_slots = mgt_object.lock().unwrap().get_mem_slots();
            for (_, slot) in mem_slots.lock().unwrap().iter() {
                let bitmap =
                    DirtyBitmap::new(slot.guest_phys_addr, slot.userspace_addr, slot.memory_size);
                bitmaps.insert(slot.slot, bitmap);
            }

            // Start logging dirty memory in migration object.
            mgt_object.lock().unwrap().start_dirty_log()?;
        }

        let mut vm_bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        *vm_bitmaps = bitmaps;

        Ok(())
    }

    /// Stop the dirty log in the migration objects and vmm.
    fn stop_dirty_log() -> Result<()> {
        // Clear dirty bitmaps from vmm.
        let mut vm_bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        *vm_bitmaps = HashMap::new();

        if let Some(mgt_object) = &MIGRATION_MANAGER.vmm.read().unwrap().mgt_object {
            // Stop logging dirty memory in migration object.
            mgt_object.lock().unwrap().stop_dirty_log()?;
        }

        Ok(())
    }

    /// Collect the dirty log from migration object and vmm.
    ///
    /// # Arguments
    ///
    /// * `slot` - The memory slot.
    fn get_dirty_log(slot: &MigrateMemSlot) -> Result<Vec<MemBlock>> {
        // Get dirty memory from vmm.
        let mut vmm_dirty_bitmap = Vec::new();
        let bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        for (_, map) in bitmaps.iter() {
            if (slot.guest_phys_addr == map.gpa) && (slot.memory_size == map.len) {
                vmm_dirty_bitmap = map.get_and_clear_dirty();
            }
        }

        // Get dirty memory from migration objects.
        let vmm = MIGRATION_MANAGER.vmm.read().unwrap();
        let mgt_object = vmm.mgt_object.as_ref().unwrap();
        let vm_dirty_bitmap = mgt_object
            .lock()
            .unwrap()
            .get_dirty_log(slot.slot, slot.memory_size)
            .unwrap();

        // Merge dirty bitmap.
        let dirty_bitmap: Vec<u64> = vm_dirty_bitmap
            .iter()
            .zip(vmm_dirty_bitmap.iter())
            .map(|(x, y)| x | y)
            .collect();

        // Convert dirty bitmaps to memory blocks.
        Ok(Self::sync_dirty_bitmap(dirty_bitmap, slot.guest_phys_addr))
    }

    /// mark the dirty log into vmm.
    ///
    /// # Arguments
    ///
    /// * `addr` - Start address of dirty memory.
    /// * `len` - Length of dirty memory.
    fn mark_dirty_log(addr: u64, len: u64) {
        if !MigrationManager::is_active() {
            return;
        }

        let bitmaps = MIGRATION_MANAGER.vmm_bitmaps.write().unwrap();
        for (_, map) in bitmaps.iter() {
            if (addr >= map.hva) && ((addr + len) <= (map.hva + map.len)) {
                map.mark_bitmap(addr - map.hva + map.gpa, len);
            }
        }
    }

    /// sync the dirty log from migration object bitmaps.
    ///
    /// # Arguments
    ///
    /// * `bitmap` - dirty bitmap from migration object.
    /// * `addr` - Start address of memory slot.
    fn sync_dirty_bitmap(bitmap: Vec<u64>, addr: u64) -> Vec<MemBlock> {
        let page_size = host_page_size();
        let mut mem_blocks: Vec<MemBlock> = Vec::new();
        let mut block: Option<MemBlock> = None;

        for (idx, num) in bitmap.iter().enumerate() {
            if *num == 0 {
                continue;
            }

            for bit in 0..64 {
                if ((num >> bit) & 1_u64) == 0 {
                    if let Some(entry) = block.take() {
                        mem_blocks.push(entry);
                    }
                    continue;
                }

                if let Some(e) = &mut block {
                    e.len += page_size;
                } else {
                    let offset = ((idx * 64) + bit) as u64 * page_size;
                    block = Some(MemBlock {
                        gpa: addr + offset,
                        len: page_size,
                    });
                }
            }
        }
        if let Some(entry) = block.take() {
            mem_blocks.push(entry);
        }

        mem_blocks
    }
}

impl Migratable for MigrationManager {}
