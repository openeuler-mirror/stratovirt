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

use std::cmp::max;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use address_space::{GuestAddress, Region, RegionOps};
use hypervisor::kvm::{MsiVector, KVM_FDS};
use log::{error, warn};
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::{
    byte_code::ByteCode,
    num_ops::round_up,
    test_helper::{add_msix_msg, is_test_enabled},
};
use vmm_sys_util::eventfd::EventFd;

use crate::config::{CapId, PciConfig, RegionType, MINMUM_BAR_SIZE_FOR_MMIO, SECONDARY_BUS_NUM};
use crate::{
    le_read_u16, le_read_u32, le_read_u64, le_write_u16, le_write_u32, le_write_u64,
    ranges_overlap, PciBus,
};
use anyhow::{anyhow, bail, Context, Result};

pub const MSIX_TABLE_ENTRY_SIZE: u16 = 16;
pub const MSIX_TABLE_SIZE_MAX: u16 = 0x7ff;
const MSIX_TABLE_VEC_CTL: u16 = 0x0c;
const MSIX_TABLE_MASK_BIT: u8 = 0x01;
pub const MSIX_TABLE_BIR: u16 = 0x07;
pub const MSIX_TABLE_OFFSET: u32 = 0xffff_fff8;
const MSIX_MSG_UPPER_ADDR: u16 = 0x04;
const MSIX_MSG_DATA: u16 = 0x08;

pub const MSIX_CAP_CONTROL: u8 = 0x02;
pub const MSIX_CAP_ENABLE: u16 = 0x8000;
pub const MSIX_CAP_FUNC_MASK: u16 = 0x4000;
pub const MSIX_CAP_SIZE: u8 = 12;
pub const MSIX_CAP_ID: u8 = 0x11;
pub const MSIX_CAP_TABLE: u8 = 0x04;
pub const MSIX_CAP_PBA: u8 = 0x08;

/// MSI-X message structure.
#[derive(Copy, Clone)]
pub struct Message {
    /// Lower 32bit address of MSI-X address.
    pub address_lo: u32,
    /// Higher 32bit address of MSI-X address.
    pub address_hi: u32,
    /// MSI-X data.
    pub data: u32,
}

/// GSI information for routing msix.
struct GsiMsiRoute {
    irq_fd: Arc<EventFd>,
    gsi: i32,
    msg: Message,
}

/// The state of msix device.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct MsixState {
    /// MSI-X entries table. Max length of msix table is 2048(`MSIX_TABLE_SIZE_MAX`).
    table: [u8; 2048],
    /// MSI-X pba table. Max length of pba table is 256.
    pba: [u8; 256],
    func_masked: bool,
    enabled: bool,
    msix_cap_offset: u16,
    dev_id: u16,
}

/// MSI-X structure.
pub struct Msix {
    /// MSI-X table.
    pub table: Vec<u8>,
    pba: Vec<u8>,
    pub func_masked: bool,
    pub enabled: bool,
    pub msix_cap_offset: u16,
    pub dev_id: Arc<AtomicU16>,
    /// Maintains a list of GSI with irqfds that are registered to kvm.
    gsi_msi_routes: HashMap<u16, GsiMsiRoute>,
}

impl Msix {
    /// Construct a new MSI-X structure.
    ///
    /// # Arguments
    ///
    /// * `table_size` - Size in bytes of MSI-X table.
    /// * `pba_size` - Size in bytes of MSI-X PBA.
    /// * `msix_cap_offset` - Offset of MSI-X capability in configuration space.
    /// * `dev_id` - Dev_id for device.
    pub fn new(
        table_size: u32,
        pba_size: u32,
        msix_cap_offset: u16,
        dev_id: Arc<AtomicU16>,
    ) -> Self {
        let mut msix = Msix {
            table: vec![0; table_size as usize],
            pba: vec![0; pba_size as usize],
            func_masked: true,
            enabled: true,
            msix_cap_offset,
            dev_id,
            gsi_msi_routes: HashMap::new(),
        };
        msix.mask_all_vectors();
        msix
    }

    pub fn reset(&mut self) {
        self.table.resize_with(self.table.len(), || 0);
        self.pba.resize_with(self.pba.len(), || 0);
        self.func_masked = true;
        self.enabled = true;
        self.mask_all_vectors();
    }

    fn mask_all_vectors(&mut self) {
        let nr_vectors: usize = self.table.len() / MSIX_TABLE_ENTRY_SIZE as usize;
        for v in 0..nr_vectors {
            let offset: usize = v * MSIX_TABLE_ENTRY_SIZE as usize + MSIX_TABLE_VEC_CTL as usize;
            self.table[offset] |= MSIX_TABLE_MASK_BIT;
        }
    }

    pub fn is_vector_masked(&self, vector: u16) -> bool {
        if !self.enabled || self.func_masked {
            return true;
        }

        let offset = (vector * MSIX_TABLE_ENTRY_SIZE + MSIX_TABLE_VEC_CTL) as usize;
        if self.table[offset] & MSIX_TABLE_MASK_BIT == 0 {
            return false;
        }
        true
    }

    fn is_vector_pending(&self, vector: u16) -> bool {
        let offset: usize = vector as usize / 64;
        let pending_bit: u64 = 1 << (vector as u64 % 64);
        let value = le_read_u64(&self.pba, offset).unwrap();
        if value & pending_bit > 0 {
            return true;
        }
        false
    }

    fn set_pending_vector(&mut self, vector: u16) {
        let offset: usize = vector as usize / 64;
        let pending_bit: u64 = 1 << (vector as u64 % 64);
        let old_val = le_read_u64(&self.pba, offset).unwrap();
        le_write_u64(&mut self.pba, offset, old_val | pending_bit).unwrap();
    }

    fn clear_pending_vector(&mut self, vector: u16) {
        let offset: usize = vector as usize / 64;
        let pending_bit: u64 = !(1 << (vector as u64 % 64));
        let old_val = le_read_u64(&self.pba, offset).unwrap();
        le_write_u64(&mut self.pba, offset, old_val & pending_bit).unwrap();
    }

    fn update_irq_routing(&mut self, vector: u16, is_masked: bool) -> Result<()> {
        let entry = self.get_message(vector);
        let route = if let Some(route) = self.gsi_msi_routes.get_mut(&vector) {
            route
        } else {
            return Ok(());
        };

        let msix_vector = MsiVector {
            msg_addr_lo: entry.address_lo,
            msg_addr_hi: entry.address_hi,
            msg_data: entry.data,
            masked: false,
            #[cfg(target_arch = "aarch64")]
            dev_id: self.dev_id.load(Ordering::Acquire) as u32,
        };

        if is_masked {
            KVM_FDS
                .load()
                .vm_fd
                .as_ref()
                .unwrap()
                .unregister_irqfd(route.irq_fd.as_ref(), route.gsi as u32)
                .map_err(|e| {
                    error!("Failed to unregister irq, error is {:?}", e);
                    e
                })?;
        } else {
            let msg = &route.msg;
            if msg.data != entry.data
                || msg.address_lo != entry.address_lo
                || msg.address_hi != entry.address_hi
            {
                KVM_FDS
                    .load()
                    .irq_route_table
                    .lock()
                    .unwrap()
                    .update_msi_route(route.gsi as u32, msix_vector)
                    .map_err(|e| {
                        error!("Failed to update MSI-X route, error is {:?}", e);
                        e
                    })?;
                KVM_FDS.load().commit_irq_routing().map_err(|e| {
                    error!("Failed to commit irq routing, error is {:?}", e);
                    e
                })?;
                route.msg = entry;
            }

            KVM_FDS
                .load()
                .vm_fd
                .as_ref()
                .unwrap()
                .register_irqfd(route.irq_fd.as_ref(), route.gsi as u32)
                .map_err(|e| {
                    error!("Failed to register irq, error is {:?}", e);
                    e
                })?;
        }
        Ok(())
    }

    pub fn register_irqfd(&mut self, vector: u16, call_fd: Arc<EventFd>) -> Result<()> {
        let entry = self.get_message(vector);
        let msix_vector = MsiVector {
            msg_addr_lo: entry.address_lo,
            msg_addr_hi: entry.address_hi,
            msg_data: entry.data,
            masked: false,
            #[cfg(target_arch = "aarch64")]
            dev_id: self.dev_id.load(Ordering::Acquire) as u32,
        };

        let gsi = KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .allocate_gsi()
            .map_err(|e| {
                error!("Failed to allocate gsi, error is {:?}", e);
                e
            })?;

        KVM_FDS
            .load()
            .irq_route_table
            .lock()
            .unwrap()
            .add_msi_route(gsi, msix_vector)
            .map_err(|e| {
                error!("Failed to add MSI-X route, error is {:?}", e);
                e
            })?;

        KVM_FDS.load().commit_irq_routing().map_err(|e| {
            error!("Failed to commit irq routing, error is {:?}", e);
            e
        })?;

        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .register_irqfd(call_fd.as_ref(), gsi)
            .map_err(|e| {
                error!("Failed to register irq, error is {:?}", e);
                e
            })?;

        let gsi_route = GsiMsiRoute {
            irq_fd: call_fd,
            gsi: gsi as i32,
            msg: entry,
        };
        self.gsi_msi_routes.insert(vector, gsi_route);
        Ok(())
    }

    pub fn unregister_irqfd(&mut self) -> Result<()> {
        for (_, route) in self.gsi_msi_routes.iter() {
            KVM_FDS
                .load()
                .unregister_irqfd(route.irq_fd.as_ref(), route.gsi as u32)
                .map_err(|e| {
                    error!("Failed to unregister irq, error is {:?}", e);
                    e
                })?;

            KVM_FDS
                .load()
                .irq_route_table
                .lock()
                .unwrap()
                .release_gsi(route.gsi as u32)
                .map_err(|e| {
                    error!("Failed to release gsi, error is {:?}", e);
                    e
                })?;
        }
        self.gsi_msi_routes.clear();
        Ok(())
    }

    fn register_memory_region(
        msix: Arc<Mutex<Self>>,
        region: &Region,
        dev_id: Arc<AtomicU16>,
        table_offset: u64,
        pba_offset: u64,
    ) -> Result<()> {
        let locked_msix = msix.lock().unwrap();
        let table_size = locked_msix.table.len() as u64;
        let pba_size = locked_msix.pba.len() as u64;

        let cloned_msix = msix.clone();
        let table_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset as usize + data.len() > cloned_msix.lock().unwrap().table.len() {
                error!(
                    "It's forbidden to read out of the msix table(size: {}), with offset of {} and size of {}",
                    cloned_msix.lock().unwrap().table.len(),
                    offset,
                    data.len()
                );
                return false;
            }
            let offset = offset as usize;
            data.copy_from_slice(&cloned_msix.lock().unwrap().table[offset..(offset + data.len())]);
            true
        };
        let cloned_msix = msix.clone();
        let table_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset as usize + data.len() > cloned_msix.lock().unwrap().table.len() {
                error!(
                    "It's forbidden to write out of the msix table(size: {}), with offset of {} and size of {}",
                    cloned_msix.lock().unwrap().table.len(),
                    offset,
                    data.len()
                );
                return false;
            }
            let mut locked_msix = cloned_msix.lock().unwrap();
            let vector: u16 = offset as u16 / MSIX_TABLE_ENTRY_SIZE;
            let was_masked: bool = locked_msix.is_vector_masked(vector);
            let offset = offset as usize;
            locked_msix.table[offset..(offset + 4)].copy_from_slice(data);

            let is_masked: bool = locked_msix.is_vector_masked(vector);
            if was_masked != is_masked && locked_msix.update_irq_routing(vector, is_masked).is_err()
            {
                return false;
            }

            // Clear the pending vector just when it is pending. Otherwise, it
            // will cause unknown error.
            if was_masked && !is_masked && locked_msix.is_vector_pending(vector) {
                locked_msix.clear_pending_vector(vector);
                locked_msix.notify(vector, dev_id.load(Ordering::Acquire));
            }

            true
        };
        let table_region_ops = RegionOps {
            read: Arc::new(table_read),
            write: Arc::new(table_write),
        };
        let table_region = Region::init_io_region(table_size, table_region_ops);
        region
            .add_subregion(table_region, table_offset)
            .with_context(|| "Failed to register MSI-X table region.")?;

        let cloned_msix = msix.clone();
        let pba_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset as usize + data.len() > cloned_msix.lock().unwrap().pba.len() {
                error!(
                    "Fail to read msi pba, illegal data length {}, offset {}",
                    data.len(),
                    offset
                );
                return false;
            }
            let offset = offset as usize;
            data.copy_from_slice(&cloned_msix.lock().unwrap().pba[offset..(offset + data.len())]);
            true
        };
        let pba_write = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let pba_region_ops = RegionOps {
            read: Arc::new(pba_read),
            write: Arc::new(pba_write),
        };
        let pba_region = Region::init_io_region(pba_size, pba_region_ops);
        region
            .add_subregion(pba_region, pba_offset)
            .with_context(|| "Failed to register MSI-X PBA region.")?;

        Ok(())
    }

    pub fn get_message(&self, vector: u16) -> Message {
        let entry_offset: u16 = vector * MSIX_TABLE_ENTRY_SIZE;
        let mut offset = entry_offset as usize;
        let address_lo = le_read_u32(&self.table, offset).unwrap();
        offset = (entry_offset + MSIX_MSG_UPPER_ADDR) as usize;
        let address_hi = le_read_u32(&self.table, offset).unwrap();
        offset = (entry_offset + MSIX_MSG_DATA) as usize;
        let data = le_read_u32(&self.table, offset).unwrap();

        Message {
            address_lo,
            address_hi,
            data,
        }
    }

    pub fn notify(&mut self, vector: u16, dev_id: u16) {
        if vector >= self.table.len() as u16 / MSIX_TABLE_ENTRY_SIZE {
            warn!("Invalid msix vector {}.", vector);
            return;
        }

        if self.is_vector_masked(vector) {
            self.set_pending_vector(vector);
            return;
        }

        send_msix(self.get_message(vector), dev_id);
    }

    pub fn write_config(&mut self, config: &[u8], dev_id: u16, offset: usize, data: &[u8]) {
        let len = data.len();
        let msix_cap_control_off: usize = self.msix_cap_offset as usize + MSIX_CAP_CONTROL as usize;
        // Only care about the bits Masked(14) & Enabled(15) in msix control register.
        if !ranges_overlap(
            offset,
            offset + len,
            msix_cap_control_off + 1,
            msix_cap_control_off + 2,
        ) {
            return;
        }

        let masked: bool = is_msix_func_masked(self.msix_cap_offset as usize, config);
        let enabled: bool = is_msix_enabled(self.msix_cap_offset as usize, config);
        let mask_state_changed = !((self.func_masked == masked) && (self.enabled == enabled));

        self.func_masked = masked;
        self.enabled = enabled;

        if mask_state_changed && (self.enabled && !self.func_masked) {
            let max_vectors_nr: u16 = self.table.len() as u16 / MSIX_TABLE_ENTRY_SIZE;
            for v in 0..max_vectors_nr {
                if !self.is_vector_masked(v) && self.is_vector_pending(v) {
                    self.clear_pending_vector(v);
                    send_msix(self.get_message(v), dev_id);
                }
            }
        }
    }
}

impl StateTransfer for Msix {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        let mut state = MsixState::default();

        for (idx, table_byte) in self.table.iter().enumerate() {
            state.table[idx] = *table_byte;
        }
        for (idx, pba_byte) in self.pba.iter().enumerate() {
            state.pba[idx] = *pba_byte;
        }
        state.func_masked = self.func_masked;
        state.enabled = self.enabled;
        state.msix_cap_offset = self.msix_cap_offset;
        state.dev_id = self.dev_id.load(Ordering::Acquire);

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        let msix_state = *MsixState::from_bytes(state)
            .ok_or_else(|| anyhow!(MigrationError::FromBytesError("MSIX_DEVICE")))?;

        let table_length = self.table.len();
        let pba_length = self.pba.len();
        self.table = msix_state.table[..table_length].to_vec();
        self.pba = msix_state.pba[..pba_length].to_vec();
        self.func_masked = msix_state.func_masked;
        self.enabled = msix_state.enabled;
        self.msix_cap_offset = msix_state.msix_cap_offset;
        self.dev_id = Arc::new(AtomicU16::new(msix_state.dev_id));

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&MsixState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for Msix {
    fn resume(&mut self) -> migration::Result<()> {
        if self.enabled && !self.func_masked {
            for vector in 0..self.table.len() as u16 / MSIX_TABLE_ENTRY_SIZE {
                if self.is_vector_masked(vector) {
                    continue;
                }

                let msg = self.get_message(vector);

                // update and commit irq routing
                {
                    let kvm_fds = KVM_FDS.load();
                    let mut locked_irq_table = kvm_fds.irq_route_table.lock().unwrap();
                    let allocated_gsi = match locked_irq_table.allocate_gsi() {
                        Ok(gsi) => gsi,
                        Err(e) => bail!("Failed to allocate new gsi: {}", e),
                    };
                    let msi_vector = MsiVector {
                        msg_addr_hi: msg.address_hi,
                        msg_addr_lo: msg.address_lo,
                        msg_data: msg.data,
                        masked: false,
                        #[cfg(target_arch = "aarch64")]
                        dev_id: self.dev_id.load(Ordering::Acquire) as u32,
                    };
                    if let Err(e) = locked_irq_table.add_msi_route(allocated_gsi, msi_vector) {
                        bail!("Failed to add msi route to global irq routing table: {}", e);
                    }
                }
                if let Err(e) = KVM_FDS.load().commit_irq_routing() {
                    bail!("Failed to commit irq routing: {}", e);
                }

                if self.is_vector_pending(vector) {
                    self.clear_pending_vector(vector);
                    send_msix(msg, self.dev_id.load(Ordering::Acquire));
                }
            }
        }

        Ok(())
    }
}

pub fn is_msix_enabled(msix_cap_offset: usize, config: &[u8]) -> bool {
    let offset: usize = msix_cap_offset + MSIX_CAP_CONTROL as usize;
    let msix_ctl = le_read_u16(config, offset).unwrap();
    if msix_ctl & MSIX_CAP_ENABLE > 0 {
        return true;
    }
    false
}

fn is_msix_func_masked(msix_cap_offset: usize, config: &[u8]) -> bool {
    let offset: usize = msix_cap_offset + MSIX_CAP_CONTROL as usize;
    let msix_ctl = le_read_u16(config, offset).unwrap();
    if msix_ctl & MSIX_CAP_FUNC_MASK > 0 {
        return true;
    }
    false
}

fn send_msix(msg: Message, dev_id: u16) {
    #[cfg(target_arch = "aarch64")]
    let flags: u32 = kvm_bindings::KVM_MSI_VALID_DEVID;
    #[cfg(target_arch = "x86_64")]
    let flags: u32 = 0;

    let kvm_msi = kvm_bindings::kvm_msi {
        address_lo: msg.address_lo,
        address_hi: msg.address_hi,
        data: msg.data,
        flags,
        devid: dev_id as u32,
        pad: [0; 12],
    };

    if is_test_enabled() {
        let data = msg.data;
        let mut addr: u64 = msg.address_hi as u64;
        addr = (addr << 32) + msg.address_lo as u64;
        add_msix_msg(addr, data);
        return;
    }

    if let Err(e) = KVM_FDS.load().vm_fd.as_ref().unwrap().signal_msi(kvm_msi) {
        error!("Send msix error: {:?}", e);
    };
}

/// MSI-X initialization.
///
/// # Arguments
///
/// * `bar_id` - BAR id.
/// * `vector_nr` - The number of vector.
/// * `config` - The PCI config.
/// * `dev_id` - Dev id.
/// * `_id` - MSI-X id used in MigrationManager.
/// * `parent_region` - Parent region which the MSI-X region registered. If none, registered in BAR.
/// * `offset_opt` - Offset of table(table_offset) and Offset of pba(pba_offset). Set the table_offset and pba_offset together.
pub fn init_msix(
    bar_id: usize,
    vector_nr: u32,
    config: &mut PciConfig,
    dev_id: Arc<AtomicU16>,
    _id: &str,
    parent_region: Option<&Region>,
    offset_opt: Option<(u32, u32)>,
) -> Result<()> {
    if vector_nr == 0 || vector_nr > MSIX_TABLE_SIZE_MAX as u32 + 1 {
        bail!(
            "invalid msix vectors, which should be in [1, {}]",
            MSIX_TABLE_SIZE_MAX + 1
        );
    }

    let msix_cap_offset: usize = config.add_pci_cap(CapId::Msix as u8, MSIX_CAP_SIZE as usize)?;
    let mut offset: usize = msix_cap_offset + MSIX_CAP_CONTROL as usize;
    le_write_u16(&mut config.config, offset, vector_nr as u16 - 1)?;
    le_write_u16(
        &mut config.write_mask,
        offset,
        MSIX_CAP_FUNC_MASK | MSIX_CAP_ENABLE,
    )?;
    offset = msix_cap_offset + MSIX_CAP_TABLE as usize;
    let table_size = vector_nr * MSIX_TABLE_ENTRY_SIZE as u32;
    let pba_size = ((round_up(vector_nr as u64, 64).unwrap() / 64) * 8) as u32;
    let (table_offset, pba_offset) = if let Some((table, pba)) = offset_opt {
        (table, pba)
    } else {
        (0, table_size)
    };
    if ranges_overlap(
        table_offset.try_into().unwrap(),
        table_size.try_into().unwrap(),
        pba_offset.try_into().unwrap(),
        pba_size.try_into().unwrap(),
    ) {
        bail!("msix table and pba table overlapped.");
    }
    le_write_u32(&mut config.config, offset, table_offset | bar_id as u32)?;
    offset = msix_cap_offset + MSIX_CAP_PBA as usize;
    le_write_u32(&mut config.config, offset, pba_offset | bar_id as u32)?;

    let msix = Arc::new(Mutex::new(Msix::new(
        table_size,
        pba_size,
        msix_cap_offset as u16,
        dev_id.clone(),
    )));
    if let Some(region) = parent_region {
        Msix::register_memory_region(
            msix.clone(),
            region,
            dev_id,
            table_offset as u64,
            pba_offset as u64,
        )?;
    } else {
        let mut bar_size = ((table_size + pba_size) as u64).next_power_of_two();
        bar_size = max(bar_size, MINMUM_BAR_SIZE_FOR_MMIO as u64);
        let region = Region::init_container_region(bar_size);
        Msix::register_memory_region(
            msix.clone(),
            &region,
            dev_id,
            table_offset as u64,
            pba_offset as u64,
        )?;
        config.register_bar(bar_id, region, RegionType::Mem32Bit, false, bar_size)?;
    }

    config.msix = Some(msix.clone());

    #[cfg(not(test))]
    MigrationManager::register_device_instance(MsixState::descriptor(), msix, _id);

    Ok(())
}

pub fn update_dev_id(parent_bus: &Weak<Mutex<PciBus>>, devfn: u8, dev_id: &Arc<AtomicU16>) {
    let bus_num = parent_bus
        .upgrade()
        .unwrap()
        .lock()
        .unwrap()
        .number(SECONDARY_BUS_NUM as usize);
    let device_id = ((bus_num as u16) << 8) | (devfn as u16);
    dev_id.store(device_id, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PCI_CONFIG_SPACE_SIZE;

    #[test]
    fn test_init_msix() {
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 2);

        // Too many vectors.
        assert!(init_msix(
            0,
            MSIX_TABLE_SIZE_MAX as u32 + 2,
            &mut pci_config,
            Arc::new(AtomicU16::new(0)),
            "msix",
            None,
            None,
        )
        .is_err());

        // No vector.
        assert!(init_msix(
            0,
            0,
            &mut pci_config,
            Arc::new(AtomicU16::new(0)),
            "msix",
            None,
            None,
        )
        .is_err());

        init_msix(
            1,
            2,
            &mut pci_config,
            Arc::new(AtomicU16::new(0)),
            "msix",
            None,
            None,
        )
        .unwrap();
        let msix_cap_start = 64_u8;
        assert_eq!(pci_config.last_cap_end, 64 + MSIX_CAP_SIZE as u16);
        // Capabilities pointer
        assert_eq!(pci_config.config[0x34], msix_cap_start);
        assert_eq!(
            pci_config.config[msix_cap_start as usize],
            CapId::Msix as u8
        );
        // Capabilities list in Status Register.
        assert!(pci_config.config[0x06] & 0x10 > 0);
        // Message control register.
        assert_eq!(
            le_read_u16(&pci_config.config, msix_cap_start as usize + 2).unwrap(),
            1
        );
        // Table BIR.
        assert_eq!(pci_config.config[msix_cap_start as usize + 4] & 0x7, 1);
        // PBA BIR.
        assert_eq!(pci_config.config[msix_cap_start as usize + 8] & 0x7, 1);
    }

    #[test]
    fn test_mask_vectors() {
        let nr_vector = 2_u32;
        let mut msix = Msix::new(
            nr_vector * MSIX_TABLE_ENTRY_SIZE as u32,
            64,
            64,
            Arc::new(AtomicU16::new(0)),
        );

        assert!(msix.table[MSIX_TABLE_VEC_CTL as usize] & MSIX_TABLE_MASK_BIT > 0);
        assert!(
            msix.table[(MSIX_TABLE_ENTRY_SIZE + MSIX_TABLE_VEC_CTL) as usize] & MSIX_TABLE_MASK_BIT
                > 0
        );
        assert!(msix.is_vector_masked(0));
        msix.func_masked = false;
        assert!(msix.is_vector_masked(1));
        msix.table[(MSIX_TABLE_ENTRY_SIZE + MSIX_TABLE_VEC_CTL) as usize] &= !MSIX_TABLE_MASK_BIT;
        assert!(!msix.is_vector_masked(1));
    }

    #[test]
    fn test_pending_vectors() {
        let mut msix = Msix::new(
            MSIX_TABLE_ENTRY_SIZE as u32,
            64,
            64,
            Arc::new(AtomicU16::new(0)),
        );

        msix.set_pending_vector(0);
        assert!(msix.is_vector_pending(0));
        msix.clear_pending_vector(0);
        assert!(!msix.is_vector_pending(0));
    }

    #[test]
    fn test_get_message() {
        let mut msix = Msix::new(
            MSIX_TABLE_ENTRY_SIZE as u32,
            64,
            64,
            Arc::new(AtomicU16::new(0)),
        );
        le_write_u32(&mut msix.table, 0, 0x1000_0000).unwrap();
        le_write_u32(&mut msix.table, 4, 0x2000_0000).unwrap();
        le_write_u32(&mut msix.table, 8, 0x3000_0000).unwrap();

        let msg = msix.get_message(0);
        assert_eq!(msg.address_lo, 0x1000_0000);
        assert_eq!(msg.address_hi, 0x2000_0000);
        assert_eq!(msg.data, 0x3000_0000);
    }

    #[test]
    fn test_write_config() {
        let mut pci_config = PciConfig::new(PCI_CONFIG_SPACE_SIZE, 2);
        init_msix(
            0,
            2,
            &mut pci_config,
            Arc::new(AtomicU16::new(0)),
            "msix",
            None,
            None,
        )
        .unwrap();
        let msix = pci_config.msix.as_ref().unwrap();
        let mut locked_msix = msix.lock().unwrap();
        locked_msix.enabled = false;
        let offset = locked_msix.msix_cap_offset as usize + MSIX_CAP_CONTROL as usize;
        let val = le_read_u16(&pci_config.config, offset).unwrap();
        le_write_u16(&mut pci_config.config, offset, val | MSIX_CAP_ENABLE).unwrap();
        locked_msix.set_pending_vector(0);
        locked_msix.write_config(
            &pci_config.config,
            0,
            offset,
            &[0, val as u8 | MSIX_CAP_ENABLE as u8],
        );

        assert!(!locked_msix.func_masked);
        assert!(locked_msix.enabled);
    }
}
