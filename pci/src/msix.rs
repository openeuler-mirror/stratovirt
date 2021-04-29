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

use std::sync::{Arc, Mutex};

use address_space::{GuestAddress, Region, RegionOps};
use kvm_ioctls::VmFd;
use util::num_ops::round_up;

use crate::config::{CapId, PciConfig, RegionType};
use crate::errors::{Result, ResultExt};
use crate::{le_read_u16, le_read_u32, le_read_u64, le_write_u16, le_write_u32, le_write_u64};

const MSIX_TABLE_ENTRY_SIZE: u16 = 16;
const MSIX_TABLE_SIZE_MAX: u16 = 0x7ff;
const MSIX_TABLE_VEC_CTL: u16 = 0x0c;
const MSIX_TABLE_MASK_BIT: u8 = 0x01;
const MSIX_MSG_UPPER_ADDR: u16 = 0x04;
const MSIX_MSG_DATA: u16 = 0x08;

const MSIX_CAP_CONTROL: u8 = 0x02;
const MSIX_CAP_ENABLE: u16 = 0x8000;
const MSIX_CAP_FUNC_MASK: u16 = 0x4000;
const MSIX_CAP_SIZE: u8 = 12;
const MSIX_CAP_TABLE: u8 = 0x04;
const MSIX_CAP_PBA: u8 = 0x08;

/// MSI-X message structure.
pub struct Message {
    /// Lower 32bit address of MSI-X address.
    pub address_lo: u32,
    /// Higer 32bit address of MSI-X address.
    pub address_hi: u32,
    /// MSI-X data.
    pub data: u32,
}

/// MSI-X structure.
pub struct Msix {
    /// MSI-X table.
    pub table: Vec<u8>,
    pba: Vec<u8>,
    func_masked: bool,
    enabled: bool,
    msix_cap_offset: u16,
}

impl Msix {
    /// Construct a new MSI-X structure.
    ///
    /// # Arguments
    ///
    /// * `table_size` - Size in bytes of MSI-X table.
    /// * `pba_size` - Size in bytes of MSI-X PBA.
    /// * `msix_cap_offset` - Offset of MSI-X capability in configuration space.
    pub fn new(table_size: u32, pba_size: u32, msix_cap_offset: u16) -> Self {
        let mut msix = Msix {
            table: vec![0; table_size as usize],
            pba: vec![0; pba_size as usize],
            func_masked: true,
            enabled: true,
            msix_cap_offset,
        };
        msix.mask_all_vectors();
        msix
    }

    fn mask_all_vectors(&mut self) {
        let nr_vectors: usize = self.table.len() / MSIX_TABLE_ENTRY_SIZE as usize;
        for v in 0..nr_vectors {
            let offset: usize = v * MSIX_TABLE_ENTRY_SIZE as usize + MSIX_TABLE_VEC_CTL as usize;
            self.table[offset] |= MSIX_TABLE_MASK_BIT;
        }
    }

    fn is_vector_masked(&self, vector: u16) -> bool {
        let offset = (vector * MSIX_TABLE_ENTRY_SIZE + MSIX_TABLE_VEC_CTL) as usize;
        if !self.enabled || self.func_masked || (self.table[offset] & MSIX_TABLE_MASK_BIT == 0) {
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

    fn register_memory_region(
        msix: Arc<Mutex<Self>>,
        region: &Region,
        vm_fd: Arc<VmFd>,
        dev_id: u16,
    ) -> Result<()> {
        let locked_msix = msix.lock().unwrap();
        let table_size = locked_msix.table.len() as u64;
        let pba_size = locked_msix.pba.len() as u64;

        let cloned_msix = msix.clone();
        let table_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            let offset = offset as usize;
            data.copy_from_slice(&cloned_msix.lock().unwrap().table[offset..(offset + 4)]);
            true
        };
        let cloned_msix = msix.clone();
        let table_write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            let mut locked_msix = cloned_msix.lock().unwrap();
            let vector: u16 = offset as u16 / MSIX_TABLE_ENTRY_SIZE;
            let was_masked: bool = locked_msix.is_vector_masked(vector);
            let offset = offset as usize;
            locked_msix.table[offset..(offset + 4)].copy_from_slice(&data[..]);

            let is_masked: bool = locked_msix.is_vector_masked(vector);
            if was_masked && !is_masked {
                locked_msix.clear_pending_vector(vector);
                locked_msix.notify(&vm_fd, vector, dev_id);
            }

            true
        };
        let table_region_ops = RegionOps {
            read: Arc::new(table_read),
            write: Arc::new(table_write),
        };
        let table_region = Region::init_io_region(table_size, table_region_ops);
        region
            .add_subregion(table_region, 0)
            .chain_err(|| "Failed to register MSI-X table region.")?;

        let cloned_msix = msix.clone();
        let pba_read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            let offset = offset as usize;
            data.copy_from_slice(&cloned_msix.lock().unwrap().pba[offset..(offset + 4)]);
            true
        };
        let pba_write = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { true };
        let pba_region_ops = RegionOps {
            read: Arc::new(pba_read),
            write: Arc::new(pba_write),
        };
        let pba_region = Region::init_io_region(pba_size, pba_region_ops);
        region
            .add_subregion(pba_region, table_size)
            .chain_err(|| "Failed to register MSI-X PBA region.")?;

        Ok(())
    }

    fn get_message(&self, vector: u16) -> Message {
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

    pub fn notify(&mut self, vm_fd: &VmFd, vector: u16, dev_id: u16) {
        if vector >= self.table.len() as u16 / MSIX_TABLE_ENTRY_SIZE {
            error!("Invaild msix vector {}.", vector);
            return;
        }

        if self.is_vector_masked(vector) {
            self.set_pending_vector(vector);
            return;
        }

        send_msix(vm_fd, self.get_message(vector), dev_id);
    }

    pub fn write_config(&mut self, config: &[u8], vm_fd: &VmFd, dev_id: u16) {
        let func_masked: bool = is_msix_func_masked(self.msix_cap_offset as usize, config);
        let enabled: bool = is_msix_enabled(self.msix_cap_offset as usize, config);

        if enabled && self.func_masked && !func_masked {
            let max_vectors_nr: u16 = self.table.len() as u16 / MSIX_TABLE_ENTRY_SIZE;
            for v in 0..max_vectors_nr {
                if !self.is_vector_masked(v) && self.is_vector_pending(v) {
                    self.clear_pending_vector(v);
                    send_msix(vm_fd, self.get_message(v), dev_id);
                }
            }
        }
        self.func_masked = func_masked;
        self.enabled = enabled;
    }
}

fn is_msix_enabled(msix_cap_offset: usize, config: &[u8]) -> bool {
    let offset: usize = msix_cap_offset + MSIX_CAP_CONTROL as usize;
    let msix_ctl = le_read_u16(&config, offset).unwrap();
    if msix_ctl & MSIX_CAP_ENABLE > 0 {
        return true;
    }
    false
}

fn is_msix_func_masked(msix_cap_offset: usize, config: &[u8]) -> bool {
    let offset: usize = msix_cap_offset + MSIX_CAP_CONTROL as usize;
    let msix_ctl = le_read_u16(&config, offset).unwrap();
    if msix_ctl & MSIX_CAP_FUNC_MASK > 0 {
        return true;
    }
    false
}

fn send_msix(vm_fd: &VmFd, msg: Message, dev_id: u16) {
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
    if let Err(e) = vm_fd.signal_msi(kvm_msi) {
        error!("Send msix error: {}", e);
    };
}

/// MSI-X initialization.
pub fn init_msix(
    vm_fd: &Arc<VmFd>,
    bar_id: usize,
    vector_nr: u32,
    config: &mut PciConfig,
    dev_id: u16,
) -> Result<()> {
    if vector_nr > MSIX_TABLE_SIZE_MAX as u32 + 1 {
        bail!("Too many msix vectors.");
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
    le_write_u32(&mut config.config, offset, bar_id as u32)?;
    offset = msix_cap_offset + MSIX_CAP_PBA as usize;
    let table_size = vector_nr * MSIX_TABLE_ENTRY_SIZE as u32;
    le_write_u32(&mut config.config, offset, table_size | bar_id as u32)?;

    let pba_size = ((round_up(vector_nr as u64, 64).unwrap() / 64) * 8) as u32;
    let msix = Arc::new(Mutex::new(Msix::new(
        table_size,
        pba_size,
        msix_cap_offset as u16,
    )));
    let bar_size = ((table_size + pba_size) as u64).next_power_of_two();
    let region = Region::init_container_region(bar_size);
    Msix::register_memory_region(msix.clone(), &region, vm_fd.clone(), dev_id)?;
    config.register_bar(bar_id, region, RegionType::Mem32Bit, false, bar_size);
    config.msix = Some(msix);

    Ok(())
}
