// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use kvm_bindings::*;
use kvm_bindings::{kvm_userspace_memory_region as KvmMemSlot, KVM_MEM_READONLY};
use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use log::{debug, warn};

use crate::HypervisorError;
use address_space::{
    AddressRange, AddressSpaceError, FlatRange, Listener, ListenerReqType, MemSlot,
    RegionIoEventFd, RegionType,
};
use util::{num_ops::round_down, unix::host_page_size};

#[derive(Clone)]
pub struct KvmMemoryListener {
    vm_fd: Option<Arc<VmFd>>,
    /// Id of AddressSpace.
    as_id: Arc<AtomicU32>,
    /// Record all MemSlots.
    slots: Arc<Mutex<Vec<MemSlot>>>,
    /// Memory slot registered in kvm.
    kvm_memslots: Arc<Mutex<HashMap<u32, KvmMemSlot>>>,
    /// Whether enabled as a memory listener.
    enabled: bool,
}

impl KvmMemoryListener {
    /// Create a new KvmMemoryListener for a VM.
    ///
    /// # Arguments
    ///
    /// * `nr_slots` - Number of slots.
    pub fn new(
        nr_slots: u32,
        vm_fd: Option<Arc<VmFd>>,
        kvm_memslots: Arc<Mutex<HashMap<u32, KvmMemSlot>>>,
    ) -> KvmMemoryListener {
        KvmMemoryListener {
            vm_fd,
            as_id: Arc::new(AtomicU32::new(0)),
            slots: Arc::new(Mutex::new(vec![MemSlot::default(); nr_slots as usize])),
            kvm_memslots,
            enabled: false,
        }
    }

    /// Find a free slot and fills it with given arguments.
    ///
    /// # Arguments
    ///
    /// * `guest_addr` - Guest address.
    /// * `size` - Size of slot.
    /// * `host_addr` - Host address.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * No available Kvm slot.
    /// * Given memory slot overlap with existed one.
    fn get_free_slot(&self, guest_addr: u64, size: u64, host_addr: u64) -> Result<u32> {
        let mut slots = self.slots.lock().unwrap();

        // check if the given address range overlaps with exist ones
        let range = AddressRange::from((guest_addr, size));
        slots.iter().try_for_each::<_, Result<()>>(|s| {
            if AddressRange::from((s.guest_addr, s.size))
                .find_intersection(range)
                .is_some()
            {
                return Err(anyhow!(HypervisorError::KvmSlotOverlap {
                    add: (guest_addr, size),
                    exist: (s.guest_addr, s.size)
                }));
            }
            Ok(())
        })?;

        for (index, slot) in slots.iter_mut().enumerate() {
            if slot.size == 0 {
                slot.index = index as u32;
                slot.guest_addr = guest_addr;
                slot.size = size;
                slot.host_addr = host_addr;
                return Ok(slot.index);
            }
        }

        Err(anyhow!(HypervisorError::NoAvailKvmSlot(slots.len())))
    }

    /// Delete a slot after finding it according to the given arguments.
    /// Return the deleted one if succeed.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address of slot.
    /// * `size` - Size of slots.
    ///
    /// # Errors
    ///
    /// Return Error if no Kem slot matched.
    fn delete_slot(&self, addr: u64, size: u64) -> Result<MemSlot> {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.guest_addr == addr && slot.size == size {
                // set slot size to zero, so it can be reused later
                slot.size = 0;
                return Ok(*slot);
            }
        }
        Err(anyhow!(HypervisorError::NoMatchedKvmSlot(addr, size)))
    }

    /// Align a piece of memory segment according to `alignment`,
    /// return AddressRange after aligned.
    ///
    /// # Arguments
    ///
    /// * `range` - One piece of memory segment.
    /// * `alignment` - Alignment base.
    ///
    /// # Errors
    ///
    /// Return Error if Memslot size is zero after aligned.
    fn align_mem_slot(range: AddressRange, alignment: u64) -> Result<AddressRange> {
        let aligned_addr = range
            .base
            .align_up(alignment)
            .with_context(|| AddressSpaceError::AddrAlignUp(range.base.raw_value(), alignment))?;

        let aligned_size = range
            .size
            .checked_sub(aligned_addr.offset_from(range.base))
            .and_then(|sz| round_down(sz, alignment))
            .filter(|&sz| sz > 0_u64)
            .with_context(||
                format!("Mem slot size is zero after aligned, addr 0x{:X}, size 0x{:X}, alignment 0x{:X}",
                    range.base.raw_value(), range.size, alignment)
            )?;

        Ok(AddressRange::new(aligned_addr, aligned_size))
    }

    /// Callback function for adding Region, which only care about Ram-type Region yet.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - Corresponding FlatRange of new-added region.
    ///
    /// # Errors
    ///
    /// Return Error if fail to delete kvm_mem_slot.
    fn add_region(&self, flat_range: &FlatRange) -> Result<()> {
        if flat_range.owner.region_type() == RegionType::RomDevice
            && !flat_range.owner.get_rom_device_romd().unwrap()
        {
            if let Err(ref e) = self.delete_region(flat_range) {
                warn!(
                    "Rom-device Region changes to IO mode, Failed to delete region: {:?}",
                    e
                );
            }
            return Ok(());
        }

        if flat_range.owner.region_type() != RegionType::Ram
            && flat_range.owner.region_type() != RegionType::RomDevice
            && flat_range.owner.region_type() != RegionType::RamDevice
        {
            return Ok(());
        }

        let (aligned_addr, aligned_size) =
            Self::align_mem_slot(flat_range.addr_range, host_page_size())
                .map(|r| (r.base, r.size))
                .with_context(|| "Failed to align mem slot")?;
        let align_adjust = aligned_addr.raw_value() - flat_range.addr_range.base.raw_value();

        // `unwrap()` won't fail because Ram-type Region definitely has hva
        let aligned_hva = flat_range.owner.get_host_address().unwrap()
            + flat_range.offset_in_region
            + align_adjust;

        let slot_idx = self
            .get_free_slot(aligned_addr.raw_value(), aligned_size, aligned_hva)
            .with_context(|| "Failed to get available KVM mem slot")?;

        let mut flags = 0_u32;
        if flat_range.owner.get_rom_device_romd().unwrap_or(false) {
            flags |= KVM_MEM_READONLY;
        }
        let kvm_region = KvmMemSlot {
            slot: slot_idx | (self.as_id.load(Ordering::SeqCst) << 16),
            guest_phys_addr: aligned_addr.raw_value(),
            memory_size: aligned_size,
            userspace_addr: aligned_hva,
            flags,
        };

        if kvm_region.flags & KVM_MEM_READONLY == 0 {
            let mut locked_slots = self.kvm_memslots.as_ref().lock().unwrap();
            locked_slots.insert(kvm_region.slot, kvm_region);
        }

        // SAFETY: All parameters in the struct of kvm_region are valid,
        // it can be guaranteed that calling the ioctl_with_ref in the function
        // of set_user_memory_region is safe.
        unsafe {
            self.vm_fd
                .as_ref()
                .unwrap()
                .set_user_memory_region(kvm_region)
                .or_else(|e| {
                    self.delete_slot(aligned_addr.raw_value(), aligned_size)
                        .with_context(|| "Failed to delete Kvm mem slot")?;
                    Err(e).with_context(|| {
                        format!(
                            "KVM register memory region failed: addr 0x{:X}, size 0x{:X}",
                            aligned_addr.raw_value(),
                            aligned_size
                        )
                    })
                })
        }
    }

    /// Callback function for deleting Region, which only care about Ram-type Region yet.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - Corresponding FlatRange of new-deleted region.
    fn delete_region(&self, flat_range: &FlatRange) -> Result<()> {
        if flat_range.owner.region_type() != RegionType::Ram
            && flat_range.owner.region_type() != RegionType::RomDevice
            && flat_range.owner.region_type() != RegionType::RamDevice
        {
            return Ok(());
        }

        let (aligned_addr, aligned_size) =
            Self::align_mem_slot(flat_range.addr_range, host_page_size())
                .map(|r| (r.base, r.size))
                .with_context(|| "Failed to align mem slot")?;

        let mem_slot = match self.delete_slot(aligned_addr.raw_value(), aligned_size) {
            Ok(m) => m,
            Err(_) => {
                debug!("no match mem slot registered to KVM, just return");
                return Ok(());
            }
        };

        let kvm_region = kvm_userspace_memory_region {
            slot: mem_slot.index | (self.as_id.load(Ordering::SeqCst) << 16),
            guest_phys_addr: mem_slot.guest_addr,
            memory_size: 0_u64,
            userspace_addr: mem_slot.host_addr,
            flags: 0,
        };

        let mut locked_slots = self.kvm_memslots.lock().unwrap();
        locked_slots.remove(&kvm_region.slot);

        // SAFETY: All parameters in the struct of kvm_region are valid,
        // it can be guaranteed that calling the ioctl_with_ref in the function
        // of set_user_memory_region is safe.
        unsafe {
            self.vm_fd
                .as_ref()
                .unwrap()
                .set_user_memory_region(kvm_region)
                .with_context(|| {
                    format!(
                        "KVM unregister memory region failed: addr 0x{:X}",
                        aligned_addr.raw_value(),
                    )
                })
        }
    }

    /// Register a IoEvent to `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent would be added.
    ///
    /// # Errors
    ///
    /// Return Error if the length of ioeventfd data is unexpected or syscall failed.
    fn add_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let vm_fd = self.vm_fd.as_ref().unwrap();
        let io_addr = IoEventAddress::Mmio(ioevtfd.addr_range.base.raw_value());
        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data),
                _ => bail!("Unexpected ioeventfd data length {}", length),
            }
        } else {
            vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.with_context(|| {
            format!(
                "KVM register ioeventfd failed, mmio addr 0x{:X}, size 0x{:X}, data_match {}",
                ioevtfd.addr_range.base.raw_value(),
                ioevtfd.addr_range.size,
                if ioevtfd.data_match {
                    ioevtfd.data
                } else {
                    u64::MAX
                }
            )
        })
    }

    /// Deletes `ioevtfd` from `/dev/kvm`
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent would be deleted.
    fn delete_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let vm_fd = self.vm_fd.as_ref().unwrap();
        let io_addr = IoEventAddress::Mmio(ioevtfd.addr_range.base.raw_value());
        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data),
                _ => bail!("Unexpected ioeventfd data length {}", length),
            }
        } else {
            vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.with_context(|| {
            format!(
                "KVM unregister ioeventfd failed: mmio addr 0x{:X}, size 0x{:X}, data_match {}",
                ioevtfd.addr_range.base.raw_value(),
                ioevtfd.addr_range.size,
                if ioevtfd.data_match {
                    ioevtfd.data
                } else {
                    u64::MAX
                }
            )
        })
    }
}

impl Listener for KvmMemoryListener {
    /// Get default priority.
    fn priority(&self) -> i32 {
        10_i32
    }

    /// Is this listener enabled to call.
    fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable listener for address space.
    fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable listener for address space.
    fn disable(&mut self) {
        self.enabled = false;
    }

    /// Deal with the request.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - FlatRange would be used to find the region.
    /// * `evtfd` - IoEvent of Region.
    /// * `req_type` - Request type.
    ///
    /// # Errors
    ///
    /// Returns Error if
    /// * Both `flat_range` and `evtfd' are not provided.
    fn handle_request(
        &self,
        flat_range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> Result<()> {
        let req_ret =
            match req_type {
                ListenerReqType::AddRegion => self
                    .add_region(flat_range.with_context(|| "No FlatRange for AddRegion request")?),
                ListenerReqType::DeleteRegion => self.delete_region(
                    flat_range.with_context(|| "No FlatRange for DeleteRegion request")?,
                ),
                ListenerReqType::AddIoeventfd => self
                    .add_ioeventfd(evtfd.with_context(|| "No IoEventFd for AddIoeventfd request")?),
                ListenerReqType::DeleteIoeventfd => self.delete_ioeventfd(
                    evtfd.with_context(|| "No IoEventFd for DeleteIoeventfd request")?,
                ),
            };

        req_ret.with_context(|| AddressSpaceError::ListenerRequest(req_type))
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Default)]
pub struct KvmIoListener {
    vm_fd: Option<Arc<VmFd>>,
    /// Whether enabled as a IO listener.
    enabled: bool,
}

#[cfg(target_arch = "x86_64")]
impl KvmIoListener {
    pub fn new(vm_fd: Option<Arc<VmFd>>) -> KvmIoListener {
        KvmIoListener {
            vm_fd,
            enabled: false,
        }
    }
    /// Register a IoEvent to `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent of Region.
    ///
    /// # Errors
    ///
    /// Return Error if the length of ioeventfd data is unexpected or syscall failed.
    fn add_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let vm_fd = self.vm_fd.as_ref().unwrap();
        let io_addr = IoEventAddress::Pio(ioevtfd.addr_range.base.raw_value());
        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data),
                _ => bail!("unexpected ioeventfd data length {}", length),
            }
        } else {
            vm_fd.register_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.with_context(|| {
            format!(
                "KVM register ioeventfd failed: io addr 0x{:X}, size 0x{:X}, data_match {}",
                ioevtfd.addr_range.base.raw_value(),
                ioevtfd.addr_range.size,
                if ioevtfd.data_match {
                    ioevtfd.data
                } else {
                    u64::MAX
                }
            )
        })
    }

    /// Delete an IoEvent from `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent of Region.
    fn delete_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let vm_fd = self.vm_fd.as_ref().unwrap();
        let io_addr = IoEventAddress::Pio(ioevtfd.addr_range.base.raw_value());
        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data),
                _ => bail!("Unexpected ioeventfd data length {}", length),
            }
        } else {
            vm_fd.unregister_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.with_context(|| {
            format!(
                "KVM unregister ioeventfd failed: io addr 0x{:X}, size 0x{:X}, data_match {}",
                ioevtfd.addr_range.base.raw_value(),
                ioevtfd.addr_range.size,
                if ioevtfd.data_match {
                    ioevtfd.data
                } else {
                    u64::MAX
                }
            )
        })
    }
}

/// Kvm io listener.
#[cfg(target_arch = "x86_64")]
impl Listener for KvmIoListener {
    /// Get the default priority.
    fn priority(&self) -> i32 {
        10_i32
    }

    /// Is this listener enabled to call.
    fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable listener for address space.
    fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable listener for address space.
    fn disable(&mut self) {
        self.enabled = false;
    }

    /// Deal with the request.
    ///
    /// # Arguments
    ///
    /// * `_range` - Corresponding FlatRange of new-added/deleted region.
    /// * `evtfd` - IoEvent of Region.
    /// * `req_type` - Request type.
    fn handle_request(
        &self,
        _range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> Result<()> {
        let handle_ret = match req_type {
            ListenerReqType::AddIoeventfd => {
                self.add_ioeventfd(evtfd.with_context(|| "No IoEventFd for AddIoeventfd request")?)
            }
            ListenerReqType::DeleteIoeventfd => self.delete_ioeventfd(
                evtfd.with_context(|| "No IoEventFd for DeleteIoeventfd request")?,
            ),
            _ => return Ok(()),
        };

        handle_ret.with_context(|| AddressSpaceError::ListenerRequest(req_type))
    }
}

#[cfg(test)]
mod test {
    use libc::EFD_NONBLOCK;
    use vmm_sys_util::eventfd::EventFd;

    use crate::kvm::KvmHypervisor;

    use super::*;
    use address_space::{GuestAddress, HostMemMapping, Region, RegionIoEventFd};

    fn generate_region_ioeventfd<T: Into<u64>>(addr: u64, datamatch: T) -> RegionIoEventFd {
        let data = datamatch.into();
        RegionIoEventFd {
            fd: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            addr_range: AddressRange::from((addr, std::mem::size_of::<T>() as u64)),
            data_match: data != 0,
            data,
        }
    }

    fn create_ram_range(addr: u64, size: u64, offset_in_region: u64) -> FlatRange {
        let mem_mapping = Arc::new(
            HostMemMapping::new(GuestAddress(addr), None, size, None, false, false, false).unwrap(),
        );
        FlatRange {
            addr_range: AddressRange::new(
                mem_mapping.start_address().unchecked_add(offset_in_region),
                mem_mapping.size() - offset_in_region,
            ),
            owner: Region::init_ram_region(mem_mapping.clone(), "ram"),
            offset_in_region,
            rom_dev_romd: None,
        }
    }

    #[test]
    fn test_alloc_slot() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let kml = KvmMemoryListener::new(4, kvm_hyp.vm_fd.clone(), kvm_hyp.mem_slots.clone());
        let host_addr = 0u64;

        assert_eq!(kml.get_free_slot(0, 100, host_addr).unwrap(), 0);
        assert_eq!(kml.get_free_slot(200, 100, host_addr).unwrap(), 1);
        assert_eq!(kml.get_free_slot(300, 100, host_addr).unwrap(), 2);
        assert_eq!(kml.get_free_slot(500, 100, host_addr).unwrap(), 3);
        assert!(kml.get_free_slot(200, 100, host_addr).is_err());
        // no available KVM mem slot
        assert!(kml.get_free_slot(600, 100, host_addr).is_err());

        kml.delete_slot(200, 100).unwrap();
        assert!(kml.delete_slot(150, 100).is_err());
        assert!(kml.delete_slot(700, 100).is_err());
        assert_eq!(kml.get_free_slot(200, 100, host_addr).unwrap(), 1);
    }

    #[test]
    fn test_add_del_ram_region() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let kml = KvmMemoryListener::new(34, kvm_hyp.vm_fd.clone(), kvm_hyp.mem_slots.clone());
        let ram_size = host_page_size();
        let ram_fr1 = create_ram_range(0, ram_size, 0);

        kml.handle_request(Some(&ram_fr1), None, ListenerReqType::AddRegion)
            .unwrap();
        // flat-range already added, adding again should make an error
        assert!(kml
            .handle_request(Some(&ram_fr1), None, ListenerReqType::AddRegion)
            .is_err());
        assert!(kml
            .handle_request(Some(&ram_fr1), None, ListenerReqType::DeleteRegion)
            .is_ok());
        // flat-range already deleted, deleting again should make an error
        assert!(kml
            .handle_request(Some(&ram_fr1), None, ListenerReqType::DeleteRegion)
            .is_ok());
    }

    #[test]
    fn test_add_region_align() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let kml = KvmMemoryListener::new(34, kvm_hyp.vm_fd.clone(), kvm_hyp.mem_slots.clone());
        // flat-range not aligned
        let page_size = host_page_size();
        let ram_fr2 = create_ram_range(page_size, 2 * page_size, 1000);
        assert!(kml
            .handle_request(Some(&ram_fr2), None, ListenerReqType::AddRegion)
            .is_ok());

        // flat-range size is zero after aligned, this step should make an error
        let ram_fr3 = create_ram_range(page_size, page_size, 1000);
        assert!(kml
            .handle_request(Some(&ram_fr3), None, ListenerReqType::AddRegion)
            .is_err());
    }

    #[test]
    fn test_add_del_ioeventfd() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let kml = KvmMemoryListener::new(34, kvm_hyp.vm_fd.clone(), kvm_hyp.mem_slots.clone());
        let evtfd = generate_region_ioeventfd(4, NoDatamatch);
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());
        // The evtfd already added, adding again should make an error.
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_err());
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
        // The evtfd already deleted, deleting again should cause an error.
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // Register an ioeventfd with data-match.
        let evtfd = generate_region_ioeventfd(64, 4_u64);
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());

        // Register an ioeventfd which has same address with previously registered ones will cause
        // an error.
        let same_addred_evtfd = generate_region_ioeventfd(64, 4_u64);
        assert!(kml
            .handle_request(
                None,
                Some(&same_addred_evtfd),
                ListenerReqType::AddIoeventfd
            )
            .is_err());

        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
    }

    #[test]
    fn test_ioeventfd_with_data_match() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let kml = KvmMemoryListener::new(34, kvm_hyp.vm_fd.clone(), kvm_hyp.mem_slots.clone());
        let evtfd_addr = 0x1000_u64;
        let mut evtfd = generate_region_ioeventfd(evtfd_addr, 64_u32);
        evtfd.addr_range.size = 3_u64;
        // Matched data's length must be 2, 4 or 8.
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_err());

        let evtfd = generate_region_ioeventfd(evtfd_addr, 64_u32);
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());

        // Delete ioeventfd with wrong address will cause an error.
        let mut evtfd_to_del = evtfd.clone();
        evtfd_to_del.addr_range.base.0 = evtfd_to_del.addr_range.base.0 - 2;
        assert!(kml
            .handle_request(None, Some(&evtfd_to_del), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // Delete ioeventfd with inconsistent data-match will cause error.
        let mut evtfd_to_del = evtfd.clone();
        evtfd_to_del.data_match = false;
        assert!(kml
            .handle_request(None, Some(&evtfd_to_del), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // Delete ioeventfd with inconsistent matched data will cause an error.
        let mut evtfd_to_del = evtfd.clone();
        evtfd_to_del.data = 128_u64;
        assert!(kml
            .handle_request(None, Some(&evtfd_to_del), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // Delete it successfully.
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());

        // Delete a not-exist ioeventfd will cause an error.
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_err());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_kvm_io_listener() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let iol = KvmIoListener::new(kvm_hyp.vm_fd.clone());
        let evtfd = generate_region_ioeventfd(4, NoDatamatch);
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());
        // evtfd already added, adding again should make an error.
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_err());
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
        // evtfd already deleted, deleting again should make an error.
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // Matched data's length must be 2, 4 or 8.
        let mut evtfd_match = generate_region_ioeventfd(4, 64_u32);
        evtfd_match.addr_range.size = 3;
        assert!(iol
            .handle_request(None, Some(&evtfd_match), ListenerReqType::AddIoeventfd)
            .is_err());
        evtfd_match.addr_range.size = 4;
        assert!(iol
            .handle_request(None, Some(&evtfd_match), ListenerReqType::AddIoeventfd)
            .is_ok());
    }
}
