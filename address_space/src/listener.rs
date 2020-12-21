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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use util::num_ops::round_down;

use crate::{page_size, AddressRange, FlatRange, RegionIoEventFd, RegionType};

pub mod errors {
    error_chain! {
        errors {
            NoAvailKvmSlot {
                display("No available kvm_mem_slot, used up")
            }
            NoMatchedKvmSlot(addr: u64, sz: u64) {
                display("Failed to find matched kvm_mem_slot, addr {}, size {}", addr, sz)
            }
            Overlap {
                display("Address range overlaps with others")
            }
        }
    }
}
use self::errors::{ErrorKind, Result, ResultExt};

/// Different operations of listener requests.
#[derive(Debug, Copy, Clone)]
pub enum ListenerReqType {
    /// Add a region.
    AddRegion,
    /// Delete a region.
    DeleteRegion,
    /// Add a io event file descriptor.
    AddIoeventfd,
    /// Delete a io event file descriptor.
    DeleteIoeventfd,
}

pub trait Listener: Send + Sync {
    /// Get priority.
    fn priority(&self) -> i32;

    /// Deal with the request.
    ///
    /// # Arguments
    ///
    /// * `_range` - FlatRange would be used to find the region.
    /// * `_evtfd` - RegionIoEventFd of Region.
    /// * `_type` - Request type.
    fn handle_request(
        &self,
        _range: Option<&FlatRange>,
        _evtfd: Option<&RegionIoEventFd>,
        _type: ListenerReqType,
    ) -> std::result::Result<(), crate::errors::Error> {
        Ok(())
    }
}

/// Memory slot constructing a link between guest address and host address.
#[derive(Default, Copy, Clone)]
struct MemSlot {
    /// Index of a memory slot.
    pub index: u32,
    /// Guest address.
    pub guest_addr: u64,
    /// Size of memory.
    pub size: u64,
    /// Host address.
    pub host_addr: u64,
    /// Flag.
    pub flag: u32,
}

/// Kvm memory listener.
#[derive(Clone)]
pub struct KvmMemoryListener {
    /// Id of AddressSpace.
    as_id: Arc<AtomicU32>,
    /// File descriptor of VM.
    fd: Arc<VmFd>,
    /// Record all MemSlots.
    slots: Arc<Mutex<Vec<MemSlot>>>,
}

impl KvmMemoryListener {
    /// Create a new KvmMemoryListener for a VM.
    ///
    /// # Arguments
    ///
    /// * `nr_slots` - Number of slots.
    /// * `vmfd` - The file descriptor of VM.
    pub fn new(nr_slots: u32, vmfd: Arc<VmFd>) -> KvmMemoryListener {
        KvmMemoryListener {
            as_id: Arc::new(AtomicU32::new(0)),
            fd: vmfd,
            slots: Arc::new(Mutex::new(vec![MemSlot::default(); nr_slots as usize])),
        }
    }

    /// Find a free slot and fills it with given arguments.
    ///
    /// # Arguments
    ///
    /// * `guest_addr` - Guest address.
    /// * `size` - Size of slots.
    /// * `host_addr` - Host address.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * no valid Kvm slot.
    /// * memory overflows.
    fn get_free_slot(&self, guest_addr: u64, size: u64, host_addr: u64) -> Result<u32> {
        let mut slots = self.slots.lock().unwrap();

        // check if the given address range overlaps with exist ones
        let range = AddressRange::from((guest_addr, size));
        slots.iter().try_for_each::<_, Result<()>>(|s| {
            if AddressRange::from((s.guest_addr, s.size))
                .find_intersection(range)
                .is_some()
            {
                return Err(ErrorKind::Overlap.into());
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

        Err(ErrorKind::NoAvailKvmSlot.into())
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
        Err(ErrorKind::NoMatchedKvmSlot(addr, size).into())
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
        let aligned_addr = range.base.align_up(alignment).chain_err(|| {
            format!(
                "Address Overflows after aligned, addr: {}",
                range.base.raw_value()
            )
        })?;

        let aligned_size = range
            .size
            .checked_sub(aligned_addr.offset_from(range.base))
            .and_then(|sz| round_down(sz, alignment))
            .filter(|&sz| sz > 0_u64)
            .ok_or_else(|| ErrorKind::Msg("Mem slot size is zero after aligned".to_string()))?;

        Ok(AddressRange::new(aligned_addr, aligned_size))
    }

    /// Add a region to KvmMemoryListener,
    /// the argument `flat_range` is used to find the region.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - FlatRange would be used to find the region.
    ///
    /// # Errors
    ///
    /// Return Error if fail to delete kvm_mem_slot.
    fn add_region(&self, flat_range: &FlatRange) -> Result<()> {
        if flat_range.owner.region_type() != RegionType::Ram {
            return Ok(());
        }

        let (aligned_addr, aligned_size) =
            Self::align_mem_slot(flat_range.addr_range, page_size()).map(|r| (r.base, r.size))?;
        let align_adjust = aligned_addr.raw_value() - flat_range.addr_range.base.raw_value();

        // `unwrap()` won't fail because Ram-type Region definitely has hva
        let aligned_hva = flat_range.owner.get_host_address().unwrap()
            + flat_range.offset_in_region
            + align_adjust;

        let slot_idx = self.get_free_slot(aligned_addr.raw_value(), aligned_size, aligned_hva)?;

        let kvm_region = kvm_userspace_memory_region {
            slot: slot_idx | (self.as_id.load(Ordering::SeqCst) << 16),
            guest_phys_addr: aligned_addr.raw_value(),
            memory_size: aligned_size,
            userspace_addr: aligned_hva,
            flags: 0,
        };
        unsafe {
            self.fd.set_user_memory_region(kvm_region).or_else(|e| {
                self.delete_slot(aligned_addr.raw_value(), aligned_size)
                    .chain_err(|| "Failed to delete kvm_mem_slot")?;
                Err(e).chain_err(|| {
                    format!(
                        "KVM register memory region failed: addr {}, size {}",
                        aligned_addr.raw_value(),
                        aligned_size
                    )
                })
            })?;
        }
        Ok(())
    }

    /// Delete a region from KvmMemoryListener.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - FlatRange would be used to find the region.
    fn delete_region(&self, flat_range: &FlatRange) -> Result<()> {
        if flat_range.owner.region_type() != RegionType::Ram {
            return Ok(());
        }

        let (aligned_addr, aligned_size) =
            Self::align_mem_slot(flat_range.addr_range, page_size()).map(|r| (r.base, r.size))?;

        let mem_slot = self.delete_slot(aligned_addr.raw_value(), aligned_size)?;

        let kvm_region = kvm_userspace_memory_region {
            slot: mem_slot.index | (self.as_id.load(Ordering::SeqCst) << 16),
            guest_phys_addr: mem_slot.guest_addr,
            memory_size: 0_u64,
            userspace_addr: mem_slot.host_addr,
            flags: 0,
        };
        unsafe {
            self.fd.set_user_memory_region(kvm_region).chain_err(|| {
                format!(
                    "KVM unregister memory region failed: addr {}",
                    aligned_addr.raw_value(),
                )
            })?;
        }

        Ok(())
    }

    /// Register a IoEvent to `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent would be added.
    ///
    /// # Errors
    ///
    /// Return Error if the length of ioeventfd data is unexpected.
    fn add_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let io_addr = IoEventAddress::Mmio(ioevtfd.addr_range.base.raw_value());

        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u64),
                _ => bail!("Unexpected ioeventfd data length"),
            }
        } else {
            self.fd.register_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.chain_err(|| {
            format!(
                "KVM register ioeventfd failed: mmio-addr {}",
                ioevtfd.addr_range.base.raw_value()
            )
        })?;

        Ok(())
    }

    /// Deletes `ioevtfd` from `/dev/kvm`
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent would be deleted.
    fn delete_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let io_addr = IoEventAddress::Mmio(ioevtfd.addr_range.base.raw_value());
        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u64),
                _ => bail!("Unexpected ioeventfd data length"),
            }
        } else {
            self.fd
                .unregister_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.chain_err(|| {
            format!(
                "KVM unregister ioeventfd failed: mmio-addr {}",
                ioevtfd.addr_range.base.raw_value()
            )
        })?;

        Ok(())
    }
}

impl Listener for KvmMemoryListener {
    /// Get default priority.
    fn priority(&self) -> i32 {
        10_i32
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
    /// * No FlatRange in argument `flat_range`.
    /// * No IoEventFd in argument `evtfd'.
    fn handle_request(
        &self,
        flat_range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> std::result::Result<(), crate::errors::Error> {
        match req_type {
            ListenerReqType::AddRegion => {
                self.add_region(flat_range.chain_err(|| "No FlatRange")?)?
            }
            ListenerReqType::DeleteRegion => {
                self.delete_region(flat_range.chain_err(|| "No FlatRange")?)?
            }
            ListenerReqType::AddIoeventfd => {
                self.add_ioeventfd(evtfd.chain_err(|| "No IoEventFd")?)?
            }
            ListenerReqType::DeleteIoeventfd => {
                self.delete_ioeventfd(evtfd.chain_err(|| "No IoEventFd")?)?
            }
        }
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub struct KvmIoListener {
    fd: Arc<VmFd>,
}

#[cfg(target_arch = "x86_64")]
impl KvmIoListener {
    /// Create a new KvmIoListener.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor of VM.
    pub fn new(fd: Arc<VmFd>) -> KvmIoListener {
        KvmIoListener { fd }
    }

    /// Register a IoEvent to `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent of Region.
    ///
    /// # Errors
    ///
    /// Return Error if the length of ioeventfd data is unexpected.
    fn add_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let io_addr = IoEventAddress::Pio(ioevtfd.addr_range.base.raw_value());

        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => self
                    .fd
                    .register_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u64),
                _ => bail!("unexpected ioeventfd data length"),
            }
        } else {
            self.fd.register_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.chain_err(|| {
            format!(
                "KVM register ioeventfd failed: mmio-addr {}",
                ioevtfd.addr_range.base.raw_value()
            )
        })?;

        Ok(())
    }

    /// Delete an IoEvent from `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `ioevtfd` - IoEvent of Region.
    fn delete_ioeventfd(&self, ioevtfd: &RegionIoEventFd) -> Result<()> {
        let io_addr = IoEventAddress::Pio(ioevtfd.addr_range.base.raw_value());

        let ioctl_ret = if ioevtfd.data_match {
            let length = ioevtfd.addr_range.size;
            match length {
                2 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u16),
                4 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u32),
                8 => self
                    .fd
                    .unregister_ioevent(&ioevtfd.fd, &io_addr, ioevtfd.data as u64),
                _ => bail!("Unexpected ioeventfd data length"),
            }
        } else {
            self.fd
                .unregister_ioevent(&ioevtfd.fd, &io_addr, NoDatamatch)
        };

        ioctl_ret.chain_err(|| {
            format!(
                "KVM unregister ioeventfd failed: io-addr {}",
                ioevtfd.addr_range.base.raw_value()
            )
        })?;

        Ok(())
    }
}

/// Kvm io listener.
#[cfg(target_arch = "x86_64")]
impl Listener for KvmIoListener {
    /// Get the default priority.
    fn priority(&self) -> i32 {
        10_i32
    }

    /// Deal with the request.
    ///
    /// # Arguments
    ///
    /// * `_range` - FlatRange would be used to find the region.
    /// * `evtfd` - IoEvent of Region.
    /// * `req_type` - Request type.
    fn handle_request(
        &self,
        _range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> std::result::Result<(), crate::errors::Error> {
        match req_type {
            ListenerReqType::AddIoeventfd => {
                self.add_ioeventfd(evtfd.chain_err(|| "No IoEventFd")?)?
            }
            ListenerReqType::DeleteIoeventfd => {
                self.delete_ioeventfd(evtfd.chain_err(|| "No IoEventFd")?)?
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use kvm_ioctls::Kvm;
    use libc::EFD_NONBLOCK;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::{GuestAddress, HostMemMapping, Region, RegionIoEventFd};

    fn generate_region_ioeventfd(addr: u64, datamatch: Option<u64>) -> RegionIoEventFd {
        RegionIoEventFd {
            fd: EventFd::new(EFD_NONBLOCK).unwrap(),
            addr_range: AddressRange::from((addr, 4)),
            data_match: datamatch.is_some(),
            data: datamatch.unwrap_or(064),
        }
    }

    fn create_ram_range(addr: u64, size: u64, offset_in_region: u64) -> FlatRange {
        let mem_mapping =
            Arc::new(HostMemMapping::new(GuestAddress(addr), size, -1, 0, false, false).unwrap());
        FlatRange {
            addr_range: AddressRange::new(
                mem_mapping.start_address().unchecked_add(offset_in_region),
                mem_mapping.size() - offset_in_region,
            ),
            owner: Region::init_ram_region(mem_mapping.clone()),
            offset_in_region,
        }
    }

    #[test]
    fn test_alloc_slot() {
        let kml = match Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Ok(vm_fd) => KvmMemoryListener::new(34, Arc::new(vm_fd)),
            Err(_) => return,
        };

        let host_addr = 0u64;
        assert_eq!(kml.get_free_slot(0, 100, host_addr).unwrap(), 0);
        assert_eq!(kml.get_free_slot(200, 100, host_addr).unwrap(), 1);
        assert_eq!(kml.get_free_slot(300, 100, host_addr).unwrap(), 2);
        assert_eq!(kml.get_free_slot(500, 100, host_addr).unwrap(), 3);
        assert!(kml.get_free_slot(200, 100, host_addr).is_err());

        kml.delete_slot(200, 100).unwrap();
        assert!(kml.delete_slot(150, 100).is_err());
        assert!(kml.delete_slot(700, 100).is_err());
        assert_eq!(kml.get_free_slot(200, 100, host_addr).unwrap(), 1);
    }

    #[test]
    fn test_add_del_ram_region() {
        let kml = match Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Ok(vm_fd) => KvmMemoryListener::new(34, Arc::new(vm_fd)),
            Err(_) => return,
        };

        let ram_size = page_size();
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
            .is_err());
    }

    #[test]
    fn test_add_region_align() {
        let kml = match Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Ok(vm_fd) => KvmMemoryListener::new(34, Arc::new(vm_fd)),
            Err(_) => return,
        };

        // flat-range not aligned
        let page_size = page_size();
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
        let kml = match Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Ok(vm_fd) => KvmMemoryListener::new(34, Arc::new(vm_fd)),
            Err(_) => return,
        };

        let evtfd = generate_region_ioeventfd(4, None);
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());
        // evtfd already added, adding again should make an error
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_err());
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
        // evtfd already deleted, deleting again should make an error
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_err());

        // register an ioeventfd with data-match
        let evtfd = generate_region_ioeventfd(64, Some(4u64));
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());
        assert!(kml
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_kvm_io_listener() {
        let iol = match Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Ok(vm_fd) => KvmIoListener::new(Arc::new(vm_fd)),
            Err(_) => return,
        };

        let evtfd = generate_region_ioeventfd(4, None);
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_ok());
        // evtfd already added, adding again should make an error
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::AddIoeventfd)
            .is_err());
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_ok());
        // evtfd already deleted, deleting again should make an error
        assert!(iol
            .handle_request(None, Some(&evtfd), ListenerReqType::DeleteIoeventfd)
            .is_err());
    }
}
