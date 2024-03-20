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

use std::fmt;
use std::fmt::Debug;
use std::io::Write;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use log::error;
use once_cell::sync::OnceCell;

use crate::{
    AddressRange, AddressSpaceError, FlatRange, GuestAddress, Listener, ListenerReqType, Region,
    RegionIoEventFd, RegionType,
};
use migration::{migration::Migratable, MigrationManager};
use util::aio::Iovec;
use util::byte_code::ByteCode;

/// Contains an array of `FlatRange`.
#[derive(Default, Clone, Debug)]
pub(crate) struct FlatView(pub(crate) Vec<FlatRange>);

impl FlatView {
    fn find_flatrange(&self, addr: GuestAddress) -> Option<&FlatRange> {
        match self.0.binary_search_by_key(&addr, |x| x.addr_range.base) {
            Ok(x) => Some(&self.0[x]),
            Err(x) if (x > 0 && addr < self.0[x - 1].addr_range.end_addr()) => Some(&self.0[x - 1]),
            _ => None,
        }
    }

    fn read(&self, dst: &mut dyn std::io::Write, addr: GuestAddress, count: u64) -> Result<()> {
        let mut len = count;
        let mut l = count;
        let mut start = addr;

        loop {
            if let Some(fr) = self.find_flatrange(start) {
                let fr_offset = start.offset_from(fr.addr_range.base);
                let region_offset = fr.offset_in_region + fr_offset;
                let region_base = fr.addr_range.base.unchecked_sub(fr.offset_in_region);
                let fr_remain = fr.addr_range.size - fr_offset;

                if fr.owner.region_type() == RegionType::Ram
                    || fr.owner.region_type() == RegionType::RamDevice
                {
                    l = std::cmp::min(l, fr_remain);
                }
                fr.owner.read(dst, region_base, region_offset, l)?;
            } else {
                return Err(anyhow!(AddressSpaceError::RegionNotFound(
                    start.raw_value()
                )));
            }

            len -= l;
            if len == 0 {
                return Ok(());
            }
            start = start.unchecked_add(l);
            l = len;
        }
    }

    fn write(&self, src: &mut dyn std::io::Read, addr: GuestAddress, count: u64) -> Result<()> {
        let mut l = count;
        let mut len = count;
        let mut start = addr;

        loop {
            if let Some(fr) = self.find_flatrange(start) {
                let fr_offset = start.offset_from(fr.addr_range.base);
                let region_offset = fr.offset_in_region + fr_offset;
                let region_base = fr.addr_range.base.unchecked_sub(fr.offset_in_region);
                let fr_remain = fr.addr_range.size - fr_offset;
                if fr.owner.region_type() == RegionType::Ram
                    || fr.owner.region_type() == RegionType::RamDevice
                {
                    l = std::cmp::min(l, fr_remain);
                }
                fr.owner.write(src, region_base, region_offset, l)?;
            } else {
                return Err(anyhow!(AddressSpaceError::RegionNotFound(
                    start.raw_value()
                )));
            }

            len -= l;
            if len == 0 {
                break;
            }
            start = start.unchecked_add(l);
            l = len;
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct RegionCache {
    pub reg_type: RegionType,
    pub host_base: u64,
    pub start: u64,
    pub end: u64,
}

type ListenerObj = Arc<Mutex<dyn Listener>>;

/// Address Space of memory.
#[derive(Clone)]
pub struct AddressSpace {
    /// the name of AddressSpace.
    name: String,
    /// Root Region of this AddressSpace.
    root: Region,
    /// `flat_view` is the output of rendering all regions in parent `address-space`,
    /// every time the topology changed (add/delete region), `flat_view` would be updated.
    flat_view: Arc<ArcSwap<FlatView>>,
    /// The triggered call-backs when flat_view changed.
    listeners: Arc<Mutex<Vec<ListenerObj>>>,
    /// The current layout of ioeventfds, which is compared with new ones in topology-update stage.
    ioeventfds: Arc<Mutex<Vec<RegionIoEventFd>>>,
    /// The backend memory region tree, used for migrate.
    machine_ram: Option<Arc<Region>>,
    /// Whether the hypervisor enables the ioeventfd.
    hyp_ioevtfd_enabled: OnceCell<bool>,
}

impl fmt::Debug for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressSpace")
            .field("root", &self.root)
            .field("flat_view", &self.flat_view)
            .field("ioeventfds", &self.ioeventfds)
            .finish()
    }
}

impl AddressSpace {
    /// Create a new `AddressSpace` according to the given root region.
    ///
    /// # Arguments
    ///
    /// * `root` - Root region of address space.
    /// * `name` - the name of AddressSpace.
    pub fn new(
        root: Region,
        name: &str,
        machine_ram: Option<Arc<Region>>,
    ) -> Result<Arc<AddressSpace>> {
        let space = Arc::new(AddressSpace {
            name: String::from(name),
            root: root.clone(),
            flat_view: Arc::new(ArcSwap::new(Arc::new(FlatView::default()))),
            listeners: Arc::new(Mutex::new(Vec::new())),
            ioeventfds: Arc::new(Mutex::new(Vec::new())),
            machine_ram,
            hyp_ioevtfd_enabled: OnceCell::new(),
        });

        root.set_belonged_address_space(&space);
        if !space.root.subregions().is_empty() {
            space
                .update_topology()
                .with_context(|| "Failed to update topology for address_space")?;
        }

        Ok(space)
    }

    pub fn get_machine_ram(&self) -> Option<&Arc<Region>> {
        if let Some(region) = &self.machine_ram {
            return Some(region);
        }
        None
    }

    /// Get the reference of root region of AddressSpace.
    pub fn root(&self) -> &Region {
        &self.root
    }

    pub fn memspace_show(&self) {
        let view = self.flat_view.load();

        println!("----- address-space flat: {} -----", self.name);
        for fr in view.0.iter() {
            println!(
                "  0x{:X} - 0x{:X}, (pri {}, {:?}) Region {} @ offset 0x{:X}",
                fr.addr_range.base.raw_value(),
                fr.addr_range.base.raw_value() + fr.addr_range.size,
                fr.owner.priority(),
                fr.owner.region_type(),
                fr.owner.name,
                fr.offset_in_region
            );
        }

        println!("------ regions show: {} --------------", self.root().name);
        self.root().mtree(0_u32);
        println!("--------------------------------------");
    }

    /// Register the listener to the `AddressSpace`.
    ///
    /// # Arguments
    ///
    /// * `listener` - Provided Listener trait object.
    ///
    /// # Errors
    ///
    /// Return Error if fail to call `listener`.
    pub fn register_listener(&self, listener: ListenerObj) -> Result<()> {
        let mut locked_listener = listener.lock().unwrap();
        for fr in self.flat_view.load().0.iter() {
            locked_listener.handle_request(Some(fr), None, ListenerReqType::AddRegion)?;
        }
        locked_listener.enable();

        let mut idx = 0;
        let mut mls = self.listeners.lock().unwrap();
        for ml in mls.iter() {
            if ml.lock().unwrap().priority() >= locked_listener.priority() {
                break;
            }
            idx += 1;
        }
        drop(locked_listener);
        mls.insert(idx, listener);
        Ok(())
    }

    /// Unregister listener from the `AddressSpace`.
    ///
    /// # Arguments
    ///
    /// * `listener` - Provided Listener trait object.
    ///
    /// # Errors
    ///
    /// Return Error if fail to call `listener`.
    pub fn unregister_listener(&self, listener: ListenerObj) -> Result<()> {
        let mut locked_listener = listener.lock().unwrap();
        for fr in self.flat_view.load().0.iter() {
            locked_listener.handle_request(Some(fr), None, ListenerReqType::DeleteRegion)?;
        }
        locked_listener.disable();
        drop(locked_listener);

        let mut mls = self.listeners.lock().unwrap();
        for (idx, ml) in mls.iter().enumerate() {
            if !ml.lock().unwrap().enabled() {
                mls.remove(idx);
                break;
            }
        }
        Ok(())
    }

    /// Call listener to deal with the request.
    ///
    /// # Arguments
    ///
    /// * `flat_range` - Available when operating `Region`.
    /// * `evtfd` - Available when operating `Ioeventfd`.
    /// * `req_type` - One selection of how to operate the `Region` or `Ioeventfd`.
    ///
    /// # Errors
    ///
    /// Return Error if fail to call listener.
    fn call_listeners(
        &self,
        flat_range: Option<&FlatRange>,
        evtfd: Option<&RegionIoEventFd>,
        req_type: ListenerReqType,
    ) -> Result<()> {
        let listeners = self.listeners.lock().unwrap();
        match req_type {
            ListenerReqType::DeleteRegion | ListenerReqType::AddIoeventfd => {
                listeners.iter().rev().try_for_each(|ml| {
                    ml.lock()
                        .unwrap()
                        .handle_request(flat_range, evtfd, req_type)
                })
            }
            _ => listeners.iter().try_for_each(|ml| {
                ml.lock()
                    .unwrap()
                    .handle_request(flat_range, evtfd, req_type)
            }),
        }
    }

    /// Update the topology pass.
    ///
    /// # Arguments
    ///
    /// * `old_view` - Old flatview.
    /// * `new_view` - New flatview.
    /// * `is_add` - Add new FlatRange in `new_view` if `true`.
    fn update_topology_pass(
        &self,
        old_view: &FlatView,
        new_view: &FlatView,
        is_add: bool,
    ) -> Result<()> {
        let old_ranges = &old_view.0;
        let new_ranges = &new_view.0;
        let mut old_idx = 0_usize;
        let mut new_idx = 0_usize;

        while old_idx < old_ranges.len() || new_idx < new_ranges.len() {
            let old_range = old_ranges.get(old_idx);
            let new_range = new_ranges.get(new_idx);

            if let Some(old_r) = old_range {
                if let Some(new_r) = new_range {
                    if old_r.addr_range.base < new_r.addr_range.base
                        || (old_r.addr_range.base == new_r.addr_range.base && old_r != new_r)
                    {
                        if !is_add {
                            self.call_listeners(Some(old_r), None, ListenerReqType::DeleteRegion)?;
                        }
                        old_idx += 1;
                        continue;
                    } else if old_r == new_r {
                        old_idx += 1;
                        new_idx += 1;
                        continue;
                    }
                } else {
                    if !is_add {
                        self.call_listeners(Some(old_r), None, ListenerReqType::DeleteRegion)
                            .with_context(|| {
                                AddressSpaceError::UpdateTopology(
                                    old_r.addr_range.base.raw_value(),
                                    old_r.addr_range.size,
                                    old_r.owner.region_type(),
                                )
                            })?;
                    }
                    old_idx += 1;
                    continue;
                }
            }

            // current old_range is None, or current new_range is before old_range
            if is_add && new_range.is_some() {
                self.call_listeners(new_range, None, ListenerReqType::AddRegion)
                    .with_context(|| {
                        AddressSpaceError::UpdateTopology(
                            new_range.unwrap().addr_range.base.raw_value(),
                            new_range.unwrap().addr_range.size,
                            new_range.unwrap().owner.region_type(),
                        )
                    })?;
            }
            new_idx += 1;
        }

        Ok(())
    }

    /// Updates ioeventfds according to New `RegionIoEventFd` array.
    ///
    /// # Arguments
    ///
    /// * `new_evtfds` - New `RegionIoEventFd` array.
    fn update_ioeventfds_pass(&self, new_evtfds: &[RegionIoEventFd]) -> Result<()> {
        let old_evtfds = self.ioeventfds.lock().unwrap();
        let mut old_idx = 0;
        let mut new_idx = 0;

        while old_idx < old_evtfds.len() || new_idx < new_evtfds.len() {
            let old_fd = old_evtfds.get(old_idx);
            let new_fd = new_evtfds.get(new_idx);

            if old_fd == new_fd {
                old_idx += 1;
                new_idx += 1;
                continue;
            }
            // Delete old_fd, but do not delete it if it's after new_fd, as it may match later.
            if old_fd.is_some() && (new_fd.is_none() || !old_fd.unwrap().after(new_fd.unwrap())) {
                self.call_listeners(None, old_fd, ListenerReqType::DeleteIoeventfd)
                    .with_context(|| {
                        AddressSpaceError::UpdateTopology(
                            old_fd.unwrap().addr_range.base.raw_value(),
                            old_fd.unwrap().addr_range.size,
                            RegionType::IO,
                        )
                    })?;
                old_idx += 1;
            }
            // Add new_fd, but do not add it if it's after old_fd, as it may match later.
            if new_fd.is_some() && (old_fd.is_none() || !new_fd.unwrap().after(old_fd.unwrap())) {
                self.call_listeners(None, new_fd, ListenerReqType::AddIoeventfd)
                    .with_context(|| {
                        AddressSpaceError::UpdateTopology(
                            new_fd.unwrap().addr_range.base.raw_value(),
                            new_fd.unwrap().addr_range.size,
                            RegionType::IO,
                        )
                    })?;
                new_idx += 1;
            }
        }

        Ok(())
    }

    /// Update IoEventfds.
    /// This function will compare new ioeventfds generated from `FlatView` with old ones
    /// which is stored in AddressSpace, and then update them.
    fn update_ioeventfds(&self) -> Result<()> {
        let mut ioeventfds = Vec::<RegionIoEventFd>::new();

        for fr in self.flat_view.load().0.iter() {
            let region_base = fr.addr_range.base.unchecked_sub(fr.offset_in_region).0;
            for evtfd in fr.owner.ioeventfds().iter() {
                let mut evtfd_clone = evtfd.clone();
                evtfd_clone.addr_range.base =
                    evtfd_clone.addr_range.base.unchecked_add(region_base);
                if fr
                    .addr_range
                    .find_intersection(evtfd_clone.addr_range)
                    .is_some()
                {
                    ioeventfds.push(evtfd_clone);
                }
            }
        }

        self.update_ioeventfds_pass(&ioeventfds)
            .with_context(|| "Failed to update ioeventfds")?;
        *self.ioeventfds.lock().unwrap() = ioeventfds;
        Ok(())
    }

    /// Return the host address according to the given `GuestAddress`.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    pub fn get_host_address(&self, addr: GuestAddress) -> Option<u64> {
        let view = self.flat_view.load();

        view.find_flatrange(addr).and_then(|range| {
            let offset = addr.offset_from(range.addr_range.base);
            range
                .owner
                .get_host_address()
                .map(|host| host + range.offset_in_region + offset)
        })
    }

    /// Return the available size and hva to the given `GuestAddress` from flat_view.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    /// Return Error if the `addr` is not mapped.
    /// or return the HVA address and available mem length
    pub fn addr_cache_init(&self, addr: GuestAddress) -> Option<(u64, u64)> {
        let view = self.flat_view.load();

        if let Some(flat_range) = view.find_flatrange(addr) {
            let fr_offset = addr.offset_from(flat_range.addr_range.base);
            let region_offset = flat_range.offset_in_region + fr_offset;

            let region_remain = flat_range.owner.size() - region_offset;
            let fr_remain = flat_range.addr_range.size - fr_offset;

            return flat_range.owner.get_host_address().map(|host| {
                (
                    host + region_offset,
                    std::cmp::min(fr_remain, region_remain),
                )
            });
        }

        None
    }

    /// Convert GPA buffer iovec to HVA buffer iovec.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    /// * `count` - Memory needed length
    pub fn get_address_map(&self, addr: GuestAddress, count: u64) -> Result<Vec<Iovec>> {
        let mut len = count;
        let mut start = addr;
        let mut hva_iovec = Vec::new();

        loop {
            let io_vec = self
                .addr_cache_init(start)
                .map(|(hva, fr_len)| Iovec {
                    iov_base: hva,
                    iov_len: std::cmp::min(len, fr_len),
                })
                .with_context(|| format!("Map iov base {:x?}, iov len {:?} failed", addr, count))?;
            start = start.unchecked_add(io_vec.iov_len);
            len -= io_vec.iov_len;
            hva_iovec.push(io_vec);

            if len == 0 {
                break;
            }
        }

        Ok(hva_iovec)
    }

    /// Return the host address according to the given `GuestAddress` from cache.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    /// * `cache` - The related region cache.
    pub fn get_host_address_from_cache(
        &self,
        addr: GuestAddress,
        cache: &Option<RegionCache>,
    ) -> Option<(u64, u64)> {
        if cache.is_none() {
            return self.addr_cache_init(addr);
        }
        let region_cache = cache.unwrap();
        if addr.0 >= region_cache.start && addr.0 < region_cache.end {
            Some((
                region_cache.host_base + addr.0 - region_cache.start,
                region_cache.end - addr.0,
            ))
        } else {
            self.addr_cache_init(addr)
        }
    }

    /// Check if the GuestAddress is in one of Ram region.
    ///
    /// # Arguments
    ///
    /// * `addr` - Guest address.
    pub fn address_in_memory(&self, addr: GuestAddress, size: u64) -> bool {
        let view = &self.flat_view.load();

        view.find_flatrange(addr).map_or(false, |range| {
            range.owner.region_type() == RegionType::Ram
                && size <= range.addr_range.end_addr().offset_from(addr)
        })
    }

    pub fn get_region_cache(&self, addr: GuestAddress) -> Option<RegionCache> {
        let view = &self.flat_view.load();
        if let Some(range) = view.find_flatrange(addr) {
            let reg_type = range.owner.region_type();
            let start = range.addr_range.base.0;
            let end = range.addr_range.end_addr().0;
            let host_base = self.get_host_address(GuestAddress(start)).unwrap_or(0);
            let cache = RegionCache {
                reg_type,
                host_base,
                start,
                end,
            };
            return Some(cache);
        }
        None
    }

    /// Return the end address of memory according to all Ram regions in AddressSpace.
    pub fn memory_end_address(&self) -> GuestAddress {
        self.flat_view
            .load()
            .0
            .iter()
            .filter(|fr| fr.owner.region_type() == RegionType::Ram)
            .max_by_key(|fr| fr.addr_range.end_addr())
            .map_or(GuestAddress(0), |fr| fr.addr_range.end_addr())
    }

    /// Read memory segment to `dst`.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination the data would be written to.
    /// * `addr` - Start address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if the `addr` is not mapped.
    pub fn read(&self, dst: &mut dyn std::io::Write, addr: GuestAddress, count: u64) -> Result<()> {
        let view = self.flat_view.load();

        view.read(dst, addr, count)?;
        Ok(())
    }

    /// Write data to specified guest address.
    ///
    /// # Arguments
    ///
    /// * `src` - Data buffer to write.
    /// * `addr` - Start address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if the `addr` is not mapped.
    pub fn write(&self, src: &mut dyn std::io::Read, addr: GuestAddress, count: u64) -> Result<()> {
        let view = self.flat_view.load();

        if !*self.hyp_ioevtfd_enabled.get_or_init(|| false) {
            let ioeventfds = self.ioeventfds.lock().unwrap();
            if let Ok(index) = ioeventfds
                .as_slice()
                .binary_search_by(|ioevtfd| ioevtfd.addr_range.base.cmp(&addr))
            {
                let evtfd = &ioeventfds[index];
                if count == evtfd.addr_range.size || evtfd.addr_range.size == 0 {
                    if !evtfd.data_match {
                        if let Err(e) = evtfd.fd.write(1) {
                            error!("Failed to write ioeventfd {:?}: {}", evtfd, e);
                        }
                        return Ok(());
                    }

                    let mut buf = Vec::new();
                    src.read_to_end(&mut buf).unwrap();

                    if buf.len() <= 8 {
                        let data = u64::from_bytes(buf.as_slice()).unwrap();
                        if *data == evtfd.data {
                            if let Err(e) = evtfd.fd.write(1) {
                                error!("Failed to write ioeventfd {:?}: {}", evtfd, e);
                            }
                            return Ok(());
                        }
                    }
                    view.write(&mut buf.as_slice(), addr, count)?;
                    return Ok(());
                }
            }
        }

        view.write(src, addr, count)?;
        Ok(())
    }

    /// Write an object to memory.
    ///
    /// # Arguments
    ///
    /// * `data` - The object that will be written to the memory.
    /// * `addr` - The start guest address where the object will be written to.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn write_object<T: ByteCode>(&self, data: &T, addr: GuestAddress) -> Result<()> {
        self.write(&mut data.as_bytes(), addr, std::mem::size_of::<T>() as u64)
            .with_context(|| "Failed to write object")
    }

    /// Write an object to memory via host address.
    ///
    /// # Arguments
    ///
    /// * `data` - The object that will be written to the memory.
    /// * `host_addr` - The start host address where the object will be written to.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn write_object_direct<T: ByteCode>(&self, data: &T, host_addr: u64) -> Result<()> {
        // Mark vmm dirty page manually if live migration is active.
        MigrationManager::mark_dirty_log(host_addr, data.as_bytes().len() as u64);

        // SAFETY: The host addr is managed by memory space, it has been verified.
        let mut dst = unsafe {
            std::slice::from_raw_parts_mut(host_addr as *mut u8, std::mem::size_of::<T>())
        };
        dst.write_all(data.as_bytes())
            .with_context(|| "Failed to write object via host address")
    }

    /// Read some data from memory to form an object.
    ///
    /// # Arguments
    ///
    /// * `addr` - The start guest address where the data will be read from.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn read_object<T: ByteCode>(&self, addr: GuestAddress) -> Result<T> {
        let mut obj = T::default();
        self.read(
            &mut obj.as_mut_bytes(),
            addr,
            std::mem::size_of::<T>() as u64,
        )
        .with_context(|| "Failed to read object")?;
        Ok(obj)
    }

    /// Read some data from memory to form an object via host address.
    ///
    /// # Arguments
    ///
    /// * `hoat_addr` - The start host address where the data will be read from.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn read_object_direct<T: ByteCode>(&self, host_addr: u64) -> Result<T> {
        let mut obj = T::default();
        let mut dst = obj.as_mut_bytes();
        // SAFETY: host_addr is managed by address_space, it has been verified for legality.
        let src = unsafe {
            std::slice::from_raw_parts_mut(host_addr as *mut u8, std::mem::size_of::<T>())
        };
        dst.write_all(src)
            .with_context(|| "Failed to read object via host address")?;

        Ok(obj)
    }

    /// Update the topology of memory.
    pub fn update_topology(&self) -> Result<()> {
        let old_fv = self.flat_view.load();

        let addr_range = AddressRange::new(GuestAddress(0), self.root.size());
        let new_fv = self
            .root
            .generate_flatview(GuestAddress(0), addr_range)
            .with_context(|| "Failed to generate new topology")?;

        self.update_topology_pass(&old_fv, &new_fv, false)
            .with_context(|| "Failed to update topology (first pass)")?;
        self.update_topology_pass(&old_fv, &new_fv, true)
            .with_context(|| "Failed to update topology (second pass)")?;

        self.flat_view.store(Arc::new(new_fv));
        self.update_ioeventfds()
            .with_context(|| "Failed to generate and update ioeventfds")?;
        Ok(())
    }

    pub fn set_ioevtfd_enabled(&self, ioevtfd_enabled: bool) {
        self.hyp_ioevtfd_enabled
            .set(ioevtfd_enabled)
            .unwrap_or_else(|_| error!("Failed to set hyp_ioevtfd_enabled"));
    }
}

#[cfg(test)]
mod test {
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::{HostMemMapping, RegionOps};

    #[derive(Default, Clone)]
    struct TestListener {
        reqs: Arc<Mutex<Vec<(ListenerReqType, AddressRange)>>>,
        enabled: bool,
    }

    impl Listener for TestListener {
        fn priority(&self) -> i32 {
            2
        }

        fn enabled(&self) -> bool {
            self.enabled
        }

        fn enable(&mut self) {
            self.enabled = true;
        }

        fn disable(&mut self) {
            self.enabled = false;
        }

        fn handle_request(
            &self,
            range: Option<&FlatRange>,
            eventfd: Option<&RegionIoEventFd>,
            req_type: ListenerReqType,
        ) -> Result<()> {
            match req_type {
                ListenerReqType::AddRegion | ListenerReqType::DeleteRegion => {
                    self.reqs
                        .lock()
                        .unwrap()
                        .push((req_type, range.unwrap().addr_range));
                }
                ListenerReqType::AddIoeventfd | ListenerReqType::DeleteIoeventfd => {
                    self.reqs
                        .lock()
                        .unwrap()
                        .push((req_type, eventfd.unwrap().addr_range));
                }
            }
            Ok(())
        }
    }

    // the listeners in AddressSpace is settled in ascending order by priority
    #[test]
    fn test_listeners() {
        // define an array of listeners in order to check the priority order
        #[derive(Default)]
        struct ListenerPrior0 {
            enabled: bool,
        }
        impl Listener for ListenerPrior0 {
            fn priority(&self) -> i32 {
                0
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn enable(&mut self) {
                self.enabled = true;
            }

            fn disable(&mut self) {
                self.enabled = false;
            }
        }
        #[derive(Default)]
        struct ListenerPrior3 {
            enabled: bool,
        }
        impl Listener for ListenerPrior3 {
            fn priority(&self) -> i32 {
                3
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn enable(&mut self) {
                self.enabled = true;
            }

            fn disable(&mut self) {
                self.enabled = false;
            }
        }
        #[derive(Default)]
        struct ListenerPrior4 {
            enabled: bool,
        }
        impl Listener for ListenerPrior4 {
            fn priority(&self) -> i32 {
                4
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn enable(&mut self) {
                self.enabled = true;
            }

            fn disable(&mut self) {
                self.enabled = false;
            }
        }
        #[derive(Default)]
        struct ListenerNeg {
            enabled: bool,
        }
        impl Listener for ListenerNeg {
            fn priority(&self) -> i32 {
                -1
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn enable(&mut self) {
                self.enabled = true;
            }

            fn disable(&mut self) {
                self.enabled = false;
            }
        }

        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root, "space", None).unwrap();
        let listener1 = Arc::new(Mutex::new(ListenerPrior0::default()));
        let listener2 = Arc::new(Mutex::new(ListenerPrior0::default()));
        let listener3 = Arc::new(Mutex::new(ListenerPrior3::default()));
        let listener4 = Arc::new(Mutex::new(ListenerPrior4::default()));
        let listener5 = Arc::new(Mutex::new(ListenerNeg::default()));
        space.register_listener(listener1.clone()).unwrap();
        space.register_listener(listener3.clone()).unwrap();
        space.register_listener(listener5.clone()).unwrap();
        space.register_listener(listener2.clone()).unwrap();
        space.register_listener(listener4.clone()).unwrap();

        let mut pre_prior = std::i32::MIN;
        for listener in space.listeners.lock().unwrap().iter() {
            let curr = listener.lock().unwrap().priority();
            assert!(pre_prior <= curr);
            pre_prior = curr;
        }

        space.unregister_listener(listener4).unwrap();
        assert_eq!(space.listeners.lock().unwrap().len(), 4);
        space.unregister_listener(listener3).unwrap();
        // It only contains listener1, listener5, listener2.
        assert_eq!(space.listeners.lock().unwrap().len(), 3);
    }

    #[test]
    fn test_unregister_listener() {
        #[derive(Default)]
        struct ListenerPrior0 {
            enabled: bool,
        }
        impl Listener for ListenerPrior0 {
            fn priority(&self) -> i32 {
                0
            }

            fn enabled(&self) -> bool {
                self.enabled
            }

            fn enable(&mut self) {
                self.enabled = true;
            }

            fn disable(&mut self) {
                self.enabled = false;
            }
        }

        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root, "space", None).unwrap();
        let listener1 = Arc::new(Mutex::new(ListenerPrior0::default()));
        let listener2 = Arc::new(Mutex::new(ListenerPrior0::default()));
        space.register_listener(listener1.clone()).unwrap();
        space.register_listener(listener2.clone()).unwrap();

        space.unregister_listener(listener2).unwrap();
        assert_eq!(space.listeners.lock().unwrap().len(), 1);
        for listener in space.listeners.lock().unwrap().iter() {
            assert_eq!(listener.lock().unwrap().enabled(), true);
        }
    }

    #[test]
    fn test_update_topology() {
        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let listener = Arc::new(Mutex::new(TestListener::default()));
        space.register_listener(listener.clone()).unwrap();

        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        // memory region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        //  B:                  [                           ]
        //
        // the flat_view is as follows, region-b is container which will not appear in the flat-view
        //        [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        let region_b = Region::init_container_region(4000, "region_b");
        let region_c = Region::init_io_region(6000, default_ops.clone(), "region_c");
        region_b.set_priority(2);
        region_c.set_priority(1);
        root.add_subregion(region_b.clone(), 2000).unwrap();
        root.add_subregion(region_c.clone(), 0).unwrap();

        assert_eq!(space.flat_view.load().0.len(), 1);
        assert_eq!(listener.lock().unwrap().reqs.lock().unwrap().len(), 1);
        assert_eq!(
            listener
                .lock()
                .unwrap()
                .reqs
                .lock()
                .unwrap()
                .get(0)
                .unwrap()
                .1,
            AddressRange::new(region_c.offset(), region_c.size())
        );
        listener.lock().unwrap().reqs.lock().unwrap().clear();

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        //  B:                  [                           ]
        //  D:                  [DDDDDD]
        // the flat_view is as follows,
        //        [CCCCCCCCCCCC][DDDDDD][CCCCCCCCCCCCCCCCCCC]
        let region_d = Region::init_io_region(1000, default_ops, "region_d");
        region_b.add_subregion(region_d.clone(), 0).unwrap();

        let locked_listener = listener.lock().unwrap();
        assert_eq!(space.flat_view.load().0.len(), 3);
        assert_eq!(locked_listener.reqs.lock().unwrap().len(), 4);
        // delete flat-range 0~6000 first, belonging to region_c
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(0).unwrap().1,
            AddressRange::new(region_c.offset(), region_c.size())
        );
        // add range 0~2000, belonging to region_c
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(1).unwrap().1,
            AddressRange::new(region_c.offset(), 2000)
        );
        // add range 2000~3000, belonging to region_d
        let region_d_range = AddressRange::new(GuestAddress(2000), region_d.size());
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(2).unwrap().1,
            region_d_range
        );
        // add range 3000~6000, belonging to region_c
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(3).unwrap().1,
            AddressRange::from((3000, 3000))
        );
    }

    #[test]
    fn test_update_ioeventfd() {
        let ioeventfds = vec![RegionIoEventFd {
            fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            addr_range: AddressRange::from((0, std::mem::size_of::<u32>() as u64)),
            data_match: true,
            data: 64_u64,
        }];
        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  b:           [BBBBBBBBBBBBB]
        //  c:                  [CCCCCCCCCCCCC]
        // the flat_view is as follows,
        //               [BBBBBBBBBBBBB][CCCCC]
        let root = Region::init_container_region(8000, "region");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let listener = Arc::new(Mutex::new(TestListener::default()));
        space.register_listener(listener.clone()).unwrap();

        let region_b = Region::init_io_region(2000, default_ops.clone(), "region_b");
        region_b.set_priority(1);
        region_b.set_ioeventfds(&ioeventfds);
        let region_c = Region::init_io_region(2000, default_ops, "region_c");
        region_c.set_ioeventfds(&ioeventfds);
        root.add_subregion(region_c, 2000).unwrap();

        assert_eq!(listener.lock().unwrap().reqs.lock().unwrap().len(), 2);
        assert_eq!(
            listener
                .lock()
                .unwrap()
                .reqs
                .lock()
                .unwrap()
                .get(1)
                .unwrap()
                .1,
            AddressRange::new(GuestAddress(2000), 4)
        );
        listener.lock().unwrap().reqs.lock().unwrap().clear();

        root.add_subregion(region_b, 1000).unwrap();
        let locked_listener = listener.lock().unwrap();
        assert_eq!(locked_listener.reqs.lock().unwrap().len(), 5);
        // add ioeventfd of region_b
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(3).unwrap().1,
            AddressRange::new(GuestAddress(1000), 4)
        );
        // ioeventfd in region_c is shawdowed, delete it
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(4).unwrap().1,
            AddressRange::new(GuestAddress(2000), 4)
        );
    }

    #[test]
    fn test_subregion_ioeventfd() {
        let ioeventfds = vec![RegionIoEventFd {
            fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            addr_range: AddressRange::from((0, 4)),
            data_match: true,
            data: 0_64,
        }];
        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  b:           [                                  ]
        //  c:                  [CCCCCC]
        // the flat_view is as follows,
        //                      [CCCCCC]
        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let listener = Arc::new(Mutex::new(TestListener::default()));
        space.register_listener(listener.clone()).unwrap();

        let region_b = Region::init_container_region(5000, "root");
        let region_c = Region::init_io_region(1000, default_ops, "region_c");
        region_c.set_ioeventfds(&ioeventfds);
        region_b.add_subregion(region_c, 1000).unwrap();

        root.add_subregion(region_b, 1000).unwrap();

        let locked_listener = listener.lock().unwrap();
        assert!(locked_listener.reqs.lock().unwrap().get(1).is_some());
        assert_eq!(
            locked_listener.reqs.lock().unwrap().get(1).unwrap().1,
            AddressRange::new(GuestAddress(2000), 4)
        );
    }

    #[test]
    fn test_get_ram_info() {
        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        let ram1 = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, 1000, None, false, false, false).unwrap(),
        );
        let ram2 = Arc::new(
            HostMemMapping::new(GuestAddress(2000), None, 1000, None, false, false, false).unwrap(),
        );
        let region_a = Region::init_ram_region(ram1.clone(), "region_a");
        let region_b = Region::init_ram_region(ram2.clone(), "region_b");
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();
        root.add_subregion(region_b, ram2.start_address().raw_value())
            .unwrap();

        assert_eq!(
            space.memory_end_address(),
            ram2.start_address().unchecked_add(ram2.size())
        );
        assert!(space.address_in_memory(GuestAddress(0), 0));
        assert_eq!(space.address_in_memory(GuestAddress(1000), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(1500), 0), false);
        assert!(space.address_in_memory(GuestAddress(2900), 0));

        assert_eq!(
            space.get_host_address(GuestAddress(500)),
            Some(ram1.host_address() + 500)
        );
        assert_eq!(
            space.get_host_address(GuestAddress(2500)),
            Some(ram2.host_address() + 500)
        );

        // region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  a:    [AAAAAA]
        //  b:                  [BBBBBB]
        //  c:            [CCCCCCCCC]
        // the flat_view is as follows,
        //        [AAAAAA][CCCCCCCCC][BB]
        let region_c = Region::init_io_region(1500, default_ops, "region_c");
        region_c.set_priority(1);
        root.add_subregion(region_c, 1000).unwrap();

        assert_eq!(
            space.memory_end_address(),
            ram2.start_address().unchecked_add(ram2.size())
        );
        assert!(space.address_in_memory(GuestAddress(0), 0));
        assert_eq!(space.address_in_memory(GuestAddress(1000), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(1500), 0), false);
        assert_eq!(space.address_in_memory(GuestAddress(2400), 0), false);
        assert!(space.address_in_memory(GuestAddress(2900), 0));

        assert_eq!(
            space.get_host_address(GuestAddress(500)),
            Some(ram1.host_address() + 500)
        );
        assert!(space.get_host_address(GuestAddress(2400)).is_none());
        assert_eq!(
            space.get_host_address(GuestAddress(2500)),
            Some(ram2.host_address() + 500)
        );
    }

    #[test]
    fn test_write_and_read_object() {
        let root = Region::init_container_region(8000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let ram1 = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, 1000, None, false, false, false).unwrap(),
        );
        let region_a = Region::init_ram_region(ram1.clone(), "region_a");
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();

        let data: u64 = 10000;
        assert!(space.write_object(&data, GuestAddress(992)).is_ok());
        let data1: u64 = space.read_object(GuestAddress(992)).unwrap();
        assert_eq!(data1, 10000);
        assert!(space.write_object(&data, GuestAddress(993)).is_err());
    }
}
