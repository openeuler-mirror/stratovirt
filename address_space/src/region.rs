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
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, warn};

use crate::address_space::FlatView;
use crate::{
    AddressRange, AddressSpace, AddressSpaceError, FileBackend, GuestAddress, HostMemMapping,
    RegionOps,
};
use migration::{migration::Migratable, MigrationManager};

/// Types of Region.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RegionType {
    /// Ram type.
    Ram,
    /// IO type.
    IO,
    /// Container type.
    Container,
    /// RomDevice type.
    RomDevice,
    /// RamDevice type.
    RamDevice,
    /// Alias type
    Alias,
}

/// Represents a memory region, used by mem-mapped IO, Ram or Rom.
#[derive(Clone)]
pub struct Region {
    /// The name of Region
    pub name: String,
    /// Type of Region, won't be changed once initialized.
    region_type: RegionType,
    /// The priority of Region, only valid in parent Container-type Region.
    priority: Arc<AtomicI32>,
    /// Size of Region.
    size: Arc<AtomicU64>,
    /// Offset in parent Container-type region. It won't be changed once initialized.
    offset: Arc<Mutex<GuestAddress>>,
    /// If not Ram, RomDevice, RamDevice Region type, `mem_mapping` is None. It won't be changed
    /// once initialized.
    mem_mapping: Option<Arc<HostMemMapping>>,
    /// `ops` provides read/write function.
    ops: Option<RegionOps>,
    /// ioeventfds within this Region.
    io_evtfds: Arc<Mutex<Vec<RegionIoEventFd>>>,
    /// Weak pointer pointing to the father address-spaces.
    space: Arc<RwLock<Weak<AddressSpace>>>,
    /// Sub-regions array, keep sorted.
    subregions: Arc<RwLock<Vec<Region>>>,
    /// This field is useful for RomDevice-type Region. If true, in read-only mode, otherwise in IO
    /// mode.
    rom_dev_romd: Arc<AtomicBool>,
    /// Max access size supported by the device.
    max_access_size: Option<u64>,
    /// Point to entity memory region
    alias: Option<Arc<Region>>,
    /// Offset in parent Alias-type region.
    alias_offset: u64,
}

impl fmt::Debug for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Region")
            .field("region_type", &self.region_type)
            .field("priority", &self.priority)
            .field("size", &self.size)
            .field("offset", &self.offset)
            .field("mem_mapping", &self.mem_mapping)
            .field("io_evtfds", &self.io_evtfds)
            .field("space", &self.space)
            .field("subregions", &self.subregions)
            .field("rom_dev_romd", &self.rom_dev_romd)
            .field("max_access_size", &self.max_access_size)
            .finish()
    }
}

/// Used to trigger events.
/// If `data_match` is enabled, the `EventFd` is triggered iff `data` is written
/// to the specified address.
#[derive(Clone)]
pub struct RegionIoEventFd {
    /// EventFd to be triggered when guest writes to the address.
    pub fd: Arc<vmm_sys_util::eventfd::EventFd>,
    /// Addr_range contains two params as follows:
    /// base: in addr_range is the address of EventFd.
    /// size: can be 2, 4, 8 bytes.
    pub addr_range: AddressRange,
    /// If data_match is enabled.
    pub data_match: bool,
    /// The specified value to trigger events.
    pub data: u64,
}

impl fmt::Debug for RegionIoEventFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegionIoEventFd")
            .field("addr_range", &self.addr_range)
            .field("data_match", &self.data_match)
            .field("data", &self.data)
            .finish()
    }
}

impl PartialEq for RegionIoEventFd {
    fn eq(&self, other: &Self) -> bool {
        self.addr_range == other.addr_range
            && self.data_match == other.data_match
            && self.data == other.data
            && self.fd.as_raw_fd() == other.fd.as_raw_fd()
    }
}

impl RegionIoEventFd {
    /// Calculate if this `RegionIoEventFd` is located after the given one.
    ///
    /// # Arguments
    ///
    /// * `other` - Other `RegionIoEventFd`.
    pub fn after(&self, other: &RegionIoEventFd) -> bool {
        self.addr_range.base.0 >= (other.addr_range.base.0 + other.addr_range.size)
    }
}

/// FlatRange is a piece of continuous memory address。
#[derive(Clone, Debug)]
pub struct FlatRange {
    /// The address range.
    pub addr_range: AddressRange,
    /// The owner of this flat-range.
    pub owner: Region,
    /// The offset within Region.
    pub offset_in_region: u64,
    /// Rom Device Read-only mode.
    pub rom_dev_romd: Option<bool>,
}

impl Eq for FlatRange {}

impl PartialEq for FlatRange {
    fn eq(&self, other: &Self) -> bool {
        self.addr_range == other.addr_range
            && self.owner.region_type == other.owner.region_type
            && self.rom_dev_romd.unwrap_or(false) == other.rom_dev_romd.unwrap_or(false)
            && self.owner == other.owner
            && self.offset_in_region == other.offset_in_region
    }
}

/// Implement PartialEq/Eq for comparison of Region.
impl PartialEq for Region {
    fn eq(&self, other: &Region) -> bool {
        Arc::as_ptr(&self.priority) == Arc::as_ptr(&other.priority)
            && self.region_type() == other.region_type()
            && Arc::as_ptr(&self.offset) == Arc::as_ptr(&other.offset)
            && Arc::as_ptr(&self.size) == Arc::as_ptr(&other.size)
    }
}

impl Eq for Region {}

/// Used for read/write for multi times.
struct MultiOpsArgs {
    /// The base address of the read/write ops.
    base: GuestAddress,
    /// The offset of the read/write ops.
    offset: u64,
    /// the number of the read/write ops in bytes.
    count: u64,
    /// The access size for one read/write in bytes.
    access_size: u64,
}

/// Read/Write for multi times.
macro_rules! rw_multi_ops {
    ( $ops: ident, $slice: expr, $args: ident ) => {
        // The data size is larger than the max access size, we split to read/write for multiple
        // times.
        let base = $args.base;
        let offset = $args.offset;
        let cnt = $args.count;
        let access_size = $args.access_size;
        let mut pos = 0;
        for _ in 0..(cnt / access_size) {
            if !$ops(
                &mut $slice[pos as usize..(pos + access_size) as usize],
                base,
                offset + pos,
            ) {
                return Err(anyhow!(AddressSpaceError::IoAccess(
                    base.raw_value(),
                    offset + pos,
                    access_size,
                )));
            }
            pos += access_size;
        }
        // Unaligned memory access.
        if cnt % access_size > 0
            && !$ops(&mut $slice[pos as usize..cnt as usize], base, offset + pos)
        {
            return Err(anyhow!(AddressSpaceError::IoAccess(
                base.raw_value(),
                offset + pos,
                cnt - pos
            )));
        }
    };
}

impl Region {
    /// The core function of initialization.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of `Region`.
    /// * `region_type` - Type of `Region`.
    /// * `mem_mapping` - Mapped memory.
    /// * `ops` - Region operations.
    fn init_region_internal(
        name: &str,
        size: u64,
        region_type: RegionType,
        mem_mapping: Option<Arc<HostMemMapping>>,
        ops: Option<RegionOps>,
    ) -> Region {
        Region {
            name: String::from(name),
            region_type,
            priority: Arc::new(AtomicI32::new(0)),
            offset: Arc::new(Mutex::new(GuestAddress(0))),
            size: Arc::new(AtomicU64::new(size)),
            mem_mapping,
            ops,
            io_evtfds: Arc::new(Mutex::new(Vec::new())),
            space: Arc::new(RwLock::new(Weak::new())),
            subregions: Arc::new(RwLock::new(Vec::new())),
            rom_dev_romd: Arc::new(AtomicBool::new(false)),
            max_access_size: None,
            alias: None,
            alias_offset: 0_u64,
        }
    }

    /// Initialize Ram-type region.
    ///
    /// # Arguments
    ///
    /// * `mem_mapping` - Mapped memory of this Ram region.
    pub fn init_ram_region(mem_mapping: Arc<HostMemMapping>, name: &str) -> Region {
        Region::init_region_internal(
            name,
            mem_mapping.size(),
            RegionType::Ram,
            Some(mem_mapping),
            None,
        )
    }

    /// Initialize IO-type region.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of IO region.
    /// * `ops` - Operation of Region.
    pub fn init_io_region(size: u64, ops: RegionOps, name: &str) -> Region {
        Region::init_region_internal(name, size, RegionType::IO, None, Some(ops))
    }

    /// Set the access size limit of the IO region.
    ///
    /// # Arguments
    ///
    /// * `access_size` - Max access size supported in bytes.
    pub fn set_access_size(&mut self, access_size: u64) {
        self.max_access_size = Some(access_size);
    }

    /// Initialize Container-type region.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of container region.
    pub fn init_container_region(size: u64, name: &str) -> Region {
        Region::init_region_internal(name, size, RegionType::Container, None, None)
    }

    /// Initialize RomDevice-type region.
    ///
    /// # Arguments
    ///
    /// * `mem_mapping` - Mapped memory of this region.
    /// * `ops` - Operation functions of this region.
    pub fn init_rom_device_region(
        mem_mapping: Arc<HostMemMapping>,
        ops: RegionOps,
        name: &str,
    ) -> Region {
        let mut region = Region::init_region_internal(
            name,
            mem_mapping.size(),
            RegionType::RomDevice,
            Some(mem_mapping),
            Some(ops),
        );
        region.rom_dev_romd = Arc::new(AtomicBool::new(true));

        region
    }

    /// Initialize RamDevice-type region.
    ///
    /// # Arguments
    ///
    /// * `mem_mapping` - Mapped memory of this region.
    pub fn init_ram_device_region(mem_mapping: Arc<HostMemMapping>, name: &str) -> Region {
        Region::init_region_internal(
            name,
            mem_mapping.size(),
            RegionType::RamDevice,
            Some(mem_mapping),
            None,
        )
    }

    /// Initialize alias-type region.
    ///
    /// # Arguments
    ///
    /// * `alias` - alias to region.
    /// * `alias_offset` - offset of alias
    /// * `size` - region size
    /// * `name` - alias name
    pub fn init_alias_region(
        alias: Arc<Region>,
        alias_offset: u64,
        size: u64,
        name: &str,
    ) -> Region {
        let mut region = Region::init_region_internal(name, size, RegionType::Alias, None, None);
        region.alias = Some(alias);
        region.alias_offset = alias_offset;
        region
    }

    /// Get the type of this region.
    pub fn region_type(&self) -> RegionType {
        self.region_type
    }

    /// Get the priority of this region.
    pub fn priority(&self) -> i32 {
        self.priority.load(Ordering::SeqCst)
    }

    /// Set the priority of this region.
    ///
    /// # Arguments
    ///
    /// * `prior` - Priority of region.
    pub fn set_priority(&self, prior: i32) {
        self.priority.store(prior, Ordering::SeqCst);
    }

    /// Get size of this region.
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::SeqCst)
    }

    /// Get offset of this region.
    pub fn alias_offset(&self) -> u64 {
        self.alias_offset
    }

    /// Get name of this alias region.
    pub fn alias_name(&self) -> Option<String> {
        self.alias.as_ref().map(|mr| mr.name.clone())
    }

    /// Get the offset of this region.
    /// The offset is within its parent region or belonged address space.
    pub fn offset(&self) -> GuestAddress {
        *self.offset.lock().unwrap()
    }

    /// Set the offset of region,
    /// this function is only used when this region is added to its parent region.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset in parent region.
    pub fn set_offset(&self, offset: GuestAddress) {
        self.offset.lock().unwrap().0 = offset.raw_value();
    }

    /// Returns the minimum address managed by the region.
    /// If this region is not `Ram`, `RamDevice`, `RomDevice` type,
    /// this function will return `None`.
    pub fn start_addr(&self) -> Option<GuestAddress> {
        if self.region_type != RegionType::Ram
            && self.region_type != RegionType::RamDevice
            && self.region_type != RegionType::RomDevice
        {
            return None;
        }

        self.mem_mapping.as_ref().map(|r| r.start_address())
    }

    /// Change mode of RomDevice-type region,
    ///
    /// # Arguments
    ///
    /// * `read_only` - Set region to read-only mode or not.
    pub fn set_rom_device_romd(&self, read_only: bool) -> Result<()> {
        if self.region_type != RegionType::RomDevice {
            return Err(anyhow!(AddressSpaceError::RegionType(self.region_type)));
        }

        let old_mode = self.rom_dev_romd.as_ref().load(Ordering::SeqCst);

        if old_mode != read_only {
            self.rom_dev_romd
                .as_ref()
                .store(read_only, Ordering::SeqCst);

            if let Some(space) = self.space.read().unwrap().upgrade() {
                space.update_topology()?;
            } else {
                debug!("set RomDevice-type region to read-only mode, which has no belonged address-space");
            }
        }

        Ok(())
    }

    /// Get read-only mode of RomDevice-type region. Return true if in read-only mode, otherwise
    /// return false. Return None if it is not a RomDevice-type region.
    pub fn get_rom_device_romd(&self) -> Option<bool> {
        if self.region_type != RegionType::RomDevice {
            None
        } else {
            Some(self.rom_dev_romd.as_ref().load(Ordering::SeqCst))
        }
    }

    /// Get the host address if this region is backed by host-memory,
    /// Return `None` if it is not a Ram-type region.
    pub fn get_host_address(&self) -> Option<u64> {
        if self.region_type != RegionType::Ram
            && self.region_type != RegionType::RamDevice
            && self.region_type != RegionType::RomDevice
        {
            return None;
        }
        self.mem_mapping.as_ref().map(|r| r.host_address())
    }

    pub fn get_host_share(&self) -> Option<bool> {
        if self.region_type != RegionType::Ram
            && self.region_type != RegionType::RamDevice
            && self.region_type != RegionType::RomDevice
        {
            return None;
        }
        self.mem_mapping.as_ref().map(|r| r.mem_shared())
    }

    /// Get the file information if this region is backed by host-memory.
    /// Return `None` if it is not a Ram-type region.
    pub fn get_file_backend(&self) -> Option<FileBackend> {
        self.mem_mapping.as_ref().and_then(|r| r.file_backend())
    }

    /// Get the region file backend page size.
    pub fn get_region_page_size(&self) -> Option<u64> {
        self.mem_mapping
            .as_ref()
            .and_then(|r| r.file_backend())
            .map(|fb| fb.page_size)
    }

    /// Return all sub-regions of this Region, the returned vector is not empty,
    /// iff this region is a container.
    pub(crate) fn subregions(&self) -> Vec<Region> {
        self.subregions.read().unwrap().clone()
    }

    /// Set `AddressSpace` for `region`,
    /// this function is called when this region is added to parent region or
    /// added to belonged address space.
    ///
    /// # Arguments
    ///
    /// * `space` - The AddressSpace that the region belongs to.
    pub(crate) fn set_belonged_address_space(&self, space: &Arc<AddressSpace>) {
        *self.space.write().unwrap() = Arc::downgrade(space);
    }

    /// Release the address space this region belongs to,
    /// this function is called when this region is removed from its parent region or
    /// removed from belonged address space.
    pub(crate) fn del_belonged_address_space(&self) {
        *self.space.write().unwrap() = Weak::new();
    }

    /// Check if the address(end address) overflows or exceeds the end of this region.
    ///
    /// # Arguments
    ///
    /// * `addr` - Start address.
    /// * `size` - Size of memory segment.
    ///
    /// # Errors
    ///
    /// Return Error if the address overflows.
    fn check_valid_offset(&self, addr: u64, size: u64) -> Result<()> {
        if addr
            .checked_add(size)
            .filter(|end| *end <= self.size())
            .is_none()
        {
            return Err(anyhow!(AddressSpaceError::Overflow(addr)));
        }
        Ok(())
    }

    /// Read memory segment to `dst`.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination the data would be written to.
    /// * `base` - Base address.
    /// * `offset` - Offset from base address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * fail to access io region.
    /// * the region is a container.
    /// * the address overflows.
    pub fn read(
        &self,
        dst: &mut dyn std::io::Write,
        base: GuestAddress,
        offset: u64,
        count: u64,
    ) -> Result<()> {
        match self.region_type {
            RegionType::Ram | RegionType::RamDevice => {
                self.check_valid_offset(offset, count).with_context(|| {
                    AddressSpaceError::InvalidOffset(offset, count, self.size())
                })?;
                let host_addr = self.mem_mapping.as_ref().unwrap().host_address();
                // SAFETY: host_addr is managed by mem_mapping, it can be guaranteed to be legal,
                // the legality of offset and count has been verified.
                let slice = unsafe {
                    std::slice::from_raw_parts((host_addr + offset) as *const u8, count as usize)
                };
                dst.write_all(slice)
                    .with_context(|| "Failed to write content of Ram to mutable buffer")?;
            }
            RegionType::RomDevice => {
                self.check_valid_offset(offset, count).with_context(|| {
                    AddressSpaceError::InvalidOffset(offset, count, self.size())
                })?;
                if self.rom_dev_romd.as_ref().load(Ordering::SeqCst) {
                    let host_addr = self.mem_mapping.as_ref().unwrap().host_address();
                    // SAFETY: host_addr is managed by mem_mapping, it can be guaranteed to be legal,
                    // the legality of offset and count has been verified.
                    let read_ret = unsafe {
                        std::slice::from_raw_parts(
                            (host_addr + offset) as *const u8,
                            count as usize,
                        )
                    };
                    dst.write_all(read_ret)?;
                } else {
                    let mut read_ret = vec![0_u8; count as usize];

                    let read_ops = self.ops.as_ref().unwrap().read.as_ref();
                    if !read_ops(&mut read_ret, base, offset) {
                        return Err(anyhow!(AddressSpaceError::IoAccess(
                            base.raw_value(),
                            offset,
                            count
                        )));
                    }
                    dst.write_all(&read_ret)?;
                }
            }
            RegionType::IO => {
                let mut slice = vec![0_u8; count as usize];
                let read_ops = self.ops.as_ref().unwrap().read.as_ref();
                if matches!(self.max_access_size, Some(access_size) if count > access_size) {
                    let args = MultiOpsArgs {
                        base,
                        offset,
                        count,
                        access_size: self.max_access_size.unwrap(),
                    };
                    rw_multi_ops!(read_ops, slice, args);
                } else if !read_ops(&mut slice, base, offset) {
                    return Err(anyhow!(AddressSpaceError::IoAccess(
                        base.raw_value(),
                        offset,
                        count
                    )));
                }
                dst.write_all(&slice).with_context(|| {
                    "Failed to write slice provided by device to mutable buffer"
                })?;
            }
            _ => {
                return Err(anyhow!(AddressSpaceError::RegionType(self.region_type())));
            }
        }
        Ok(())
    }

    /// Write data segment from `src` to memory.
    ///
    /// # Arguments
    ///
    /// * `src` - Source data.
    /// * `base` - Base address.
    /// * `offset` - Offset from base address.
    /// * `count` - Size of data.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * fail to access io region.
    /// * the region is a container.
    /// * the address overflows.
    pub fn write(
        &self,
        src: &mut dyn std::io::Read,
        base: GuestAddress,
        offset: u64,
        count: u64,
    ) -> Result<()> {
        self.check_valid_offset(offset, count).with_context(|| {
            format!(
                "Invalid offset: offset 0x{:X}, data length 0x{:X}, region size 0x{:X}",
                offset,
                count,
                self.size()
            )
        })?;

        match self.region_type {
            RegionType::Ram | RegionType::RamDevice => {
                let host_addr = self.mem_mapping.as_ref().unwrap().host_address();
                // Mark vmm dirty page manually if live migration is active.
                MigrationManager::mark_dirty_log(host_addr + offset, count);

                // SAFETY: host_addr is managed by mem_mapping, it can be guaranteed to be legal,
                // the legality of offset and count has been verified.
                let slice = unsafe {
                    std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, count as usize)
                };
                src.read_exact(slice)
                    .with_context(|| "Failed to write buffer to Ram")?;
            }
            RegionType::RomDevice | RegionType::IO => {
                if count >= std::usize::MAX as u64 {
                    return Err(anyhow!(AddressSpaceError::Overflow(count)));
                }
                let mut slice = vec![0_u8; count as usize];
                src.read_exact(&mut slice).with_context(|| {
                    "Failed to write buffer to slice, which will be provided for device"
                })?;

                let write_ops = self.ops.as_ref().unwrap().write.as_ref();
                if matches!(self.max_access_size, Some(access_size) if count > access_size) {
                    let args = MultiOpsArgs {
                        base,
                        offset,
                        count,
                        access_size: self.max_access_size.unwrap(),
                    };
                    rw_multi_ops!(write_ops, slice, args);
                } else if !write_ops(&slice, base, offset) {
                    return Err(anyhow!(AddressSpaceError::IoAccess(
                        base.raw_value(),
                        offset,
                        count
                    )));
                }
            }
            _ => {
                return Err(anyhow!(AddressSpaceError::RegionType(self.region_type())));
            }
        }
        Ok(())
    }

    /// Set the ioeventfds within this Region,
    /// Return the IoEvent of a `Region`.
    pub fn set_ioeventfds(&self, new_fds: &[RegionIoEventFd]) {
        *self.io_evtfds.lock().unwrap() = new_fds.to_vec();
    }

    /// Get the ioeventfds within this Region,
    /// these fds will be register to `Hypervisor` supporting
    /// ioeventfd and used for guest notifier.
    pub fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        self.io_evtfds.lock().unwrap().to_vec()
    }

    /// Add sub-region to this region, but not produce flat view
    ///
    /// # Arguments
    ///
    /// * `child` - Subregion of this region.
    /// * `offset` - Offset of subregion
    pub fn add_subregion_not_update(&self, child: Region, offset: u64) -> Result<()> {
        // check parent Region's property, and check if child Region's offset is valid or not
        if self.region_type() != RegionType::Container {
            return Err(anyhow!(AddressSpaceError::RegionType(self.region_type())));
        }
        self.check_valid_offset(offset, child.size())
            .with_context(|| {
                format!(
                    "Invalid offset: offset 0x{:X}, child length 0x{:X}, region size 0x{:X}",
                    offset,
                    child.size(),
                    self.size()
                )
            })?;

        // set child region's offset and father address-space
        child.set_offset(GuestAddress(offset));
        if let Some(space) = self.space.read().unwrap().upgrade() {
            child.set_belonged_address_space(&space)
        }

        // insert to `subregion` array and update topology of father address-space
        let mut sub_regions = self.subregions.write().unwrap();
        let mut index = 0_usize;
        while index < sub_regions.len() {
            if child.priority() >= sub_regions.get(index).unwrap().priority() {
                break;
            }
            index += 1;
        }
        sub_regions.insert(index, child);
        drop(sub_regions);

        Ok(())
    }

    /// Add sub-region to this region and production flat view
    ///
    /// # Arguments
    ///
    /// * `child` - Subregion of this region.
    /// * `offset` - Offset of subregion.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * This region is not a Container.
    /// * The argument `offset` plus child region's size overflows or exceed this region's size.
    /// * The child-region already exists in sub-regions array.
    /// * Failed to generate flat view (topology changed after adding sub-region).
    pub fn add_subregion(&self, child: Region, offset: u64) -> Result<()> {
        self.add_subregion_not_update(child, offset)?;

        if let Some(space) = self.space.read().unwrap().upgrade() {
            space
                .update_topology()
                .with_context(|| "Failed to update topology for address_space")?;
        } else {
            debug!("add subregion to container region, which has no belonged address-space");
        }

        Ok(())
    }

    /// Delete sub-region of this region.
    ///
    /// # Arguments
    ///
    /// * `child` - Subregion of this region.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * The child-region does not exist in sub-regions array.
    /// * Failed to generate flat view (topology changed after removing sub-region).
    pub fn delete_subregion(&self, child: &Region) -> Result<()> {
        // check parent Region's property, and check if child Region's offset is valid or not
        if self.region_type() != RegionType::Container {
            return Err(anyhow!(AddressSpaceError::RegionType(self.region_type())));
        }

        let mut sub_regions = self.subregions.write().unwrap();
        let mut removed = false;
        for (index, sub_r) in sub_regions.iter().enumerate() {
            if child == sub_r {
                sub_regions.remove(index);
                removed = true;
                break;
            }
        }
        drop(sub_regions);

        if !removed {
            warn!("Failed to delete subregion from parent region: not found");
            return Err(anyhow!(AddressSpaceError::RegionNotFound(
                child.offset().raw_value()
            )));
        }

        // get father address-space and update topology
        if let Some(space) = self.space.read().unwrap().upgrade() {
            space
                .update_topology()
                .with_context(|| "Failed to update topology for address_space")?;
        } else {
            debug!("delete subregion from container region, which has no belonged address-space");
        }
        child.del_belonged_address_space();

        Ok(())
    }

    /// Recursive function to render region, terminate if this region is not a container.
    ///
    /// # Arguments
    ///
    /// * `base` - Base address of a Region.
    /// * `addr_range` - Address Range.
    /// * `flat_view` - FlatView of a Region.
    ///
    /// # Errors
    ///
    /// Return Error if the input address range `addr_range` has no intersection with this region.
    fn render_region_pass(
        &self,
        base: GuestAddress,
        addr_range: AddressRange,
        flat_view: &mut FlatView,
    ) -> Result<()> {
        let region_base = base.unchecked_add(self.offset().raw_value());
        let region_range = AddressRange::new(region_base, self.size());
        let intersect = match region_range.find_intersection(addr_range) {
            Some(r) => r,
            None => return Ok(()),
        };
        match self.region_type {
            RegionType::Container => {
                for sub_r in self.subregions.read().unwrap().iter() {
                    sub_r
                        .render_region_pass(region_base, intersect, flat_view)
                        .with_context(|| {
                            format!(
                                "Failed to render subregion, base 0x{:X}, addr_range (0x{:X}, 0x{:X})",
                                base.raw_value(),
                                addr_range.base.raw_value(),
                                addr_range.size
                            )
                        })?;
                }
            }
            RegionType::Alias => {
                if let Some(alias_region) = &self.alias {
                    let alias_base = region_base
                        .unchecked_sub(self.alias_offset)
                        .unchecked_sub(alias_region.offset().raw_value());
                    alias_region.render_region_pass(alias_base, intersect, flat_view).with_context(|| {
                        format!(
                            "Failed to render subregion, alias_base 0x{:X}, intersect (0x{:X}, 0x{:X})",
                            alias_base.raw_value(),
                            intersect.base.raw_value(),
                            intersect.size
                        )
                    })?;
                }
            }
            RegionType::Ram | RegionType::IO | RegionType::RomDevice | RegionType::RamDevice => {
                self.render_terminate_region(base, addr_range, flat_view)
                    .with_context(||
                        format!(
                            "Failed to render terminate region, base 0x{:X}, addr_range (0x{:X}, 0x{:X})",
                            base.raw_value(), addr_range.base.raw_value(),
                            addr_range.size
                        ))?;
            }
        }
        Ok(())
    }

    /// Render terminate region.
    ///
    /// # Arguments
    ///
    /// * `base` - Base address of a Region.
    /// * `addr_range` - Address Range.
    /// * `flat_view` - FlatView of a Region.
    ///
    /// # Errors
    ///
    /// Return Error if the input address range `addr_range` has no intersection with this region.
    fn render_terminate_region(
        &self,
        base: GuestAddress,
        addr_range: AddressRange,
        flat_view: &mut FlatView,
    ) -> Result<()> {
        let region_range =
            AddressRange::new(base.unchecked_add(self.offset().raw_value()), self.size());
        let intersect = match region_range.find_intersection(addr_range) {
            Some(r) => r,
            None => bail!(
                "Generate flat view failed: region_addr 0x{:X} exceeds parent region range (0x{:X}, 0x{:X})",
                region_range.base.raw_value(),
                addr_range.base.raw_value(),
                addr_range.size
            ),
        };

        let mut offset_in_region = intersect.base.offset_from(region_range.base);
        let mut start = intersect.base;
        let mut remain = intersect.size;

        let mut index = 0_usize;
        while index < flat_view.0.len() {
            let fr = &flat_view.0[index];
            let fr_end = fr.addr_range.end_addr();
            if start >= fr.addr_range.end_addr() {
                index += 1;
                continue;
            }

            if start < fr.addr_range.base {
                let range_size = std::cmp::min(remain, fr.addr_range.base.offset_from(start));

                flat_view.0.insert(
                    index,
                    FlatRange {
                        addr_range: AddressRange {
                            base: start,
                            size: range_size,
                        },
                        owner: self.clone(),
                        offset_in_region,
                        rom_dev_romd: self.get_rom_device_romd(),
                    },
                );
                index += 1;
            }
            let step = std::cmp::min(fr_end.offset_from(start), remain);
            start = start.unchecked_add(step);
            offset_in_region += step;
            remain -= step;
            if remain == 0 {
                break;
            }
            index += 1;
        }

        if remain > 0 {
            flat_view.0.insert(
                index,
                FlatRange {
                    addr_range: AddressRange::new(start, remain),
                    owner: self.clone(),
                    offset_in_region,
                    rom_dev_romd: self.get_rom_device_romd(),
                },
            );
        }

        Ok(())
    }

    /// Create corresponding `FlatView` for the `Region`.
    /// Return the `FlatView`.
    ///
    /// # Arguments
    ///
    /// * `base` - Base address.
    /// * `addr_range` - Address range.
    pub(crate) fn generate_flatview(
        &self,
        base: GuestAddress,
        addr_range: AddressRange,
    ) -> Result<FlatView> {
        let mut flat_view = FlatView::default();
        match self.region_type {
            RegionType::Container => {
                self.render_region_pass(base, addr_range, &mut flat_view)
                .with_context(|| {
                    format!(
                        "Failed to render terminate region, base 0x{:X}, addr_range (0x{:X}, 0x{:X})",
                        base.raw_value(),
                        addr_range.base.raw_value(),
                        addr_range.size
                    )
                })?;
            }
            _ => bail!("Generate flat view failed: only the container supported"),
        }
        Ok(flat_view)
    }

    fn get_region_type_name(&self) -> String {
        match self.region_type() {
            RegionType::Ram => String::from("ram"),
            RegionType::IO => String::from("i/o"),
            RegionType::RomDevice => String::from("romd"),
            RegionType::RamDevice => String::from("ramd"),
            _ => String::from("err type"),
        }
    }

    pub fn mtree(&self, level: u32) {
        let mut tab = String::new();
        let mut num = 0_u32;

        loop {
            if num == level {
                break;
            }
            tab.push_str("    ");
            num += 1;
        }
        match self.region_type() {
            RegionType::Container => {
                println!(
                    "{}0x{:X} - 0x{:X}, (Prio {}, Container) : {}",
                    tab,
                    self.offset().raw_value(),
                    self.offset().raw_value() + self.size(),
                    self.priority(),
                    self.name
                );
                for sub_r in self.subregions().iter() {
                    sub_r.mtree(level + 1);
                }
            }
            RegionType::Ram | RegionType::IO | RegionType::RomDevice | RegionType::RamDevice => {
                println!(
                    "{}0x{:X} - 0x{:X}, (Prio {}, {}) : {}",
                    tab,
                    self.offset().raw_value(),
                    self.offset().raw_value() + self.size(),
                    self.priority(),
                    self.get_region_type_name(),
                    self.name
                );
            }
            RegionType::Alias => {
                println!(
                    "{}0x{:X} - 0x{:X}, (Prio {}, alias) : {} @alias name: {}",
                    tab,
                    self.alias_offset(),
                    self.alias_offset() + self.size(),
                    self.priority(),
                    self.name,
                    self.alias_name().unwrap(),
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read, Seek, SeekFrom};

    use libc::EFD_NONBLOCK;
    use vmm_sys_util::eventfd::EventFd;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[derive(Default)]
    struct TestDevice {
        head: u64,
    }

    impl TestDevice {
        fn read(&mut self, data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
            if data.len() != std::mem::size_of::<u64>() {
                return false;
            }

            for i in 0..std::mem::size_of::<u64>() {
                data[i] = (self.head >> (8 * i)) as u8;
            }
            true
        }

        fn write(&mut self, data: &[u8], _addr: GuestAddress, _offset: u64) -> bool {
            if data.len() != std::mem::size_of::<u64>() {
                return false;
            }
            self.head = match unsafe { data.align_to::<u64>() } {
                (_, [m], _) => *m,
                _ => return false,
            };
            true
        }
    }

    #[test]
    fn test_ram_region() {
        let mem_mapping = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, 1024, None, false, false, false).unwrap(),
        );
        let ram_region = Region::init_ram_region(mem_mapping.clone(), "mem_mapping");
        let data: [u8; 10] = [10; 10];
        let mut res_data: [u8; 10] = [0; 10];
        let count = data.len() as u64;

        assert_eq!(ram_region.region_type(), RegionType::Ram);

        assert_eq!(ram_region.offset(), GuestAddress(0u64));
        ram_region.set_offset(GuestAddress(0x11u64));
        assert_eq!(ram_region.offset(), GuestAddress(0x11u64));

        // test read/write
        assert!(ram_region
            .write(&mut data.as_ref(), GuestAddress(0), 0, count)
            .is_ok());
        assert!(ram_region
            .read(&mut res_data.as_mut(), GuestAddress(0), 0, count)
            .is_ok());
        assert_eq!(&data, &mut res_data);

        assert_eq!(
            ram_region.get_host_address().unwrap(),
            mem_mapping.host_address()
        );

        assert!(ram_region.check_valid_offset(0, 1000).is_ok());
        assert!(ram_region.check_valid_offset(100, 1000).is_err());
    }

    #[test]
    fn test_ram_region_access() {
        // the target guest address is 0~1024 (1024 not included)
        let rgn_start = GuestAddress(0);
        let host_mmap = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, 1024, None, false, false, false).unwrap(),
        );
        let ram_region = Region::init_ram_region(host_mmap, "mem_mapping");

        let file = TempFile::new().unwrap();
        let mut file_read = std::fs::File::open(file.as_path()).unwrap();
        let slice: [u8; 24] = [91; 24];
        let mut res_slice: [u8; 24] = [0; 24];
        let mut res_slice2: [u8; 24] = [0; 24];

        // write 91 to 1000~1024 (1024 not included)
        ram_region
            .write(&mut slice.as_ref(), rgn_start, 1000, slice.len() as u64)
            .unwrap();

        // read the ram to the file, then check the file's content
        assert!(ram_region
            .read(&mut file.as_file(), rgn_start, 1000, 24)
            .is_ok());
        assert!(file_read.read(&mut res_slice).is_ok());
        assert_eq!(&slice, &mut res_slice);

        // write the file content to 0~24 (24 not included)
        // then check the ram's content
        file_read.seek(SeekFrom::Start(0)).unwrap();
        assert!(ram_region.write(&mut file_read, rgn_start, 0, 24).is_ok());
        ram_region
            .read(&mut res_slice2.as_mut(), rgn_start, 0, 24)
            .unwrap();
        assert_eq!(&slice, &mut res_slice2);
    }

    #[test]
    fn test_io_region() {
        let test_dev = Arc::new(Mutex::new(TestDevice::default()));
        let test_dev_clone = test_dev.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = test_dev_clone.lock().unwrap();
            device_locked.read(data, addr, offset)
        };
        let test_dev_clone = test_dev.clone();
        let write_ops = move |data: &[u8], addr: GuestAddress, offset: u64| -> bool {
            let mut device_locked = test_dev_clone.lock().unwrap();
            device_locked.write(data, addr, offset)
        };

        let test_dev_ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };

        let io_region = Region::init_io_region(16, test_dev_ops.clone(), "io_region");
        let data = [0x01u8; 8];
        let mut data_res = [0x0u8; 8];
        let count = data.len() as u64;

        assert_eq!(io_region.region_type(), RegionType::IO);

        // test read/write
        assert!(io_region
            .write(&mut data.as_ref(), GuestAddress(0), 0, count)
            .is_ok());
        assert!(io_region
            .read(&mut data_res.as_mut(), GuestAddress(0), 0, count)
            .is_ok());
        assert_eq!(data.to_vec(), data_res.to_vec());

        assert!(io_region.get_host_address().is_none());
    }

    #[test]
    fn test_region_ioeventfd() {
        let mut fd1 = RegionIoEventFd {
            fd: Arc::new(EventFd::new(EFD_NONBLOCK).unwrap()),
            addr_range: AddressRange::from((1000, 4u64)),
            data_match: false,
            data: 0,
        };
        // compare unchanged
        let mut fd2 = fd1.clone();
        assert!(fd2 == fd1);

        // compare fd
        fd2.fd = Arc::new(EventFd::new(EFD_NONBLOCK).unwrap());
        assert!(fd2 != fd1);

        // compare length
        fd2.fd = fd1.fd.clone();
        assert!(fd2 == fd1);
        fd2.addr_range.size = 8;
        assert!(fd1 != fd2);

        // compare address
        fd2.addr_range.size = 4;
        assert!(fd2 == fd1);
        fd2.addr_range.base.0 = 1024;
        assert!(fd1 != fd2);

        // compare datamatch
        fd2.addr_range = fd1.addr_range;
        assert!(fd2 == fd1);
        fd2.data_match = true;
        assert!(fd1 != fd2);

        // if datamatch, compare data
        fd1.data_match = true;
        assert!(fd2 == fd1);
        fd2.data = 10u64;
        assert!(fd1 != fd2);

        // test after
        fd2.data = 0;
        assert!(fd2 == fd1);
        assert!(!fd2.after(&fd1));
        fd2.addr_range.base.0 = 1004;
        assert!(fd2.after(&fd1));
    }

    // test add/del sub-region to container-region, and check priority
    #[test]
    fn test_add_del_subregion() {
        let container = Region::init_container_region(1 << 10, "root");
        assert_eq!(container.region_type(), RegionType::Container);
        assert_eq!(container.priority(), 0);

        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        let io_region = Region::init_io_region(1 << 4, default_ops.clone(), "io1");
        let io_region2 = Region::init_io_region(1 << 4, default_ops.clone(), "io2");
        io_region2.set_priority(10);

        // add duplicate io-region or ram-region will fail
        assert!(container.add_subregion(io_region.clone(), 0u64).is_ok());
        assert!(container.add_subregion(io_region2.clone(), 20u64).is_ok());

        // sub_regions are stored in descending order of priority
        assert_eq!(container.subregions.read().unwrap().len(), 2);
        assert_eq!(
            container
                .subregions
                .read()
                .unwrap()
                .get(1)
                .unwrap()
                .priority(),
            0
        );
        assert_eq!(
            container
                .subregions
                .read()
                .unwrap()
                .get(0)
                .unwrap()
                .priority(),
            10
        );

        assert!(container.delete_subregion(&io_region).is_ok());
        assert!(container.delete_subregion(&io_region2).is_ok());
        assert!(container.delete_subregion(&io_region2).is_err());

        assert_eq!(container.subregions.read().unwrap().len(), 0);
    }

    #[test]
    fn test_generate_flatview() {
        let default_ops = RegionOps {
            read: Arc::new(|_: &mut [u8], _: GuestAddress, _: u64| -> bool { true }),
            write: Arc::new(|_: &[u8], _: GuestAddress, _: u64| -> bool { true }),
        };

        // memory region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  A:    [                                                       ]
        //  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
        //  B:                  [                          ]
        //  D:                  [DDDDD]
        //  E:                                [EEEEE]
        //
        // the flat_view is as follows
        //        [CCCCCCCCCCCC][DDDDD][CCCCC][EEEEE][CCCCC]
        {
            let region_a = Region::init_container_region(8000, "region_a");
            let region_b = Region::init_container_region(4000, "region_b");
            let region_c = Region::init_io_region(6000, default_ops.clone(), "region_c");
            let region_d = Region::init_io_region(1000, default_ops.clone(), "region_d");
            let region_e = Region::init_io_region(1000, default_ops.clone(), "region_e");

            region_b.set_priority(2);
            region_c.set_priority(1);
            region_a.add_subregion(region_b.clone(), 2000).unwrap();
            region_a.add_subregion(region_c.clone(), 0).unwrap();
            region_b.add_subregion(region_d.clone(), 0).unwrap();
            region_b.add_subregion(region_e.clone(), 2000).unwrap();

            let addr_range = AddressRange::from((0u64, region_a.size()));
            let view = region_a
                .generate_flatview(GuestAddress(0), addr_range)
                .unwrap();

            assert_eq!(view.0.len(), 5);
            // Expected address range in flat_range, and the priority of corresponding region.
            let expected_fw: &[(u64, u64, i32)] = &[
                (0, 2000, 1),
                (2000, 1000, 0),
                (3000, 1000, 1),
                (4000, 1000, 0),
                (5000, 1000, 1),
            ];
            for (index, fr) in view.0.iter().enumerate() {
                assert_eq!(fr.addr_range.base.raw_value(), expected_fw[index].0);
                assert_eq!(fr.addr_range.size, expected_fw[index].1);
                assert_eq!(fr.owner.priority(), expected_fw[index].2);
            }
        }

        // memory region layout
        //        0      1000   2000   3000   4000   5000   6000   7000   8000
        //        |------|------|------|------|------|------|------|------|
        //  A:    [                                                       ]
        //  C:    [CCCCCC]                                                    1
        //  B:                  [                                  ]          1
        //  D:                  [DDDDDDDDDDDDDDDDDDDD]                        2
        //  E:                                [EEEEEEEEEEEEE]                 3
        //
        // the flat_view is as follows
        //        [CCCCCC]      [DDDDDDDDDDDD][EEEEEEEEEEEEE]
        {
            let region_a = Region::init_container_region(8000, "region_a");
            let region_b = Region::init_container_region(5000, "region_b");
            let region_c = Region::init_io_region(1000, default_ops.clone(), "regionc");
            let region_d = Region::init_io_region(3000, default_ops.clone(), "region_d");
            let region_e = Region::init_io_region(2000, default_ops.clone(), "region_e");

            region_a.add_subregion(region_b.clone(), 2000).unwrap();
            region_a.add_subregion(region_c.clone(), 0).unwrap();
            region_d.set_priority(2);
            region_e.set_priority(3);
            region_b.add_subregion(region_d.clone(), 0).unwrap();
            region_b.add_subregion(region_e.clone(), 2000).unwrap();

            let addr_range = AddressRange::from((0u64, region_a.size()));
            let view = region_a
                .generate_flatview(GuestAddress(0), addr_range)
                .unwrap();

            assert_eq!(view.0.len(), 3);
            // Expected address range in flat_range, and the priority of corresponding region.
            let expected_fw: &[(u64, u64, i32)] = &[(0, 1000, 0), (2000, 2000, 2), (4000, 2000, 3)];
            for (index, fr) in view.0.iter().enumerate() {
                assert_eq!(fr.addr_range.base.raw_value(), expected_fw[index].0);
                assert_eq!(fr.addr_range.size, expected_fw[index].1);
                assert_eq!(fr.owner.priority(), expected_fw[index].2);
            }
        }
    }
}
