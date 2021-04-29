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

use std::sync::Arc;

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::VmFd;

use super::host_mmap::HostMemMapping;
use super::{Error, LayoutEntryType, Result, MEM_LAYOUT};
use crate::helper::byte_code::ByteCode;

#[derive(Clone)]
pub struct GuestMemory {
    host_mmaps: Vec<Arc<HostMemMapping>>,
}

impl GuestMemory {
    /// Construct function.
    pub fn new(vm_fd: &Arc<VmFd>, mem_size: u64) -> Result<GuestMemory> {
        let ranges = Self::arch_ram_ranges(mem_size);

        let mut host_mmaps = Vec::new();
        for (index, range) in ranges.iter().enumerate() {
            let host_mmap = Arc::new(HostMemMapping::new(range.0, range.1)?);
            host_mmaps.push(host_mmap.clone());

            let kvm_region = kvm_userspace_memory_region {
                slot: index as u32,
                guest_phys_addr: host_mmap.guest_address(),
                memory_size: host_mmap.size(),
                userspace_addr: host_mmap.host_address(),
                flags: 0,
            };
            unsafe {
                vm_fd
                    .set_user_memory_region(kvm_region)
                    .map_err(Error::KvmSetMR)?;
            }
        }

        Ok(GuestMemory { host_mmaps })
    }

    /// Calculate the ranges of memory according to architecture.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - memory size of VM.
    ///
    /// # Returns
    ///
    /// A array of ranges, it's element represents (start_addr, size).
    /// On x86_64, there is a gap ranged below 4G, which will be skipped.
    pub fn arch_ram_ranges(mem_size: u64) -> Vec<(u64, u64)> {
        // ranges is the vector of (start_addr, size)
        let mut ranges = Vec::<(u64, u64)>::new();

        #[cfg(target_arch = "aarch64")]
        ranges.push((MEM_LAYOUT[LayoutEntryType::Mem as usize].0, mem_size));

        #[cfg(target_arch = "x86_64")]
        {
            let gap_start = MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].0
                + MEM_LAYOUT[LayoutEntryType::MemBelow4g as usize].1;
            ranges.push((0, std::cmp::min(gap_start, mem_size)));
            if mem_size > gap_start {
                let gap_end = MEM_LAYOUT[LayoutEntryType::MemAbove4g as usize].0;
                ranges.push((gap_end, mem_size - gap_start));
            }
        }

        ranges
    }

    /// Find corresponding host mem mapping according to guest address.
    fn find_host_mmap(&self, addr: u64, size: u64) -> Result<Arc<HostMemMapping>> {
        for host_mmap in &self.host_mmaps {
            if addr >= host_mmap.guest_address()
                && addr < host_mmap.guest_address() + host_mmap.size()
            {
                if addr + size > host_mmap.guest_address() + host_mmap.size() {
                    return Err(Error::Overflow(
                        addr - host_mmap.guest_address(),
                        size,
                        host_mmap.size(),
                    ));
                }
                return Ok(host_mmap.clone());
            }
        }
        Err(Error::HostMmapNotFound(addr))
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
    pub fn read(&self, dst: &mut dyn std::io::Write, addr: u64, count: u64) -> Result<()> {
        let host_mmap = self.find_host_mmap(addr, count)?;
        let offset = addr - host_mmap.guest_address();
        let host_addr = host_mmap.host_address();

        let slice = unsafe {
            std::slice::from_raw_parts((host_addr + offset) as *const u8, count as usize)
        };
        dst.write_all(slice).map_err(Error::IoError)?;

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
    pub fn write(&self, src: &mut dyn std::io::Read, addr: u64, count: u64) -> Result<()> {
        let host_mmap = self.find_host_mmap(addr, count)?;
        let offset = addr - host_mmap.guest_address();
        let host_addr = host_mmap.host_address();

        let slice = unsafe {
            std::slice::from_raw_parts_mut((host_addr + offset) as *mut u8, count as usize)
        };
        src.read_exact(slice).map_err(Error::IoError)?;

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
    pub fn write_object<T: ByteCode>(&self, data: &T, addr: u64) -> Result<()> {
        self.write(&mut data.as_bytes(), addr, std::mem::size_of::<T>() as u64)
    }

    /// Read some data from memory to form an object.
    ///
    /// # Arguments
    ///
    /// * `addr` - The start guest address where the data will be read from.
    ///
    /// # Note
    /// To use this method, it is necessary to implement `ByteCode` trait for your object.
    pub fn read_object<T: ByteCode>(&self, addr: u64) -> Result<T> {
        let mut obj = T::default();
        self.read(
            &mut obj.as_mut_bytes(),
            addr,
            std::mem::size_of::<T>() as u64,
        )?;
        Ok(obj)
    }

    /// Get guest memory end address.
    pub fn memory_end_address(&self) -> u64 {
        let mut end_address = 0;
        for host_mmap in self.host_mmaps.iter() {
            let addr = host_mmap.guest_address() + host_mmap.size();
            if addr > end_address {
                end_address = addr;
            }
        }

        end_address
    }
}
