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

use crate::errors::{ErrorKind, Result};
use crate::{AddressRange, GuestAddress};

/// Create a new HostMemMapping.
///
/// # Arguments
///
/// * `ranges` - The guest address range that will be mapped.
/// * `omit_vm_memory` - Dump guest memory in core file or not.
pub fn create_host_mmaps(
    ranges: &[(u64, u64)],
    omit_vm_memory: bool,
) -> Result<Vec<Arc<HostMemMapping>>> {
    let mut mappings = Vec::new();

    for range in ranges.iter() {
        mappings.push(Arc::new(HostMemMapping::new(
            GuestAddress(range.0),
            range.1,
            omit_vm_memory,
        )?));
    }

    Ok(mappings)
}

/// Record information of memory mapping.
pub struct HostMemMapping {
    /// Record the range of one memory segment.
    address_range: AddressRange,
    /// The start address of mapped memory.
    host_addr: *mut u8,
}

// Send and Sync is not auto-implemented for raw pointer type
// implementing them is safe because field of HostMemMapping won't change once initialized,
// only access(r/w) is permitted
unsafe impl Send for HostMemMapping {}
unsafe impl Sync for HostMemMapping {}

impl HostMemMapping {
    /// Construct a new HostMemMapping.
    ///
    /// # Arguments
    ///
    /// * `guest_addr` - The start address im memory.
    /// * `size` - Size of memory that will be mapped.
    /// * `omit_vm_memory` - Dump guest memory in core file or not.
    ///
    /// # Errors
    ///
    /// Return Error if fail to map memory.
    pub fn new(
        guest_addr: GuestAddress,
        size: u64,
        omit_vm_memory: bool,
    ) -> Result<HostMemMapping> {
        let host_addr = unsafe {
            let hva = libc::mmap(
                std::ptr::null_mut() as *mut libc::c_void,
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            );
            if hva == libc::MAP_FAILED {
                return Err(ErrorKind::Mmap.into());
            }
            hva
        };

        if omit_vm_memory {
            unsafe {
                let madvise_res = libc::madvise(
                    host_addr as *mut libc::c_void,
                    size as libc::size_t,
                    libc::MADV_DONTDUMP,
                );
                if madvise_res < 0 {
                    error!("madvise with MADV_DONTDUMP failed");
                }
            }
        }

        Ok(HostMemMapping {
            address_range: AddressRange {
                base: guest_addr,
                size,
            },
            host_addr: host_addr as *mut u8,
        })
    }

    /// Get size of mapped memory.
    pub fn size(&self) -> u64 {
        self.address_range.size
    }

    /// Get start address of mapped memory.
    pub fn start_address(&self) -> GuestAddress {
        self.address_range.base
    }

    /// Get start `HVA` (host virtual address) of mapped memory.
    #[inline]
    pub fn host_address(&self) -> u64 {
        self.host_addr as u64
    }
}

impl Drop for HostMemMapping {
    /// Release the memory mapping.
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.host_addr as *mut libc::c_void,
                self.size() as libc::size_t,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn identify(ram: HostMemMapping, st: u64, end: u64) {
        assert_eq!(ram.start_address(), GuestAddress(st));
        assert_eq!(ram.size(), end - st);
    }

    #[test]
    fn test_ramblock_creation() {
        let ram1 = HostMemMapping::new(GuestAddress(0), 100u64, false).unwrap();
        let ram2 = HostMemMapping::new(GuestAddress(0), 100u64, false).unwrap();
        identify(ram1, 0, 100);
        identify(ram2, 0, 100);
    }
}
