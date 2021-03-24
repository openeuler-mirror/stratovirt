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

use super::{Error, Result};

/// Record information of memory mapping.
pub struct HostMemMapping {
    /// Address of Host mem mapping.
    guest_addr: u64,
    /// Size of Host mem mapping.
    size: u64,
    /// Host virtual address of mem mapping.
    host_addr: u64,
}

impl HostMemMapping {
    /// Construct a new HostMemMapping.
    ///
    /// # Arguments
    ///
    /// * `guest_addr` - The start address im memory.
    /// * `size` - Size of memory that will be mapped.
    /// * `file_back` - Information of file and offset-in-file that backs memory.
    /// * `dump_guest_core` - Include guest memory in core file or not.
    /// * `is_share` - This mapping is sharable or not.
    ///
    /// # Errors
    ///
    /// Return Error if fail to map memory.
    pub fn new(guest_addr: u64, size: u64) -> Result<HostMemMapping> {
        let flags = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

        let host_addr = unsafe {
            let hva = libc::mmap(
                std::ptr::null_mut() as *mut libc::c_void,
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            );
            if hva == libc::MAP_FAILED {
                return Err(Error::Mmap(std::io::Error::last_os_error()));
            }
            hva
        };

        Ok(HostMemMapping {
            guest_addr,
            size,
            host_addr: host_addr as u64,
        })
    }

    /// Get size of mapped memory.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get start address of mapped memory.
    pub fn guest_address(&self) -> u64 {
        self.guest_addr
    }

    /// Get start `HVA` (host virtual address) of mapped memory.
    pub fn host_address(&self) -> u64 {
        self.host_addr
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
