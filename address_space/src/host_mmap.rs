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

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::{AddressRange, GuestAddress};

/// FileBackend represents backend-file of `HostMemMapping`.
pub struct FileBackend {
    /// File we used to map memory.
    pub file: File,
    /// Offset from where the file begins.
    pub offset: u64,
}

impl FileBackend {
    /// Construct a new FileBackend according to path and length.
    /// If the file is already created, this function does not change its length.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path of file.
    /// * `file_len` - The size of file.
    ///
    /// # Errors
    ///
    /// Return Error if
    /// * fail to create the file.
    /// * fail to open the file.
    /// * fail to set file length.
    pub fn new(file_path: &str, file_len: u64) -> Result<FileBackend> {
        let path = std::path::Path::new(&file_path);
        let file = if path.is_dir() {
            let fs_path = format!("{}{}", file_path, "/stratovirt_backmem_XXXXXX");
            let fs_cstr = std::ffi::CString::new(fs_path).unwrap().into_raw();

            let raw_fd = unsafe { libc::mkstemp(fs_cstr) };
            if raw_fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .chain_err(|| "Create file-backend failed");
            }

            unsafe { libc::unlink(fs_cstr) };
            unsafe { File::from_raw_fd(raw_fd) }
        } else {
            // Open the file, if not exist, create it.
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .chain_err(|| "Open file-backend failed")?
        };

        if file.metadata().unwrap().len() == 0 {
            file.set_len(file_len)
                .chain_err(|| "Set file length failed.")?;
        }

        Ok(FileBackend {
            file,
            offset: 0_u64,
        })
    }
}

/// Create HostMemMappings according to address ranges.
///
/// # Arguments
///
/// * `ranges` - The guest address range that will be mapped.
/// * `file_path` - The path of backend-file.
/// * `dump_guest_core` - Include guest memory in core file or not.
pub fn create_host_mmaps(
    ranges: &[(u64, u64)],
    file_path: Option<&str>,
    dump_guest_core: bool,
) -> Result<Vec<Arc<HostMemMapping>>> {
    let mut mappings = Vec::new();

    match file_path {
        Some(path) => {
            // create file-backend
            let file_len = ranges.iter().fold(0, |acc, x| acc + x.1);
            let mut f_back = FileBackend::new(path, file_len)?;
            for range in ranges.iter() {
                mappings.push(Arc::new(HostMemMapping::new(
                    GuestAddress(range.0),
                    range.1,
                    f_back.file.as_raw_fd(),
                    f_back.offset,
                    dump_guest_core,
                )?));

                f_back.offset += range.1;
            }
        }
        None => {
            for range in ranges.iter() {
                mappings.push(Arc::new(HostMemMapping::new(
                    GuestAddress(range.0),
                    range.1,
                    -1,
                    0,
                    dump_guest_core,
                )?));
            }
        }
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
    /// * `file_back` - The file's raw fd that backs memory,
    /// * `file_offset` - Offset in the file that backs memory.
    /// * `dump_guest_core` - Include guest memory in core file or not.
    ///
    /// # Errors
    ///
    /// Return Error if fail to map memory.
    pub fn new(
        guest_addr: GuestAddress,
        size: u64,
        file_back: RawFd,
        file_offset: u64,
        dump_guest_core: bool,
    ) -> Result<HostMemMapping> {
        let mut flags = libc::MAP_PRIVATE | libc::MAP_NORESERVE;
        if file_back == -1 {
            flags |= libc::MAP_ANONYMOUS;
        }

        let host_addr = unsafe {
            let hva = libc::mmap(
                std::ptr::null_mut() as *mut libc::c_void,
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                file_back,
                file_offset as i64,
            );
            if hva == libc::MAP_FAILED {
                return Err(ErrorKind::Mmap.into());
            }
            hva
        };

        if !dump_guest_core {
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
        let ram1 = HostMemMapping::new(GuestAddress(0), 100u64, -1, 0, false).unwrap();
        let ram2 = HostMemMapping::new(GuestAddress(0), 100u64, -1, 0, false).unwrap();
        identify(ram1, 0, 100);
        identify(ram2, 0, 100);
    }

    #[test]
    fn test_file_backend() {
        let file_path = String::from("/tmp/");
        let file_size = 100u64;
        let f_back = FileBackend::new(&file_path, file_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
    }
}
