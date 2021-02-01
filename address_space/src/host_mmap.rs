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

use machine_manager::config::MachineMemConfig;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::{AddressRange, GuestAddress};

/// FileBackend represents backend-file of `HostMemMapping`.
#[derive(Clone)]
pub struct FileBackend {
    /// File we used to map memory.
    pub file: Arc<File>,
    /// Represents HostMmapping's offset in this file.
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
                    .chain_err(|| format!("Failed to create file in directory: {} ", file_path));
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
                .chain_err(|| format!("Failed to Open file: {}", file_path))?
        };

        let old_file_len = file.metadata().unwrap().len();
        if old_file_len == 0 {
            file.set_len(file_len)
                .chain_err(|| format!("Failed to set length of file: {}", file_path))?;
        } else if old_file_len < file_len {
            bail!("Backing file {} does not has sufficient resource for allocating RAM (size is 0x{:X})", file_path, file_len);
        }

        Ok(FileBackend {
            file: Arc::new(file),
            offset: 0_u64,
        })
    }
}

/// Create HostMemMappings according to address ranges.
///
/// # Arguments
///
/// * `ranges` - The guest address range that will be mapped.
/// * `mem_config` - Machine memory config.
pub fn create_host_mmaps(
    ranges: &[(u64, u64)],
    mem_config: &MachineMemConfig,
) -> Result<Vec<Arc<HostMemMapping>>> {
    let mut f_back: Option<FileBackend> = None;

    if let Some(path) = &mem_config.mem_path {
        let file_len = ranges.iter().fold(0, |acc, x| acc + x.1);
        f_back = Some(
            FileBackend::new(&path, file_len)
                .chain_err(|| "Failed to create file that backs memory")?,
        );
    } else if mem_config.mem_share {
        let file_len = ranges.iter().fold(0, |acc, x| acc + x.1);
        let anon_mem_name = String::from("stratovirt_anon_mem");

        let anon_fd =
            unsafe { libc::syscall(libc::SYS_memfd_create, anon_mem_name.as_ptr(), 0) } as RawFd;
        if anon_fd < 0 {
            return Err(std::io::Error::last_os_error()).chain_err(|| "Failed to create memfd");
        }

        let anon_file = unsafe { File::from_raw_fd(anon_fd) };
        anon_file
            .set_len(file_len)
            .chain_err(|| "Failed to set the length of anonymous file that backs memory")?;

        f_back = Some(FileBackend {
            file: Arc::new(anon_file),
            offset: 0,
        });
    }

    let mut mappings = Vec::new();
    for range in ranges.iter() {
        mappings.push(Arc::new(
            HostMemMapping::new(
                GuestAddress(range.0),
                range.1,
                f_back.clone(),
                mem_config.dump_guest_core,
                mem_config.mem_share,
            )
            .chain_err(|| "Failed to create HostMemMapping")?,
        ));

        if let Some(mut fb) = f_back.as_mut() {
            fb.offset += range.1
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
    /// Represents file and offset-in-file that backs this mapping.
    file_back: Option<FileBackend>,
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
    /// * `file_back` - Information of file and offset-in-file that backs memory.
    /// * `dump_guest_core` - Include guest memory in core file or not.
    /// * `is_share` - This mapping is sharable or not.
    ///
    /// # Errors
    ///
    /// Return Error if fail to map memory.
    pub fn new(
        guest_addr: GuestAddress,
        size: u64,
        file_back: Option<FileBackend>,
        dump_guest_core: bool,
        is_share: bool,
    ) -> Result<HostMemMapping> {
        let mut flags = libc::MAP_NORESERVE;
        if file_back.is_none() {
            flags |= libc::MAP_ANONYMOUS;
        }
        if is_share {
            flags |= libc::MAP_SHARED;
        } else {
            flags |= libc::MAP_PRIVATE;
        }

        let host_addr = unsafe {
            let hva = libc::mmap(
                std::ptr::null_mut() as *mut libc::c_void,
                size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                file_back
                    .clone()
                    .map(|fb| fb.file.as_raw_fd())
                    .unwrap_or(-1),
                file_back.clone().map(|fb| fb.offset).unwrap_or(0) as i64,
            );
            if hva == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error()).chain_err(|| ErrorKind::Mmap);
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
                    error!(
                        "Syscall madvise(with MADV_DONTDUMP) failed, OS error is {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }

        Ok(HostMemMapping {
            address_range: AddressRange {
                base: guest_addr,
                size,
            },
            host_addr: host_addr as *mut u8,
            file_back,
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

    /// Get File backend information if this mapping is backed be host-memory.
    /// return None if this mapping is an anonymous mapping.
    pub fn file_backend(&self) -> Option<FileBackend> {
        self.file_back.clone()
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
        let ram1 = HostMemMapping::new(GuestAddress(0), 100u64, None, false, false).unwrap();
        let ram2 = HostMemMapping::new(GuestAddress(0), 100u64, None, false, false).unwrap();
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

    #[test]
    fn test_create_file_backend() {
        let file_path = String::from("back_mem_test1");
        let file_size = 100_u64;
        let f_back = FileBackend::new(&file_path, file_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
        assert_eq!(
            f_back.as_ref().unwrap().file.metadata().unwrap().len(),
            100u64
        );

        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_exist_file_backend() {
        let file_path = String::from("back_mem_test2");
        let file = File::create(file_path.clone()).unwrap();
        file.set_len(50_u64).unwrap();

        let file_size = 100_u64;
        let f_back = FileBackend::new(&file_path, file_size);
        assert!(f_back.is_err());

        let file_size = 20_u64;
        let f_back = FileBackend::new(&file_path, file_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
        assert_eq!(
            f_back.as_ref().unwrap().file.metadata().unwrap().len(),
            50_u64
        );

        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_create_host_mmaps() {
        let addr_ranges = [(0x0, 0x10_0000), (0x100000, 0x10_0000)];
        let mem_config = MachineMemConfig {
            mem_size: 0x20_0000,
            mem_path: Some(String::from("/tmp")),
            dump_guest_core: false,
            mem_share: false,
        };

        let host_mmaps = create_host_mmaps(&addr_ranges, &mem_config).unwrap();
        assert_eq!(host_mmaps.len(), 2);

        // check the start address and size of HostMemMapping
        for (index, mmap) in host_mmaps.iter().enumerate() {
            assert_eq!(mmap.start_address().raw_value(), addr_ranges[index].0);
            assert_eq!(mmap.size(), addr_ranges[index].1);
            assert!(mmap.file_backend().is_some());
        }

        // check the file backends' total size, should equal to mem_size in config.
        let total_file_size = host_mmaps[0]
            .file_backend()
            .unwrap()
            .file
            .metadata()
            .unwrap()
            .len();
        let total_mem_size = addr_ranges.iter().fold(0_u64, |acc, x| acc + x.1);
        let total_mmaps_size = host_mmaps.iter().fold(0_u64, |acc, x| acc + x.size());
        assert_eq!(total_mem_size, total_file_size);
        assert_eq!(total_mem_size, total_mmaps_size);
    }
}
