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

use std::cmp::min;
use std::ffi::CString;
use std::fs::{remove_file, File};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::thread;

use anyhow::{bail, Context, Result};
use log::{error, info};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::sys::statfs::fstatfs;
use nix::unistd::{mkstemp, sysconf, unlink, SysconfVar};

use crate::{AddressRange, GuestAddress, Region};
use machine_manager::config::{HostMemPolicy, MachineMemConfig, MemZoneConfig};
use util::{
    syscall::mbind,
    unix::{do_mmap, host_page_size},
};

const MAX_PREALLOC_THREAD: u8 = 16;
/// Verify existing pages in the mapping.
const MPOL_MF_STRICT: u32 = 1;
/// Move pages owned by this process to conform to mapping.
const MPOL_MF_MOVE: u32 = 2;

/// FileBackend represents backend-file of `HostMemMapping`.
#[derive(Clone, Debug)]
pub struct FileBackend {
    /// File we used to map memory.
    pub file: Arc<File>,
    /// Represents HostMmapping's offset in this file.
    pub offset: u64,
    /// Page size of this file.
    pub page_size: u64,
}

fn file_unlink(file_path: &str) {
    if let Err(e) = remove_file(file_path) {
        error!("Failed to unlink file \"{}\", error: {:?}", file_path, e);
    }
}

impl FileBackend {
    /// Construct a new FileBackend with an opened file.
    ///
    /// # Arguments
    ///
    /// * `fd` - Opened backend file.
    pub fn new_common(fd: File) -> Self {
        Self {
            file: Arc::new(fd),
            offset: 0,
            page_size: 0,
        }
    }

    /// Construct a new FileBackend with memory backend.
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
    pub fn new_mem(file_path: &str, file_len: u64) -> Result<FileBackend> {
        let path = std::path::Path::new(&file_path);
        let mut need_unlink = false;
        let file = if path.is_dir() {
            // The last six characters of template file must be "XXXXXX" for `mkstemp`
            // function to create unique temporary file.
            let fs_path = format!("{}{}", file_path, "/stratovirt_backmem_XXXXXX");

            let (raw_fd, fs_tmp_path) = match mkstemp(fs_path.as_str()) {
                Ok((fd, p)) => (fd, p),
                Err(_) => {
                    return Err(std::io::Error::last_os_error()).with_context(|| {
                        format!("Failed to create file in directory: {} ", file_path)
                    });
                }
            };

            if unlink(fs_tmp_path.as_path()).is_err() {
                error!(
                    "Failed to unlink file \"{:?}\", error: {:?}",
                    fs_tmp_path.as_path(),
                    std::io::Error::last_os_error()
                )
            }

            // SAFETY: only one FileBackend instance has the ownership of the file descriptor
            unsafe { File::from_raw_fd(raw_fd) }
        } else {
            need_unlink = !path.exists();
            // Open the file, if not exist, create it.
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .with_context(|| format!("Failed to open file: {}", file_path))?
        };

        let fstat = fstatfs(&file).with_context(|| "Failed to fstatfs file")?;
        info!(
            "Using memory backing file, the page size is {}",
            fstat.optimal_transfer_size()
        );

        let old_file_len = file.metadata().unwrap().len();
        if old_file_len == 0 {
            if file.set_len(file_len).is_err() {
                if need_unlink {
                    file_unlink(file_path);
                }
                bail!("Failed to set length of file: {}", file_path);
            }
        } else if old_file_len < file_len {
            bail!(
                "Backing file {} does not has sufficient resource for allocating RAM (size is 0x{:X})",
                file_path,
                file_len
            );
        }

        Ok(FileBackend {
            file: Arc::new(file),
            offset: 0_u64,
            page_size: fstat.optimal_transfer_size() as _,
        })
    }
}

/// Get the max number of threads that can be used to touch pages.
///
/// # Arguments
///
/// * `nr_vcpus` - Number of vcpus.
fn max_nr_threads(nr_vcpus: u8) -> u8 {
    let conf = sysconf(SysconfVar::_NPROCESSORS_ONLN);

    // If fails to call `sysconf` function, just use a single thread to touch pages.
    if conf.is_err() || conf.unwrap().is_none() {
        log::warn!("Failed to get sysconf of _NPROCESSORS_ONLN");
        return 1;
    }
    let nr_host_cpu = conf.unwrap().unwrap();
    if nr_host_cpu <= 0 {
        log::warn!(
            "The sysconf of _NPROCESSORS_ONLN: {} is ignored",
            nr_host_cpu
        );
        return 1;
    }

    min(min(nr_host_cpu as u8, MAX_PREALLOC_THREAD), nr_vcpus)
}

/// Touch pages to pre-alloc memory for VM.
///
/// # Arguments
///
/// * `start` - The start host address of memory segment.
/// * `page_size` - Size of host page.
/// * `nr_pages` - Number of pages.
fn touch_pages(start: u64, page_size: u64, nr_pages: u64) {
    let mut addr = start;
    for _i in 0..nr_pages {
        // SAFETY: The data read from raw pointer is written to the same address.
        unsafe {
            let read_addr = addr as *mut u8;
            let data: u8 = *read_addr;
            // This function is used to prevent compiler optimization.
            // If `*read = data` is used, the compiler optimizes it as no-op,
            // which means that the pages will not be touched.
            std::ptr::write_volatile(read_addr, data);
        }
        addr += page_size;
    }
}

/// Pre-alloc memory for virtual machine.
///
/// # Arguments
///
/// * `host_addr` - The start host address to pre allocate.
/// * `size` - Size of memory.
/// * `nr_vcpus` - Number of vcpus.
fn mem_prealloc(host_addr: u64, size: u64, nr_vcpus: u8) {
    let page_size = host_page_size();
    let threads = max_nr_threads(nr_vcpus);
    let nr_pages = (size + page_size - 1) / page_size;
    let pages_per_thread = nr_pages / (threads as u64);
    let left = nr_pages % (threads as u64);
    let mut addr = host_addr;
    let mut threads_join = Vec::new();
    for i in 0..threads {
        let touch_nr_pages = if i < (left as u8) {
            pages_per_thread + 1
        } else {
            pages_per_thread
        };
        let thread = thread::spawn(move || {
            touch_pages(addr, page_size, touch_nr_pages);
        });
        threads_join.push(thread);
        addr += touch_nr_pages * page_size;
    }
    // join all threads to wait for pre-allocating.
    while let Some(thread) = threads_join.pop() {
        if let Err(ref e) = thread.join() {
            error!("Failed to join thread: {:?}", e);
        }
    }
}

/// If the memory is not configured numa, use this
///
/// # Arguments
///
/// * `mem_config` - The config of default memory.
/// * `thread_num` - The num of mem preallocv threads, typically the number of vCPUs.
pub fn create_default_mem(mem_config: &MachineMemConfig, thread_num: u8) -> Result<Region> {
    let mut f_back: Option<FileBackend> = None;

    if let Some(path) = &mem_config.mem_path {
        f_back = Some(
            FileBackend::new_mem(path, mem_config.mem_size)
                .with_context(|| "Failed to create file that backs memory")?,
        );
    } else if mem_config.mem_share {
        let anon_fd = memfd_create(
            &CString::new("stratovirt_anon_mem")?,
            MemFdCreateFlag::empty(),
        )?;
        if anon_fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| "Failed to create memfd");
        }

        // SAFETY: The parameters is constant.
        let anon_file = unsafe { File::from_raw_fd(anon_fd) };
        anon_file
            .set_len(mem_config.mem_size)
            .with_context(|| "Failed to set the length of anonymous file that backs memory")?;

        f_back = Some(FileBackend {
            file: Arc::new(anon_file),
            offset: 0,
            page_size: host_page_size(),
        });
    }
    let block = Arc::new(HostMemMapping::new(
        GuestAddress(0),
        None,
        mem_config.mem_size,
        f_back,
        mem_config.dump_guest_core,
        mem_config.mem_share,
        false,
    )?);

    if mem_config.mem_prealloc {
        mem_prealloc(block.host_address(), mem_config.mem_size, thread_num);
    }
    let region = Region::init_ram_region(block, "DefaultRam");

    Ok(region)
}

/// If the memory is configured numa, use this
///
/// # Arguments
///
/// * `mem_config` - The config of default memory.
/// * `thread_num` - The num of mem preallocv threads, typically the number of vCPUs.
pub fn create_backend_mem(mem_config: &MemZoneConfig, thread_num: u8) -> Result<Region> {
    let mut f_back: Option<FileBackend> = None;

    if mem_config.memfd {
        let anon_fd = memfd_create(
            &CString::new("stratovirt_anon_mem")?,
            MemFdCreateFlag::empty(),
        )?;
        if anon_fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| "Failed to create memfd");
        }

        // SAFETY: The parameters is constant.
        let anon_file = unsafe { File::from_raw_fd(anon_fd) };
        anon_file
            .set_len(mem_config.size)
            .with_context(|| "Failed to set the length of anonymous file that backs memory")?;

        f_back = Some(FileBackend {
            file: Arc::new(anon_file),
            offset: 0,
            page_size: host_page_size(),
        });
    } else if let Some(path) = &mem_config.mem_path {
        f_back = Some(
            FileBackend::new_mem(path, mem_config.size)
                .with_context(|| "Failed to create file that backs memory")?,
        );
    }
    let block = Arc::new(HostMemMapping::new(
        GuestAddress(0),
        None,
        mem_config.size,
        f_back,
        mem_config.dump_guest_core,
        mem_config.share,
        false,
    )?);
    if mem_config.prealloc {
        mem_prealloc(block.host_address(), mem_config.size, thread_num);
    }
    set_host_memory_policy(&block, mem_config)?;

    let region = Region::init_ram_region(block, mem_config.id.as_str());
    Ok(region)
}

/// Set host memory backend numa policy.
///
/// # Arguments
///
/// * `mem_mappings` - The host virtual address of mapped memory information.
/// * `zone` - Memory zone config info.
fn set_host_memory_policy(mem_mappings: &Arc<HostMemMapping>, zone: &MemZoneConfig) -> Result<()> {
    if zone.host_numa_nodes.is_none() {
        return Ok(());
    }
    let host_addr_start = mem_mappings.host_address();
    let nodes = zone.host_numa_nodes.as_ref().unwrap();
    let mut max_node = nodes[nodes.len() - 1] as usize;

    let mut nmask: Vec<u64> = Vec::new();
    // Upper limit of max_node is MAX_NODES.
    nmask.resize(max_node / 64 + 1, 0);
    for node in nodes.iter() {
        nmask[(*node / 64) as usize] |= 1_u64 << (*node % 64);
    }
    // We need to pass node_id + 1 as mbind() max_node argument.
    // It is kind of linux bug or feature which will cut off the last node.
    max_node += 1;

    let policy = HostMemPolicy::from(zone.policy.clone());
    if policy == HostMemPolicy::Default {
        max_node = 0;
        nmask = vec![0_u64; max_node];
    }

    mbind(
        host_addr_start,
        zone.size,
        policy as u32,
        nmask,
        max_node as u64,
        MPOL_MF_STRICT | MPOL_MF_MOVE,
    )
    .with_context(|| "Failed to call mbind")?;

    Ok(())
}

/// Record information of memory mapping.
#[derive(Debug)]
pub struct HostMemMapping {
    /// Record the range of one memory segment.
    address_range: AddressRange,
    /// The start address of mapped memory.
    host_addr: *mut u8,
    /// Represents file and offset-in-file that backs this mapping.
    file_back: Option<FileBackend>,
    /// share mem flag
    is_share: bool,
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type,
// implementing them is safe because field of HostMemMapping won't change
// once initialized, only access(r/w) is permitted
unsafe impl Send for HostMemMapping {}
// SAFETY: Same reason as above.
unsafe impl Sync for HostMemMapping {}

impl HostMemMapping {
    /// Construct a new HostMemMapping.
    ///
    /// # Arguments
    ///
    /// * `guest_addr` - Base GPA.
    /// * `host_addr` - Base HVA.
    /// * `size` - Size of memory that will be mapped.
    /// * `file_back` - File backend for memory.
    /// * `dump_guest_core` - Dump guest memory during coredump or not.
    /// * `is_share` - This mapping is sharable or not.
    /// * `read_only` - This mapping is read only or not.
    pub fn new(
        guest_addr: GuestAddress,
        host_addr: Option<u64>,
        size: u64,
        file_back: Option<FileBackend>,
        dump_guest_core: bool,
        is_share: bool,
        read_only: bool,
    ) -> Result<Self> {
        let host_addr = if let Some(addr) = host_addr {
            addr
        } else {
            let fb = file_back.as_ref();
            do_mmap(
                &fb.map(|f| f.file.as_ref()),
                size,
                fb.map_or(0, |f| f.offset),
                read_only,
                is_share,
                dump_guest_core,
            )?
        };

        Ok(Self {
            address_range: AddressRange {
                base: guest_addr,
                size,
            },
            host_addr: host_addr as *mut u8,
            file_back,
            is_share,
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

    pub fn mem_shared(&self) -> bool {
        self.is_share
    }
}

impl Drop for HostMemMapping {
    /// Release the memory mapping.
    fn drop(&mut self) {
        // SAFETY: self.host_addr and self.size has already been verified during initialization.
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
    use std::io::{Read, Seek, SeekFrom, Write};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    fn identify(ram: HostMemMapping, st: u64, end: u64) {
        assert_eq!(ram.start_address(), GuestAddress(st));
        assert_eq!(ram.size(), end - st);
    }

    #[test]
    fn test_ramblock_creation() {
        let ram1 =
            HostMemMapping::new(GuestAddress(0), None, 100, None, false, false, false).unwrap();
        let host_addr = ram1.host_address();
        let slice = unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, 1) };

        let temp_file = TempFile::new().unwrap();
        let mut f = temp_file.into_file();
        f.write("This is temp file".as_bytes()).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        assert!(f.read_exact(slice).is_ok());

        identify(ram1, 0, 100);
    }

    #[test]
    fn test_write_host_mem_read_only() {
        const BAD_ADDRESS: i32 = 14;

        let ram1 = Arc::new(
            HostMemMapping::new(GuestAddress(0), None, 100, None, false, false, true).unwrap(),
        );
        let host_addr = ram1.host_address();
        let slice = unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, 1) };

        let temp_file = TempFile::new().unwrap();
        let mut f = temp_file.into_file();
        f.write("This is temp file".as_bytes()).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            f.read_exact(slice).unwrap_err().raw_os_error(),
            Some(BAD_ADDRESS)
        );
    }

    #[test]
    fn test_file_backend_with_dir() {
        // Create file backend in the current directory,
        // and the file will be removed after test-thread exits.
        let file_path = std::env::current_dir()
            .unwrap()
            .as_path()
            .to_str()
            .unwrap()
            .to_string();
        let file_size = 100u64;
        let f_back = FileBackend::new_mem(&file_path, file_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
    }

    #[test]
    fn test_file_backend_with_file() {
        // Create file backend in the current directory,
        // and the file will be removed after test-thread exits.
        let file_path = String::from("back_mem_test1");
        let file_size = 100_u64;
        let f_back = FileBackend::new_mem(&file_path, file_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
        assert_eq!(
            f_back.as_ref().unwrap().file.metadata().unwrap().len(),
            100u64
        );
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_file_backend_with_exist_file() {
        // Create file backend in the current directory, and the file is removed manually.
        let file_path = String::from("back_mem_test2");
        let file = File::create(file_path.clone()).unwrap();
        file.set_len(50_u64).unwrap();

        let mem_size = 100_u64;
        let f_back = FileBackend::new_mem(&file_path, mem_size);
        assert!(f_back.is_err());

        let mem_size = 20_u64;
        let f_back = FileBackend::new_mem(&file_path, mem_size);
        assert!(f_back.is_ok());
        assert_eq!(f_back.as_ref().unwrap().offset, 0u64);
        assert_eq!(
            f_back.as_ref().unwrap().file.metadata().unwrap().len(),
            50_u64
        );

        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    fn test_memory_prealloc() {
        // Mmap and prealloc with anonymous memory.
        let host_addr = do_mmap(&None, 0x20_0000, 0, false, false, false).unwrap();
        // Check the thread number equals to minimum value.
        assert_eq!(max_nr_threads(1), 1);
        // The max threads limit is 16, or the number of host CPUs, it will never be 20.
        assert_ne!(max_nr_threads(20), 20);
        mem_prealloc(host_addr, 0x20_0000, 20);

        // Mmap and prealloc with file backend.
        let file_path = String::from("back_mem_test");
        let file_size = 0x10_0000;
        let f_back = FileBackend::new_mem(&file_path, file_size).unwrap();
        let host_addr = do_mmap(
            &Some(f_back.file.as_ref()),
            0x10_0000,
            f_back.offset,
            false,
            true,
            false,
        )
        .unwrap();
        mem_prealloc(host_addr, 0x10_0000, 2);
        std::fs::remove_file(file_path).unwrap();
    }
}
