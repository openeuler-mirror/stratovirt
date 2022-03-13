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
use std::os::unix::io::AsRawFd;

use super::errors::{ErrorKind, Result, ResultExt};

/// This function returns the caller's thread ID(TID).
pub fn gettid() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}

/// This function used to remove group and others permission using libc::chmod.
pub fn limit_permission(path: &str) -> Result<()> {
    let file_path = path.as_bytes().to_vec();
    let cstr_file_path = std::ffi::CString::new(file_path).unwrap();
    let ret = unsafe { libc::chmod(cstr_file_path.as_ptr(), 0o600) };

    if ret == 0 {
        Ok(())
    } else {
        Err(ErrorKind::ChmodFailed(ret).into())
    }
}

/// Gets the page size of host.
pub fn host_page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

#[derive(PartialEq, Debug)]
/// Three path type in unix.
pub enum UnixPath {
    File = 0,
    Unix = 1,
    Tcp = 2,
    Unknown = 3,
}

impl From<&str> for UnixPath {
    fn from(s: &str) -> Self {
        match s {
            "file" | "File" | "FILE" => UnixPath::File,
            "unix" | "Unix" | "UNIX" => UnixPath::Unix,
            "tcp" | "Tcp" | "TCP" => UnixPath::Tcp,
            _ => UnixPath::Unknown,
        }
    }
}

/// Parse unix uri to unix path.
///
/// # Notions
///
/// Unix uri is the string as `file:/xxx/xxx` or `unix:/xxx/xxx` or `tcp:xxx.xxx.xxx`.
pub fn parse_uri(uri: &str) -> Result<(UnixPath, String)> {
    let parse_vec: Vec<&str> = uri.split(':').collect();
    if parse_vec.len() == 2 {
        match UnixPath::from(parse_vec[0]) {
            UnixPath::File => Ok((UnixPath::File, String::from(parse_vec[1]))),
            UnixPath::Unix => Ok((UnixPath::Unix, String::from(parse_vec[1]))),
            _ => bail!("Unsupported unix path type."),
        }
    } else {
        bail!("Invalid unix uri: {}", uri)
    }
}

/// Call libc::mmap to allocate memory or map disk file.
///
/// # Arguments
///
/// * `file` - Backend file.
/// * `len` - Length of maping.
/// * `offset` - Offset in the file (or other object).
/// * `read_only` - Allow to write or not.
/// * `is_share` - Share the mapping or not.
/// * `dump_guest_core` - Exclude from a core dump or not.
///
/// # Errors
///
/// * Failed to do mmap.
pub fn do_mmap(
    file: &Option<&File>,
    len: u64,
    offset: u64,
    read_only: bool,
    is_share: bool,
    dump_guest_core: bool,
) -> Result<u64> {
    let mut flags: i32 = 0;
    let mut fd: i32 = -1;
    if let Some(f) = file {
        fd = f.as_raw_fd();
    } else {
        flags |= libc::MAP_ANONYMOUS;
    }

    if is_share {
        flags |= libc::MAP_SHARED;
    } else {
        flags |= libc::MAP_PRIVATE;
    }

    let mut prot = libc::PROT_READ;
    if !read_only {
        prot |= libc::PROT_WRITE;
    }

    // Safe because the return value is checked.
    let hva = unsafe {
        libc::mmap(
            std::ptr::null_mut() as *mut libc::c_void,
            len as libc::size_t,
            prot,
            flags,
            fd as libc::c_int,
            offset as libc::off_t,
        )
    };
    if hva == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).chain_err(|| "Mmap failed.");
    }
    if !dump_guest_core {
        set_memory_undumpable(hva, len);
    }

    Ok(hva as u64)
}

fn set_memory_undumpable(host_addr: *mut libc::c_void, size: u64) {
    // Safe because host_addr and size are valid and return value is checked.
    let ret = unsafe { libc::madvise(host_addr, size as libc::size_t, libc::MADV_DONTDUMP) };
    if ret < 0 {
        error!(
            "Syscall madvise(with MADV_DONTDUMP) failed, OS error is {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_uri, UnixPath};

    #[test]
    fn test_parse_uri() {
        let test_uri_01 = "file:/tmp/test_file";
        assert!(parse_uri(test_uri_01).is_ok());
        assert_eq!(
            parse_uri(test_uri_01).unwrap(),
            (UnixPath::File, String::from("/tmp/test_file"))
        );

        let test_uri_02 = "file:/tmp/test_file:file";
        assert!(parse_uri(test_uri_02).is_err());

        let test_uri_03 = "tcp:127.0.0.1";
        assert!(parse_uri(test_uri_03).is_err());
    }
}
