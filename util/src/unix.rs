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

extern crate libc;

use super::errors::{ErrorKind, Result};

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
