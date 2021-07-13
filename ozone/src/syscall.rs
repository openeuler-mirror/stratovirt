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

use std::convert::Into;
use std::ffi::CString;
use std::io::Result;
use std::os::raw::c_int;
use std::ptr::null;

/// Wrapper to syscall exit codes and transfer them into "io::Result"
pub struct SyscallResult {
    ret: c_int,
}

impl From<SyscallResult> for Result<c_int> {
    /// Transfer exit codes to "io::Result"
    fn from(res: SyscallResult) -> Self {
        if res.ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res.ret)
        }
    }
}

impl From<SyscallResult> for Result<()> {
    /// Transfer exit codes to "io::Result"
    fn from(res: SyscallResult) -> Self {
        let return_code: Result<c_int> = res.into();
        return_code.map(|_| ())
    }
}

/// Transfer &str to CString.
///
/// # Arguments
///
/// * `item` - 'item' is &str type.
fn into_cstring(item: &str) -> Result<CString> {
    CString::new(item).map_err(|_| std::io::ErrorKind::InvalidInput.into())
}

/// Umount destination directory.
///
/// # Arguments
///
/// * `dst_path` - Path of destination directory.
pub fn umount(dst_path: &str) -> Result<()> {
    let target = into_cstring(dst_path)?;

    SyscallResult {
        ret: unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) },
    }
    .into()
}

/// Mount destination directory.
///
/// # Arguments
///
/// * `dst_path` - Path of destination directory.
pub fn mount(source_file: Option<&str>, new_root_dir: &str, flag: libc::c_ulong) -> Result<()> {
    let target = into_cstring(new_root_dir)?;
    if let Some(path) = source_file {
        let source = into_cstring(path)?;
        SyscallResult {
            ret: unsafe { libc::mount(source.as_ptr(), target.as_ptr(), null(), flag, null()) },
        }
        .into()
    } else {
        SyscallResult {
            ret: unsafe { libc::mount(null(), target.as_ptr(), null(), flag, null()) },
        }
        .into()
    }
}

/// Change owner of file
///
/// # Arguments
///
/// * `uid` - User id.
/// * `gid` - Group id.
pub fn chown(file_path: &str, uid: u32, gid: u32) -> Result<()> {
    let path = into_cstring(file_path)?;
    SyscallResult {
        ret: unsafe { libc::chown(path.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) },
    }
    .into()
}

/// Close file descriptor
///
/// # Arguments
///
/// * `fd` - file descriptor.
pub fn close(fd: libc::c_int) -> Result<()> {
    SyscallResult {
        ret: unsafe { libc::close(fd) },
    }
    .into()
}
