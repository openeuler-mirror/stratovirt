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

use crate::capability::{CapUserData, CapUserHeader};

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

/// Unshare into a new mount namespace.
///
/// # Arguments
///
/// * `flags` - Flags of unshare syscall.
pub fn unshare(flags: libc::c_int) -> Result<()> {
    SyscallResult {
        ret: unsafe { libc::unshare(flags) },
    }
    .into()
}

/// Set hostname
///
/// # Arguments
///
/// * `Hostname` - The host name.
pub fn set_host_name(host_name: &str) -> Result<()> {
    let len = host_name.len() as libc::size_t;
    let name = into_cstring(host_name)?;
    SyscallResult {
        ret: unsafe { libc::sethostname(name.as_ptr(), len) },
    }
    .into()
}

/// Reassociate thread with a namespace.
///
/// # Arguments
///
/// * `fd` - File descriptor referring to one of magic links in a /proc/`\[`pid`\]`/ns/ directory.
/// * `nstype` - Namespace type.
pub fn setns(fd: i32, nstype: i32) -> Result<()> {
    SyscallResult {
        ret: unsafe { libc::setns(fd, nstype) },
    }
    .into()
}

/// Create folder using a relative path.
///
/// # Arguments
///
/// * `path` - The relative path of filder.
pub fn mkdir(path: &str) -> Result<()> {
    let path_ptr = into_cstring(path)?;
    SyscallResult {
        ret: unsafe { libc::mkdir(path_ptr.as_ptr(), libc::S_IRUSR | libc::S_IWUSR) },
    }
    .into()
}

/// Change the root mount in the mount namespace of the calling process.
///
/// # Arguments
///
/// * `new_root` - The new root path, but can't be "/".
/// * `put_old` - The old root path.
pub fn pivot_root(new_root: &str, put_root: &str) -> Result<()> {
    let new_path = into_cstring(new_root)?;
    let old_path = into_cstring(put_root)?;
    SyscallResult {
        ret: unsafe { libc::syscall(libc::SYS_pivot_root, new_path.as_ptr(), old_path.as_ptr()) }
            as libc::c_int,
    }
    .into()
}

/// Change working directory.
///
/// # Arguments
///
/// * `new_path` - The new path of working directory.
pub fn chdir(new_path: &str) -> Result<()> {
    let path = into_cstring(new_path)?;

    SyscallResult {
        ret: unsafe { libc::chdir(path.as_ptr()) },
    }
    .into()
}

/// Change permissions of file or directory.
///
/// # Arguments
///
/// * `file_path` - The path of file.
/// * `mode` - The file permissions.
pub fn chmod(file_path: &str, mode: libc::mode_t) -> Result<()> {
    let path = into_cstring(file_path)?;
    SyscallResult {
        ret: unsafe { libc::chmod(path.as_ptr(), mode) },
    }
    .into()
}

/// Manage device number
///
/// # Arguments
///
/// * `major_id` - The major device number.
/// * `minor_id` - The minor device number.
pub fn makedev(major_id: u32, minor_id: u32) -> Result<libc::dev_t> {
    Ok(libc::makedev(major_id, minor_id))
}

/// Create a special or ordinary file.
///
/// # Arguments
///
/// * `node_path` - The path of file node.
/// * `mode` - The node permissions.
/// * `dev` - The device number.
pub fn mknod(node_path: &str, mode: libc::mode_t, dev: libc::dev_t) -> Result<()> {
    let path = into_cstring(node_path)?;
    SyscallResult {
        ret: unsafe { libc::mknod(path.as_ptr(), mode, dev) },
    }
    .into()
}

pub fn capget(hdr: &mut CapUserHeader, data: &mut CapUserData) -> Result<()> {
    SyscallResult {
        ret: unsafe { libc::syscall(libc::SYS_capget, hdr, data) as i32 },
    }
    .into()
}

pub fn drop_bounding_caps(cap: u8) -> Result<()> {
    SyscallResult {
        ret: unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_uint::from(cap), 0, 0) },
    }
    .into()
}

#[cfg(test)]
mod tests {
    pub use super::*;

    #[test]
    fn test_into_cstring() {
        let str = into_cstring("stratovirt");
        assert!(str.is_ok());
        let str = str.unwrap();
        let cstr = CString::new("stratovirt").unwrap();
        assert_eq!(cstr, str);
    }
}
