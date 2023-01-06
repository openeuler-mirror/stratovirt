// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

const MAX_PATH_LEN: usize = 4096;
const OFFSET_MAX: u64 = 0x7fffffffffffffff;

use std::ffi::CString;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use super::fuse_msg::*;

/// The pointer to open a directory.
pub type DirPtr = *mut libc::DIR;
/// The pointer to a directory entry in the directory stream.
pub type DirentPtr = *mut libc::dirent;

/// Get the information of a file with path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `flags` - The flags used to get the information of the file.
pub fn fstat_at(file: &File, name: CString, flags: i32) -> (libc::stat, i32) {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };

    errno::set_errno(errno::Errno(0));
    if unsafe { libc::fstatat(file.as_raw_fd(), name.as_ptr(), &mut stat, flags) } < 0 {
        return (stat, errno::errno().0);
    }

    (stat, FUSE_OK)
}

/// Open a file with the path name.
///
/// # Arguments
///
/// * `name` - The path name in the host filesystem.
/// * `flags` - The flags used to open a file.
pub fn open(name: CString, flags: i32) -> (Option<File>, i32) {
    errno::set_errno(errno::Errno(0));
    let fd = unsafe { libc::open(name.as_ptr(), flags) };
    if fd < 0 {
        return (None, errno::errno().0);
    }

    let file = unsafe { File::from_raw_fd(fd) };

    (Some(file), FUSE_OK)
}

/// Open a file with path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `mode` - The mode used to open a file.
pub fn open_at(file: &File, name: CString, flags: i32, mode: u32) -> (Option<File>, i32) {
    errno::set_errno(errno::Errno(0));

    let fd = unsafe { libc::openat(file.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return (None, errno::errno().0);
    }

    let file = unsafe { File::from_raw_fd(fd) };

    (Some(file), FUSE_OK)
}

/// Change permissions of a file.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `mode` - The mode indicates the permissions of the file will be set.
pub fn fchmod(file: &File, mode: u32) -> i32 {
    errno::set_errno(errno::Errno(0));
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Change permissions of a file with path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `mode` - The mode indicates the permissions of the file will be set.
pub fn fchmod_at(file: &File, name: CString, mode: u32) -> i32 {
    errno::set_errno(errno::Errno(0));
    if unsafe { libc::fchmodat(file.as_raw_fd(), name.as_ptr(), mode, 0) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Change the owner and group of a file with path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `uid` - The user id will be set.
/// * `gid` - The group id will be set.
/// * `flags` - The flags indicates the action of file will be set.
pub fn fchown_at(file: &File, name: CString, uid: u32, gid: u32, flags: i32) -> i32 {
    errno::set_errno(errno::Errno(0));
    if unsafe { libc::fchownat(file.as_raw_fd(), name.as_ptr(), uid, gid, flags) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Truncate file to specified length.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `size` - The size of truncating file.
pub fn ftruncate(file: &File, size: u64) -> i32 {
    errno::set_errno(errno::Errno(0));
    if unsafe { libc::ftruncate(file.as_raw_fd(), size as i64) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Update the timestamps of a file with nanosecond precision.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `a_sec` - The second of last access time.
/// * `a_nsec` - The nanosecond of last access time.
/// * `m_sec` - The second of last modification time.
/// * `m_nsec` - The nanosecond of last modification time.
pub fn futimens(file: &File, a_sec: u64, a_nsec: i64, m_sec: u64, m_nsec: i64) -> i32 {
    let tv = vec![
        libc::timespec {
            tv_sec: a_sec as i64,
            tv_nsec: a_nsec,
        },
        libc::timespec {
            tv_sec: m_sec as i64,
            tv_nsec: m_nsec,
        },
    ];

    errno::set_errno(errno::Errno(0));
    if unsafe { libc::futimens(file.as_raw_fd(), tv.as_ptr()) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Update the timestamps with nanosecond precision by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `a_sec` - The second of last access time.
/// * `a_nsec` - The nanosecond of last access time.
/// * `m_sec` - The second of last modification time.
/// * `m_nsec` - The nanosecond of last modification time.
pub fn utimensat(
    file: &File,
    name: CString,
    a_sec: u64,
    a_nsec: i64,
    m_sec: u64,
    m_nsec: i64,
    flags: i32,
) -> i32 {
    let tv = vec![
        libc::timespec {
            tv_sec: a_sec as i64,
            tv_nsec: a_nsec,
        },
        libc::timespec {
            tv_sec: m_sec as i64,
            tv_nsec: m_nsec,
        },
    ];

    errno::set_errno(errno::Errno(0));
    if unsafe { libc::utimensat(file.as_raw_fd(), name.as_ptr(), tv.as_ptr(), flags) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Read value of a symbolic link by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
pub fn readlinkat(file: &File, path: CString) -> (Option<Vec<u8>>, i32) {
    let mut buf = vec![0; MAX_PATH_LEN + 1];

    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            path.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };

    if ret == -1 {
        return (None, errno::errno().0);
    }

    buf.resize(ret as usize, 0);

    (Some(buf), FUSE_OK)
}

/// Creates a symbolic link to the target path name.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `link_name` - The link name is new path name for the target path name.
pub fn symlinkat(file: &File, name: CString, link_name: CString) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = unsafe { libc::symlinkat(link_name.as_ptr(), file.as_raw_fd(), name.as_ptr()) };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Change user id and group id in the process.
///
/// # Arguments
///
/// * `new_uid` - The user id will be changed to the current user id.
/// * `new_gid` - The group id will be changed to the current group id.
/// * `old_uid` - The old user id will be returned.
/// * `old_gid` - The old group id will be returned.
pub fn change_uid_gid(new_uid: u32, new_gid: u32, old_uid: &mut u32, old_gid: &mut u32) -> i32 {
    let current_uid = unsafe { libc::geteuid() };
    let current_gid = unsafe { libc::getegid() };

    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::syscall(libc::SYS_setresgid, -1, new_gid, -1) };
    if ret == -1 {
        return errno::errno().0;
    }

    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::syscall(libc::SYS_setresuid, -1, new_uid, -1) };
    if ret == -1 {
        unsafe { libc::syscall(libc::SYS_setresgid, -1, current_gid, -1) };

        return errno::errno().0;
    }

    *old_uid = current_uid;
    *old_gid = current_gid;
    FUSE_OK
}

/// Recover user id and group id in the process.
///
/// # Arguments
///
/// * `old_uid` - The old user id will be recovered in the process.
/// * `old_gid` - The old group id will be recovered in the process.
pub fn recover_uid_gid(old_uid: u32, old_gid: u32) -> i32 {
    let ret = unsafe { libc::syscall(libc::SYS_setresuid, -1, old_uid, -1) };
    if ret == -1 {
        panic!("Failed to recover uid {} {}", old_uid, old_gid);
    }

    let ret = unsafe { libc::syscall(libc::SYS_setresgid, -1, old_gid, -1) };
    if ret == -1 {
        panic!("Failed to recover gid {} {}", old_uid, old_gid);
    }

    FUSE_OK
}

/// Create a special or ordinary file by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `mode` - The mode indicates both the file mode to use and the type of node to be created.
/// * `rdev` - The rdev indicates the major and minor numbers of the special file.
pub fn mknodat(file: &File, name: CString, mode: u32, rdev: u32) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = unsafe { libc::mknodat(file.as_raw_fd(), name.as_ptr(), mode, rdev as u64) };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Create a directory by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `mode` - The mode indicates the permissions of the new directory.
pub fn mkdir_at(file: &File, name: CString, mode: u32) -> i32 {
    errno::set_errno(errno::Errno(0));
    if unsafe { libc::mkdirat(file.as_raw_fd(), name.as_ptr(), mode) } < 0 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Delete a name in host filesystem by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the file descriptor of starting directory to look up for the
/// file.
/// * `name` - The name indicates the file path is relative to the starting directory.
/// * `flags` - The flags indicates the operation of deleting a name.
pub fn unlinkat(file: &File, name: CString, flags: i32) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = unsafe { libc::unlinkat(file.as_raw_fd(), name.as_ptr(), flags) };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Modify a name in host filesystem by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `olddir` - The directory file handler saves the file descriptor of starting directory to look up for the
/// old file.
/// * `name` - The name indicates the file path is relative to the starting of old directory.
/// * `newdir` - The directory file handler saves the file descriptor of starting directory to look up for the
/// new file.
/// * `newname` - The name indicates the file path is relative to the starting of new directory.
pub fn rename(olddir: &File, name: CString, newdir: &File, newname: CString) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = unsafe {
        libc::renameat(
            olddir.as_raw_fd(),
            name.as_ptr(),
            newdir.as_raw_fd(),
            newname.as_ptr(),
        )
    };

    if ret != FUSE_OK {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Change a name for file in host filesystem by path name that is relative to the starting directory.
///
/// # Arguments
///
/// * `old_file` - The file handler saves the file descriptor of starting old directory to look up for the
/// file.
/// * `old_name` - The name indicates the file path is relative to the starting of old directory.
/// * `new_file` - The file handler saves the file descriptor of starting new directory to look up for the
/// file.
/// * `new_name` - The name indicates the file path is relative to the starting of new directory.
/// * `flags` - The flags indicates the operation of change a name.
pub fn linkat(
    old_file: &File,
    old_name: CString,
    new_file: &File,
    new_name: CString,
    flags: i32,
) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = unsafe {
        libc::linkat(
            old_file.as_raw_fd(),
            old_name.as_ptr(),
            new_file.as_raw_fd(),
            new_name.as_ptr(),
            flags,
        )
    };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Get the information about a mounted filesystem.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
pub fn fstat_vfs(file: &File) -> (libc::statvfs, i32) {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    errno::set_errno(errno::Errno(0));
    if unsafe { libc::fstatvfs(file.as_raw_fd(), &mut stat) } < 0 {
        return (stat, errno::errno().0);
    }

    (stat, FUSE_OK)
}

/// Synchronize the data of file to storage device.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `datasync` - The datasync indicates whether to use the fdatasync
/// or fsync interface.
pub fn fsync(file: &File, datasync: bool) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret = if datasync {
        unsafe { libc::fdatasync(file.as_raw_fd()) }
    } else {
        unsafe { libc::fsync(file.as_raw_fd()) }
    };

    if ret != FUSE_OK {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Change current working directory.
///
/// # Arguments
///
/// * `file` - The file handler saves the open directory descriptor.
pub fn fchdir(file: &File) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::fchdir(file.as_raw_fd()) };
    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Set an extended attribute value.
///
/// # Arguments
///
/// * `path` - The path in the host filesystem.
/// * `name` - The name of extended attribute.
/// * `value` - The value of extended attribute.
/// * `size` - The size of the string of value.
/// * `flags` - The flags indicates the attribute will be set.
pub fn set_xattr(path: CString, name: CString, value: CString, size: u32, flags: u32) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            size as usize,
            flags as i32,
        )
    };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Set an extended attribute value by the open file file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `name` - The name of extended attribute.
/// * `value` - The value of extended attribute.
/// * `size` - The size of the string of value.
/// * `flags` - The flags indicates the attribute will be set.
pub fn fset_xattr(file: &File, name: CString, value: CString, size: u32, flags: u32) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            size as usize,
            flags as i32,
        )
    };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Get an extended attribute value.
///
/// # Arguments
///
/// * `path` - The path in the host filesystem.
/// * `name` - The name of extended attribute.
/// * `size` - The size of the extended attribute value that needs to be get.
pub fn get_xattr(path: CString, name: CString, size: usize) -> (Option<Vec<u8>>, i32) {
    let mut buf = vec![0; size];

    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            size,
        )
    };
    if ret == -1 {
        return (None, errno::errno().0);
    }

    buf.resize(ret as usize, 0);

    (Some(buf), FUSE_OK)
}

/// Get an extended attribute value by the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `name` - The name of extended attribute.
/// * `size` - The size of the extended attribute value that needs to be get.
pub fn fget_xattr(file: &File, name: CString, size: usize) -> (Option<Vec<u8>>, i32) {
    let mut buf = vec![0; size];

    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            size,
        )
    };
    if ret == -1 {
        return (None, errno::errno().0);
    }

    buf.resize(ret as usize, 0);

    (Some(buf), FUSE_OK)
}

/// List extended attribute names.
///
/// # Arguments
///
/// * `path` - The path in the host filesystem.
/// * `size` - The size of the extended attribute names that needs to be get.
pub fn list_xattr(path: CString, size: usize) -> (Option<Vec<u8>>, i32) {
    let mut buf = vec![0; size];

    errno::set_errno(errno::Errno(0));
    let ret =
        unsafe { libc::listxattr(path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, size) };
    if ret == -1 {
        return (None, errno::errno().0);
    }

    buf.resize(ret as usize, 0);

    (Some(buf), FUSE_OK)
}

/// List extended attribute names by the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `size` - The size of the extended attribute names that needs to be get.
pub fn flist_xattr(file: &File, size: usize) -> (Option<Vec<u8>>, i32) {
    let mut buf = vec![0; size];

    errno::set_errno(errno::Errno(0));
    let ret = unsafe {
        libc::flistxattr(
            file.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_char,
            size,
        )
    };
    if ret == -1 {
        return (None, errno::errno().0);
    }

    buf.resize(ret as usize, 0);

    (Some(buf), FUSE_OK)
}

/// Remove an extended attribute value.
///
/// # Arguments
///
/// * `path` - The path in the host filesystem.
/// * `name` - The name of the extended attribute value.
pub fn remove_xattr(path: CString, name: CString) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };
    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Remove an extended attribute value by the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `name` - The name of the extended attribute value.
pub fn fremove_xattr(file: &File, name: CString) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) };
    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Set mask for file mode creation.
///
/// # Arguments
///
/// * `umask` - The umask indicates the permissions in the umask are turned off.
pub fn umask(umask: u32) {
    unsafe { libc::umask(umask) };
}

/// Open a directory stream by the file descriptor.
///
/// # Arguments
///
/// * `fd` - The open file descriptor used to open a directory stream.
pub fn fdopen_dir(fd: RawFd) -> (Option<DirPtr>, i32) {
    errno::set_errno(errno::Errno(0));

    let dirp = unsafe { libc::fdopendir(fd) };
    if errno::errno().0 != 0 {
        return (None, errno::errno().0);
    }

    (Some(dirp), FUSE_OK)
}

/// Set the position of the next readdir() in the directory stream.
///
/// # Arguments
///
/// * `dirp` - The pointer to open a directory.
/// * `offset` - The position of the next readdir().
pub fn seek_dir(dirp: &mut DirPtr, offset: u64) {
    unsafe {
        libc::seekdir(*dirp, offset as i64);
    };
}

/// Read a directory entry in the directory stream.
///
/// # Arguments
///
/// * `dirp` - The pointer to open a directory.
pub fn read_dir(dirp: &mut DirPtr) -> (Option<DirentPtr>, i32) {
    errno::set_errno(errno::Errno(0));

    let direntp = unsafe { libc::readdir(*dirp) };
    if errno::errno().0 != 0 {
        return (None, errno::errno().0);
    }

    (Some(direntp), FUSE_OK)
}

/// Lock the file or unlock the file by BSD lock by the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `operation` - The operation of lock type.
pub fn flock(file: &File, operation: i32) -> i32 {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Lock the file or unlock the file by POSIX lock by the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `cmd` - The command for creating, lock and unlock in POSIX lock.
/// * `file_lock` - The information of file lock will be set.
/// * `file_lock_out` - The information of file lock will be returned.
pub fn fcntl_flock(
    file: &File,
    cmd: i32,
    file_lock: &FuseFileLock,
    file_lock_out: &mut FuseFileLock,
) -> i32 {
    let mut flock: libc::flock = unsafe { std::mem::zeroed() };

    flock.l_type = file_lock.lock_type as i16;
    flock.l_whence = libc::SEEK_SET as i16;
    flock.l_start = file_lock.start as i64;
    flock.l_pid = file_lock.pid as i32;

    if file_lock.end == OFFSET_MAX {
        flock.l_len = 0;
    } else {
        flock.l_len = file_lock.end as i64 - file_lock.start as i64 + 1;
    }

    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &mut flock) };

    if ret == -1 {
        return errno::errno().0;
    }

    file_lock_out.lock_type = flock.l_type as u32;
    if flock.l_type != libc::F_ULOCK as i16 {
        file_lock_out.start = flock.l_start as u64;
        if flock.l_len == 0 {
            file_lock_out.end = OFFSET_MAX;
        } else {
            file_lock_out.end = (flock.l_start + flock.l_len - 1) as u64;
        }
    }

    file_lock_out.pid = flock.l_pid as u32;

    FUSE_OK
}

/// Allocate the disk space with the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `mode` - The mode determines the operation to be performed on the given range.
/// * `offset` - The offset in the file.
/// * `length` - The length that needs to be allocated.
pub fn fallocate(file: &File, mode: u32, offset: u64, length: u64) -> i32 {
    errno::set_errno(errno::Errno(0));

    let ret =
        unsafe { libc::fallocate(file.as_raw_fd(), mode as i32, offset as i64, length as i64) };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}

/// Reposition the file offset of the open file descriptor.
///
/// # Arguments
///
/// * `file` - The file handler saves the open file descriptor.
/// * `offset` - The offset in the file used together with the whence.
/// * `whence` - The length that needs to be allocated.
pub fn lseek(file: &File, offset: u64, whence: u32) -> (u64, i32) {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::lseek(file.as_raw_fd(), offset as i64, whence as i32) };

    if ret == -1 {
        return (0, errno::errno().0);
    }

    (ret as u64, FUSE_OK)
}

/// Set file resource limits.
///
/// # Arguments
///
/// * `rlim_cur` - The soft limit of the file resource.
/// * `rlim_max` - The hard limit of the file resource.
pub fn set_rlimit(rlim_cur: u64, rlim_max: u64) -> i32 {
    let limit = libc::rlimit { rlim_cur, rlim_max };

    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };

    if ret == -1 {
        return errno::errno().0;
    }

    FUSE_OK
}
