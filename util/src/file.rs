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

use std::fs::{remove_file, File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Ok, Result};
use nix::fcntl::{fcntl, FcntlArg};
use nix::unistd::getpid;

pub const MAX_FILE_ALIGN: u32 = 4096;
/// Permission to read
const FILE_LOCK_READ: u64 = 0x01;
/// Permission to write
const FILE_LOCK_WRITE: u64 = 0x02;
/// All permissions
const FILE_LOCK_ALL: [u64; 2] = [FILE_LOCK_READ, FILE_LOCK_WRITE];
/// Permission lock base address, consistent with qemu
const LOCK_PERM_BASE: u64 = 100;
/// Shared lock base address, consistent with qemu
const LOCK_SHARED_BASE: u64 = 200;

pub fn open_file(path: &str, read_only: bool, direct: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(!read_only);
    if direct {
        options.custom_flags(libc::O_DIRECT);
    }
    let file = options.open(path).with_context(|| {
        format!(
            "failed to open the file for block {}. Error: {}",
            path,
            std::io::Error::last_os_error(),
        )
    })?;

    Ok(file)
}

pub fn get_file_alignment(file: &File, direct: bool) -> Result<(u32, u32)> {
    if !direct {
        return Ok((1, 1));
    }

    // DirectIO may degrade into bufferIO when not aligned, and IO will not report errors at this time.
    // Detecting alignment by judging the return value of IO is unreliable.
    // Directly obtain the alignment values presented by the Filesystem.
    let metadata = file
        .metadata()
        .with_context(|| "Failed to get file metadata.")?;
    let blk_size = metadata.blksize() as u32;

    Ok((blk_size, blk_size))
}

fn do_fcntl_lock(
    file: &File,
    path: &str,
    lockname: &str,
    flock: libc::flock,
    is_lock: bool,
) -> Result<()> {
    let err = match fcntl(file.as_raw_fd(), FcntlArg::F_SETLK(&flock)) {
        Err(e) => e,
        _ => return Ok(()),
    };

    if is_lock {
        bail!(
            "Failed to get {} on file: {}. Is it used more than once or \
            another process using the same file? Error: {}",
            lockname,
            path,
            err as i32,
        );
    } else {
        bail!(
            "Failed to release lock on file: {}. Error: {}",
            path,
            err as i32,
        );
    }
}

fn lock_or_unlock_file(
    file: &File,
    path: &str,
    lock_op: i16,
    lock_name: &str,
    is_lock: bool,
) -> Result<()> {
    let pid = getpid().as_raw();
    let mut flock = libc::flock {
        l_whence: libc::SEEK_SET as i16,
        l_len: 1,
        l_pid: pid,
        l_type: lock_op,
        l_start: 0,
    };

    for lock in FILE_LOCK_ALL {
        flock.l_start = (LOCK_PERM_BASE + lock) as i64;
        do_fcntl_lock(file, path, lock_name, flock, is_lock)?;
    }
    flock.l_start = (LOCK_SHARED_BASE + FILE_LOCK_WRITE) as i64;
    do_fcntl_lock(file, path, lock_name, flock, is_lock)?;

    Ok(())
}

pub fn lock_file(file: &File, path: &str, read_only: bool) -> Result<()> {
    let (lock_op, lock_name) = if read_only {
        (libc::F_RDLCK, "read lock")
    } else {
        (libc::F_WRLCK, "write lock")
    };
    lock_or_unlock_file(file, path, lock_op as i16, lock_name, true)
}

pub fn unlock_file(file: &File, path: &str) -> Result<()> {
    lock_or_unlock_file(file, path, libc::F_UNLCK as i16, "", false)
}

pub fn clear_file(path: String) -> Result<()> {
    if Path::new(&path).exists() {
        remove_file(&path)
            .with_context(|| format!("File {} exists, but failed to remove it.", &path))?;
    }

    Ok(())
}
