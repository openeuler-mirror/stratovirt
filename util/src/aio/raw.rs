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

use std::os::unix::io::RawFd;

use libc::{c_int, c_void, fdatasync, iovec, off_t, pread, preadv, pwrite, pwritev, size_t};
use log::error;
use vmm_sys_util::fallocate::{fallocate, FallocateMode};

use super::Iovec;

pub fn raw_read(fd: RawFd, buf: u64, size: usize, offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pread(
                fd as c_int,
                buf as *mut c_void,
                size as size_t,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (nix::errno::errno() == libc::EINTR || nix::errno::errno() == libc::EAGAIN))
        {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pread: buf{}, size{}, offset{}, errno{}.",
            buf,
            size,
            offset,
            nix::errno::errno()
        );
    }
    ret
}

pub fn raw_readv(fd: RawFd, iovec: &[Iovec], offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            preadv(
                fd as c_int,
                iovec.as_ptr() as *const iovec,
                iovec.len() as c_int,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (nix::errno::errno() == libc::EINTR || nix::errno::errno() == libc::EAGAIN))
        {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to preadv: offset{}, errno{}.",
            offset,
            nix::errno::errno(),
        );
    }
    ret
}

pub fn raw_write(fd: RawFd, buf: u64, size: usize, offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pwrite(
                fd as c_int,
                buf as *mut c_void,
                size as size_t,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (nix::errno::errno() == libc::EINTR || nix::errno::errno() == libc::EAGAIN))
        {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pwrite: buf{}, size{}, offset{}, errno{}.",
            buf,
            size,
            offset,
            nix::errno::errno(),
        );
    }
    ret
}

pub fn raw_writev(fd: RawFd, iovec: &[Iovec], offset: usize) -> i64 {
    let mut ret;
    loop {
        // SAFETY: fd and buf is valid.
        ret = unsafe {
            pwritev(
                fd as c_int,
                iovec.as_ptr() as *const iovec,
                iovec.len() as c_int,
                offset as off_t,
            ) as i64
        };
        if !(ret < 0 && (nix::errno::errno() == libc::EINTR || nix::errno::errno() == libc::EAGAIN))
        {
            break;
        }
    }
    if ret < 0 {
        error!(
            "Failed to pwritev: offset{}, errno{}.",
            offset,
            nix::errno::errno(),
        );
    }
    ret
}

pub fn raw_datasync(fd: RawFd) -> i64 {
    // SAFETY: fd is valid.
    let ret = unsafe { i64::from(fdatasync(fd)) };
    if ret < 0 {
        error!("Failed to fdatasync: errno{}.", nix::errno::errno());
    }
    ret
}

pub fn raw_discard(fd: RawFd, offset: usize, size: u64) -> i32 {
    let ret = do_fallocate(fd, FallocateMode::PunchHole, true, offset as u64, size);

    if ret < 0 && ret != -libc::ENOTSUP {
        error!("Failed to fallocate for {}, errno {}.", fd, ret);
    }
    ret
}

pub fn raw_write_zeroes(fd: RawFd, offset: usize, size: u64) -> i32 {
    let ret = do_fallocate(fd, FallocateMode::ZeroRange, false, offset as u64, size);

    if ret < 0 && ret != -libc::ENOTSUP {
        error!(
            "Failed to fallocate zero range for fd {}, errno {}.",
            fd, ret,
        );
    }
    ret
}

fn do_fallocate(
    fd: RawFd,
    fallocate_mode: FallocateMode,
    keep_size: bool,
    offset: u64,
    size: u64,
) -> i32 {
    let mut ret = 0;
    loop {
        let mode = match &fallocate_mode {
            FallocateMode::PunchHole => FallocateMode::PunchHole,
            FallocateMode::ZeroRange => FallocateMode::ZeroRange,
        };

        if let Err(e) = fallocate(&fd, mode, keep_size, offset, size) {
            ret = e.errno()
        };

        if ret == 0 {
            return ret;
        }

        if ret != libc::EINTR {
            break;
        }
    }

    if [libc::ENODEV, libc::ENOSYS, libc::EOPNOTSUPP, libc::ENOTTY].contains(&ret) {
        ret = libc::ENOTSUP;
    }

    -ret
}
