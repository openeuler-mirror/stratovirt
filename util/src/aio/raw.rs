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

use super::Result;
use anyhow::bail;
use libc::{c_void, fdatasync, pread, pwrite};
use std::os::unix::io::RawFd;

pub fn raw_read(fd: RawFd, buf: u64, size: usize, offset: usize) -> Result<i64> {
    let mut ret;
    loop {
        ret = unsafe { pread(fd, buf as *mut c_void, size, offset as i64) as i64 };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 || ret as usize != size {
        bail!("Failed to pread for {}, size {} return {}.", fd, size, ret);
    }

    Ok(ret)
}

pub fn raw_write(fd: RawFd, buf: u64, size: usize, offset: usize) -> Result<i64> {
    let mut ret;
    loop {
        ret = unsafe { pwrite(fd, buf as *mut c_void, size, offset as i64) as i64 };
        if !(ret < 0 && (errno::errno().0 == libc::EINTR || errno::errno().0 == libc::EAGAIN)) {
            break;
        }
    }
    if ret < 0 || ret as usize != size {
        bail!("Failed to pwrite for {}, size {} return {}.", fd, size, ret);
    }

    Ok(ret)
}

pub fn raw_datasync(fd: RawFd) -> Result<i64> {
    let ret = unsafe { i64::from(fdatasync(fd)) };
    if ret < 0 {
        bail!("Failed to fdatasync for {}, return {}.", fd, ret);
    }

    Ok(ret)
}
