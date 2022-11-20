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

use super::{AioContext, IoEvent, Result};
use anyhow::bail;
use kvm_bindings::__IncompleteArrayField;

pub const IOCB_FLAG_RESFD: u32 = 1;
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1;

#[derive(Debug, Clone)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default)]
pub struct IoCb {
    pub data: u64,
    pub key: u32,
    pub aio_reserved1: u32,
    pub aio_lio_opcode: u16,
    pub aio_reqprio: u16,
    pub aio_fildes: u32,
    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: u64,
    pub aio_reserved2: u64,
    pub aio_flags: u32,
    pub aio_resfd: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq)]
pub enum IoCmd {
    Pread = 0,
    Pwrite = 1,
    Fsync = 2,
    Fdsync = 3,
    Noop = 6,
    Preadv = 7,
    Pwritev = 8,
}

#[allow(non_camel_case_types)]
pub enum IoContext {}

pub struct EventResult {
    pub events: Vec<IoEvent>,
    pub nr: usize,
}

pub struct LibaioContext {
    pub ctx: *mut IoContext,
    pub max_size: i32,
}

impl Drop for LibaioContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { libc::syscall(libc::SYS_io_destroy, self.ctx) };
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct AioRing {
    id: u32,
    nr: u32,
    head: u32,
    tail: u32,

    magic: u32,
    compat_features: u32,
    incompat_features: u32,
    header_length: u32,

    io_events: __IncompleteArrayField<IoEvent>,
}

impl LibaioContext {
    pub fn new(max_size: i32) -> Result<Self> {
        let mut ctx = std::ptr::null_mut();

        let ret = unsafe { libc::syscall(libc::SYS_io_setup, max_size, &mut ctx) };
        if ret < 0 {
            bail!("Failed to setup aio context, return {}.", ret);
        }

        Ok(LibaioContext { ctx, max_size })
    }
}

/// Implements the AioContext for libaio.
impl AioContext for LibaioContext {
    /// Submit requests.
    fn submit(&mut self, nr: i64, iocbp: &mut [*mut IoCb]) -> Result<()> {
        let ret = unsafe { libc::syscall(libc::SYS_io_submit, self.ctx, nr, iocbp.as_ptr()) };
        if ret < 0 {
            bail!("Failed to submit aio, return {}.", ret);
        }

        Ok(())
    }

    /// Get the IO events.
    fn get_events(&mut self) -> (&[IoEvent], usize, usize) {
        let ring = self.ctx as *mut AioRing;
        let head = unsafe { (*ring).head };
        let tail = unsafe { (*ring).tail };
        let ring_nr = unsafe { (*ring).nr };
        let nr = if tail >= head {
            tail - head
        } else {
            ring_nr - head
        };
        unsafe { (*ring).head = (head + nr) % ring_nr };

        let io_events: &[IoEvent] = unsafe { (*ring).io_events.as_slice(ring_nr as usize) };

        (io_events, head as usize, (head + nr) as usize)
    }
}
