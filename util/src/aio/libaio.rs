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
#[derive(Copy, Clone)]
pub enum IoCmd {
    PREAD = 0,
    PWRITE = 1,
    FSYNC = 2,
    FDSYNC = 3,
    NOOP = 6,
    PREADV = 7,
    PWRITEV = 8,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Default)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
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

impl LibaioContext {
    pub fn new(max_size: i32) -> Result<Self> {
        let mut ctx = std::ptr::null_mut();

        let ret = unsafe { libc::syscall(libc::SYS_io_setup, max_size, &mut ctx) };
        if ret < 0 {
            bail!("Failed to setup aio context, return {}.", ret);
        }

        Ok(LibaioContext { ctx, max_size })
    }

    pub fn submit(&self, nr: i64, iocbp: &mut Vec<*mut IoCb>) -> Result<()> {
        let ret = unsafe { libc::syscall(libc::SYS_io_submit, self.ctx, nr, iocbp.as_ptr()) };
        if ret < 0 {
            bail!("Failed to submit aio, return {}.", ret);
        }

        Ok(())
    }

    #[allow(clippy::zero_ptr)]
    pub fn get_events(&self) -> Result<EventResult> {
        let mut events: Vec<_> = (0..self.max_size).map(|_| IoEvent::default()).collect();

        let evt_cnt = unsafe {
            libc::syscall(
                libc::SYS_io_getevents,
                self.ctx,
                0,
                i64::from(self.max_size),
                events.as_mut_ptr(),
                0 as *mut libc::timespec,
            )
        };
        if evt_cnt < 0 {
            bail!("Failed to get aio events, return {}.", evt_cnt);
        }

        Ok(EventResult {
            events,
            nr: evt_cnt as usize,
        })
    }
}
