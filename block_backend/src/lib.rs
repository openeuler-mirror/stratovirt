// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod raw;

mod file;

use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;

use util::aio::{Iovec, WriteZeroesState};

/// Callback function which is called when aio handle failed.
pub type BlockIoErrorCallback = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Clone)]
pub struct BlockProperty {
    pub iothread: Option<String>,
    pub direct: bool,
    pub req_align: u32,
    pub buf_align: u32,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
}

pub trait BlockDriverOps<T: Clone>: Send {
    fn disk_size(&mut self) -> Result<u64>;

    fn read_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()>;

    fn write_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()>;

    fn datasync(&mut self, completecb: T) -> Result<()>;

    fn discard(&mut self, offset: usize, nbytes: u64, completecb: T) -> Result<()>;

    fn write_zeroes(
        &mut self,
        offset: usize,
        nbytes: u64,
        completecb: T,
        unmap: bool,
    ) -> Result<()>;

    fn flush_request(&mut self) -> Result<()>;

    fn register_io_event(
        &mut self,
        device_broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()>;

    fn unregister_io_event(&mut self) -> Result<()>;
}
