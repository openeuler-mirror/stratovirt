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

use std::{
    fs::File,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use anyhow::{bail, Result};

use machine_manager::config::DiskFormat;
use raw::RawDriver;
use util::aio::{Aio, Iovec, WriteZeroesState};

/// Callback function which is called when aio handle failed.
pub type BlockIoErrorCallback = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Clone)]
pub struct BlockProperty {
    pub format: DiskFormat,
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

    fn drain_request(&self);

    fn register_io_event(
        &mut self,
        device_broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()>;

    fn unregister_io_event(&mut self) -> Result<()>;
}

pub fn create_block_backend<T: Clone + 'static + Send + Sync>(
    file: File,
    aio: Aio<T>,
    prop: BlockProperty,
) -> Result<Arc<Mutex<dyn BlockDriverOps<T>>>> {
    match prop.format {
        DiskFormat::Raw => {
            let raw_file = RawDriver::new(file, aio, prop);
            Ok(Arc::new(Mutex::new(raw_file)))
        }
        DiskFormat::Qcow2 => {
            bail!("Disk format qcow2 not supported");
        }
    }
}
