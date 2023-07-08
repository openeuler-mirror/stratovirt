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

use std::{
    fs::File,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use anyhow::Result;

use crate::{
    file::{CombineRequest, FileDriver},
    BlockDriverOps, BlockIoErrorCallback, BlockProperty, BlockStatus,
};
use util::aio::{get_iov_size, Aio, Iovec};

pub struct RawDriver<T: Clone + 'static> {
    driver: FileDriver<T>,
    status: Arc<Mutex<BlockStatus>>,
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type in Aio.
// We use Arc<Mutex<RawDriver<T>>> to allow used in multi-threading.
unsafe impl<T: Clone + 'static> Send for RawDriver<T> {}
unsafe impl<T: Clone + 'static> Sync for RawDriver<T> {}

impl<T: Clone + 'static> RawDriver<T> {
    pub fn new(file: File, aio: Aio<T>, prop: BlockProperty) -> Self {
        Self {
            driver: FileDriver::new(file, aio, prop),
            status: Arc::new(Mutex::new(BlockStatus::Init)),
        }
    }
}

impl<T: Clone + Send + Sync> BlockDriverOps<T> for RawDriver<T> {
    fn read_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(iovec);
        self.driver.read_vectored(
            vec![CombineRequest::new(iovec.to_vec(), offset as u64, nbytes)],
            completecb,
        )
    }

    fn write_vectored(&mut self, iovec: &[Iovec], offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(iovec);
        self.driver.write_vectored(
            vec![CombineRequest::new(iovec.to_vec(), offset as u64, nbytes)],
            completecb,
        )
    }

    fn write_zeroes(
        &mut self,
        offset: usize,
        nbytes: u64,
        completecb: T,
        unmap: bool,
    ) -> Result<()> {
        self.driver.write_zeroes(
            vec![CombineRequest::new(Vec::new(), offset as u64, nbytes)],
            completecb,
            unmap,
        )
    }

    fn discard(&mut self, offset: usize, nbytes: u64, completecb: T) -> Result<()> {
        self.driver.discard(
            vec![CombineRequest::new(Vec::new(), offset as u64, nbytes)],
            completecb,
        )
    }

    fn datasync(&mut self, completecb: T) -> Result<()> {
        self.driver.datasync(completecb)
    }

    fn flush_request(&mut self) -> Result<()> {
        self.driver.flush_request()
    }

    fn drain_request(&self) {
        self.driver.drain_request();
    }

    fn register_io_event(
        &mut self,
        broken: Arc<AtomicBool>,
        error_cb: BlockIoErrorCallback,
    ) -> Result<()> {
        self.driver.register_io_event(broken, error_cb)
    }

    fn unregister_io_event(&mut self) -> Result<()> {
        self.driver.unregister_io_event()
    }

    fn disk_size(&mut self) -> Result<u64> {
        self.driver.disk_size()
    }

    fn get_status(&mut self) -> Arc<Mutex<BlockStatus>> {
        self.status.clone()
    }
}
