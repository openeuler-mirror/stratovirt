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
    os::unix::io::AsRawFd,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc, Mutex,
    },
};

use anyhow::{bail, Result};

use crate::{
    file::{CombineRequest, FileDriver},
    qcow2::is_aligned,
    BlockDriverOps, BlockIoErrorCallback, BlockProperty, BlockStatus, CheckResult, CreateOptions,
    SECTOR_SIZE,
};
use util::{
    aio::{get_iov_size, raw_write, Aio, Iovec},
    file::MAX_FILE_ALIGN,
    unix::host_page_size,
};

pub struct RawDriver<T: Clone + 'static> {
    driver: FileDriver<T>,
    status: Arc<Mutex<BlockStatus>>,
}

// SAFETY: Send and Sync is not auto-implemented for raw pointer type in Aio.
// We use Arc<Mutex<RawDriver<T>>> to allow used in multi-threading.
unsafe impl<T: Clone + 'static> Send for RawDriver<T> {}
// SAFETY: The reason is same as above.
unsafe impl<T: Clone + 'static> Sync for RawDriver<T> {}

impl<T: Clone + 'static> RawDriver<T> {
    pub fn new(file: File, aio: Aio<T>, prop: BlockProperty) -> Self {
        Self {
            driver: FileDriver::new(file, aio, prop),
            status: Arc::new(Mutex::new(BlockStatus::Init)),
        }
    }

    // Fill the first block with zero.
    // get_file_alignment() detects the alignment length by submitting IO to the first sector.
    // If this area is fallocated, misaligned IO will also return success, so we pre fill this area.
    pub fn alloc_first_block(&mut self, new_size: u64) -> Result<()> {
        let write_size = if new_size < MAX_FILE_ALIGN as u64 {
            SECTOR_SIZE
        } else {
            MAX_FILE_ALIGN as u64
        };
        let max_align = std::cmp::max(MAX_FILE_ALIGN as u64, host_page_size()) as usize;
        // SAFETY: allocate aligned memory and free it later.
        let align_buf = unsafe { libc::memalign(max_align, write_size as usize) };
        if align_buf.is_null() {
            bail!("Failed to alloc memory for write.");
        }

        let ret = raw_write(
            self.driver.file.as_raw_fd(),
            align_buf as u64,
            write_size as usize,
            0,
        );
        // SAFETY: the memory is allocated in this function.
        unsafe { libc::free(align_buf) };

        if ret < 0 {
            bail!("Failed to alloc first block, ret={}", ret);
        }
        Ok(())
    }
}

impl<T: Clone + Send + Sync> BlockDriverOps<T> for RawDriver<T> {
    fn create_image(&mut self, options: &CreateOptions) -> Result<String> {
        let raw_options = options.raw()?;
        self.resize(raw_options.img_size)?;
        let image_info = format!("fmt=raw size={}", raw_options.img_size);
        Ok(image_info)
    }

    fn check_image(&mut self, _res: &mut CheckResult, _quite: bool, _fix: u64) -> Result<()> {
        bail!("This image format does not support checks");
    }

    fn read_vectored(&mut self, iovec: Vec<Iovec>, offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(&iovec);
        trace::block_read_vectored(&self.driver.block_prop.id, offset, nbytes);
        self.driver.read_vectored(
            vec![CombineRequest::new(iovec, offset as u64, nbytes)],
            completecb,
        )
    }

    fn write_vectored(&mut self, iovec: Vec<Iovec>, offset: usize, completecb: T) -> Result<()> {
        let nbytes = get_iov_size(&iovec);
        trace::block_write_vectored(&self.driver.block_prop.id, offset, nbytes);
        self.driver.write_vectored(
            vec![CombineRequest::new(iovec, offset as u64, nbytes)],
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
        trace::block_write_zeroes(&self.driver.block_prop.id, offset, nbytes, unmap);
        self.driver.write_zeroes(
            vec![CombineRequest::new(Vec::new(), offset as u64, nbytes)],
            completecb,
            unmap,
        )
    }

    fn discard(&mut self, offset: usize, nbytes: u64, completecb: T) -> Result<()> {
        trace::block_discard(&self.driver.block_prop.id, offset, nbytes);
        self.driver.discard(
            vec![CombineRequest::new(Vec::new(), offset as u64, nbytes)],
            completecb,
        )
    }

    fn datasync(&mut self, completecb: T) -> Result<()> {
        trace::block_datasync(&self.driver.block_prop.id);
        self.driver.datasync(completecb)
    }

    fn flush_request(&mut self) -> Result<()> {
        trace::block_flush_request(&self.driver.block_prop.id);
        self.driver.flush_request()
    }

    fn resize(&mut self, new_size: u64) -> Result<()> {
        if !is_aligned(SECTOR_SIZE, new_size) {
            bail!(
                "The new size {} is not aligned to {}",
                new_size,
                SECTOR_SIZE
            );
        }

        let old_size = self.disk_size()?;
        if new_size == old_size {
            return Ok(());
        }

        let meta_data = self.driver.file.metadata()?;
        if !meta_data.is_file() {
            bail!("Cannot resize unregular file");
        }

        self.driver.extend_to_len(new_size)?;
        if old_size == 0 {
            self.alloc_first_block(new_size)?;
        }

        Ok(())
    }

    fn drain_request(&self) {
        trace::block_drain_request(&self.driver.block_prop.id);
        self.driver.drain_request();
    }

    fn get_inflight(&self) -> Arc<AtomicU64> {
        self.driver.incomplete.clone()
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
