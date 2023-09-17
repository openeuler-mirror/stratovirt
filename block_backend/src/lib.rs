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

pub mod file;
pub mod qcow2;
pub mod raw;

use std::{
    fs::File,
    sync::{atomic::AtomicBool, Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use log::{error, info};

use machine_manager::{
    config::DiskFormat,
    temp_cleaner::{ExitNotifier, TempCleaner},
};
use qcow2::{qcow2_flush_metadata, Qcow2Driver, QCOW2_LIST};
use raw::RawDriver;
use util::aio::{Aio, Iovec, WriteZeroesState};

/// Callback function which is called when aio handle failed.
pub type BlockIoErrorCallback = Arc<dyn Fn() + Send + Sync>;

pub const SECTOR_BITS: u64 = 9;
pub const SECTOR_SIZE: u64 = 1 << SECTOR_BITS;
pub const CLUSTER_SIZE_MIN: u64 = 1 << 9;
pub const CLUSTER_SIZE_MAX: u64 = 1 << 21;
pub const NO_FIX: u64 = 0;
pub const FIX_LEAKS: u64 = 1;
pub const FIX_ERRORS: u64 = 2;

const DEFAULT_QCOW2_VERSION: u32 = 3;
const DEFAULT_CLUSTER_BITS: u64 = 16;
const DEFAULT_CLUSTER_SIZE: u64 = 1 << DEFAULT_CLUSTER_BITS;
const DEFAULT_REFCOUNT_BITS: u64 = 16;
const MAX_REFCOUNT_BITS: u64 = 64;

#[macro_export]
macro_rules! output_msg {
    ($lvl:expr, $($arg:tt)*) => {
        if !$lvl {
            println!($($arg)*)
        }
    }
}

pub struct RawCreateOptions {
    pub path: String,
    pub img_size: u64,
}

pub struct Qcow2CreateOptions {
    pub path: String,
    pub img_size: u64,
    pub version: u32,
    pub cluster_size: u64,
    pub refcount_bits: u64,
}

#[derive(Default)]
pub struct CreateOptions {
    pub path: String,
    pub img_size: u64,
    pub cluster_size: Option<u64>,
    pub refcount_bits: Option<u64>,
    pub conf: BlockProperty,
}

#[derive(Default, Clone, Copy)]
pub struct DiskFragments {
    pub allocated_clusters: u64,
    pub total_clusters: u64,
    pub fragments: u64,
    pub compressed_clusters: u64,
}

#[derive(Default, Clone, Copy)]
pub struct CheckResult {
    /// Number of leaked clusters.
    pub leaks: i32,
    /// Number of leaked clusters that have been fixed.
    pub leaks_fixed: i32,
    /// Number of corruptions clusters.
    pub corruptions: i32,
    /// Number of corruptions clusters that have been fixed.
    pub corruptions_fixed: i32,
    /// File length of virtual disk.
    pub image_end_offset: u64,
    /// Whether the refcount block table needs to be rebuilt.
    pub need_rebuild: bool,
    /// Total number of errors during the check.
    pub err_num: u64,
    /// Statistics information for clusters of virtual disk.
    pub disk_frag: DiskFragments,
}

pub enum BlockStatus {
    Init,
    NormalIO,
    Snapshot,
}

#[derive(Debug, Clone)]
pub struct BlockProperty {
    pub id: String,
    pub format: DiskFormat,
    pub iothread: Option<String>,
    pub direct: bool,
    pub req_align: u32,
    pub buf_align: u32,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
    pub l2_cache_size: Option<u64>,
    pub refcount_cache_size: Option<u64>,
}

impl Default for BlockProperty {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            format: DiskFormat::Raw,
            iothread: None,
            direct: false,
            req_align: 1_u32,
            buf_align: 1_u32,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            l2_cache_size: None,
            refcount_cache_size: None,
        }
    }
}

pub trait BlockDriverOps<T: Clone>: Send {
    fn create_image(&mut self, options: &CreateOptions) -> Result<String>;

    fn check_image(&mut self, res: &mut CheckResult, quite: bool, fix: u64) -> Result<()>;

    fn disk_size(&mut self) -> Result<u64>;

    fn read_vectored(&mut self, iovec: Vec<Iovec>, offset: usize, completecb: T) -> Result<()>;

    fn write_vectored(&mut self, iovec: Vec<Iovec>, offset: usize, completecb: T) -> Result<()>;

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

    fn get_status(&mut self) -> Arc<Mutex<BlockStatus>>;
}

pub fn create_block_backend<T: Clone + 'static + Send + Sync>(
    file: File,
    aio: Aio<T>,
    prop: BlockProperty,
) -> Result<Arc<Mutex<dyn BlockDriverOps<T>>>> {
    match prop.format {
        DiskFormat::Raw => {
            let mut raw_file = RawDriver::new(file, aio, prop.clone());
            let file_size = raw_file.disk_size()?;
            if file_size & (prop.req_align as u64 - 1) != 0 {
                bail!("The size of raw file is not aligned to {}.", prop.req_align);
            }
            Ok(Arc::new(Mutex::new(raw_file)))
        }
        DiskFormat::Qcow2 => {
            let mut qcow2 = Qcow2Driver::new(file, aio, prop.clone())
                .with_context(|| "Failed to create qcow2 driver")?;
            let file_size = qcow2.disk_size()?;
            if file_size & (prop.req_align as u64 - 1) != 0 {
                bail!(
                    "The size of qcow2 file is not aligned to {}.",
                    prop.req_align
                );
            }
            let new_qcow2 = Arc::new(Mutex::new(qcow2));
            QCOW2_LIST
                .lock()
                .unwrap()
                .insert(prop.id.clone(), new_qcow2.clone());
            let cloned_qcow2 = Arc::downgrade(&new_qcow2);
            // NOTE: we can drain request when request in io thread.
            let drain = prop.iothread.is_some();
            let cloned_drive_id = prop.id.clone();
            let exit_notifier = Arc::new(move || {
                if let Some(qcow2) = cloned_qcow2.upgrade() {
                    let mut locked_qcow2 = qcow2.lock().unwrap();
                    info!("clean up qcow2 {:?} resources.", cloned_drive_id);
                    if let Err(e) = locked_qcow2.flush() {
                        error!("Failed to flush qcow2 {:?}", e);
                    }
                    if drain {
                        locked_qcow2.drain_request();
                    }
                }
            }) as Arc<ExitNotifier>;
            TempCleaner::add_exit_notifier(prop.id, exit_notifier);

            // Add timer for flushing qcow2 metadata.
            qcow2_flush_metadata(Arc::downgrade(&new_qcow2));

            Ok(new_qcow2)
        }
    }
}

pub fn remove_block_backend(id: &str) {
    QCOW2_LIST.lock().unwrap().remove(id);
}
