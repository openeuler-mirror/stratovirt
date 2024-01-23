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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Result};

use crate::ScsiBus::{aio_complete_cb, ScsiBus, ScsiCompleteCb};
use crate::{Device, DeviceBase};
use block_backend::{create_block_backend, BlockDriverOps, BlockProperty};
use machine_manager::config::{DriveFile, ScsiDevConfig, VmConfig};
use machine_manager::event_loop::EventLoop;
use util::aio::{Aio, AioEngine, WriteZeroesState};

/// SCSI DEVICE TYPES.
pub const SCSI_TYPE_DISK: u32 = 0x00;
pub const SCSI_TYPE_TAPE: u32 = 0x01;
pub const SCSI_TYPE_PRINTER: u32 = 0x02;
pub const SCSI_TYPE_PROCESSOR: u32 = 0x03;
pub const SCSI_TYPE_WORM: u32 = 0x04;
pub const SCSI_TYPE_ROM: u32 = 0x05;
pub const SCSI_TYPE_SCANNER: u32 = 0x06;
pub const SCSI_TYPE_MOD: u32 = 0x07;
pub const SCSI_TYPE_MEDIUM_CHANGER: u32 = 0x08;
pub const SCSI_TYPE_STORAGE_ARRAY: u32 = 0x0c;
pub const SCSI_TYPE_ENCLOSURE: u32 = 0x0d;
pub const SCSI_TYPE_RBC: u32 = 0x0e;
pub const SCSI_TYPE_OSD: u32 = 0x11;
pub const SCSI_TYPE_ZBC: u32 = 0x14;
pub const SCSI_TYPE_WLUN: u32 = 0x1e;
pub const SCSI_TYPE_NOT_PRESENT: u32 = 0x1f;
pub const SCSI_TYPE_INACTIVE: u32 = 0x20;
pub const SCSI_TYPE_NO_LUN: u32 = 0x7f;

pub const SCSI_DISK_F_REMOVABLE: u32 = 0;
pub const SCSI_DISK_F_DPOFUA: u32 = 1;

/// Used to compute the number of sectors.
pub const SECTOR_SHIFT: u8 = 9;
pub const DEFAULT_SECTOR_SIZE: u32 = 1_u32 << SECTOR_SHIFT;

/// Scsi disk's block size is 512 Bytes.
pub const SCSI_DISK_DEFAULT_BLOCK_SIZE_SHIFT: u32 = 9;
pub const SCSI_DISK_DEFAULT_BLOCK_SIZE: u32 = 1 << SCSI_DISK_DEFAULT_BLOCK_SIZE_SHIFT;

/// Scsi media device's block size is 2048 Bytes.
pub const SCSI_CDROM_DEFAULT_BLOCK_SIZE_SHIFT: u32 = 11;
pub const SCSI_CDROM_DEFAULT_BLOCK_SIZE: u32 = 1 << SCSI_CDROM_DEFAULT_BLOCK_SIZE_SHIFT;

#[derive(Clone, Default)]
pub struct ScsiDevState {
    /// Features which the scsi device supports.
    pub features: u32,
    /// Scsi device vendor identification.
    pub vendor: String,
    /// Scsi device product identification.
    pub product: String,
    /// Scsi device id.
    pub device_id: String,
    /// The standard version which the scsi device complies to.
    pub version: String,
    /// Scsi device serial number.
    pub serial: String,
}

impl ScsiDevState {
    fn new() -> Self {
        ScsiDevState {
            features: 0,
            vendor: "STRA".to_string(),
            product: "".to_string(),
            device_id: "".to_string(),
            version: "".to_string(),
            serial: "".to_string(),
        }
    }
}

impl Device for ScsiDevice {
    fn device_base(&self) -> &DeviceBase {
        &self.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base
    }
}

pub struct ScsiDevice {
    pub base: DeviceBase,
    /// Configuration of the scsi device.
    pub config: ScsiDevConfig,
    /// State of the scsi device.
    pub state: ScsiDevState,
    /// Block backend opened by scsi device.
    pub block_backend: Option<Arc<Mutex<dyn BlockDriverOps<ScsiCompleteCb>>>>,
    /// The align requirement of request(offset/len).
    pub req_align: u32,
    /// The align requirement of buffer(iova_base).
    pub buf_align: u32,
    /// Number of sectors of the image file.
    pub disk_sectors: u64,
    /// Scsi Device block size.
    pub block_size: u32,
    /// Scsi device type.
    pub scsi_type: u32,
    /// Scsi Bus attached to.
    pub parent_bus: Weak<Mutex<ScsiBus>>,
    /// Drive backend files.
    drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    /// Aio context.
    pub aio: Option<Arc<Mutex<Aio<ScsiCompleteCb>>>>,
}

// SAFETY: the devices attached in one scsi controller will process IO in the same thread.
unsafe impl Send for ScsiDevice {}
// SAFETY: The reason is same as above.
unsafe impl Sync for ScsiDevice {}

impl ScsiDevice {
    pub fn new(
        config: ScsiDevConfig,
        scsi_type: u32,
        drive_files: Arc<Mutex<HashMap<String, DriveFile>>>,
    ) -> ScsiDevice {
        ScsiDevice {
            base: DeviceBase::new(config.id.clone(), false),
            config,
            state: ScsiDevState::new(),
            block_backend: None,
            req_align: 1,
            buf_align: 1,
            disk_sectors: 0,
            block_size: 0,
            scsi_type,
            parent_bus: Weak::new(),
            drive_files,
            aio: None,
        }
    }

    pub fn realize(&mut self, iothread: Option<String>) -> Result<()> {
        match self.scsi_type {
            SCSI_TYPE_DISK => {
                self.block_size = SCSI_DISK_DEFAULT_BLOCK_SIZE;
                self.state.product = "STRA HARDDISK".to_string();
            }
            SCSI_TYPE_ROM => {
                self.block_size = SCSI_CDROM_DEFAULT_BLOCK_SIZE;
                self.state.product = "STRA CDROM".to_string();
            }
            _ => {
                bail!("Scsi type {} does not support now", self.scsi_type);
            }
        }

        if let Some(serial) = &self.config.serial {
            self.state.serial = serial.clone();
        }

        let drive_files = self.drive_files.lock().unwrap();
        // File path can not be empty string. And it has also been checked in CmdParser::parse.
        let file = VmConfig::fetch_drive_file(&drive_files, &self.config.path_on_host)?;

        let alignments = VmConfig::fetch_drive_align(&drive_files, &self.config.path_on_host)?;
        self.req_align = alignments.0;
        self.buf_align = alignments.1;
        let drive_id = VmConfig::get_drive_id(&drive_files, &self.config.path_on_host)?;

        let mut thread_pool = None;
        if self.config.aio_type != AioEngine::Off {
            thread_pool = Some(EventLoop::get_ctx(None).unwrap().thread_pool.clone());
        }
        let aio = Aio::new(Arc::new(aio_complete_cb), self.config.aio_type, thread_pool)?;
        let conf = BlockProperty {
            id: drive_id,
            format: self.config.format,
            iothread,
            direct: self.config.direct,
            req_align: self.req_align,
            buf_align: self.buf_align,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            l2_cache_size: self.config.l2_cache_size,
            refcount_cache_size: self.config.refcount_cache_size,
        };
        let backend = create_block_backend(file, aio, conf)?;
        let disk_size = backend.lock().unwrap().disk_size()?;
        self.block_backend = Some(backend);
        self.disk_sectors = disk_size >> SECTOR_SHIFT;

        Ok(())
    }
}
