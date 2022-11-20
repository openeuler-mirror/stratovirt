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

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};

use crate::ScsiBus::ScsiBus;
use machine_manager::config::ScsiDevConfig;
use util::file::open_disk_file;

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
const SECTOR_SHIFT: u8 = 9;
/// Size of the dummy block device.
const DUMMY_IMG_SIZE: u64 = 0;
pub const DEFAULT_SECTOR_SIZE: u32 = 1_u32 << SECTOR_SHIFT;

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

#[derive(Clone)]
pub struct ScsiDevice {
    /// Configuration of the scsi device.
    pub config: ScsiDevConfig,
    /// State of the scsi device.
    pub state: ScsiDevState,
    /// Image file opened.
    pub disk_image: Option<Arc<File>>,
    /// Number of sectors of the image file.
    pub disk_sectors: u64,
    /// Scsi device type.
    pub scsi_type: u32,
    /// Scsi Bus attached to.
    pub parent_bus: Weak<Mutex<ScsiBus>>,
}

impl Default for ScsiDevice {
    fn default() -> Self {
        ScsiDevice {
            config: Default::default(),
            state: Default::default(),
            disk_image: None,
            disk_sectors: 0,
            scsi_type: SCSI_TYPE_DISK,
            parent_bus: Weak::new(),
        }
    }
}

impl ScsiDevice {
    pub fn new(config: ScsiDevConfig, scsi_type: u32) -> ScsiDevice {
        ScsiDevice {
            config,
            state: ScsiDevState::new(),
            disk_image: None,
            disk_sectors: 0,
            scsi_type,
            parent_bus: Weak::new(),
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        match self.scsi_type {
            SCSI_TYPE_DISK => {
                self.state.product = "STRA HARDDISK".to_string();
            }
            _ => {
                bail!("Scsi type {} does not support now", self.scsi_type);
            }
        }

        if let Some(serial) = &self.config.serial {
            self.state.serial = serial.clone();
        }
        let mut disk_size = DUMMY_IMG_SIZE;

        if !self.config.path_on_host.is_empty() {
            self.disk_image = None;

            let mut file = open_disk_file(
                &self.config.path_on_host,
                self.config.read_only,
                self.config.direct,
            )?;

            disk_size = file
                .seek(SeekFrom::End(0))
                .with_context(|| "Failed to seek the end for scsi device")?
                as u64;

            self.disk_image = Some(Arc::new(file));
        } else {
            self.disk_image = None;
        }

        self.disk_sectors = disk_size >> SECTOR_SHIFT;

        Ok(())
    }
}
