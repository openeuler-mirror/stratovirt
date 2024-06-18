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

use std::fs::{metadata, File};
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use log::error;
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, parse_size, valid_id, valid_path};
use crate::config::{parse_bool, str_slip_to_clap, ConfigCheck, VmConfig, MAX_STRING_LENGTH};
use util::aio::{aio_probe, AioEngine, WriteZeroesState};

const MAX_IOPS: u64 = 1_000_000;
const MAX_UNIT_ID: usize = 2;

// L2 Cache max size is 32M.
pub const MAX_L2_CACHE_SIZE: u64 = 32 * (1 << 20);
// Refcount table cache max size is 32M.
const MAX_REFTABLE_CACHE_SIZE: u64 = 32 * (1 << 20);

/// Represent a single drive backend file.
pub struct DriveFile {
    /// Drive id.
    pub id: String,
    /// The opened file.
    pub file: Arc<File>,
    /// The num of drives share same file.
    pub count: u32,
    /// File path.
    pub path: String,
    /// File is read only or not.
    pub read_only: bool,
    /// File lock status.
    pub locked: bool,
    /// The align requirement of request(offset/len).
    pub req_align: u32,
    /// The align requirement of buffer(iova_base).
    pub buf_align: u32,
}

#[derive(Debug, Clone)]
pub struct BootIndexInfo {
    pub boot_index: u8,
    pub id: String,
    pub dev_path: String,
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiskFormat {
    #[default]
    Raw,
    Qcow2,
}

impl FromStr for DiskFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "raw" => Ok(DiskFormat::Raw),
            "qcow2" => Ok(DiskFormat::Qcow2),
            _ => Err(anyhow!("Unknown format type")),
        }
    }
}

impl ToString for DiskFormat {
    fn to_string(&self) -> String {
        match *self {
            DiskFormat::Raw => "raw".to_string(),
            DiskFormat::Qcow2 => "qcow2".to_string(),
        }
    }
}

fn valid_l2_cache_size(s: &str) -> Result<u64> {
    let size = parse_size(s)?;
    if size > MAX_L2_CACHE_SIZE {
        return Err(anyhow!(ConfigError::IllegalValue(
            "l2-cache-size".to_string(),
            0,
            true,
            MAX_L2_CACHE_SIZE,
            true
        )));
    }
    Ok(size)
}

fn valid_refcount_cache_size(s: &str) -> Result<u64> {
    let size = parse_size(s)?;
    if size > MAX_REFTABLE_CACHE_SIZE {
        return Err(anyhow!(ConfigError::IllegalValue(
            "refcount-cache-size".to_string(),
            0,
            true,
            MAX_REFTABLE_CACHE_SIZE,
            true
        )));
    }
    Ok(size)
}

/// Config struct for `drive`, including `block drive` and `pflash drive`.
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct DriveConfig {
    #[arg(long, default_value = "")]
    pub id: String,
    #[arg(long, alias = "if", default_value = "none", value_parser = ["none", "pflash"])]
    pub drive_type: String,
    #[arg(long, value_parser = clap::value_parser!(u8).range(..MAX_UNIT_ID as i64))]
    pub unit: Option<u8>,
    #[arg(long, alias = "file", value_parser = valid_path)]
    pub path_on_host: String,
    #[arg(long, default_value = "off", value_parser = parse_bool, action = ArgAction::Append)]
    pub readonly: bool,
    #[arg(long, default_value = "true", value_parser = parse_bool, action = ArgAction::Append)]
    pub direct: bool,
    #[arg(long, alias = "throttling.iops-total", value_parser = clap::value_parser!(u64).range(..=MAX_IOPS as u64))]
    pub iops: Option<u64>,
    #[arg(
        long,
        default_value = "native",
        default_value_if("direct", "false", "off"),
        default_value_if("direct", "off", "off")
    )]
    pub aio: AioEngine,
    #[arg(long, default_value = "disk", value_parser = ["disk", "cdrom"])]
    pub media: String,
    #[arg(long, default_value = "ignore", value_parser = parse_bool, action = ArgAction::Append)]
    pub discard: bool,
    #[arg(long, alias = "detect-zeroes", default_value = "off")]
    pub write_zeroes: WriteZeroesState,
    #[arg(long, default_value = "raw")]
    pub format: DiskFormat,
    #[arg(long, value_parser = valid_l2_cache_size)]
    pub l2_cache_size: Option<u64>,
    #[arg(long, value_parser = valid_refcount_cache_size)]
    pub refcount_cache_size: Option<u64>,
}

impl DriveConfig {
    /// Check whether the drive file path on the host is valid.
    pub fn check_path(&self) -> Result<()> {
        let blk = Path::new(&self.path_on_host);
        match metadata(blk) {
            Ok(meta) => {
                if ((meta.st_mode() & libc::S_IFREG) != libc::S_IFREG)
                    && ((meta.st_mode() & libc::S_IFBLK) != libc::S_IFBLK)
                {
                    return Err(anyhow!(ConfigError::UnRegularFileOrBlk(
                        self.path_on_host.clone()
                    )));
                }
            }
            Err(e) => {
                error!("Failed to check the drive metadata: {:?}", e);
                return Err(anyhow!(ConfigError::NoMetadata(
                    self.path_on_host.clone(),
                    e.to_string(),
                )));
            }
        }
        if let Some(file_name) = blk.file_name() {
            if file_name.len() > MAX_STRING_LENGTH {
                return Err(anyhow!(ConfigError::StringLengthTooLong(
                    "File name".to_string(),
                    MAX_STRING_LENGTH,
                )));
            }
        } else {
            error!("Failed to check the drive file name");
            return Err(anyhow!(ConfigError::InvalidParam(
                self.path_on_host.clone(),
                "file".to_string(),
            )));
        }
        Ok(())
    }
}

impl ConfigCheck for DriveConfig {
    fn check(&self) -> Result<()> {
        if self.drive_type == "pflash" {
            self.unit.with_context(|| {
                ConfigError::FieldIsMissing("unit".to_string(), "pflash".to_string())
            })?;
            if self.format.to_string() != "raw" {
                bail!("Only \'raw\' type of pflash is supported");
            }
        } else {
            if self.id.is_empty() {
                return Err(anyhow!(ConfigError::FieldIsMissing(
                    "id".to_string(),
                    "blk".to_string()
                )));
            }
            valid_id(&self.id)?;
            valid_path(&self.path_on_host)?;
            if self.iops > Some(MAX_IOPS) {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "iops of block device".to_string(),
                    0,
                    true,
                    MAX_IOPS,
                    true,
                )));
            }
            if self.l2_cache_size > Some(MAX_L2_CACHE_SIZE) {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "l2-cache-size".to_string(),
                    0,
                    true,
                    MAX_L2_CACHE_SIZE,
                    true
                )));
            }
            if self.refcount_cache_size > Some(MAX_REFTABLE_CACHE_SIZE) {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "refcount-cache-size".to_string(),
                    0,
                    true,
                    MAX_REFTABLE_CACHE_SIZE,
                    true
                )));
            }

            if self.aio != AioEngine::Off {
                if self.aio == AioEngine::Native && !self.direct {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        "aio".to_string(),
                        "native aio type should be used with \"direct\" on".to_string(),
                    )));
                }
                aio_probe(self.aio)?;
            } else if self.direct {
                return Err(anyhow!(ConfigError::InvalidParam(
                    "aio".to_string(),
                    "low performance expected when use sync io with \"direct\" on".to_string(),
                )));
            }
        }

        #[cfg(not(test))]
        self.check_path()?;

        Ok(())
    }
}

impl VmConfig {
    /// Add '-drive ...' drive config to `VmConfig`, including `block drive` and `pflash drive`.
    pub fn add_drive(&mut self, drive_config: &str) -> Result<DriveConfig> {
        let drive_cfg = DriveConfig::try_parse_from(str_slip_to_clap(drive_config, false, false))?;
        drive_cfg.check()?;
        match drive_cfg.drive_type.as_str() {
            "none" => {
                self.add_drive_with_config(drive_cfg.clone())?;
            }
            "pflash" => {
                self.add_flashdev(drive_cfg.clone())?;
            }
            _ => {
                bail!("Unknow 'if' argument: {:?}", &drive_cfg.drive_type);
            }
        }

        Ok(drive_cfg)
    }

    /// Add drive config to vm config.
    ///
    /// # Arguments
    ///
    /// * `drive_conf` - The drive config to be added to the vm.
    pub fn add_drive_with_config(&mut self, drive_conf: DriveConfig) -> Result<()> {
        let drive_id = drive_conf.id.clone();
        if self.drives.get(&drive_id).is_some() {
            bail!("Drive {} has been added", drive_id);
        }
        self.drives.insert(drive_id, drive_conf);
        Ok(())
    }

    /// Delete drive config in vm config by id.
    ///
    /// # Arguments
    ///
    /// * `drive_id` - Drive id.
    pub fn del_drive_by_id(&mut self, drive_id: &str) -> Result<String> {
        if self.drives.get(drive_id).is_some() {
            Ok(self.drives.remove(drive_id).unwrap().path_on_host)
        } else {
            bail!("Drive {} not found", drive_id);
        }
    }

    /// Add new flash device to `VmConfig`.
    fn add_flashdev(&mut self, pflash: DriveConfig) -> Result<()> {
        if self.pflashs.is_some() {
            for pf in self.pflashs.as_ref().unwrap() {
                if pf.unit.unwrap() == pflash.unit.unwrap() {
                    return Err(anyhow!(ConfigError::IdRepeat(
                        "pflash".to_string(),
                        pf.unit.unwrap().to_string()
                    )));
                }
            }
            self.pflashs.as_mut().unwrap().push(pflash);
        } else {
            self.pflashs = Some(vec![pflash]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pflash_drive_config_cmdline_parser() {
        // Test1: Right.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0,format=raw")
            .is_ok());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 1);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit.unwrap(), 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.readonly, true);

        // Test2: Change parameters sequence.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,file=flash0.fd,unit=0,if=pflash")
            .is_ok());
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,if=pflash,file=flash0.fd,unit=0")
            .is_ok());

        // Test3: Add duplicate pflash.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0")
            .is_ok());
        assert!(vm_config
            .add_drive("if=pflash,file=flash1.fd,unit=1")
            .is_ok());
        assert!(vm_config
            .add_drive("if=pflash,file=flash1.fd,unit=1")
            .is_err());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 2);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit.unwrap(), 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.readonly, true);
        let pflash_cfg = &pflash[1];
        assert_eq!(pflash_cfg.unit.unwrap(), 1);
        assert_eq!(pflash_cfg.path_on_host, "flash1.fd".to_string());
        assert_eq!(pflash_cfg.readonly, false);

        // Test4: Illegal parameters unit/format.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=2")
            .is_err());
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0,format=qcow2")
            .is_err());

        // Test5: Missing parameters file/unit.
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_drive("if=pflash,readonly=on,unit=2").is_err());
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd")
            .is_err());
    }

    #[test]
    fn test_block_drive_config_cmdline_parser() {
        // Test1: Right.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=qcow2,readonly=off,direct=on,throttling.iops-total=200,discard=unmap,detect-zeroes=unmap")
            .is_ok());
        assert!(vm_config.drives.len() == 1);
        let drive_cfg = &vm_config.drives.remove("rootfs").unwrap();

        assert_eq!(drive_cfg.id, "rootfs");
        assert_eq!(drive_cfg.path_on_host, "/path/to/rootfs");
        assert_eq!(drive_cfg.format.to_string(), "qcow2");
        assert_eq!(drive_cfg.readonly, false);
        assert_eq!(drive_cfg.direct, true);
        assert_eq!(drive_cfg.iops.unwrap(), 200);
        assert_eq!(drive_cfg.discard, true);
        assert_eq!(
            drive_cfg.write_zeroes,
            WriteZeroesState::from_str("unmap").unwrap()
        );

        // Test2: Change parameters sequence.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("throttling.iops-total=200,file=/path/to/rootfs,format=qcow2,id=rootfs,readonly=off,direct=on,discard=unmap,detect-zeroes=unmap")
            .is_ok());

        // Test3: Add duplicate block drive config.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=qcow2,readonly=off,direct=on")
            .is_ok());
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=qcow2,readonly=off,direct=on")
            .is_err());
        let drive_cfg = &vm_config.drives.remove("rootfs");
        assert!(drive_cfg.is_some());

        // Test4: Illegal parameters.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=vhdx")
            .is_err());
        assert!(vm_config
            .add_drive("id=rootfs,if=illegal,file=/path/to/rootfs,format=vhdx")
            .is_err());
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=raw,throttling.iops-total=1000001")
            .is_err());
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=raw,media=illegal")
            .is_err());
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,format=raw,detect-zeroes=illegal")
            .is_err());

        // Test5: Missing parameters id/file.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("file=/path/to/rootfs,format=qcow2,readonly=off,direct=on,throttling.iops-total=200")
            .is_err());
        assert!(vm_config
            .add_drive("id=rootfs,format=qcow2,readonly=off,direct=on,throttling.iops-total=200")
            .is_err());
    }

    #[test]
    fn test_add_drive_with_config() {
        let mut vm_config = VmConfig::default();

        let drive_list = ["drive-0", "drive-1", "drive-2"];
        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.add_drive_with_config(drive_conf).is_ok());

            let drive = vm_config.drives.get(*id).unwrap();
            assert_eq!(*id, drive.id);
        }

        let mut drive_conf = DriveConfig::default();
        drive_conf.id = String::from("drive-0");
        assert!(vm_config.add_drive_with_config(drive_conf).is_err());
    }

    #[test]
    fn test_del_drive_by_id() {
        let mut vm_config = VmConfig::default();

        assert!(vm_config.del_drive_by_id("drive-0").is_err());

        let drive_list = ["drive-0", "drive-1", "drive-2"];
        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.add_drive_with_config(drive_conf).is_ok());
        }

        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.drives.get(*id).is_some());
            assert!(vm_config.del_drive_by_id(*id).is_ok());
            assert!(vm_config.drives.get(*id).is_none());
        }
    }

    #[test]
    fn test_drive_config_discard() {
        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,discard=ignore")
            .unwrap();
        assert_eq!(drive_conf.discard, false);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,discard=unmap")
            .unwrap();
        assert_eq!(drive_conf.discard, true);

        let mut vm_config = VmConfig::default();
        let ret = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,discard=invalid")
            .is_err();
        assert_eq!(ret, true);
    }

    #[test]
    fn test_drive_config_write_zeroes() {
        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=off")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::Off);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=on")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::On);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=unmap")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::Unmap);

        let mut vm_config = VmConfig::default();
        let ret = vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=invalid")
            .is_err();
        assert_eq!(ret, true);
    }
}
