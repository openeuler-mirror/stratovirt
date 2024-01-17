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

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, pci_args_check, M};
use crate::config::{
    check_arg_too_long, get_chardev_socket_path, memory_unit_conversion, CmdParser, ConfigCheck,
    ExBool, VmConfig, DEFAULT_VIRTQUEUE_SIZE, MAX_PATH_LENGTH, MAX_STRING_LENGTH, MAX_VIRTIO_QUEUE,
};
use util::aio::{aio_probe, AioEngine, WriteZeroesState};

const MAX_SERIAL_NUM: usize = 20;
const MAX_IOPS: u64 = 1_000_000;
const MAX_UNIT_ID: usize = 2;

// Seg_max = queue_size - 2. So, size of each virtqueue for virtio-blk should be larger than 2.
const MIN_QUEUE_SIZE_BLK: u16 = 2;
// Max size of each virtqueue for virtio-blk.
const MAX_QUEUE_SIZE_BLK: u16 = 1024;

// L2 Cache max size is 32M.
pub const MAX_L2_CACHE_SIZE: u64 = 32 * (1 << 20);
// Refcount table cache max size is 32M.
const MAX_REFTABLE_CACHE_SIZE: u64 = 32 * (1 << 20);

/// Represent a single drive backend file.
pub struct DriveFile {
    /// Drive id.
    pub id: String,
    /// The opened file.
    pub file: File,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlkDevConfig {
    pub id: String,
    pub path_on_host: String,
    pub read_only: bool,
    pub direct: bool,
    pub serial_num: Option<String>,
    pub iothread: Option<String>,
    pub iops: Option<u64>,
    pub queues: u16,
    pub boot_index: Option<u8>,
    pub chardev: Option<String>,
    pub socket_path: Option<String>,
    pub aio: AioEngine,
    pub queue_size: u16,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
    pub format: DiskFormat,
    pub l2_cache_size: Option<u64>,
    pub refcount_cache_size: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BootIndexInfo {
    pub boot_index: u8,
    pub id: String,
    pub dev_path: String,
}

impl Default for BlkDevConfig {
    fn default() -> Self {
        BlkDevConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            serial_num: None,
            iothread: None,
            iops: None,
            queues: 1,
            boot_index: None,
            chardev: None,
            socket_path: None,
            aio: AioEngine::Native,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            format: DiskFormat::Raw,
            l2_cache_size: None,
            refcount_cache_size: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiskFormat {
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

/// Config struct for `drive`.
/// Contains block device's attr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveConfig {
    pub id: String,
    pub path_on_host: String,
    pub read_only: bool,
    pub direct: bool,
    pub iops: Option<u64>,
    pub aio: AioEngine,
    pub media: String,
    pub discard: bool,
    pub write_zeroes: WriteZeroesState,
    pub format: DiskFormat,
    pub l2_cache_size: Option<u64>,
    pub refcount_cache_size: Option<u64>,
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            iops: None,
            aio: AioEngine::Native,
            media: "disk".to_string(),
            discard: false,
            write_zeroes: WriteZeroesState::Off,
            format: DiskFormat::Raw,
            l2_cache_size: None,
            refcount_cache_size: None,
        }
    }
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
        check_arg_too_long(&self.id, "Drive id")?;

        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "Drive device path".to_string(),
                MAX_PATH_LENGTH,
            )));
        }
        if self.iops > Some(MAX_IOPS) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "iops of block device".to_string(),
                0,
                true,
                MAX_IOPS,
                true,
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

        if !["disk", "cdrom"].contains(&self.media.as_str()) {
            return Err(anyhow!(ConfigError::InvalidParam(
                "media".to_string(),
                "media should be \"disk\" or \"cdrom\"".to_string(),
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

        Ok(())
    }
}

impl ConfigCheck for BlkDevConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "drive device id")?;
        if self.serial_num.is_some() && self.serial_num.as_ref().unwrap().len() > MAX_SERIAL_NUM {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "drive serial number".to_string(),
                MAX_SERIAL_NUM,
            )));
        }

        if self.iothread.is_some() && self.iothread.as_ref().unwrap().len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "iothread name".to_string(),
                MAX_STRING_LENGTH,
            )));
        }

        if self.queues < 1 || self.queues > MAX_VIRTIO_QUEUE as u16 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "number queues of block device".to_string(),
                1,
                true,
                MAX_VIRTIO_QUEUE as u64,
                true,
            )));
        }

        if self.queue_size <= MIN_QUEUE_SIZE_BLK || self.queue_size > MAX_QUEUE_SIZE_BLK {
            return Err(anyhow!(ConfigError::IllegalValue(
                "queue size of block device".to_string(),
                MIN_QUEUE_SIZE_BLK as u64,
                false,
                MAX_QUEUE_SIZE_BLK as u64,
                true
            )));
        }

        if self.queue_size & (self.queue_size - 1) != 0 {
            bail!("Queue size should be power of 2!");
        }

        let fake_drive = DriveConfig {
            path_on_host: self.path_on_host.clone(),
            direct: self.direct,
            iops: self.iops,
            aio: self.aio,
            ..Default::default()
        };
        fake_drive.check()?;
        #[cfg(not(test))]
        if self.chardev.is_none() {
            fake_drive.check_path()?;
        }

        Ok(())
    }
}

fn parse_drive(cmd_parser: CmdParser) -> Result<DriveConfig> {
    let mut drive = DriveConfig::default();
    if let Some(fmt) = cmd_parser.get_value::<DiskFormat>("format")? {
        drive.format = fmt;
    }

    drive.id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| ConfigError::FieldIsMissing("id".to_string(), "blk".to_string()))?;
    drive.path_on_host = cmd_parser
        .get_value::<String>("file")?
        .with_context(|| ConfigError::FieldIsMissing("file".to_string(), "blk".to_string()))?;

    if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
        drive.read_only = read_only.into();
    }
    if let Some(direct) = cmd_parser.get_value::<ExBool>("direct")? {
        drive.direct = direct.into();
    }
    drive.iops = cmd_parser.get_value::<u64>("throttling.iops-total")?;
    drive.aio = cmd_parser.get_value::<AioEngine>("aio")?.unwrap_or({
        if drive.direct {
            AioEngine::Native
        } else {
            AioEngine::Off
        }
    });
    drive.media = cmd_parser
        .get_value::<String>("media")?
        .unwrap_or_else(|| "disk".to_string());
    if let Some(discard) = cmd_parser.get_value::<ExBool>("discard")? {
        drive.discard = discard.into();
    }
    drive.write_zeroes = cmd_parser
        .get_value::<WriteZeroesState>("detect-zeroes")?
        .unwrap_or(WriteZeroesState::Off);

    if let Some(l2_cache) = cmd_parser.get_value::<String>("l2-cache-size")? {
        let sz = memory_unit_conversion(&l2_cache, M)
            .with_context(|| format!("Invalid l2 cache size: {}", l2_cache))?;
        drive.l2_cache_size = Some(sz);
    }
    if let Some(rc_cache) = cmd_parser.get_value::<String>("refcount-cache-size")? {
        let sz = memory_unit_conversion(&rc_cache, M)
            .with_context(|| format!("Invalid refcount cache size: {}", rc_cache))?;
        drive.refcount_cache_size = Some(sz);
    }

    drive.check()?;
    #[cfg(not(test))]
    drive.check_path()?;
    Ok(drive)
}

pub fn parse_blk(
    vm_config: &mut VmConfig,
    drive_config: &str,
    queues_auto: Option<u16>,
) -> Result<BlkDevConfig> {
    let mut cmd_parser = CmdParser::new("virtio-blk");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("drive")
        .push("bootindex")
        .push("serial")
        .push("iothread")
        .push("num-queues")
        .push("queue-size");

    cmd_parser.parse(drive_config)?;

    pci_args_check(&cmd_parser)?;

    let mut blkdevcfg = BlkDevConfig::default();
    if let Some(boot_index) = cmd_parser.get_value::<u8>("bootindex")? {
        blkdevcfg.boot_index = Some(boot_index);
    }

    let blkdrive = cmd_parser
        .get_value::<String>("drive")?
        .with_context(|| ConfigError::FieldIsMissing("drive".to_string(), "blk".to_string()))?;

    if let Some(iothread) = cmd_parser.get_value::<String>("iothread")? {
        blkdevcfg.iothread = Some(iothread);
    }

    if let Some(serial) = cmd_parser.get_value::<String>("serial")? {
        blkdevcfg.serial_num = Some(serial);
    }

    blkdevcfg.id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| "No id configured for blk device")?;

    if let Some(queues) = cmd_parser.get_value::<u16>("num-queues")? {
        blkdevcfg.queues = queues;
    } else if let Some(queues) = queues_auto {
        blkdevcfg.queues = queues;
    }

    if let Some(queue_size) = cmd_parser.get_value::<u16>("queue-size")? {
        blkdevcfg.queue_size = queue_size;
    }

    let drive_arg = &vm_config
        .drives
        .remove(&blkdrive)
        .with_context(|| "No drive configured matched for blk device")?;
    blkdevcfg.path_on_host = drive_arg.path_on_host.clone();
    blkdevcfg.read_only = drive_arg.read_only;
    blkdevcfg.direct = drive_arg.direct;
    blkdevcfg.iops = drive_arg.iops;
    blkdevcfg.aio = drive_arg.aio;
    blkdevcfg.discard = drive_arg.discard;
    blkdevcfg.write_zeroes = drive_arg.write_zeroes;
    blkdevcfg.format = drive_arg.format;
    blkdevcfg.l2_cache_size = drive_arg.l2_cache_size;
    blkdevcfg.refcount_cache_size = drive_arg.refcount_cache_size;
    blkdevcfg.check()?;
    Ok(blkdevcfg)
}

pub fn parse_vhost_user_blk(
    vm_config: &mut VmConfig,
    drive_config: &str,
    queues_auto: Option<u16>,
) -> Result<BlkDevConfig> {
    let mut cmd_parser = CmdParser::new("vhost-user-blk-pci");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("num-queues")
        .push("chardev")
        .push("queue-size")
        .push("bootindex");

    cmd_parser.parse(drive_config)?;

    pci_args_check(&cmd_parser)?;

    let mut blkdevcfg = BlkDevConfig::default();

    if let Some(boot_index) = cmd_parser.get_value::<u8>("bootindex")? {
        blkdevcfg.boot_index = Some(boot_index);
    }

    blkdevcfg.chardev = cmd_parser
        .get_value::<String>("chardev")?
        .map(Some)
        .with_context(|| {
            ConfigError::FieldIsMissing("chardev".to_string(), "vhost-user-blk-pci".to_string())
        })?;

    blkdevcfg.id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| "No id configured for blk device")?;

    if let Some(queues) = cmd_parser.get_value::<u16>("num-queues")? {
        blkdevcfg.queues = queues;
    } else if let Some(queues) = queues_auto {
        blkdevcfg.queues = queues;
    }

    if let Some(size) = cmd_parser.get_value::<u16>("queue-size")? {
        blkdevcfg.queue_size = size;
    }

    if let Some(chardev) = &blkdevcfg.chardev {
        blkdevcfg.socket_path = Some(get_chardev_socket_path(chardev, vm_config)?);
    }
    blkdevcfg.check()?;
    Ok(blkdevcfg)
}

/// Config struct for `pflash`.
/// Contains pflash device's attr.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PFlashConfig {
    pub path_on_host: String,
    pub read_only: bool,
    pub unit: usize,
}

impl ConfigCheck for PFlashConfig {
    fn check(&self) -> Result<()> {
        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "drive device path".to_string(),
                MAX_PATH_LENGTH,
            )));
        }

        if self.unit >= MAX_UNIT_ID {
            return Err(anyhow!(ConfigError::UnitIdError(
                "PFlash unit id".to_string(),
                self.unit,
                MAX_UNIT_ID - 1
            )));
        }
        Ok(())
    }
}

impl VmConfig {
    /// Add '-drive ...' drive config to `VmConfig`.
    pub fn add_drive(&mut self, drive_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser.push("if");

        cmd_parser.get_parameters(drive_config)?;
        let drive_type = cmd_parser
            .get_value::<String>("if")?
            .unwrap_or_else(|| "none".to_string());
        match drive_type.as_str() {
            "none" => {
                self.add_block_drive(drive_config)?;
            }
            "pflash" => {
                self.add_pflash(drive_config)?;
            }
            _ => {
                bail!("Unknow 'if' argument: {:?}", drive_type.as_str());
            }
        }

        Ok(())
    }

    /// Add block drive config to vm and return the added drive config.
    pub fn add_block_drive(&mut self, block_config: &str) -> Result<DriveConfig> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser
            .push("file")
            .push("id")
            .push("readonly")
            .push("direct")
            .push("format")
            .push("if")
            .push("throttling.iops-total")
            .push("aio")
            .push("media")
            .push("discard")
            .push("detect-zeroes")
            .push("format")
            .push("l2-cache-size")
            .push("refcount-cache-size");

        cmd_parser.parse(block_config)?;
        let drive_cfg = parse_drive(cmd_parser)?;
        self.add_drive_with_config(drive_cfg.clone())?;
        Ok(drive_cfg)
    }

    /// Add drive config to vm config.
    ///
    /// # Arguments
    ///
    /// * `drive_conf` - The drive config to be added to the vm.
    pub fn add_drive_with_config(&mut self, drive_conf: DriveConfig) -> Result<()> {
        let drive_id = drive_conf.id.clone();
        if self.drives.get(&drive_id).is_none() {
            self.drives.insert(drive_id, drive_conf);
        } else {
            bail!("Drive {} has been added", drive_id);
        }
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
    fn add_flashdev(&mut self, pflash: PFlashConfig) -> Result<()> {
        if self.pflashs.is_some() {
            for pf in self.pflashs.as_ref().unwrap() {
                if pf.unit == pflash.unit {
                    return Err(anyhow!(ConfigError::IdRepeat(
                        "pflash".to_string(),
                        pf.unit.to_string()
                    )));
                }
            }
            self.pflashs.as_mut().unwrap().push(pflash);
        } else {
            self.pflashs = Some(vec![pflash]);
        }
        Ok(())
    }

    /// Add '-pflash ...' pflash config to `VmConfig`.
    pub fn add_pflash(&mut self, pflash_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("pflash");
        cmd_parser
            .push("if")
            .push("file")
            .push("format")
            .push("readonly")
            .push("unit");

        cmd_parser.parse(pflash_config)?;

        let mut pflash = PFlashConfig::default();

        if let Some(format) = cmd_parser.get_value::<String>("format")? {
            if format.ne("raw") {
                bail!("Only \'raw\' type of pflash is supported");
            }
        }
        pflash.path_on_host = cmd_parser.get_value::<String>("file")?.with_context(|| {
            ConfigError::FieldIsMissing("file".to_string(), "pflash".to_string())
        })?;

        if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
            pflash.read_only = read_only.into();
        }

        pflash.unit = cmd_parser.get_value::<u64>("unit")?.with_context(|| {
            ConfigError::FieldIsMissing("unit".to_string(), "pflash".to_string())
        })? as usize;

        pflash.check()?;
        self.add_flashdev(pflash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::get_pci_bdf;

    #[test]
    fn test_drive_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive(
                "id=rootfs,file=/path/to/rootfs,readonly=off,direct=on,throttling.iops-total=200"
            )
            .is_ok());
        let blk_cfg_res = parse_blk(
            &mut vm_config,
            "virtio-blk-device,drive=rootfs,id=rootfs,iothread=iothread1,serial=111111,num-queues=4",
            None,
        );
        assert!(blk_cfg_res.is_ok());
        let blk_device_config = blk_cfg_res.unwrap();
        assert_eq!(blk_device_config.id, "rootfs");
        assert_eq!(blk_device_config.path_on_host, "/path/to/rootfs");
        assert_eq!(blk_device_config.direct, true);
        assert_eq!(blk_device_config.read_only, false);
        assert_eq!(blk_device_config.serial_num, Some(String::from("111111")));
        assert_eq!(blk_device_config.queues, 4);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,readonly=off,direct=on")
            .is_ok());
        let blk_cfg_res = parse_blk(
            &mut vm_config,
            "virtio-blk-device,drive=rootfs1,id=rootfs1,iothread=iothread1,iops=200,serial=111111",
            None,
        );
        assert!(blk_cfg_res.is_err()); // Can not find drive named "rootfs1".
    }

    #[test]
    fn test_pci_block_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,readonly=off,direct=on")
            .is_ok());
        let blk_cfg = "virtio-blk-pci,id=rootfs,bus=pcie.0,addr=0x1.0x2,drive=rootfs,serial=111111,num-queues=4";
        let blk_cfg_res = parse_blk(&mut vm_config, blk_cfg, None);
        assert!(blk_cfg_res.is_ok());
        let drive_configs = blk_cfg_res.unwrap();
        assert_eq!(drive_configs.id, "rootfs");
        assert_eq!(drive_configs.path_on_host, "/path/to/rootfs");
        assert_eq!(drive_configs.direct, true);
        assert_eq!(drive_configs.read_only, false);
        assert_eq!(drive_configs.serial_num, Some(String::from("111111")));
        assert_eq!(drive_configs.queues, 4);

        let pci_bdf = get_pci_bdf(blk_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));

        //  drive "rootfs" has been removed.
        let blk_cfg_res = parse_blk(&mut vm_config, blk_cfg, None);
        assert!(blk_cfg_res.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,readonly=off,direct=on")
            .is_ok());
        let blk_cfg =
            "virtio-blk-pci,id=blk1,bus=pcie.0,addr=0x1.0x2,drive=rootfs,multifunction=on";
        assert!(parse_blk(&mut vm_config, blk_cfg, None).is_ok());
    }

    #[test]
    fn test_pflash_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0")
            .is_ok());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 1);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit, 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.read_only, true);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,file=flash0.fd,unit=0,if=pflash")
            .is_ok());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,if=pflash,file=flash0.fd,unit=0")
            .is_ok());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=2")
            .is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0")
            .is_ok());
        assert!(vm_config
            .add_drive("if=pflash,file=flash1.fd,unit=1")
            .is_ok());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 2);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit, 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.read_only, true);
        let pflash_cfg = &pflash[1];
        assert_eq!(pflash_cfg.unit, 1);
        assert_eq!(pflash_cfg.path_on_host, "flash1.fd".to_string());
        assert_eq!(pflash_cfg.read_only, false);
    }

    #[test]
    fn test_drive_config_check() {
        let mut drive_conf = DriveConfig::default();
        for _ in 0..MAX_STRING_LENGTH {
            drive_conf.id += "A";
        }
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.id += "A";
        assert!(drive_conf.check().is_err());

        let mut drive_conf = DriveConfig::default();
        for _ in 0..MAX_PATH_LENGTH {
            drive_conf.path_on_host += "A";
        }
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.path_on_host += "A";
        assert!(drive_conf.check().is_err());

        let mut drive_conf = DriveConfig::default();
        drive_conf.iops = Some(MAX_IOPS);
        assert!(drive_conf.check().is_ok());

        let mut drive_conf = DriveConfig::default();
        drive_conf.iops = None;
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.iops = Some(MAX_IOPS + 1);
        assert!(drive_conf.check().is_err());
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
            .add_block_drive("id=rootfs,file=/path/to/rootfs,discard=ignore")
            .unwrap();
        assert_eq!(drive_conf.discard, false);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,discard=unmap")
            .unwrap();
        assert_eq!(drive_conf.discard, true);

        let mut vm_config = VmConfig::default();
        let ret = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,discard=invalid")
            .is_err();
        assert_eq!(ret, true);
    }

    #[test]
    fn test_drive_config_write_zeroes() {
        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=off")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::Off);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=on")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::On);

        let mut vm_config = VmConfig::default();
        let drive_conf = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=unmap")
            .unwrap();
        assert_eq!(drive_conf.write_zeroes, WriteZeroesState::Unmap);

        let mut vm_config = VmConfig::default();
        let ret = vm_config
            .add_block_drive("id=rootfs,file=/path/to/rootfs,detect-zeroes=invalid")
            .is_err();
        assert_eq!(ret, true);
    }
}
