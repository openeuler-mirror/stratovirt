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

extern crate serde;
extern crate serde_json;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_SERIAL_NUM: usize = 20;
const MAX_IOPS: u64 = 1_000_000;

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
    pub serial_num: Option<String>,
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            serial_num: None,
        }
    }
}

impl ConfigCheck for BlkDevConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if self.serial_num.is_some() && self.serial_num.as_ref().unwrap().len() > MAX_SERIAL_NUM {
            return Err(ErrorKind::StringLengthTooLong(
                "drive serial number".to_string(),
                MAX_SERIAL_NUM,
            )
            .into());
        }

        if self.iothread.is_some() && self.iothread.as_ref().unwrap().len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "iothread name".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.iops.is_some() && self.iops.unwrap() > MAX_IOPS {
            return Err(ErrorKind::IllegalValue(
                "iops of block device".to_string(),
                0,
                true,
                MAX_IOPS,
                true,
            )
            .into());
        }

        Ok(())
    }
}

pub fn parse_drive(cmd_parser: CmdParser) -> Result<DriveConfig> {
    let mut drive = DriveConfig::default();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        drive.id = id;
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "blk").into());
    }

    if let Some(file) = cmd_parser.get_value::<String>("file")? {
        drive.path_on_host = file;
    } else {
        return Err(ErrorKind::FieldIsMissing("file", "blk").into());
    }

    if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
        drive.read_only = read_only.into();
    }
    if let Some(direct) = cmd_parser.get_value::<ExBool>("direct")? {
        drive.direct = direct.into();
    }
    if let Some(serial) = cmd_parser.get_value::<String>("serial")? {
        drive.serial_num = Some(serial);
    }
    Ok(drive)
}

pub fn parse_blk(vm_config: &VmConfig, drive_config: &str) -> Result<BlkDevConfig> {
    let mut cmd_parser = CmdParser::new("virtio-blk-device");
    cmd_parser
        .push("")
        .push("drive")
        .push("iothread")
        .push("iops");

    cmd_parser.parse(drive_config)?;

    let mut blkdevcfg = BlkDevConfig::default();
    let blkdrive = if let Some(drive) = cmd_parser.get_value::<String>("drive")? {
        drive
    } else {
        return Err(ErrorKind::FieldIsMissing("drive", "blk").into());
    };

    if let Some(iothread) = cmd_parser.get_value::<String>("iothread")? {
        blkdevcfg.iothread = Some(iothread);
    }
    if let Some(iops) = cmd_parser.get_value::<String>("iops")? {
        blkdevcfg.iothread = Some(iops);
    }

    let drv_cfg = &vm_config.drives;
    if drv_cfg.is_none() {
        bail!("No drive configured for blk device");
    }

    if let Some(drive_arg) = drv_cfg.as_ref().unwrap().get(&blkdrive) {
        blkdevcfg.id = drive_arg.id.clone();
        blkdevcfg.path_on_host = drive_arg.path_on_host.clone();
        blkdevcfg.read_only = drive_arg.read_only;
        blkdevcfg.direct = drive_arg.direct;
        blkdevcfg.serial_num = drive_arg.serial_num.clone();
    } else {
        bail!("No drive configured matched for blk device");
    }
    blkdevcfg.check()?;
    Ok(blkdevcfg)
}

impl VmConfig {
    /// Add '-drive ...' drive config to `VmConfig`.
    pub fn add_drive(&mut self, drive_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser
            .push("file")
            .push("id")
            .push("readonly")
            .push("direct")
            .push("serial");

        cmd_parser.parse(drive_config)?;
        let drive_cfg = parse_drive(cmd_parser)?;
        if self.drives.is_none() {
            self.drives = Some(HashMap::new());
        }
        let drive_id = drive_cfg.id.clone();
        if self.drives.as_mut().unwrap().get(&drive_id).is_none() {
            self.drives.as_mut().unwrap().insert(drive_id, drive_cfg);
        } else {
            bail!("Drive {:?} has been added", drive_id);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drive_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,serial=111111,readonly=off,direct=on")
            .is_ok());
        let blk_cfg_res = parse_blk(
            &vm_config,
            "virtio-blk-device,drive=rootfs,iothread=iothread1,iops=200",
        );
        assert!(blk_cfg_res.is_ok());
        let blk_device_config = blk_cfg_res.unwrap();
        assert_eq!(blk_device_config.id, "rootfs");
        assert_eq!(blk_device_config.path_on_host, "/path/to/rootfs");
        assert_eq!(blk_device_config.direct, true);
        assert_eq!(blk_device_config.read_only, false);
        assert_eq!(blk_device_config.serial_num, Some(String::from("111111")));

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,serial=111111,readonly=off,direct=on")
            .is_ok());
        let blk_cfg_res = parse_blk(
            &vm_config,
            "virtio-blk-device,drive=rootfs1,iothread=iothread1,iops=200",
        );
        assert!(blk_cfg_res.is_err()); // Can not find drive named "rootfs1".
    }
}
