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

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_SERIAL_NUM: usize = 20;
const MAX_IOPS: u64 = 1_000_000;

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
    pub iothread: Option<String>,
    pub iops: Option<u64>,
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
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

impl ConfigCheck for DriveConfig {
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

impl VmConfig {
    /// Add '-drive ...' drive config to `VmConfig`.
    pub fn add_drive(&mut self, drive_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser
            .push("file")
            .push("id")
            .push("readonly")
            .push("direct")
            .push("serial")
            .push("iothread")
            .push("iops");

        cmd_parser.parse(drive_config)?;

        let mut drive = DriveConfig::default();
        if let Some(drive_path) = cmd_parser.get_value::<String>("file")? {
            drive.path_on_host = drive_path;
        } else {
            return Err(ErrorKind::FieldIsMissing("file", "drive").into());
        }
        if let Some(drive_id) = cmd_parser.get_value::<String>("id")? {
            drive.id = drive_id;
        } else {
            return Err(ErrorKind::FieldIsMissing("id", "drive").into());
        }
        if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
            drive.read_only = read_only.into();
        }
        if let Some(direct) = cmd_parser.get_value::<ExBool>("direct")? {
            drive.direct = direct.into();
        }
        drive.serial_num = cmd_parser.get_value::<String>("serial")?;
        drive.iothread = cmd_parser.get_value::<String>("iothread")?;
        drive.iops = cmd_parser.get_value::<u64>("iops")?;

        if self.drives.is_some() {
            for d in self.drives.as_ref().unwrap() {
                if d.id == drive.id {
                    return Err(ErrorKind::IdRepeat("drive".to_string(), d.id.to_string()).into());
                }
            }
            self.drives.as_mut().unwrap().push(drive);
        } else {
            self.drives = Some(vec![drive]);
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
        let configs = vm_config.drives.clone();
        assert!(configs.is_some());
        let mut drive_configs = configs.unwrap();
        assert_eq!(drive_configs[0].id, "rootfs");
        assert_eq!(drive_configs[0].path_on_host, "/path/to/rootfs");
        assert_eq!(drive_configs[0].direct, true);
        assert_eq!(drive_configs[0].read_only, false);
        assert_eq!(drive_configs[0].serial_num, Some(String::from("111111")));
        assert!(drive_configs[0].check().is_ok());
        drive_configs[0].serial_num = Some(String::from("22222222222222222222"));
        assert!(drive_configs[0].check().is_ok());
        drive_configs[0].serial_num = Some(String::from("222222222222222222222"));
        assert!(drive_configs[0].check().is_err());
    }
}
