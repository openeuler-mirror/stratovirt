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
use crate::config::{CmdParams, ConfigCheck, ParamOperation, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_SERIAL_NUM: usize = 20;

/// Config struct for `drive`.
/// Contains block device's attr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveConfig {
    pub drive_id: String,
    pub path_on_host: String,
    pub read_only: bool,
    pub direct: bool,
    pub serial_num: Option<String>,
}

impl DriveConfig {
    /// Create `DriveConfig` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Option<Vec<Self>> {
        serde_json::from_value(value.clone()).ok()
    }
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
            drive_id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            serial_num: None,
        }
    }
}

impl ConfigCheck for DriveConfig {
    fn check(&self) -> Result<()> {
        if self.drive_id.len() > MAX_STRING_LENGTH {
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

        Ok(())
    }
}

impl VmConfig {
    /// Add new block device to `VmConfig`.
    fn add_drive(&mut self, drive: DriveConfig) {
        if let Some(mut drives) = self.drives.clone() {
            drives.push(drive);
            self.drives = Some(drives);
        } else {
            let mut drives: Vec<DriveConfig> = Vec::new();
            drives.push(drive);
            self.drives = Some(drives);
        }
    }

    /// Update '-drive ...' drive config to `VmConfig`.
    pub fn update_drive(&mut self, drive_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(drive_config);
        let mut drive = DriveConfig::default();
        if let Some(drive_path) = cmd_params.get("file") {
            drive.path_on_host = drive_path.value;
        }
        if let Some(drive_id) = cmd_params.get("id") {
            drive.drive_id = drive_id.value;
        }
        if let Some(read_only) = cmd_params.get("readonly") {
            drive.read_only = read_only.to_bool();
        }
        if let Some(direct) = cmd_params.get("direct") {
            drive.direct = direct.to_bool();
        }
        drive.serial_num = cmd_params.get_value_str("serial");

        self.add_drive(drive);
    }
}
