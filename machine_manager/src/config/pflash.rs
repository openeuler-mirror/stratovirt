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

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

const MAX_PATH_LENGTH: usize = 4096;
const MAX_UNIT_ID: usize = 2;

/// Config struct for `pflash`.
/// Contains pflash device's attr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PFlashConfig {
    pub path_on_host: String,
    pub read_only: bool,
    pub unit: usize,
    pub if_pflash: String,
}

impl PFlashConfig {
    /// Create `PFlashConfig` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Result<Vec<Self>> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
    }
}

impl Default for PFlashConfig {
    fn default() -> Self {
        PFlashConfig {
            path_on_host: String::new(),
            read_only: false,
            unit: 0_usize,
            if_pflash: String::new(),
        }
    }
}

impl ConfigCheck for PFlashConfig {
    fn check(&self) -> Result<()> {
        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if self.unit >= MAX_UNIT_ID {
            return Err(ErrorKind::UnitIDError(self.unit, MAX_UNIT_ID).into());
        }
        Ok(())
    }
}

impl VmConfig {
    /// Add new flash device to `VmConfig`.
    fn add_flashdev(&mut self, pflash: PFlashConfig) -> Result<()> {
        if self.pflashs.is_some() {
            for pf in self.pflashs.as_ref().unwrap() {
                if pf.unit == pflash.unit {
                    return Err(
                        ErrorKind::IdRepeat("pflash".to_string(), pf.unit.to_string()).into(),
                    );
                }
            }
            self.pflashs.as_mut().unwrap().push(pflash);
        } else {
            self.pflashs = Some(vec![pflash]);
        }
        Ok(())
    }

    /// Update '-pflash ...' pflash config to `VmConfig`.
    pub fn update_pflash(&mut self, pflash_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser
            .push("file")
            .push("readonly")
            .push("unit")
            .push("if");

        cmd_parser.parse(pflash_config)?;

        let mut pflash = PFlashConfig::default();

        if let Some(drive_path) = cmd_parser.get_value::<String>("file")? {
            pflash.path_on_host = drive_path;
        } else {
            return Err(ErrorKind::FieldIsMissing("file", "pflash").into());
        }

        if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
            pflash.read_only = read_only.into();
        }

        if let Some(unit_id) = cmd_parser.get_value::<u64>("unit")? {
            pflash.unit = unit_id as usize;
        } else {
            return Err(ErrorKind::FieldIsMissing("unit", "pflash").into());
        }

        if let Some(if_pflash) = cmd_parser.get_value::<String>("if")? {
            pflash.if_pflash = if_pflash;
        }

        self.add_flashdev(pflash)
    }
}
