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
use crate::config::{CmdParser, ConfigCheck, VmConfig};

const MAX_PATH_LENGTH: usize = 4096;
const MAX_BYTE_PER_SEC: u64 = 1_000_000_000;

/// Config structure for virtio-rng.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RngConfig {
    pub random_file: String,
    pub bytes_per_sec: Option<u64>,
}

impl RngConfig {
    /// Create `RngConfig` from `Value` structure.
    /// `Value` structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
    }
}

impl ConfigCheck for RngConfig {
    fn check(&self) -> Result<()> {
        if self.random_file.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "rng random file".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if let Some(bytes_per_sec) = self.bytes_per_sec {
            if bytes_per_sec > MAX_BYTE_PER_SEC {
                return Err(ErrorKind::IllegalValue(
                    "The bytes per second of rng device".to_string(),
                    0,
                    true,
                    MAX_BYTE_PER_SEC,
                    true,
                )
                .into());
            }
        }

        Ok(())
    }
}

impl VmConfig {
    pub fn update_rng(&mut self, rng_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("rng");
        cmd_parser.push("random_file").push("bytes_per_sec");

        cmd_parser.parse(rng_config)?;

        let random_file =
            if let Some(random_file) = cmd_parser.get_value::<String>("random_file")? {
                random_file
            } else {
                return Err(ErrorKind::FieldIsMissing("random_file", "rng").into());
            };

        let bytes_per_sec = cmd_parser.get_value::<u64>("bytes_per_sec")?;

        self.rng = Some(RngConfig {
            random_file,
            bytes_per_sec,
        });

        Ok(())
    }
}
