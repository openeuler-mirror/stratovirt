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
use crate::config::{CmdParser, ConfigCheck, VmConfig, MAX_STRING_LENGTH};

const MAX_IOTHREAD_NUM: usize = 8;

/// Config structure for iothread.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IothreadConfig {
    pub id: String,
}

impl IothreadConfig {
    /// Create `IothreadConfig` from `Value` structure.
    /// `Value` structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Result<Vec<Self>> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
    }
}

impl ConfigCheck for IothreadConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "iothread id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        Ok(())
    }
}

impl VmConfig {
    /// Add new iothread device to `VmConfig`.
    fn add_iothread(&mut self, iothread: IothreadConfig) -> Result<()> {
        if self.iothreads.is_some() {
            if self.iothreads.as_ref().unwrap().len() >= MAX_IOTHREAD_NUM {
                return Err(ErrorKind::IllegalValue(
                    "Iothread number".to_string(),
                    0,
                    true,
                    MAX_IOTHREAD_NUM as u64,
                    true,
                )
                .into());
            }

            for t in self.iothreads.as_ref().unwrap() {
                if t.id == iothread.id {
                    return Err(
                        ErrorKind::IdRepeat("iothread".to_string(), t.id.to_string()).into(),
                    );
                }
            }

            self.iothreads.as_mut().unwrap().push(iothread);
        } else {
            self.iothreads = Some(vec![iothread]);
        }

        Ok(())
    }

    pub fn update_iothread(&mut self, iothread_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("iothread");
        cmd_parser.push("id");

        cmd_parser.parse(iothread_config)?;

        let mut iothread = IothreadConfig::default();
        if let Some(id) = cmd_parser.get_value::<String>("id")? {
            iothread.id = id;
        }

        self.add_iothread(iothread)
    }
}
