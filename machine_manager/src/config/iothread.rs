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

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use crate::config::{check_arg_too_long, CmdParser, ConfigCheck, VmConfig};

const MAX_IOTHREAD_NUM: usize = 8;

/// Config structure for iothread.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IothreadConfig {
    pub id: String,
}

impl ConfigCheck for IothreadConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "iothread id")
    }
}

impl VmConfig {
    /// Add new iothread device to `VmConfig`.
    pub fn add_iothread(&mut self, iothread_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("iothread");
        cmd_parser.push("").push("id");
        cmd_parser.parse(iothread_config)?;

        let mut iothread = IothreadConfig::default();
        if let Some(id) = cmd_parser.get_value::<String>("id")? {
            iothread.id = id;
        }
        iothread.check()?;

        if self.iothreads.is_some() {
            if self.iothreads.as_ref().unwrap().len() >= MAX_IOTHREAD_NUM {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "Iothread number".to_string(),
                    0,
                    true,
                    MAX_IOTHREAD_NUM as u64,
                    true,
                )));
            }

            for t in self.iothreads.as_ref().unwrap() {
                if t.id == iothread.id {
                    return Err(anyhow!(ConfigError::IdRepeat(
                        "iothread".to_string(),
                        t.id.to_string()
                    )));
                }
            }

            self.iothreads.as_mut().unwrap().push(iothread);
        } else {
            self.iothreads = Some(vec![iothread]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iothread_config_cmdline_parser_01() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object("iothread,id=iothread0").is_ok());
        assert!(vm_config.iothreads.is_some());
        let iothreads = vm_config.iothreads.unwrap();
        assert!(iothreads.len().eq(&1));
    }

    #[test]
    fn test_iothread_config_cmdline_parser_02() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object("iothread,id=iothread0").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread1").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread2").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread3").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread4").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread5").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread6").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread7").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread8").is_err());
    }

    #[test]
    fn test_iothread_config_cmdline_parser_03() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object("iothread,id=iothread0").is_ok());
        assert!(vm_config.add_object("iothread,id=iothread0").is_err());
    }
}
