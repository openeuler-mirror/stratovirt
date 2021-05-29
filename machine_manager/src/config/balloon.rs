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
use crate::config::{CmdParser, ExBool, VmConfig};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalloonConfig {
    pub id: String,
    pub deflate_on_oom: bool,
}

impl VmConfig {
    pub fn add_balloon(&mut self, balloon_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("balloon");
        cmd_parser.push("").push("id").push("deflate-on-oom");

        cmd_parser.parse(balloon_config)?;

        let mut balloon: BalloonConfig = Default::default();
        if let Some(default) = cmd_parser.get_value::<ExBool>("deflate-on-oom")? {
            balloon.deflate_on_oom = default.into();
        }
        if let Some(balloon_id) = cmd_parser.get_value("id")? {
            balloon.id = balloon_id;
        }
        if let Some(should_empty) = cmd_parser.get_value::<String>("")? {
            if !should_empty.is_empty() {
                return Err(ErrorKind::InvalidParam(should_empty).into());
            }
        }

        self.balloon = Some(balloon);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balloon_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.balloon.is_none());
        assert!(vm_config.add_balloon("deflate-on-oom=on").is_ok());
        assert!(vm_config.balloon.is_some());
        assert_eq!(vm_config.balloon.as_ref().unwrap().deflate_on_oom, true);
        assert!(vm_config.add_balloon("deflate-on-oom=off").is_ok());
        assert_eq!(vm_config.balloon.as_ref().unwrap().deflate_on_oom, false);
        assert!(vm_config.add_balloon("deflate-on-oom=true").is_ok());
        assert_eq!(vm_config.balloon.as_ref().unwrap().deflate_on_oom, true);
        assert!(vm_config.add_balloon("deflate-on-oom=false").is_ok());
        assert_eq!(vm_config.balloon.as_ref().unwrap().deflate_on_oom, false);
    }
}
