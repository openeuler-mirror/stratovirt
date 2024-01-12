// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{anyhow, bail, Context, Result};

use super::error::ConfigError;
use crate::config::{
    pci_args_check, ChardevType, CmdParser, ConfigCheck, VmConfig, MAX_SOCK_PATH_LENGTH,
    MAX_STRING_LENGTH, MAX_TAG_LENGTH,
};

/// Config struct for `fs`.
/// Contains fs device's attr.
#[derive(Debug, Clone)]
pub struct FsConfig {
    /// Device tag.
    pub tag: String,
    /// Device id.
    pub id: String,
    /// Char device sock path.
    pub sock: String,
}

impl Default for FsConfig {
    fn default() -> Self {
        FsConfig {
            tag: "".to_string(),
            id: "".to_string(),
            sock: "".to_string(),
        }
    }
}

impl ConfigCheck for FsConfig {
    fn check(&self) -> Result<()> {
        if self.tag.len() >= MAX_TAG_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "fs device tag".to_string(),
                MAX_TAG_LENGTH - 1,
            )));
        }

        if self.id.len() >= MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "fs device id".to_string(),
                MAX_STRING_LENGTH - 1,
            )));
        }

        if self.sock.len() > MAX_SOCK_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "fs sock path".to_string(),
                MAX_SOCK_PATH_LENGTH,
            )));
        }

        Ok(())
    }
}

pub fn parse_fs(vm_config: &mut VmConfig, fs_config: &str) -> Result<FsConfig> {
    let mut cmd_parser = CmdParser::new("fs");
    cmd_parser
        .push("")
        .push("tag")
        .push("id")
        .push("chardev")
        .push("bus")
        .push("addr")
        .push("multifunction");
    cmd_parser.parse(fs_config)?;
    pci_args_check(&cmd_parser)?;

    let mut fs_cfg = FsConfig {
        tag: cmd_parser.get_value::<String>("tag")?.with_context(|| {
            ConfigError::FieldIsMissing("tag".to_string(), "virtio-fs".to_string())
        })?,
        id: cmd_parser.get_value::<String>("id")?.with_context(|| {
            ConfigError::FieldIsMissing("id".to_string(), "virtio-fs".to_string())
        })?,
        ..Default::default()
    };

    if let Some(name) = cmd_parser.get_value::<String>("chardev")? {
        if let Some(char_dev) = vm_config.chardev.remove(&name) {
            match &char_dev.backend {
                ChardevType::UnixSocket { path, .. } => {
                    fs_cfg.sock = path.clone();
                }
                _ => {
                    bail!("Chardev {:?} backend should be unix-socket type.", &name);
                }
            }
        } else {
            bail!("Chardev {:?} not found or is in use", &name);
        }
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "chardev".to_string(),
            "virtio-fs".to_string()
        )));
    }
    fs_cfg.check()?;

    Ok(fs_cfg)
}
