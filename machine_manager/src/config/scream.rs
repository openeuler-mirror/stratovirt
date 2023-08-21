// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use super::{pci_args_check, CmdParser};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScreamInterface {
    #[cfg(feature = "scream_alsa")]
    Alsa,
    #[cfg(feature = "scream_pulseaudio")]
    PulseAudio,
    Demo,
}

impl FromStr for ScreamInterface {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "scream_alsa")]
            "ALSA" => Ok(ScreamInterface::Alsa),
            #[cfg(feature = "scream_pulseaudio")]
            "PulseAudio" => Ok(ScreamInterface::PulseAudio),
            "Demo" => Ok(ScreamInterface::Demo),
            _ => Err(anyhow!("Unknown scream interface")),
        }
    }
}

pub struct ScreamConfig {
    pub memdev: String,
    pub interface: ScreamInterface,
    pub playback: String,
    pub record: String,
}

impl ScreamConfig {
    pub fn new() -> Self {
        Self {
            memdev: "".to_string(),
            interface: ScreamInterface::Demo,
            playback: "".to_string(),
            record: "".to_string(),
        }
    }
}

impl Default for ScreamConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_scream(cfg_args: &str) -> Result<ScreamConfig> {
    let mut cmd_parser = CmdParser::new("scream");
    cmd_parser
        .push("")
        .push("memdev")
        .push("interface")
        .push("playback")
        .push("record")
        .push("id")
        .push("bus")
        .push("addr");
    cmd_parser.parse(cfg_args)?;

    pci_args_check(&cmd_parser)?;

    let mut dev_cfg = ScreamConfig::new();

    dev_cfg.memdev = cmd_parser
        .get_value::<String>("memdev")?
        .with_context(|| "No memdev configured for scream device")?;

    dev_cfg.interface = cmd_parser
        .get_value::<ScreamInterface>("interface")?
        .with_context(|| "No interface configured for scream device")?;

    if dev_cfg.interface == ScreamInterface::Demo {
        dev_cfg.playback = cmd_parser
            .get_value::<String>("playback")?
            .with_context(|| "No playback configured for interface")?;
        dev_cfg.record = cmd_parser
            .get_value::<String>("record")?
            .with_context(|| "No record configured for interface")?;
    }

    Ok(dev_cfg)
}
