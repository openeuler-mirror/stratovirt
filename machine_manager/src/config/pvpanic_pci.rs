// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use crate::config::{CmdParser, ConfigCheck};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const PVPANIC_PANICKED: u32 = 1 << 0;
pub const PVPANIC_CRASHLOADED: u32 = 1 << 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PvpanicDevConfig {
    pub id: String,
    pub supported_features: u32,
}

impl Default for PvpanicDevConfig {
    fn default() -> Self {
        PvpanicDevConfig {
            id: "".to_string(),
            supported_features: PVPANIC_PANICKED | PVPANIC_CRASHLOADED,
        }
    }
}

impl ConfigCheck for PvpanicDevConfig {
    fn check(&self) -> Result<()> {
        Ok(())
    }
}

pub fn parse_pvpanic(args_config: &str) -> Result<PvpanicDevConfig> {
    let mut cmd_parser = CmdParser::new("pvpanic");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("supported-features");
    cmd_parser.parse(args_config)?;

    let mut pvpanicdevcfg = PvpanicDevConfig::default();

    if let Some(features) = cmd_parser.get_value::<u32>("supported-features")? {
        pvpanicdevcfg.supported_features =
            match features & !(PVPANIC_PANICKED | PVPANIC_CRASHLOADED) {
                0 => features,
                _ => bail!("Unsupported pvpanic device features {}", features),
            }
    }

    pvpanicdevcfg.id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| "No id configured for pvpanic device")?;

    Ok(pvpanicdevcfg)
}
