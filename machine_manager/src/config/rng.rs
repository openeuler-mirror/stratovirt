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

use super::errors::{ErrorKind, Result};
use super::{pci_args_check, ObjConfig};
use crate::config::{CmdParser, ConfigCheck, VmConfig};

const MAX_PATH_LENGTH: usize = 4096;
const MIN_BYTES_PER_SEC: u64 = 64;
const MAX_BYTES_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone, Default)]
pub struct RngObjConfig {
    pub id: String,
    pub filename: String,
}

/// Config structure for virtio-rng.
#[derive(Debug, Clone, Default)]
pub struct RngConfig {
    pub id: String,
    pub random_file: String,
    pub bytes_per_sec: Option<u64>,
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
            if !(MIN_BYTES_PER_SEC..=MAX_BYTES_PER_SEC).contains(&bytes_per_sec) {
                return Err(ErrorKind::IllegalValue(
                    "The bytes per second of rng device".to_string(),
                    MIN_BYTES_PER_SEC,
                    true,
                    MAX_BYTES_PER_SEC,
                    true,
                )
                .into());
            }
        }

        Ok(())
    }
}

pub fn parse_rng_dev(vm_config: &VmConfig, rng_config: &str) -> Result<RngConfig> {
    let mut cmd_parser = CmdParser::new("rng");
    cmd_parser
        .push("")
        .push("bus")
        .push("addr")
        .push("max-bytes")
        .push("period")
        .push("rng");

    cmd_parser.parse(rng_config)?;
    pci_args_check(&cmd_parser)?;
    let mut rng_cfg = RngConfig::default();
    let rng = if let Some(rng_id) = cmd_parser.get_value::<String>("rng")? {
        rng_id
    } else {
        return Err(ErrorKind::FieldIsMissing("rng", "rng").into());
    };

    if let Some(max) = cmd_parser.get_value::<u64>("max-bytes")? {
        if let Some(peri) = cmd_parser.get_value::<u64>("period")? {
            let mul = if let Some(res) = max.checked_mul(1000) {
                res
            } else {
                bail!("Illegal max-bytes arguments: {:?}", max)
            };
            let div = if let Some(res) = mul.checked_div(peri) {
                res
            } else {
                bail!("Illegal period arguments: {:?}", peri)
            };
            rng_cfg.bytes_per_sec = Some(div);
        } else {
            bail!("Argument 'period' is missing");
        }
    } else if cmd_parser.get_value::<u64>("period")?.is_some() {
        bail!("Argument 'max-bytes' is missing");
    }
    let obj_config = &vm_config.object;

    if let Some(object_cfg) = obj_config.get(&rng) {
        rng_cfg.id = rng;
        #[allow(irrefutable_let_patterns)]
        if let ObjConfig::Rng(obj_cfg) = object_cfg {
            rng_cfg.random_file = obj_cfg.filename.clone();
        }
    } else {
        bail!("Object for rng-random device not found");
    }

    rng_cfg.check()?;
    Ok(rng_cfg)
}
