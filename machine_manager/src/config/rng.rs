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

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::pci_args_check;
use crate::config::{CmdParser, ConfigCheck, VmConfig, MAX_PATH_LENGTH};

const MIN_BYTES_PER_SEC: u64 = 64;
const MAX_BYTES_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
        if self.id.len() > MAX_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "rng id".to_string(),
                MAX_PATH_LENGTH
            )));
        }

        if self.random_file.len() > MAX_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "rng random file".to_string(),
                MAX_PATH_LENGTH,
            )));
        }

        if let Some(bytes_per_sec) = self.bytes_per_sec {
            if !(MIN_BYTES_PER_SEC..=MAX_BYTES_PER_SEC).contains(&bytes_per_sec) {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "The bytes per second of rng device".to_string(),
                    MIN_BYTES_PER_SEC,
                    true,
                    MAX_BYTES_PER_SEC,
                    true,
                )));
            }
        }

        Ok(())
    }
}

pub fn parse_rng_dev(vm_config: &mut VmConfig, rng_config: &str) -> Result<RngConfig> {
    let mut cmd_parser = CmdParser::new("rng");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("max-bytes")
        .push("period")
        .push("rng");

    cmd_parser.parse(rng_config)?;
    pci_args_check(&cmd_parser)?;
    let mut rng_cfg = RngConfig::default();
    let rng = cmd_parser
        .get_value::<String>("rng")?
        .with_context(|| ConfigError::FieldIsMissing("rng".to_string(), "rng".to_string()))?;

    rng_cfg.id = cmd_parser.get_value::<String>("id")?.unwrap_or_default();

    if let Some(max) = cmd_parser.get_value::<u64>("max-bytes")? {
        if let Some(peri) = cmd_parser.get_value::<u64>("period")? {
            let mul = max
                .checked_mul(1000)
                .with_context(|| format!("Illegal max-bytes arguments: {:?}", max))?;
            let div = mul
                .checked_div(peri)
                .with_context(|| format!("Illegal period arguments: {:?}", peri))?;
            rng_cfg.bytes_per_sec = Some(div);
        } else {
            bail!("Argument 'period' is missing");
        }
    } else if cmd_parser.get_value::<u64>("period")?.is_some() {
        bail!("Argument 'max-bytes' is missing");
    }

    rng_cfg.random_file = vm_config
        .object
        .rng_object
        .remove(&rng)
        .map(|rng_object| rng_object.filename)
        .with_context(|| "Object for rng-random device not found")?;

    rng_cfg.check()?;
    Ok(rng_cfg)
}

pub fn parse_rng_obj(object_args: &str) -> Result<RngObjConfig> {
    let mut cmd_params = CmdParser::new("rng-object");
    cmd_params.push("").push("id").push("filename");

    cmd_params.parse(object_args)?;
    let id = cmd_params
        .get_value::<String>("id")?
        .with_context(|| ConfigError::FieldIsMissing("id".to_string(), "rng-object".to_string()))?;
    let filename = cmd_params
        .get_value::<String>("filename")?
        .with_context(|| {
            ConfigError::FieldIsMissing("filename".to_string(), "rng-object".to_string())
        })?;
    let rng_obj_cfg = RngObjConfig { id, filename };

    Ok(rng_obj_cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::get_pci_bdf;

    #[test]
    fn test_rng_config_cmdline_parser_01() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(&mut vm_config, "virtio-rng-device,rng=objrng0");
        assert!(rng_config.is_ok());
        let config = rng_config.unwrap();
        assert_eq!(config.random_file, "/path/to/random_file");
        assert_eq!(config.bytes_per_sec, None);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(
            &mut vm_config,
            "virtio-rng-device,rng=objrng0,max-bytes=1234,period=1000",
        );
        assert!(rng_config.is_ok());
        let config = rng_config.unwrap();
        assert_eq!(config.random_file, "/path/to/random_file");
        assert_eq!(config.bytes_per_sec, Some(1234));
    }

    #[test]
    fn test_rng_config_cmdline_parser_02() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(
            &mut vm_config,
            "virtio-rng-device,rng=objrng0,max-bytes=63,period=1000",
        );
        assert!(rng_config.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(
            &mut vm_config,
            "virtio-rng-device,rng=objrng0,max-bytes=64,period=1000",
        );
        assert!(rng_config.is_ok());
        let config = rng_config.unwrap();
        assert_eq!(config.random_file, "/path/to/random_file");
        assert_eq!(config.bytes_per_sec, Some(64));

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(
            &mut vm_config,
            "virtio-rng-device,rng=objrng0,max-bytes=1000000000,period=1000",
        );
        assert!(rng_config.is_ok());
        let config = rng_config.unwrap();
        assert_eq!(config.random_file, "/path/to/random_file");
        assert_eq!(config.bytes_per_sec, Some(1000000000));

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_config = parse_rng_dev(
            &mut vm_config,
            "virtio-rng-device,rng=objrng0,max-bytes=1000000001,period=1000",
        );
        assert!(rng_config.is_err());
    }

    #[test]
    fn test_pci_rng_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_cfg = "virtio-rng-pci,rng=objrng0,bus=pcie.0,addr=0x1.0x3";
        let rng_config = parse_rng_dev(&mut vm_config, rng_cfg);
        assert!(rng_config.is_ok());
        let config = rng_config.unwrap();
        assert_eq!(config.random_file, "/path/to/random_file");
        assert_eq!(config.bytes_per_sec, None);
        let pci_bdf = get_pci_bdf(rng_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 3));

        // object "objrng0" has been removed.
        let rng_config = parse_rng_dev(&mut vm_config, rng_cfg);
        assert!(rng_config.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_cfg = "virtio-rng-device,rng=objrng0,bus=pcie.0,addr=0x1.0x3";
        let rng_config = parse_rng_dev(&mut vm_config, rng_cfg);
        assert!(rng_config.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("rng-random,id=objrng0,filename=/path/to/random_file")
            .is_ok());
        let rng_cfg = "virtio-rng-pci,rng=objrng0,bus=pcie.0,addr=0x1.0x3,multifunction=on";
        assert!(parse_rng_dev(&mut vm_config, rng_cfg).is_ok());
    }
}
