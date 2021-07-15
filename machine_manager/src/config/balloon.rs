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

use super::{
    errors::{ErrorKind, Result},
    pci_args_check, ConfigCheck, MAX_STRING_LENGTH,
};
use crate::config::{CmdParser, ExBool, VmConfig};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalloonConfig {
    pub id: String,
    pub deflate_on_oom: bool,
}

impl ConfigCheck for BalloonConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "balloon id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        Ok(())
    }
}

pub fn parse_balloon(vm_config: &mut VmConfig, balloon_config: &str) -> Result<BalloonConfig> {
    if vm_config.dev_name.get("balloon").is_some() {
        bail!("Only one balloon device is supported for each vm.");
    }
    let mut cmd_parser = CmdParser::new("virtio-balloon");
    cmd_parser
        .push("")
        .push("bus")
        .push("addr")
        .push("id")
        .push("deflate-on-oom");
    cmd_parser.parse(balloon_config)?;

    pci_args_check(&cmd_parser)?;
    let mut balloon: BalloonConfig = Default::default();
    if let Some(default) = cmd_parser.get_value::<ExBool>("deflate-on-oom")? {
        balloon.deflate_on_oom = default.into();
    }
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        balloon.id = id;
    }
    balloon.check()?;
    vm_config.dev_name.insert("balloon".to_string(), 1);
    Ok(balloon)
}

#[cfg(test)]
mod tests {
    use crate::config::get_pci_bdf;

    use super::*;

    #[test]
    fn test_balloon_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        let bln_cfg_res = parse_balloon(
            &mut vm_config,
            "virtio-balloon-device,deflate-on-oom=true,id=balloon0",
        );
        assert!(bln_cfg_res.is_ok());
        let balloon_configs = bln_cfg_res.unwrap();
        assert_eq!(balloon_configs.id, "balloon0".to_string());
        assert_eq!(balloon_configs.deflate_on_oom, true);
    }

    #[test]
    fn test_pci_block_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        let bln_cfg = "virtio-balloon-pci,deflate-on-oom=true,bus=pcie.0,addr=0x1.0x2,id=balloon0";
        let bln_cfg_res = parse_balloon(&mut vm_config, bln_cfg);
        assert!(bln_cfg_res.is_ok());
        let balloon_configs = bln_cfg_res.unwrap();
        assert_eq!(balloon_configs.id, "balloon0".to_string());
        assert_eq!(balloon_configs.deflate_on_oom, true);

        let pci_bdf = get_pci_bdf(bln_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));
    }

    #[test]
    fn test_two_balloon_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        let bln_cfg_res1 = parse_balloon(
            &mut vm_config,
            "virtio-balloon-device,deflate-on-oom=true,id=balloon0",
        );
        assert!(bln_cfg_res1.is_ok());
        let bln_cfg_res2 = parse_balloon(
            &mut vm_config,
            "virtio-balloon-device,deflate-on-oom=true,id=balloon1",
        );
        assert!(bln_cfg_res2.is_err());
    }
}
