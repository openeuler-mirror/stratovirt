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

use anyhow::{bail, Result};

use super::{pci_args_check, CmdParser, VmConfig};

/// Config struct for `demo_dev`.
/// Contains demo_dev device's attr.
#[derive(Debug, Clone)]
pub struct DemoDevConfig {
    pub id: String,
}

pub fn parse_demo_dev(_vm_config: &mut VmConfig, args_str: String) -> Result<DemoDevConfig> {
    let mut cmd_parser = CmdParser::new("demo-dev");
    cmd_parser.push("").push("id").push("addr").push("bus");
    cmd_parser.parse(&args_str)?;

    pci_args_check(&cmd_parser)?;

    let mut demo_dev_cfg = DemoDevConfig { id: "".to_string() };

    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        demo_dev_cfg.id = id;
    } else {
        bail!("No id configured for demo device");
    }

    Ok(demo_dev_cfg)
}
