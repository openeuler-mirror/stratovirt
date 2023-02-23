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
    pub bar_num: u8,
    // every bar has the same size just for simplification.
    pub bar_size: u64,
}

impl DemoDevConfig {
    pub fn new() -> Self {
        Self {
            id: "".to_string(),
            bar_num: 0,
            bar_size: 0,
        }
    }
}

impl Default for DemoDevConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_demo_dev(_vm_config: &mut VmConfig, args_str: String) -> Result<DemoDevConfig> {
    let mut cmd_parser = CmdParser::new("demo-dev");
    cmd_parser
        .push("")
        .push("id")
        .push("addr")
        .push("bus")
        .push("bar_num")
        .push("bar_size");
    cmd_parser.parse(&args_str)?;

    pci_args_check(&cmd_parser)?;

    let mut demo_dev_cfg = DemoDevConfig::new();

    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        demo_dev_cfg.id = id;
    } else {
        bail!("No id configured for demo device");
    }

    if let Some(bar_num) = cmd_parser.get_value::<u8>("bar_num")? {
        demo_dev_cfg.bar_num = bar_num;
    }

    // todo: support parsing hex num "0x**". It just supports decimal number now.
    if let Some(bar_size) = cmd_parser.get_value::<u64>("bar_size")? {
        demo_dev_cfg.bar_size = bar_size;
    }

    Ok(demo_dev_cfg)
}
