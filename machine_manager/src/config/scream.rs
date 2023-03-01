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

use anyhow::{anyhow, Result};

use super::{pci_args_check, CmdParser};

pub fn parse_scream(cfg_args: &str) -> Result<String> {
    let mut cmd_parser = CmdParser::new("scream");
    cmd_parser
        .push("")
        .push("memdev")
        .push("id")
        .push("bus")
        .push("addr");
    cmd_parser.parse(cfg_args)?;

    pci_args_check(&cmd_parser)?;

    cmd_parser
        .get_value::<String>("memdev")?
        .ok_or_else(|| anyhow!("No memdev configured for scream device"))
}
