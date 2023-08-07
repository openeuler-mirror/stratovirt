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

use anyhow::Result;

use crate::config::CmdParser;

pub fn parse_ramfb(cfg_args: &str) -> Result<bool> {
    let mut cmd_parser = CmdParser::new("ramfb");
    cmd_parser.push("").push("install").push("id");
    cmd_parser.parse(cfg_args)?;

    let install = cmd_parser.get_value::<bool>("install")?.unwrap_or(false);
    Ok(install)
}
