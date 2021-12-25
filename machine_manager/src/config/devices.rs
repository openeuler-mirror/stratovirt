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

use super::errors::Result;
use super::{CmdParser, VmConfig};

impl VmConfig {
    pub fn add_devices(&mut self, device_config: &str) -> Result<()> {
        let mut cmd_params = CmdParser::new("device");
        cmd_params.push("");

        cmd_params.get_parameters(&device_config)?;
        if let Some(device_type) = cmd_params.get_value::<String>("")? {
            self.devices.push((device_type, device_config.to_string()));
        }

        Ok(())
    }
}

pub fn parse_device_id(device_config: &str) -> Result<String> {
    let mut cmd_parser = CmdParser::new("device");
    cmd_parser.push("id");

    cmd_parser.get_parameters(device_config)?;
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        Ok(id)
    } else {
        Ok(String::new())
    }
}
