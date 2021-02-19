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

extern crate serde;
extern crate serde_json;
use crate::config::{CmdParams, ParamOperation, VmConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalloonConfig {
    pub deflate_on_oom: bool,
}

impl BalloonConfig {
    pub fn from_value(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }
}

impl VmConfig {
    pub fn update_balloon(&mut self, balloon_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(balloon_config);
        let mut balloon: BalloonConfig = Default::default();
        if let Some(default) = cmd_params.get("deflate-on-oom") {
            balloon.deflate_on_oom = default.to_bool();
        }
        self.balloon = Some(balloon);
    }
}
