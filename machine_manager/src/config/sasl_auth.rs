// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::config::{str_slip_to_clap, valid_id, ConfigError, VmConfig};

#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SaslAuthObjConfig {
    #[arg(long, value_parser = ["authz-simple"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    /// Authentication User Name.
    #[arg(long, default_value = "")]
    pub identity: String,
}

impl VmConfig {
    pub fn add_saslauth(&mut self, saslauth_config: &str) -> Result<()> {
        let saslauth =
            SaslAuthObjConfig::try_parse_from(str_slip_to_clap(saslauth_config, true, false))?;
        let id = saslauth.id.clone();
        if self.object.sasl_object.contains_key(&id) {
            return Err(anyhow!(ConfigError::IdRepeat("saslauth".to_string(), id)));
        }
        self.object.sasl_object.insert(id, saslauth);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_saslauth() {
        let id = String::from("authz0");
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_object("authz-simple,id=authz0,identity=test")
            .is_ok());
        assert!(vm_config.object.sasl_object.get(&id).is_some());
        if let Some(obj_cfg) = vm_config.object.sasl_object.get(&id) {
            assert_eq!(obj_cfg.identity, "test".to_string());
        }

        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object("authz-simple,id=authz0").is_ok());
        assert!(vm_config.object.sasl_object.get(&id).is_some());
        if let Some(obj_cfg) = vm_config.object.sasl_object.get(&id) {
            assert!(obj_cfg.identity == *"");
        }
    }
}
