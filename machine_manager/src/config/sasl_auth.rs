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

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigError, {CmdParser, VmConfig},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SaslAuthObjConfig {
    /// Object Id.
    pub id: String,
    /// Authentication User Name.
    pub identity: String,
}

impl VmConfig {
    pub fn add_saslauth(&mut self, saslauth_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("authz-simple");
        cmd_parser.push("").push("id").push("identity");
        cmd_parser.parse(saslauth_config)?;

        let mut saslauth = SaslAuthObjConfig {
            id: cmd_parser.get_value::<String>("id")?.with_context(|| {
                ConfigError::FieldIsMissing("id".to_string(), "vnc sasl_auth".to_string())
            })?,
            ..Default::default()
        };

        if let Some(identity) = cmd_parser.get_value::<String>("identity")? {
            saslauth.identity = identity;
        }

        let id = saslauth.id.clone();
        if self.object.sasl_object.get(&id).is_none() {
            self.object.sasl_object.insert(id, saslauth);
        } else {
            return Err(anyhow!(ConfigError::IdRepeat("saslauth".to_string(), id)));
        }

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
            assert!(obj_cfg.identity == "".to_string());
        }
    }
}
