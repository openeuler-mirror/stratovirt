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

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigError, {CmdParser, VmConfig},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsCredObjConfig {
    pub id: String,
    pub dir: String,
    pub cred_type: String,
    pub endpoint: Option<String>,
    pub verifypeer: bool,
}

impl VmConfig {
    pub fn add_tlscred(&mut self, tlscred_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("tls-creds-x509");
        cmd_parser
            .push("")
            .push("id")
            .push("dir")
            .push("endpoint")
            .push("verify-peer");
        cmd_parser.parse(tlscred_config)?;

        let mut tlscred = TlsCredObjConfig {
            id: cmd_parser.get_value::<String>("id")?.with_context(|| {
                ConfigError::FieldIsMissing("id".to_string(), "vnc tls_creds".to_string())
            })?,
            ..Default::default()
        };

        if let Some(dir) = cmd_parser.get_value::<String>("dir")? {
            if Path::new(&dir).is_dir() {
                tlscred.dir = dir;
            } else {
                return Err(anyhow!(ConfigError::DirNotExist(dir)));
            }
        }
        if let Some(endpoint) = cmd_parser.get_value::<String>("endpoint")? {
            tlscred.endpoint = Some(endpoint);
        }
        if let Some(verifypeer) = cmd_parser.get_value::<String>("verify-peer")? {
            tlscred.verifypeer = verifypeer == *"true";
        }
        tlscred.cred_type = "x509".to_string();

        let id = tlscred.id.clone();
        if self.object.tls_object.get(&id).is_none() {
            self.object.tls_object.insert(id, tlscred);
        } else {
            return Err(anyhow!(ConfigError::IdRepeat("tlscred".to_string(), id)));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use super::*;

    #[test]
    fn test_add_tlscred() {
        let mut dir = env::current_dir().unwrap();
        dir.push("test_pki");
        // Create file.
        if !dir.is_dir() {
            fs::create_dir(dir.clone()).unwrap();
        }
        assert_eq!(dir.is_dir(), true);

        // Certificate directory is exist.
        let tls_config: String = format!(
            "tls-creds-x509,id=vnc-tls-creds0,dir={},endpoint=server,verify-peer=false",
            dir.to_str().unwrap()
        );
        let id = String::from("vnc-tls-creds0");
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object(tls_config.as_str()).is_ok());
        assert!(vm_config.object.tls_object.get(&id).is_some());
        if let Some(tls_cred_cfg) = vm_config.object.tls_object.get(&id) {
            assert_eq!(tls_cred_cfg.dir, dir.to_str().unwrap());
            assert_eq!(tls_cred_cfg.endpoint, Some("server".to_string()));
            assert_eq!(tls_cred_cfg.verifypeer, false);
        }

        // Delete file.
        fs::remove_dir(dir.clone()).unwrap();
        assert_eq!(dir.is_dir(), false);
        // Certificate directory does not exist.
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_object(tls_config.as_str()).is_err());
    }
}
