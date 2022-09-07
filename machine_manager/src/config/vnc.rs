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

use serde::{Deserialize, Serialize};

use super::errors::Result;
use crate::config::{
    errors::ErrorKind,
    {CmdParser, VmConfig},
};

/// Configuration of vnc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VncConfig {
    /// Listening ip.
    pub ip: String,
    /// Listening port.
    pub port: String,
    /// Configuration of encryption.
    pub tls_creds: String,
    /// Authentication switch.
    pub sasl: bool,
    /// Configuration of authentication.
    pub sasl_authz: String,
}

impl VmConfig {
    /// Make configuration for vnc: "chardev" -> "vnc".
    pub fn add_vnc(&mut self, vnc_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("vnc");
        cmd_parser
            .push("")
            .push("tls-creds")
            .push("sasl")
            .push("sasl-authz");
        cmd_parser.parse(vnc_config)?;

        let mut vnc_config = VncConfig::default();
        if let Some(addr) = cmd_parser.get_value::<String>("")? {
            let v: Vec<&str> = addr.split(':').collect();
            if v.len() != 2 {
                return Err(ErrorKind::FieldIsMissing("ip", "port").into());
            }
            vnc_config.ip = v[0].to_string();
            vnc_config.port = v[1].to_string();
        } else {
            return Err(ErrorKind::FieldIsMissing("ip", "port").into());
        }

        if let Some(tls_creds) = cmd_parser.get_value::<String>("tls-creds")? {
            vnc_config.tls_creds = tls_creds
        }
        if let Some(_sasl) = cmd_parser.get_value::<String>("sasl")? {
            vnc_config.sasl = true
        } else {
            vnc_config.sasl = false
        }
        if let Some(sasl_authz) = cmd_parser.get_value::<String>("sasl-authz")? {
            vnc_config.sasl_authz = sasl_authz;
        }

        self.vnc = Some(vnc_config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_vnc() {
        let mut vm_config = VmConfig::default();
        vm_config
            .add_vnc("0.0.0.0:1,tls-creds=vnc-tls-creds0,sasl,sasl-authz=authz0")
            .unwrap();
        let vnc_config = vm_config.vnc.unwrap();
        assert_eq!(vnc_config.ip, String::from("0.0.0.0"));
        assert_eq!(vnc_config.port, String::from("1"));
        assert_eq!(vnc_config.tls_creds, String::from("vnc-tls-creds0"));
        assert_eq!(vnc_config.sasl, true);
        assert_eq!(vnc_config.sasl_authz, String::from("authz0"));

        let mut vm_config = VmConfig::default();
        vm_config
            .add_vnc("0.0.0.0:1,tls-creds=vnc-tls-creds0")
            .unwrap();
        let vnc_config = vm_config.vnc.unwrap();
        assert_eq!(vnc_config.sasl, false);

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_vnc("tls-creds=vnc-tls-creds0");
        assert!(res.is_err());

        let mut vm_config = VmConfig::default();
        let _res = vm_config.add_vnc("0.0.0.0:1,sasl,sasl-authz=authz0");
        let vnc_config = vm_config.vnc.unwrap();
        assert_eq!(vnc_config.tls_creds, "".to_string());
    }
}
