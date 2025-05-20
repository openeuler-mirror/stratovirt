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

use std::net::Ipv4Addr;

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};

use crate::config::{str_slip_to_clap, ConfigError, VmConfig};

/// Configuration of vnc.
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct VncConfig {
    /// Vnc listening addr (ip, port).
    #[arg(long, alias = "classtype", value_parser = parse_ip_port)]
    pub addr: (String, u16),
    /// Configuration of encryption.
    #[arg(long, alias = "tls-creds", default_value = "")]
    pub tls_creds: String,
    /// Authentication switch.
    #[arg(long, default_value = "false", action = ArgAction::SetTrue)]
    pub sasl: bool,
    /// Configuration of authentication.
    #[arg(long, alias = "sasl-authz", default_value = "")]
    pub sasl_authz: String,
}

const VNC_MAX_PORT_NUM: i32 = 65535;
const VNC_PORT_OFFSET: i32 = 5900;

impl VmConfig {
    /// Make configuration for vnc: "chardev" -> "vnc".
    pub fn add_vnc(&mut self, vnc_config: &str) -> Result<()> {
        let vnc_config = VncConfig::try_parse_from(str_slip_to_clap(vnc_config, true, false))?;
        self.vnc = Some(vnc_config);
        Ok(())
    }
}

fn parse_ip_port(addr: &str) -> Result<(String, u16)> {
    let v: Vec<&str> = addr.split(':').collect();
    if v.len() != 2 {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "ip".to_string(),
            "port".to_string()
        )));
    }
    let ip = v[0]
        .parse::<Ipv4Addr>()
        .with_context(|| "Invalid Ip param for vnc!")?;
    let base_port = v[1]
        .parse::<i32>()
        .with_context(|| "Invalid Port param for vnc!")?;
    // Prevent the base_port out of bounds.
    if !(0..=VNC_MAX_PORT_NUM - VNC_PORT_OFFSET).contains(&base_port) {
        return Err(anyhow!(ConfigError::InvalidParam(
            base_port.to_string(),
            "port".to_string()
        )));
    }

    Ok((ip.to_string(), (base_port + VNC_PORT_OFFSET) as u16))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_vnc() {
        let mut vm_config = VmConfig::default();
        let config_line = "0.0.0.0:1,tls-creds=vnc-tls-creds0,sasl,sasl-authz=authz0";
        assert!(vm_config.add_vnc(config_line).is_ok());
        let vnc_config = vm_config.vnc.unwrap();
        assert_eq!(vnc_config.addr.0, String::from("0.0.0.0"));
        assert_eq!(vnc_config.addr.1, 5901);
        assert_eq!(vnc_config.tls_creds, String::from("vnc-tls-creds0"));
        assert!(vnc_config.sasl);
        assert_eq!(vnc_config.sasl_authz, String::from("authz0"));

        let mut vm_config = VmConfig::default();
        let config_line = "0.0.0.0:5900,tls-creds=vnc-tls-creds0";
        assert!(vm_config.add_vnc(config_line).is_ok());
        let vnc_config = vm_config.vnc.unwrap();
        assert!(!vnc_config.sasl);
        assert_eq!(vnc_config.addr.1, 11800);

        let mut vm_config = VmConfig::default();
        let config_line = "0.0.0.0:1,sasl,sasl-authz=authz0";
        assert!(vm_config.add_vnc(config_line).is_ok());
        let vnc_config = vm_config.vnc.unwrap();
        assert_eq!(vnc_config.tls_creds, "".to_string());

        // Invalie format of ip:port.
        let config_lines = [
            "tls-creds=vnc-tls-creds0", // No ip:port.
            "127.0.0.1",                // No port.
            "1",                        // No ip.
            "0.0.0.0:65536",            // Invalid port.
            "0.0.0.0:59636",            // Invalid port.
            "0.0.0.0:2147483647",       // Invalie port.
            "0.0.0.0:-1",               // Invalid port.
            "0.0.0.0:123ab",            // Invalid port.
            "127.257.0.1:0",            // Invalid ip.
            "127.0.0.0.1:0",            // Invalid ip.
            "127.12ab.0.1:0",           // Invalid ip.
            "127.0.1:0",                // Invalid ip.
        ];
        for config_line in config_lines {
            let mut vm_config = VmConfig::default();
            assert!(vm_config.add_vnc(config_line).is_err());
        }
    }
}
