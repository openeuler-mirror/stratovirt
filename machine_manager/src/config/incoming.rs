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

use std::net::Ipv4Addr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::VmConfig;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MigrateMode {
    File,
    Unix,
    Tcp,
    Unknown,
}

impl From<&str> for MigrateMode {
    fn from(s: &str) -> Self {
        match s {
            "file" | "File" | "FILE" => MigrateMode::File,
            "unix" | "Unix" | "UNIX" => MigrateMode::Unix,
            "tcp" | "Tcp" | "TCP" => MigrateMode::Tcp,
            _ => MigrateMode::Unknown,
        }
    }
}

/// Parse `-incoming` cmdline to migrate mode and path.
pub fn parse_incoming_uri(uri: &str) -> Result<(MigrateMode, String)> {
    let parse_vec: Vec<&str> = uri.split(':').collect();
    if parse_vec.len() == 2 {
        match MigrateMode::from(parse_vec[0]) {
            MigrateMode::File => Ok((MigrateMode::File, String::from(parse_vec[1]))),
            MigrateMode::Unix => Ok((MigrateMode::Unix, String::from(parse_vec[1]))),
            _ => bail!("Invalid incoming uri {}", uri),
        }
    } else if parse_vec.len() == 3 {
        match MigrateMode::from(parse_vec[0]) {
            MigrateMode::Tcp => {
                if parse_vec[1].parse::<Ipv4Addr>().is_err() {
                    bail!("Invalid ip address {}", parse_vec[1]);
                }
                if parse_vec[2].parse::<u16>().is_err() {
                    bail!("Invalid ip port {}", parse_vec[2]);
                }

                Ok((
                    MigrateMode::Tcp,
                    format!("{}:{}", parse_vec[1], parse_vec[2]),
                ))
            }

            _ => bail!("Invalid incoming uri {}", uri),
        }
    } else {
        bail!("Invalid incoming uri {}", uri)
    }
}

pub type Incoming = (MigrateMode, String);

impl VmConfig {
    /// Add incoming mode and path.
    pub fn add_incoming(&mut self, config: &str) -> Result<()> {
        let (mode, uri) = parse_incoming_uri(config)?;
        let incoming = match mode {
            MigrateMode::File => (MigrateMode::File, uri),
            MigrateMode::Unix => (MigrateMode::Unix, uri),
            MigrateMode::Tcp => (MigrateMode::Tcp, uri),
            MigrateMode::Unknown => {
                bail!("Unsupported incoming unix path type")
            }
        };

        self.incoming = Some(incoming);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrate_mode() {
        assert_eq!(MigrateMode::from("File"), MigrateMode::File);
        assert_eq!(MigrateMode::from("UNIX"), MigrateMode::Unix);
        assert_eq!(MigrateMode::from("tcp"), MigrateMode::Tcp);
        assert_eq!(MigrateMode::from("fd"), MigrateMode::Unknown);
    }

    #[test]
    fn test_parse_incoming_uri() {
        let incoming_case1 = "unix:/tmp/stratovirt.sock";
        let result = parse_incoming_uri(incoming_case1);
        assert!(result.is_ok());
        let result_1 = result.unwrap();
        assert_eq!(result_1.0, MigrateMode::Unix);
        assert_eq!(result_1.1, "/tmp/stratovirt.sock".to_string());

        let incoming_case2 = "tcp:192.168.1.2:2022";
        let result = parse_incoming_uri(incoming_case2);
        assert!(result.is_ok());
        let result_2 = result.unwrap();
        assert_eq!(result_2.0, MigrateMode::Tcp);
        assert_eq!(result_2.1, "192.168.1.2:2022".to_string());

        let incoming_case3 = "tcp:192.168.1.2:2:2";
        let result_3 = parse_incoming_uri(incoming_case3);
        assert!(result_3.is_err());

        let incoming_case4 = "tcp:300.168.1.2:22";
        let result_4 = parse_incoming_uri(incoming_case4);
        assert!(result_4.is_err());

        let incoming_case5 = "tcp:192.168.1.2:65568";
        let result_5 = parse_incoming_uri(incoming_case5);
        assert!(result_5.is_err());
    }

    #[test]
    fn test_add_incoming() {
        let mut vm_config_case1 = VmConfig::default();
        assert!(vm_config_case1.add_incoming("tcp:192.168.1.2:2022").is_ok());
        assert_eq!(
            vm_config_case1.incoming.unwrap(),
            (MigrateMode::Tcp, "192.168.1.2:2022".to_string())
        );

        let mut vm_config_case2 = VmConfig::default();
        assert!(vm_config_case2
            .add_incoming("unix:/tmp/stratovirt.sock")
            .is_ok());
        assert_eq!(
            vm_config_case2.incoming.unwrap(),
            (MigrateMode::Unix, "/tmp/stratovirt.sock".to_string())
        );

        let mut vm_config_case2 = VmConfig::default();
        assert!(vm_config_case2.add_incoming("unknown:/tmp/").is_err());
    }
}
