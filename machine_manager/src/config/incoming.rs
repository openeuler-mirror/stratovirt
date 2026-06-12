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
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};

use super::{str_slip_to_clap, VmConfig};

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

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SnapshotMemoryMode {
    Full,
    External,
}

impl FromStr for SnapshotMemoryMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "full" | "Full" | "FULL" => Ok(SnapshotMemoryMode::Full),
            "external" | "External" | "EXTERNAL" => Ok(SnapshotMemoryMode::External),
            _ => Err(format!("Unsupported memory snapshot mode {}", s)),
        }
    }
}

/// Config struct for `incoming`.
#[derive(Parser, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct IncomingConfig {
    // Migration mode. There are four modes in total: Tcp, Unix, File and Unknown.
    #[arg(long)]
    pub mode: MigrateMode,
    // Path.
    #[arg(long)]
    pub uri: String,
    // File MigrateMode specific. Determine whether to directly map the file.
    // Quick start is true to map the file. Memory snapshot is false to read from
    // the file instead of mapping.
    #[arg(long, default_value = "true", action = ArgAction::Append)]
    pub mapped: bool,
    // UFFD lazy-load: Unix socket path of the external uffd daemon.
    // When set, memory is served on demand via userfaultfd instead of being
    // loaded from disk upfront.  File mode only.
    #[arg(long = "uffd_sock")]
    pub uffd_sock: Option<String>,
    #[arg(long = "memory", default_value = "full")]
    pub memory: SnapshotMemoryMode,
}

impl Default for IncomingConfig {
    fn default() -> Self {
        Self {
            mode: MigrateMode::Unknown,
            uri: String::new(),
            mapped: true,
            uffd_sock: None,
            memory: SnapshotMemoryMode::Full,
        }
    }
}

impl IncomingConfig {
    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split(',');
        let (mode, uri) = parts
            .next()
            .and_then(|s| s.split_once(':'))
            .with_context(|| format!("Invalid incoming config {}", s))?;
        let mut cli_args = format!("mode={},uri={}", mode, uri);
        // Collect all remaining key=value options (mapped, uffd_sock, …)
        for extra in parts {
            cli_args.push_str(&format!(",{}", extra));
        }

        let config = IncomingConfig::try_parse_from(str_slip_to_clap(&cli_args, false, false))?;
        Ok(config)
    }

    fn check_common_valid(&self) -> Result<()> {
        let uri_vec: Vec<&str> = self.uri.split(':').collect();
        let uri_vec_len = uri_vec.len();
        // File or Unix should not have ':'. TCP/IP address should have.
        if ![1, 2].contains(&uri_vec_len)
            || ((self.mode == MigrateMode::File || self.mode == MigrateMode::Unix)
                && uri_vec_len != 1)
            || (self.mode == MigrateMode::Tcp && uri_vec_len != 2)
        {
            bail!("Invalid incoming uri. {:?}", self);
        }

        if self.mode == MigrateMode::Tcp {
            uri_vec[0]
                .parse::<Ipv4Addr>()
                .with_context(|| format!("Invalid ip address {}", uri_vec[0]))?;
            uri_vec[1]
                .parse::<u16>()
                .with_context(|| format!("Invalid ip port {}", uri_vec[1]))?;
        }

        if self.uffd_sock.is_some() && self.mode != MigrateMode::File {
            bail!("uffd_sock is only valid with file mode");
        }

        if self.uffd_sock.is_some() && self.mapped {
            bail!("uffd_sock and mapped=true are mutually exclusive: memory is served by the uffd daemon, not mmap'd from disk");
        }

        if self.memory == SnapshotMemoryMode::External && self.mode != MigrateMode::File {
            bail!("memory=external is only valid with file mode");
        }

        Ok(())
    }

    fn check_incoming_valid(&self) -> Result<()> {
        self.check_common_valid()?;

        if self.memory == SnapshotMemoryMode::External && self.mapped {
            bail!("memory=external requires mapped=false");
        }

        if self.memory == SnapshotMemoryMode::External && self.uffd_sock.is_none() {
            bail!("memory=external requires uffd_sock");
        }

        Ok(())
    }

    fn check_migrate_valid(&self) -> Result<()> {
        self.check_common_valid()?;

        if self.uffd_sock.is_some() {
            bail!("uffd_sock is only valid with incoming snapshot restore");
        }

        Ok(())
    }
}

/// Parse `-incoming` cmdline to migrate mode and path.
pub fn parse_incoming_uri(uri: &str) -> Result<IncomingConfig> {
    let incoming_cfg = IncomingConfig::from_str(uri)?;
    incoming_cfg.check_incoming_valid()?;
    Ok(incoming_cfg)
}

/// Parse QMP migrate URI.
pub fn parse_migrate_uri(uri: &str) -> Result<IncomingConfig> {
    let migrate_cfg = IncomingConfig::from_str(uri)?;
    migrate_cfg.check_migrate_valid()?;
    Ok(migrate_cfg)
}

impl VmConfig {
    /// Add incoming mode and path.
    pub fn add_incoming(&mut self, config: &str) -> Result<()> {
        let incoming_cfg = parse_incoming_uri(config)?;
        if incoming_cfg.mode == MigrateMode::Unknown {
            bail!("Unsupported incoming unix path type");
        }

        self.incoming = Some(incoming_cfg);
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
        assert_eq!(result_1.mode, MigrateMode::Unix);
        assert_eq!(result_1.uri, "/tmp/stratovirt.sock".to_string());
        assert_eq!(result_1.uffd_sock, None);
        assert_eq!(result_1.memory, SnapshotMemoryMode::Full);

        let incoming_case2 = "tcp:192.168.1.2:2022";
        let result = parse_incoming_uri(incoming_case2);
        assert!(result.is_ok());
        let result_2 = result.unwrap();
        assert_eq!(result_2.mode, MigrateMode::Tcp);
        assert_eq!(result_2.uri, "192.168.1.2:2022".to_string());

        let incoming_case3 = "tcp:192.168.1.2:2:2";
        let result_3 = parse_incoming_uri(incoming_case3);
        assert!(result_3.is_err());

        let incoming_case4 = "tcp:300.168.1.2:22";
        let result_4 = parse_incoming_uri(incoming_case4);
        assert!(result_4.is_err());

        let incoming_case5 = "tcp:192.168.1.2:65568";
        let result_5 = parse_incoming_uri(incoming_case5);
        assert!(result_5.is_err());

        let incoming_case6 = "file:/tmp/incoming_file";
        let result = parse_incoming_uri(incoming_case6);
        assert!(result.is_ok());
        let result_6 = result.unwrap();
        assert_eq!(result_6.mode, MigrateMode::File);
        assert_eq!(result_6.uri, "/tmp/incoming_file".to_string());
        assert_eq!(result_6.mapped, true);
        assert_eq!(result_6.uffd_sock, None);
        assert_eq!(result_6.memory, SnapshotMemoryMode::Full);

        let incoming_case7 = "file:/tmp/incoming_file,mapped=false";
        let result7 = parse_incoming_uri(incoming_case7);
        assert!(result7.is_ok());
        assert_eq!(result7.unwrap().mapped, false);

        // UFFD fields
        let incoming_uffd = "file:/tmp/snap,mapped=false,uffd_sock=/run/uffd.sock";
        let result_uffd = parse_incoming_uri(incoming_uffd);
        assert!(result_uffd.is_ok());
        let cfg = result_uffd.unwrap();
        assert_eq!(cfg.mode, MigrateMode::File);
        assert_eq!(cfg.uri, "/tmp/snap".to_string());
        assert_eq!(cfg.mapped, false);
        assert_eq!(cfg.uffd_sock, Some("/run/uffd.sock".to_string()));
        assert_eq!(cfg.memory, SnapshotMemoryMode::Full);

        let incoming_external =
            "file:/tmp/snap,memory=external,mapped=false,uffd_sock=/run/uffd.sock";
        let result_external = parse_incoming_uri(incoming_external);
        assert!(result_external.is_ok());
        let cfg = result_external.unwrap();
        assert_eq!(cfg.memory, SnapshotMemoryMode::External);
        assert_eq!(cfg.mapped, false);
        assert_eq!(cfg.uffd_sock, Some("/run/uffd.sock".to_string()));

        // UFFD fields are rejected on non-file mode
        let bad_uffd = "unix:/tmp/sock,uffd_sock=/run/uffd.sock";
        assert!(parse_incoming_uri(bad_uffd).is_err());

        // uffd_sock + mapped=true is rejected (mutually exclusive)
        let bad_uffd_mapped = "file:/tmp/snap,uffd_sock=/run/uffd.sock";
        assert!(parse_incoming_uri(bad_uffd_mapped).is_err());

        let bad_uffd_mapped_explicit = "file:/tmp/snap,mapped=true,uffd_sock=/run/uffd.sock";
        assert!(parse_incoming_uri(bad_uffd_mapped_explicit).is_err());

        let bad_external_without_uffd = "file:/tmp/snap,memory=external,mapped=false";
        assert!(parse_incoming_uri(bad_external_without_uffd).is_err());

        let bad_external_mapped =
            "file:/tmp/snap,memory=external,mapped=true,uffd_sock=/run/uffd.sock";
        assert!(parse_incoming_uri(bad_external_mapped).is_err());

        let bad_memory_mode = "file:/tmp/snap,memory=unknown";
        assert!(parse_incoming_uri(bad_memory_mode).is_err());
    }

    #[test]
    fn test_parse_migrate_uri() {
        let migrate_external = parse_migrate_uri("file:/tmp/snap,memory=external");
        assert!(migrate_external.is_ok());
        let cfg = migrate_external.unwrap();
        assert_eq!(cfg.mode, MigrateMode::File);
        assert_eq!(cfg.uri, "/tmp/snap".to_string());
        assert_eq!(cfg.memory, SnapshotMemoryMode::External);
        assert_eq!(cfg.mapped, true);
        assert_eq!(cfg.uffd_sock, None);

        let bad_external_tcp = "tcp:127.0.0.1:2022,memory=external";
        assert!(parse_migrate_uri(bad_external_tcp).is_err());

        let save_side_mapped_false = parse_migrate_uri("file:/tmp/snap,mapped=false");
        assert!(save_side_mapped_false.is_ok());
        assert!(!save_side_mapped_false.unwrap().mapped);

        let external_mapped_false =
            parse_migrate_uri("file:/tmp/snap,memory=external,mapped=false");
        assert!(external_mapped_false.is_ok());
        let cfg = external_mapped_false.unwrap();
        assert_eq!(cfg.memory, SnapshotMemoryMode::External);
        assert!(!cfg.mapped);

        let restore_only_uffd_sock = "file:/tmp/snap,uffd_sock=/run/uffd.sock";
        assert!(parse_migrate_uri(restore_only_uffd_sock).is_err());
    }

    #[test]
    fn test_add_incoming() {
        let mut vm_config_case1 = VmConfig::default();
        assert!(vm_config_case1.add_incoming("tcp:192.168.1.2:2022").is_ok());
        assert_eq!(
            vm_config_case1.incoming.unwrap(),
            IncomingConfig {
                mode: MigrateMode::Tcp,
                uri: "192.168.1.2:2022".to_string(),
                mapped: true,
                uffd_sock: None,
                memory: SnapshotMemoryMode::Full,
            }
        );

        let mut vm_config_case2 = VmConfig::default();
        assert!(vm_config_case2
            .add_incoming("unix:/tmp/stratovirt.sock")
            .is_ok());
        assert_eq!(
            vm_config_case2.incoming.unwrap(),
            IncomingConfig {
                mode: MigrateMode::Unix,
                uri: "/tmp/stratovirt.sock".to_string(),
                mapped: true,
                uffd_sock: None,
                memory: SnapshotMemoryMode::Full,
            }
        );

        let mut vm_config_case3 = VmConfig::default();
        assert!(vm_config_case3.add_incoming("unknown:/tmp/").is_err());

        let mut vm_config_case4 = VmConfig::default();
        assert!(vm_config_case4
            .add_incoming("file:/tmp/stratovirt_file,mapped=false")
            .is_ok());
        assert_eq!(
            vm_config_case4.incoming.unwrap(),
            IncomingConfig {
                mode: MigrateMode::File,
                uri: "/tmp/stratovirt_file".to_string(),
                mapped: false,
                uffd_sock: None,
                memory: SnapshotMemoryMode::Full,
            }
        );

        // UFFD fields
        let mut vm_config_case5 = VmConfig::default();
        assert!(vm_config_case5
            .add_incoming("file:/tmp/snap,mapped=false,uffd_sock=/run/uffd.sock")
            .is_ok());
        assert_eq!(
            vm_config_case5.incoming.unwrap(),
            IncomingConfig {
                mode: MigrateMode::File,
                uri: "/tmp/snap".to_string(),
                mapped: false,
                uffd_sock: Some("/run/uffd.sock".to_string()),
                memory: SnapshotMemoryMode::Full,
            }
        );

        let mut vm_config_case6 = VmConfig::default();
        assert!(vm_config_case6
            .add_incoming("file:/tmp/snap,memory=external,mapped=false,uffd_sock=/run/uffd.sock")
            .is_ok());
        assert_eq!(
            vm_config_case6.incoming.unwrap(),
            IncomingConfig {
                mode: MigrateMode::File,
                uri: "/tmp/snap".to_string(),
                mapped: false,
                uffd_sock: Some("/run/uffd.sock".to_string()),
                memory: SnapshotMemoryMode::External,
            }
        );
    }
}
