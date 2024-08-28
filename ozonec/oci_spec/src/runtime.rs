// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{collections::HashMap, fs::File, io::BufReader, path::Path};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use crate::linux::IdMapping;
#[cfg(target_family = "unix")]
use crate::posix::Root;
use crate::{linux::LinuxPlatform, posix::Hooks, process::Process, vm::VmPlatform};

/// Additional mounts beyond root.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Mount {
    /// Destination of mount point: path inside container.
    pub destination: String,
    /// A device name, but can also be a file or directory name for bind mounts
    /// or a dummy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Mount options of the filesystem to be used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// The type of the filesystem to be mounted.
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    pub fs_type: Option<String>,
    /// The mapping to convert UIDs from the source file system to the
    /// destination mount point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uidMappings: Option<IdMapping>,
    /// The mapping to convert GIDs from the source file system to the
    /// destination mount point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gidMappings: Option<IdMapping>,
}

/// Metadata necessary to implement standard operations against the container.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuntimeConfig {
    /// Version of the Open Container Initiative Runtime Specification
    /// with which the bundle complies.
    pub ociVersion: String,
    /// Container's root filesystem.
    pub root: Root,
    /// Additional mounts beyond root.
    pub mounts: Vec<Mount>,
    /// Container process.
    pub process: Process,
    /// Container's hostname as seen by processes running inside the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Container's domainname as seen by processes running inside the
    /// container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,
    /// Linux-specific section of the container configuration.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxPlatform>,
    /// Vm-specific section of the container configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vm: Option<VmPlatform>,
    /// Custom actions related to the lifecycle of the container.
    #[cfg(target_family = "unix")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,
    /// Arbitrary metadata for the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

impl RuntimeConfig {
    pub fn from_file(path: &String) -> Result<RuntimeConfig> {
        let file = File::open(Path::new(path)).with_context(|| "Failed to open config.json")?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| anyhow!("Failed to load config.json: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_mounts() {
        let json = r#"{
            "mounts": [
                {
                    "destination": "/proc",
                    "type": "proc",
                    "source": "proc"
                },
                {
                    "destination": "/dev",
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": [
                        "nosuid",
                        "strictatime",
                        "mode=755",
                        "size=65536k"
                    ]
                }
            ]
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            mounts: Vec<Mount>,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.mounts.len(), 2);
        assert_eq!(section.mounts[0].destination, "/proc");
        assert_eq!(section.mounts[0].fs_type, Some("proc".to_string()));
        assert_eq!(section.mounts[0].source, Some("proc".to_string()));
        let options = section.mounts[1].options.as_ref().unwrap();
        assert_eq!(options.len(), 4);
        assert_eq!(options[0], "nosuid");
        assert_eq!(options[1], "strictatime");
        assert_eq!(options[2], "mode=755");
        assert_eq!(options[3], "size=65536k");
    }
}
