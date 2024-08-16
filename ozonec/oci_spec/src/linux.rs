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

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use nix::sched::CloneFlags;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, Hash)]
#[serde(rename_all = "snake_case")]
/// Available Linux namespaces.
pub enum NamespaceType {
    Cgroup = 0x0200_0000,
    Ipc = 0x0800_0000,
    Network = 0x4000_0000,
    Mount = 0x0002_0000,
    Pid = 0x2000_0000,
    Time = 0x0000_0080,
    User = 0x1000_0000,
    Uts = 0x0400_0000,
}

impl TryInto<CloneFlags> for NamespaceType {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<CloneFlags> {
        match self {
            NamespaceType::Cgroup => Ok(CloneFlags::CLONE_NEWCGROUP),
            NamespaceType::Ipc => Ok(CloneFlags::CLONE_NEWIPC),
            NamespaceType::Network => Ok(CloneFlags::CLONE_NEWNET),
            NamespaceType::Mount => Ok(CloneFlags::CLONE_NEWNS),
            NamespaceType::Pid => Ok(CloneFlags::CLONE_NEWPID),
            NamespaceType::Time => Err(anyhow!("Time namespace not supported with clone")),
            NamespaceType::User => Ok(CloneFlags::CLONE_NEWUSER),
            NamespaceType::Uts => Ok(CloneFlags::CLONE_NEWUTS),
        }
    }
}

impl From<NamespaceType> for String {
    fn from(ns_type: NamespaceType) -> Self {
        match ns_type {
            NamespaceType::Cgroup => String::from("cgroup"),
            NamespaceType::Ipc => String::from("ipc"),
            NamespaceType::Network => String::from("net"),
            NamespaceType::Mount => String::from("mnt"),
            NamespaceType::Pid => String::from("pid"),
            NamespaceType::Time => String::from("time"),
            NamespaceType::User => String::from("user"),
            NamespaceType::Uts => String::from("uts"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Namespaces.
pub struct Namespace {
    /// Namespace type.
    #[serde(rename = "type")]
    pub ns_type: NamespaceType,
    /// Namespace file. If path is not specified, a new namespace is created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// User namespace mappings.
pub struct IdMapping {
    /// Starting uid/gid in the container.
    pub containerID: u32,
    /// Starting uid/gid on the host to be mapped to containerID.
    pub hostID: u32,
    /// Number of ids to be mapped.
    pub size: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Offset for Time Namespace.
pub struct TimeOffsets {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Offset of clock (in seconds) in the container.
    pub secs: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Offset of clock (in nanoseconds) in the container.
    pub nanosecs: Option<u32>,
}

/// Devices available in the container.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Device {
    /// Type of device.
    #[serde(rename = "type")]
    pub dev_type: String,
    /// Full path to device inside container.
    pub path: String,
    /// Major number for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    /// Minor number for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    /// File mode for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fileMode: Option<u32>,
    /// Id of device owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Id of device group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;

    #[test]
    fn test_namespaces() {
        let json = r#"{
            "namespaces": [
                {
                    "type": "pid",
                    "path": "/proc/1234/ns/pid"
                },
                {
                    "type": "network",
                    "path": "/var/run/netns/neta"
                },
                {
                    "type": "mount"
                },
                {
                    "type": "ipc"
                },
                {
                    "type": "uts"
                },
                {
                    "type": "user"
                },
                {
                    "type": "cgroup"
                },
                {
                    "type": "time"
                }
            ]
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            namespaces: Vec<Namespace>,
        }

        let ns: Section = serde_json::from_str(json).unwrap();
        assert_eq!(ns.namespaces.len(), 8);
        assert_eq!(ns.namespaces[0].ns_type, NamespaceType::Pid);
        assert_eq!(ns.namespaces[1].ns_type, NamespaceType::Network);
        assert_eq!(ns.namespaces[2].ns_type, NamespaceType::Mount);
        assert_eq!(ns.namespaces[3].ns_type, NamespaceType::Ipc);
        assert_eq!(ns.namespaces[4].ns_type, NamespaceType::Uts);
        assert_eq!(ns.namespaces[5].ns_type, NamespaceType::User);
        assert_eq!(ns.namespaces[6].ns_type, NamespaceType::Cgroup);
        assert_eq!(ns.namespaces[7].ns_type, NamespaceType::Time);
    }

    #[test]
    fn test_ids_mapping() {
        let json = r#"{
            "uidMappings": [
                {
                    "containerID": 0,
                    "hostID": 1000,
                    "size": 32000
                }
            ],
            "gidMappings": [
                {
                    "containerID": 0,
                    "hostID": 1000,
                    "size": 32000
                }
            ]
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            uidMappings: Vec<IdMapping>,
            gidMappings: Vec<IdMapping>,
        }

        let ids_mapping: Section = serde_json::from_str(json).unwrap();
        assert_eq!(ids_mapping.uidMappings.len(), 1);
        assert_eq!(ids_mapping.uidMappings[0].size, 32000 as u32);
        assert_eq!(ids_mapping.gidMappings.len(), 1);
        assert_eq!(ids_mapping.gidMappings[0].size, 32000 as u32);
    }

    #[test]
    fn test_time_offsets() {
        let json = r#"{
            "timeOffsets": {
                "secs": 100
            }
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            timeOffsets: TimeOffsets,
        }

        let time_offsets: Section = serde_json::from_str(json).unwrap();
        assert_eq!(time_offsets.timeOffsets.secs, Some(100));
        assert_eq!(time_offsets.timeOffsets.nanosecs, None);
    }

    #[test]
    fn test_devices() {
        let json = r#"{
            "devices": [
                {
                    "path": "/dev/fuse",
                    "type": "c",
                    "major": 10,
                    "minor": 229,
                    "fileMode": 438,
                    "uid": 0,
                    "gid": 0
                },
                {
                    "path": "/dev/sda",
                    "type": "b",
                    "major": 8,
                    "minor": 0
                }
            ]
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            devices: Vec<Device>,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.devices.len(), 2);
        assert_eq!(section.devices[1].path, "/dev/sda");
        assert_eq!(section.devices[1].dev_type, "b");
        assert_eq!(section.devices[1].major, Some(8));
        assert_eq!(section.devices[1].minor, Some(0));
        assert_eq!(section.devices[1].fileMode, None);
        assert_eq!(section.devices[1].uid, None);
        assert_eq!(section.devices[1].gid, None);
    }
}
