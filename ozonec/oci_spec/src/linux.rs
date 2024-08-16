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

fn default_device_type() -> String {
    "a".to_string()
}

/// Allowed device in Device Cgroup.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CgroupDevice {
    /// Whether the entry is allowed or denied.
    pub allow: bool,
    /// Type of device.
    #[serde(default = "default_device_type", rename = "type")]
    pub dev_type: String,
    /// Major number for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<i64>,
    /// Minor number for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<i64>,
    /// Cgroup permissions for device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

/// Cgroup subsystem to set limits on the container's memory usage.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryCgroup {
    /// Limit of memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// Soft limit of memory usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation: Option<i64>,
    /// Limits of memory +Swap usage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<i64>,
    /// Hard limit for kernel memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<i64>,
    /// Hard limit for kernel TCP buffer memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernelTCP: Option<i64>,
    /// Swappiness parameter of vmscan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swappiness: Option<u64>,
    /// Enable or disable the OOM killer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disableOOMKiller: Option<bool>,
    /// Enable or disable hierarchical memory accounting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub useHierarchy: Option<bool>,
    /// Enable container memory usage check before setting a new limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkBeforeUpdate: Option<bool>,
}

/// Cgroup subsystems cpu and cpusets.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CpuCgroup {
    /// Relative share of CPU time available to the tasks in a cgroup.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shares: Option<u64>,
    /// Total amount of time in microseconds for which all tasks in a
    /// cgroup can run during one period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<i64>,
    /// Maximum amount of accumulated time in microseconds for which
    /// all tasks in a cgroup can run additionally for burst during
    /// one period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u64>,
    /// Period of time in microseconds for how regularly a cgroup's access
    /// to CPU resources should be reallocated (CFS scheduler only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
    /// Period of time in microseconds for the longest continuous period
    /// in which the tasks in a cgrouop have access to CPU resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtimeRuntime: Option<i64>,
    /// Same as period but applies to realtime scheduler only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realtimePeriod: Option<i64>,
    /// List of CPUs the container will run on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<String>,
    /// List of memory nodes the container will run on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mems: Option<String>,
    /// Cgroups are configured with minimum weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle: Option<i64>,
}

/// Per-device bandwidth weights.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WeightDevice {
    /// Major number for device.
    pub major: i64,
    /// Minor number for device.
    pub minor: i64,
    /// Bandwidth weight for the device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// Bandwidth weight for the device while competing with the cgroup's
    /// child cgroups (CFS scheduler only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leafWeight: Option<u16>,
}

/// Per-device bandwidth rate limits.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ThrottleDevice {
    /// Major number for device.
    pub major: i64,
    /// Minor number for device.
    pub minor: i64,
    /// Bandwidth rate limit in bytes per second or IO rate limit for
    /// the device.
    pub rate: u64,
}

/// Cgroup subsystem blkio which implements the block IO controller.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockIoCgroup {
    /// Per-cgroup weight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<u16>,
    /// Equivalents of weight for the purpose of deciding how much
    /// weight tasks in the given cgroup has while competing with
    /// the cgroup's child cgroups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leafWeight: Option<u16>,
    /// Array of per-device bandwidth weights.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weightDevice: Option<Vec<WeightDevice>>,
    /// Array of per-device read bandwidth rate limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttleReadBpsDevice: Option<Vec<ThrottleDevice>>,
    /// Array of per-device write bandwidth rate limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttleWriteBpsDevice: Option<Vec<ThrottleDevice>>,
    /// Array of per-device read IO rate limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttleReadIOPSDevice: Option<Vec<ThrottleDevice>>,
    /// Array of per-device write IO rate limits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttleWriteIOPSDevice: Option<Vec<ThrottleDevice>>,
}

/// hugetlb controller which allows to limit the HugeTLB reservations
/// (if supported) or usage (page fault).
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HugetlbCgroup {
    /// Hugepage size
    pub pageSize: String,
    /// Limit in bytes of hugepagesize HugeTLB reservations
    /// (if supported) or usage.
    pub limit: u64,
}

/// Priority assigned to traffic originating from processes in the
/// group and egressing the system on various interfaces.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetPriority {
    /// Interface name.
    pub name: String,
    /// Priority applied to the interface.
    pub priority: u32,
}

/// Cgroup subsystems net_cls and net_prio.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkCgroup {
    /// Network class identifier the cgroup's network packets will
    /// be tagged with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classID: Option<u32>,
    /// List of objects of the priorities assigned to traffic
    /// originating from processes in the group and egressing the
    /// system on various interfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priorities: Option<Vec<NetPriority>>,
}

/// Cgroup subsystem pids.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PidsCgroup {
    /// Maximum number of tasks in the cgroup.
    pub limit: i64,
}

/// Per-device rdma limit.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RdmaLimit {
    /// Maximum number of hca_handles in the cgroup.
    pub hcaHandles: Option<u32>,
    /// Maximum number of hca_objects in the cgroup.
    pub hcaObjects: Option<u32>,
}

/// Cgroup subsystem rdma.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RdmaCgroup {
    /// Rdma limit for mlx5_1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mlx5_1: Option<RdmaLimit>,
    /// Rdma limit for mlx4_0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mlx4_0: Option<RdmaLimit>,
    /// Rdma limit for rxe3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rxe3: Option<RdmaLimit>,
}

/// Cgroups to restrict resource usage for a container and
/// handle device access.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Cgroups {
    /// Device cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<CgroupDevice>>,
    /// Memory cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryCgroup>,
    /// Cpu and Cpuset cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuCgroup>,
    /// Blkio cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockIO: Option<BlockIoCgroup>,
    /// Hugetlb cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugepageLimits: Option<Vec<HugetlbCgroup>>,
    /// Network cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkCgroup>,
    /// Pids cgroup settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<PidsCgroup>,
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

    #[test]
    fn test_cgroup_devices() {
        let json = r#"{
            "devices": [
                {
                    "allow": false
                },
                {
                    "allow": true,
                    "type": "c",
                    "major": 10,
                    "minor": 229,
                    "access": "rw"
                }
            ]
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            devices: Vec<CgroupDevice>,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.devices.len(), 2);
        assert_eq!(section.devices[0].allow, false);
        assert_eq!(section.devices[0].dev_type, "a");
        assert_eq!(section.devices[0].major, None);
        assert_eq!(section.devices[0].minor, None);
        assert_eq!(section.devices[0].access, None);
        assert_eq!(section.devices[1].allow, true);
        assert_eq!(section.devices[1].dev_type, "c");
        assert_eq!(section.devices[1].major, Some(10));
        assert_eq!(section.devices[1].minor, Some(229));
        assert_eq!(section.devices[1].access, Some("rw".to_string()));
    }

    #[test]
    fn test_cgroup_memory_01() {
        let json = r#"{
            "memory": {
                "limit": 536870912,
                "reservation": 536870912,
                "swap": 536870912,
                "kernel": -1,
                "kernelTCP": -1,
                "swappiness": 0,
                "disableOOMKiller": false
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            memory: MemoryCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.memory.limit, Some(536870912));
        assert_eq!(section.memory.reservation, Some(536870912));
        assert_eq!(section.memory.swap, Some(536870912));
        assert_eq!(section.memory.kernel, Some(-1));
        assert_eq!(section.memory.kernelTCP, Some(-1));
        assert_eq!(section.memory.swappiness, Some(0));
        assert_eq!(section.memory.disableOOMKiller, Some(false));
        assert_eq!(section.memory.useHierarchy, None);
        assert_eq!(section.memory.checkBeforeUpdate, None);
    }

    #[test]
    fn test_cgroup_memory_02() {
        let json = r#"{
            "memory": {
                "useHierarchy": true,
                "checkBeforeUpdate": true
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            memory: MemoryCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.memory.limit, None);
        assert_eq!(section.memory.reservation, None);
        assert_eq!(section.memory.swap, None);
        assert_eq!(section.memory.kernel, None);
        assert_eq!(section.memory.kernelTCP, None);
        assert_eq!(section.memory.swappiness, None);
        assert_eq!(section.memory.disableOOMKiller, None);
        assert_eq!(section.memory.useHierarchy, Some(true));
        assert_eq!(section.memory.checkBeforeUpdate, Some(true));
    }

    #[test]
    fn test_cgroup_cpu_01() {
        let json = r#"{
            "cpu": {
                "shares": 1024,
                "quota": 1000000,
                "burst": 1000000,
                "period": 500000,
                "realtimeRuntime": 950000,
                "realtimePeriod": 1000000,
                "cpus": "2-3",
                "mems": "0-7",
                "idle": 0
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            cpu: CpuCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.cpu.shares, Some(1024));
        assert_eq!(section.cpu.quota, Some(1000000));
        assert_eq!(section.cpu.burst, Some(1000000));
        assert_eq!(section.cpu.period, Some(500000));
        assert_eq!(section.cpu.realtimeRuntime, Some(950000));
        assert_eq!(section.cpu.realtimePeriod, Some(1000000));
        assert_eq!(section.cpu.cpus, Some("2-3".to_string()));
        assert_eq!(section.cpu.mems, Some("0-7".to_string()));
        assert_eq!(section.cpu.idle, Some(0));
    }

    #[test]
    fn test_cgroup_cpu_02() {
        let json = r#"{
            "cpu": {}
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            cpu: CpuCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.cpu.shares, None);
        assert_eq!(section.cpu.quota, None);
        assert_eq!(section.cpu.burst, None);
        assert_eq!(section.cpu.period, None);
        assert_eq!(section.cpu.realtimeRuntime, None);
        assert_eq!(section.cpu.realtimePeriod, None);
        assert_eq!(section.cpu.cpus, None);
        assert_eq!(section.cpu.mems, None);
        assert_eq!(section.cpu.idle, None);
    }

    #[test]
    fn test_cgroup_blkio() {
        let json = r#"{
            "blockIO": {
                "weight": 10,
                "leafWeight": 10,
                "weightDevice": [
                    {
                        "major": 8,
                        "minor": 0,
                        "weight": 500,
                        "leafWeight": 300
                    },
                    {
                        "major": 8,
                        "minor": 16
                    }
                ],
                "throttleReadBpsDevice": [
                    {
                        "major": 8,
                        "minor": 0,
                        "rate": 600
                    },
                    {
                        "major": 8,
                        "minor": 16,
                        "rate": 300
                    }
                ]
            }
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            blockIO: BlockIoCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.blockIO.weight, Some(10));
        assert_eq!(section.blockIO.leafWeight, Some(10));
        assert_eq!(section.blockIO.throttleReadIOPSDevice, None);
        assert_eq!(section.blockIO.throttleWriteBpsDevice, None);
        assert_eq!(section.blockIO.throttleWriteIOPSDevice, None);

        let weight_device = section.blockIO.weightDevice.as_ref().unwrap();
        assert_eq!(weight_device.len(), 2);
        assert_eq!(weight_device[0].major, 8);
        assert_eq!(weight_device[0].minor, 0);
        assert_eq!(weight_device[0].weight, Some(500));
        assert_eq!(weight_device[0].leafWeight, Some(300));
        assert_eq!(weight_device[1].major, 8);
        assert_eq!(weight_device[1].minor, 16);
        assert_eq!(weight_device[1].weight, None);
        assert_eq!(weight_device[1].leafWeight, None);

        let throttle = section.blockIO.throttleReadBpsDevice.as_ref().unwrap();
        assert_eq!(throttle.len(), 2);
        assert_eq!(throttle[1].major, 8);
        assert_eq!(throttle[1].minor, 16);
        assert_eq!(throttle[1].rate, 300);
    }
}
