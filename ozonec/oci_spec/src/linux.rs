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

use std::{collections::HashMap, path::PathBuf};

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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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

#[cfg(target_arch = "x86_64")]
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Intel Resource Director Technology
pub struct IntelRdt {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Identity for RDT Class of Service (CLOS).
    pub closID: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Schema for L3 cache id and capacity bitmask (CBM).
    pub l3CacheSchema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Schema of memory bandwidth per L3 cache id.
    pub memBwSchema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// If Intel RDT CMT should be enabled.
    pub enableCMT: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// If Intel RDT MBM should be enabled.
    pub enableMBM: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u32)]
/// Action for seccomp rules.
pub enum SeccompAction {
    ScmpActKill = 0x0000_0000,
    ScmpActKillProcess = 0x8000_0000,
    ScmpActTrap = 0x0003_0000,
    ScmpActErrno = 0x0005_0001,
    ScmpActNotify = 0x7fc0_0000,
    ScmpActTrace = 0x7ff0_0001,
    ScmpActLog = 0x7ffc_0000,
    ScmpActAllow = 0x7fff_0000,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u32)]
/// Operator for syscall arguments in seccomp.
pub enum SeccompOp {
    ScmpCmpNe = 1,
    ScmpCmpLt = 2,
    ScmpCmpLe = 3,
    #[default]
    ScmpCmpEq = 4,
    ScmpCmpGe = 5,
    ScmpCmpGt = 6,
    ScmpCmpMaskedEq = 7,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// The specific syscall in seccomp.
pub struct SeccompSyscallArg {
    /// Index for syscall arguments.
    pub index: usize,
    /// Value for syscall arguments.
    pub value: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Value for syscall arguments.
    pub valueTwo: Option<u64>,
    /// Operator for syscall arguments.
    pub op: SeccompOp,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Match a syscall in seccomp.
pub struct SeccompSyscall {
    /// Names of the syscalls.
    pub names: Vec<String>,
    /// Action for seccomp rules.
    pub action: SeccompAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Errno return code to use.
    pub errnoRet: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Specific syscall in seccomp.
    pub args: Option<Vec<SeccompSyscallArg>>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Seccomp provides application sandboxing mechanism in the Linux kernel.
pub struct Seccomp {
    /// Default action for seccomp.
    pub defaultAction: SeccompAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Errno return code to use.
    pub defaultErrnoRet: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Architecture used for system calls.
    pub architectures: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// List of flags to use with seccomp.
    pub flags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Path of UNIX domain socket over which the runtime will send the
    /// container process state data structure when the SCMP_ACT_NOTIFY
    /// action is used.
    pub listennerPath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Seccomp file descriptor returned by the seccomp syscall.
    pub seccompFd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Opaque data to pass to the seccomp agent.
    pub listenerMetadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Match a syscall in seccomp.
    pub syscalls: Option<Vec<SeccompSyscall>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Linux execution personality.
pub struct Personality {
    /// Execution domain.
    pub domain: String,
    /// Additional flags to apply.
    pub flags: Option<Vec<String>>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Linux-specific configuration.
pub struct LinuxPlatform {
    /// A namespace wraps a global system resource in an abstraction.
    pub namespaces: Vec<Namespace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// User namespace uid mappings from the host to the container.
    pub uidMappings: Option<Vec<IdMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// User namespace gid mappings from the host to the container.
    pub gidMappings: Option<Vec<IdMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Offset for Time Namespace.
    pub timeOffsets: Option<TimeOffsets>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Lists devices that MUST be available in the container.
    pub devices: Option<Vec<Device>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Path to the cgroups.
    pub cgroupsPath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Rootfs's mount propagation.
    pub rootfsPropagation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Mask over the provided paths inside the container so
    /// that they cannot be read.
    pub maskedPaths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Set the provided paths as readonly inside the container.
    pub readonlyPaths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Selinux context for the mounts in the container.
    pub mountLabel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Linux execution personality.
    pub personality: Option<Personality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Configure a container's cgroups.
    pub resources: Option<Cgroups>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The cgroup subsystem rdma.
    pub rdma: Option<RdmaCgroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Allows cgroup v2 parameters to be to be set and modified
    /// for the container.
    pub unified: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Kernel parameters to be modified at runtime for the
    /// container.
    pub sysctl: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Seccomp provides application sandboxing mechanism in
    /// the Linux kernel.
    pub seccomp: Option<Seccomp>,
    #[cfg(target_arch = "x86_64")]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Intel Resource Director Technology.
    pub intelRdt: Option<IntelRdt>,
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

    #[test]
    fn test_cgroup_hugetlb() {
        let json = r#"{
            "hugepageLimits": [
                {
                    "pageSize": "2MB",
                    "limit": 209715200
                }
            ]
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            hugepageLimits: Vec<HugetlbCgroup>,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.hugepageLimits[0].pageSize, "2MB");
        assert_eq!(section.hugepageLimits[0].limit, 209715200);
    }

    #[test]
    fn test_cgroup_network_01() {
        let json = r#"{
            "network": {
                "classID": 1048577,
                "priorities": [
                    {
                        "name": "eth0",
                        "priority": 500
                    }
                ]
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            network: NetworkCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.network.classID, Some(1048577));
        let priorities = section.network.priorities.as_ref().unwrap();
        assert_eq!(priorities[0].name, "eth0");
        assert_eq!(priorities[0].priority, 500);
    }

    #[test]
    fn test_cgroup_network_02() {
        let json = r#"{
            "network": {}
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            network: NetworkCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.network.classID, None);
        assert_eq!(section.network.priorities, None);
    }

    #[test]
    fn test_cgroup_pid() {
        let json = r#"{
            "pids": {
                "limit": 32771
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            pids: PidsCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.pids.limit, 32771);
    }

    #[test]
    fn test_cgroup_rdma() {
        let json = r#"{
            "rdma": {
                "mlx5_1": {
                    "hcaHandles": 3,
                    "hcaObjects": 10000
                },
                "mlx4_0": {
                    "hcaObjects": 1000
                },
                "rxe3": {
                    "hcaHandles": 10000
                }
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            rdma: RdmaCgroup,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        let rdma_limit = section.rdma.mlx5_1.as_ref().unwrap();
        assert_eq!(rdma_limit.hcaHandles, Some(3));
        assert_eq!(rdma_limit.hcaObjects, Some(10000));
        let rdma_limit = section.rdma.mlx4_0.as_ref().unwrap();
        assert_eq!(rdma_limit.hcaHandles, None);
        assert_eq!(rdma_limit.hcaObjects, Some(1000));
        let rdma_limit = section.rdma.rxe3.as_ref().unwrap();
        assert_eq!(rdma_limit.hcaHandles, Some(10000));
        assert_eq!(rdma_limit.hcaObjects, None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_intel_rdt() {
        let json = r#"{
            "intelRdt": {
                "closID": "guaranteed_group",
                "l3CacheSchema": "L3:0=7f0;1=1f",
                "memBwSchema": "MB:0=20;1=70",
                "enableCMT": true,
                "enableMBM": true
            }
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            intelRdt: IntelRdt,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(
            section.intelRdt.closID,
            Some("guaranteed_group".to_string())
        );
        assert_eq!(
            section.intelRdt.l3CacheSchema,
            Some("L3:0=7f0;1=1f".to_string())
        );
        assert_eq!(
            section.intelRdt.memBwSchema,
            Some("MB:0=20;1=70".to_string())
        );
        assert_eq!(section.intelRdt.enableCMT, Some(true));
        assert_eq!(section.intelRdt.enableMBM, Some(true));
    }

    #[test]
    fn test_seccomp() {
        let json = r#"{
            "seccomp": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "architectures": [
                    "SCMP_ARCH_X86",
                    "SCMP_ARCH_X32"
                ],
                "syscalls": [
                    {
                        "names": [
                            "getcwd",
                            "chmod"
                        ],
                        "action": "SCMP_ACT_ERRNO"
                    }
                ]
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            seccomp: Seccomp,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.seccomp.defaultAction, SeccompAction::ScmpActAllow);
        let architectures = section.seccomp.architectures.as_ref().unwrap();
        assert_eq!(architectures.len(), 2);
        assert_eq!(architectures[0], "SCMP_ARCH_X86");
        assert_eq!(architectures[1], "SCMP_ARCH_X32");
        let syscall_names = section.seccomp.syscalls.as_ref().unwrap();
        assert_eq!(syscall_names[0].names.len(), 2);
        assert_eq!(syscall_names[0].names[0], "getcwd");
        assert_eq!(syscall_names[0].names[1], "chmod");
        assert_eq!(syscall_names[0].action, SeccompAction::ScmpActErrno);
    }

    #[test]
    fn test_personality() {
        let json = r#"{
            "personality": {
                "domain": "LINUX"
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            personality: Personality,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.personality.domain, "LINUX");
        assert_eq!(section.personality.flags, None);
    }
}
