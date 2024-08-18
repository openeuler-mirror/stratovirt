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

use serde::{Deserialize, Serialize};

use crate::{
    linux::{Capbilities, ExecCpuAffinity, IdMapping, IoPriority, Scheduler},
    posix::{Rlimits, User},
};

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

/// Console size in characters of the terminal.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConsoleSize {
    /// Height size in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// Width size in characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
}

/// Container process.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Process {
    /// Working directory that will be set for the executable.
    pub cwd: String,
    /// Similar semantics to IEEE Std 1003.1-2008 execvp's argv.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Same semantics as IEEE Std 1003.1-2008's environ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    /// Whether a terminal is attached to the process.
    #[serde(default)]
    pub terminal: bool,
    /// Console size in characters of the terminal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consoleSize: Option<ConsoleSize>,
    /// Full command line to be executed on Windows.
    #[cfg(target_os = "windows")]
    pub commandLine: Option<String>,
    /// Resource limits for the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rlimits: Option<Vec<Rlimits>>,
    /// Name of the AppArmor profile for the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmorProfile: Option<String>,
    /// Arrays that specifies the sets of capabilities for the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capbilities>,
    /// Setting noNewPrivileges to true prevents the process from
    /// gaining additional privileges.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noNewPrivileges: Option<bool>,
    /// Oom-killer score in [pid]/oom_score_adj for the process's
    /// [pid] in a proc pseudo-filesystem.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oomScoreAdj: Option<i32>,
    /// Scheduler properties for the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<Scheduler>,
    /// SELinux label for the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinuxLabel: Option<String>,
    /// I/O priority settings for the container's processes within
    /// the process group.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioPriority: Option<IoPriority>,
    /// CPU affinity used to execute the process.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execCPUAffinity: Option<ExecCpuAffinity>,
    /// The user for the process that allows specific control over
    /// which user the process runs as.
    pub user: User,
}
