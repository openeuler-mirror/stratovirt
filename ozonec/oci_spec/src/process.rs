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

#[cfg(test)]
mod tests {
    use crate::linux::IoPriClass;

    use super::*;
    use serde_json;

    #[test]
    fn test_process() {
        let json = r#"{
            "process": {
                "terminal": true,
                "consoleSize": {
                    "height": 25,
                    "width": 80
                },
                "user": {
                    "uid": 1,
                    "gid": 1,
                    "umask": 63,
                    "additionalGids": [5, 6]
                },
                "env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "TERM=xterm"
                ],
                "cwd": "/root",
                "args": [
                    "sh"
                ],
                "apparmorProfile": "acme_secure_profile",
                "selinuxLabel": "system_u:system_r:svirt_lxc_net_t:s0:c124,c675",
                "ioPriority": {
                    "class": "IOPRIO_CLASS_IDLE",
                    "priority": 4
                },
                "noNewPrivileges": true,
                "capabilities": {
                    "bounding": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL",
                        "CAP_NET_BIND_SERVICE"
                    ],
                    "permitted": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL",
                        "CAP_NET_BIND_SERVICE"
                    ],
                    "inheritable": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL",
                        "CAP_NET_BIND_SERVICE"
                    ],
                    "effective": [
                        "CAP_AUDIT_WRITE",
                        "CAP_KILL"
                    ],
                    "ambient": [
                        "CAP_NET_BIND_SERVICE"
                    ]
                },
                "rlimits": [
                    {
                        "type": "RLIMIT_NOFILE",
                        "hard": 1024,
                        "soft": 1024
                    }
                ],
                "execCPUAffinity": {
                    "initial": "7",
                    "final": "0-3,7"
                }
            }
        }"#;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize)]
        struct Section {
            process: Process,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.process.terminal, true);
        let console_size = section.process.consoleSize.as_ref().unwrap();
        assert_eq!(console_size.height, Some(25));
        assert_eq!(console_size.width, Some(80));
        assert_eq!(section.process.user.uid, 1);
        assert_eq!(section.process.user.gid, 1);
        assert_eq!(section.process.user.umask, Some(63));
        assert_eq!(section.process.user.additionalGids, Some(vec![5, 6]));
        let env = section.process.env.as_ref().unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(
            env[0],
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
        assert_eq!(env[1], "TERM=xterm");
        assert_eq!(section.process.cwd, "/root");
        let args = section.process.args.as_ref().unwrap();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0], "sh");
        assert_eq!(
            section.process.apparmorProfile,
            Some("acme_secure_profile".to_string())
        );
        assert_eq!(
            section.process.selinuxLabel,
            Some("system_u:system_r:svirt_lxc_net_t:s0:c124,c675".to_string())
        );
        let io_pri = section.process.ioPriority.as_ref().unwrap();
        assert_eq!(io_pri.class, IoPriClass::IoprioClassIdle);
        assert_eq!(io_pri.priority, 4);
        assert_eq!(section.process.noNewPrivileges, Some(true));
        let caps = section.process.capabilities.as_ref().unwrap();
        let bonding_caps = caps.bounding.as_ref().unwrap();
        assert_eq!(bonding_caps.len(), 3);
        assert_eq!(bonding_caps[0], "CAP_AUDIT_WRITE");
        assert_eq!(bonding_caps[1], "CAP_KILL");
        assert_eq!(bonding_caps[2], "CAP_NET_BIND_SERVICE");
        let permitted_caps = caps.permitted.as_ref().unwrap();
        assert_eq!(permitted_caps.len(), 3);
        assert_eq!(permitted_caps[0], "CAP_AUDIT_WRITE");
        assert_eq!(permitted_caps[1], "CAP_KILL");
        assert_eq!(permitted_caps[2], "CAP_NET_BIND_SERVICE");
        let inheritable_caps = caps.inheritable.as_ref().unwrap();
        assert_eq!(inheritable_caps.len(), 3);
        assert_eq!(inheritable_caps[0], "CAP_AUDIT_WRITE");
        assert_eq!(inheritable_caps[1], "CAP_KILL");
        assert_eq!(inheritable_caps[2], "CAP_NET_BIND_SERVICE");
        let effective_caps = caps.effective.as_ref().unwrap();
        assert_eq!(effective_caps.len(), 2);
        assert_eq!(effective_caps[0], "CAP_AUDIT_WRITE");
        assert_eq!(effective_caps[1], "CAP_KILL");
        let ambient_caps = caps.ambient.as_ref().unwrap();
        assert_eq!(ambient_caps.len(), 1);
        assert_eq!(ambient_caps[0], "CAP_NET_BIND_SERVICE");
        let rlimits = section.process.rlimits.as_ref().unwrap();
        assert_eq!(rlimits.len(), 1);
        assert_eq!(rlimits[0].rlimit_type, "RLIMIT_NOFILE");
        assert_eq!(rlimits[0].hard, 1024);
        assert_eq!(rlimits[0].soft, 1024);
        let exec_cpu_affinity = section.process.execCPUAffinity.as_ref().unwrap();
        assert_eq!(exec_cpu_affinity.initial, Some("7".to_string()));
        assert_eq!(exec_cpu_affinity.final_cpus, Some("0-3,7".to_string()));
    }
}
