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

/// Container's root filesystem.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Root {
    /// Path to the root filesystem for the container.
    pub path: String,
    #[serde(default)]
    /// If true then the root filesystem MUST be read-only inside the container.
    pub readonly: bool,
}

/// Resource limits for the process.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rlimits {
    /// The platform resource being limited.
    #[serde(rename = "type")]
    pub rlimit_type: String,
    /// Value of the limit enforced for the corresponding resource.
    pub soft: u64,
    /// Ceiling for the soft limit that could be set by an
    /// unprivileged process.
    pub hard: u64,
}

/// The user for the process that allows specific control over which user
/// the process runs as.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    /// User ID in the container namespace.
    pub uid: u32,
    /// Group ID in the container namespace.
    pub gid: u32,
    /// [umask][umask_2] of the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<i32>,
    /// Additional group IDs in the container namespace to be added
    /// to the process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additionalGids: Option<Vec<u32>>,
}

/// Hook Entry.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HookEntry {
    /// Similar semantics to IEEE Std 1003.1-2008 execv's path.
    pub path: String,
    /// Same semantics as IEEE Std 1003.1-2008 execv's argv.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Same semantics as IEEE Std 1003.1-2008's environ.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    /// Number of seconds before aborting the hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i32>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Hooks {
    /// Array of prestart hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    prestart: Option<Vec<HookEntry>>,
    /// Array of createRuntime hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    createRuntime: Option<Vec<HookEntry>>,
    /// Array of createContainer hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    createContainer: Option<Vec<HookEntry>>,
    /// Array of startContainer hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    startContainer: Option<Vec<HookEntry>>,
    /// Array of poststart hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    poststart: Option<Vec<HookEntry>>,
    /// Array of poststop hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    poststop: Option<Vec<HookEntry>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_root() {
        let json = r#"{
            "root": {
                "path": "rootfs",
                "readonly": true
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            root: Root,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        assert_eq!(section.root.path, "rootfs");
        assert_eq!(section.root.readonly, true);
    }

    #[test]
    fn test_hooks() {
        let json = r#"{
            "hooks": {
                "prestart": [
                    {
                        "path": "/usr/bin/fix-mounts",
                        "args": ["fix-mounts", "arg1", "arg2"],
                        "env":  [ "key1=value1"]
                    },
                    {
                        "path": "/usr/bin/setup-network"
                    }
                ],
                "createRuntime": [
                    {
                        "path": "/usr/bin/fix-mounts",
                        "args": ["fix-mounts", "arg1", "arg2"],
                        "env":  [ "key1=value1"]
                    },
                    {
                        "path": "/usr/bin/setup-network"
                    }
                ],
                "createContainer": [
                    {
                        "path": "/usr/bin/mount-hook",
                        "args": ["-mount", "arg1", "arg2"],
                        "env":  [ "key1=value1"]
                    }
                ],
                "startContainer": [
                    {
                        "path": "/usr/bin/refresh-ldcache"
                    }
                ],
                "poststart": [
                    {
                        "path": "/usr/bin/notify-start",
                        "timeout": 5
                    }
                ],
                "poststop": [
                    {
                        "path": "/usr/sbin/cleanup.sh",
                        "args": ["cleanup.sh", "-f"]
                    }
                ]
            }
        }"#;

        #[derive(Serialize, Deserialize)]
        struct Section {
            hooks: Hooks,
        }

        let section: Section = serde_json::from_str(json).unwrap();
        let prestart = section.hooks.prestart.as_ref().unwrap();
        assert_eq!(prestart.len(), 2);
        assert_eq!(prestart[0].path, "/usr/bin/fix-mounts");
        let args = prestart[0].args.as_ref().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "fix-mounts");
        assert_eq!(args[1], "arg1");
        assert_eq!(args[2], "arg2");
        let env = prestart[0].env.as_ref().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0], "key1=value1");
        assert_eq!(prestart[0].timeout, None);
        assert_eq!(prestart[1].path, "/usr/bin/setup-network");
        assert_eq!(prestart[1].args, None);
        assert_eq!(prestart[1].env, None);
        assert_eq!(prestart[1].timeout, None);

        let create_runtime = section.hooks.createRuntime.as_ref().unwrap();
        assert_eq!(create_runtime.len(), 2);
        assert_eq!(create_runtime[0].path, "/usr/bin/fix-mounts");
        let args = create_runtime[0].args.as_ref().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "fix-mounts");
        assert_eq!(args[1], "arg1");
        assert_eq!(args[2], "arg2");
        let env = create_runtime[0].env.as_ref().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0], "key1=value1");
        assert_eq!(create_runtime[0].timeout, None);
        assert_eq!(create_runtime[1].path, "/usr/bin/setup-network");
        assert_eq!(create_runtime[1].args, None);
        assert_eq!(create_runtime[1].env, None);
        assert_eq!(create_runtime[1].timeout, None);

        let create_container = section.hooks.createContainer.as_ref().unwrap();
        assert_eq!(create_container.len(), 1);
        assert_eq!(create_container[0].path, "/usr/bin/mount-hook");
        let args = create_container[0].args.as_ref().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[0], "-mount");
        assert_eq!(args[1], "arg1");
        assert_eq!(args[2], "arg2");
        let env = create_container[0].env.as_ref().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0], "key1=value1");
        assert_eq!(create_container[0].timeout, None);

        let start_container = section.hooks.startContainer.as_ref().unwrap();
        assert_eq!(start_container.len(), 1);
        assert_eq!(start_container[0].path, "/usr/bin/refresh-ldcache");
        assert_eq!(start_container[0].args, None);
        assert_eq!(start_container[0].env, None);
        assert_eq!(start_container[0].timeout, None);

        let poststart = section.hooks.poststart.as_ref().unwrap();
        assert_eq!(poststart.len(), 1);
        assert_eq!(poststart[0].path, "/usr/bin/notify-start");
        assert_eq!(poststart[0].args, None);
        assert_eq!(poststart[0].env, None);
        assert_eq!(poststart[0].timeout, Some(5));

        let poststop = section.hooks.poststop.as_ref().unwrap();
        assert_eq!(poststop.len(), 1);
        assert_eq!(poststop[0].path, "/usr/sbin/cleanup.sh");
        let args = poststop[0].args.as_ref().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "cleanup.sh");
        assert_eq!(args[1], "-f");
        assert_eq!(poststop[0].env, None);
        assert_eq!(poststop[0].timeout, None);
    }
}
