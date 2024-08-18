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
