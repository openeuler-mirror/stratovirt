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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Runtime state of the container.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Creating,
    Created,
    Running,
    #[default]
    Stopped,
}

impl ToString for ContainerStatus {
    fn to_string(&self) -> String {
        match *self {
            ContainerStatus::Creating => String::from("creating"),
            ContainerStatus::Created => String::from("created"),
            ContainerStatus::Running => String::from("running"),
            ContainerStatus::Stopped => String::from("stopped"),
        }
    }
}

/// The state of a container.
#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct State {
    /// Version of the Open Container Initiative Runtime Specification
    /// with which the state complies.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ociVersion: String,
    /// Container's ID.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Runtime state of the container.
    pub status: ContainerStatus,
    /// ID of the container process.
    #[serde(default)]
    pub pid: i32,
    /// Absolute path to the container's bundle directory.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bundle: String,
    /// List of annotations associated with the container.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_state() {
        let json = r#"{
            "ociVersion": "0.2.0",
            "id": "oci-container1",
            "status": "running",
            "pid": 4422,
            "bundle": "/containers/redis",
            "annotations": {
                "myKey": "myValue"
            }
        }"#;

        let state: State = serde_json::from_str(json).unwrap();
        assert_eq!(state.ociVersion, "0.2.0");
        assert_eq!(state.id, "oci-container1");
        assert_eq!(state.status, ContainerStatus::Running);
        assert_eq!(state.pid, 4422);
        assert_eq!(state.bundle, "/containers/redis");
        assert!(state.annotations.contains_key("myKey"));
        assert_eq!(state.annotations.get("myKey"), Some(&"myValue".to_string()));
    }
}
