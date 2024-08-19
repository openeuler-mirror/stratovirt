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

use std::{
    fs::{DirBuilder, OpenOptions},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use libc::pid_t;
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};

use oci_spec::{runtime::RuntimeConfig, state::State as OciState};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub pid: pid_t,
    pub root: PathBuf,
    pub bundle: PathBuf,
    pub rootfs: String,
    pub start_time: u64,
    pub created_time: DateTime<Utc>,
    pub config: Option<RuntimeConfig>,
}

impl State {
    pub fn new(
        root: &Path,
        bundle: &Path,
        oci_state: OciState,
        start_time: u64,
        created_time: SystemTime,
        config: &RuntimeConfig,
    ) -> Self {
        Self {
            oci_version: oci_state.ociVersion,
            id: oci_state.id,
            pid: oci_state.pid,
            root: root.to_path_buf(),
            bundle: bundle.to_path_buf(),
            rootfs: config.root.path.clone(),
            start_time,
            created_time: DateTime::from(created_time),
            config: Some(config.clone()),
        }
    }

    fn file_path(root: &Path, id: &str) -> PathBuf {
        root.join(id).join("state.json")
    }

    pub fn save(&self) -> Result<()> {
        if !&self.root.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(Mode::S_IRWXU.bits())
                .create(&self.root)
                .with_context(|| "Failed to create root directory")?;
        }

        let path = Self::file_path(&self.root, &self.id);
        let state_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| "Failed to open state file")?;
        serde_json::to_writer(&state_file, self)?;
        Ok(())
    }

    pub fn update(&mut self) {
        let linux = self.config.as_mut().unwrap().linux.as_mut();
        if let Some(config) = linux {
            for ns in &mut config.namespaces {
                if ns.path.is_none() {
                    let ns_name: String = ns.ns_type.into();
                    ns.path = Some(PathBuf::from(format!("/proc/{}/ns/{}", self.pid, ns_name)))
                }
            }
        }
    }
}
