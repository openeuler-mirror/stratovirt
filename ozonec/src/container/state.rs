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
    fs::{self, DirBuilder, File, OpenOptions},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use libc::pid_t;
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};

use oci_spec::{runtime::RuntimeConfig, state::State as OciState};

use crate::utils::OzonecErr;

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
            .open(&path)
            .with_context(|| OzonecErr::OpenFile(path.to_string_lossy().to_string()))?;
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

    pub fn load(root: &Path, id: &str) -> Result<Self> {
        let path = Self::file_path(root, id);
        if !path.exists() {
            bail!("Container {} doesn't exist", id);
        }

        let state_file = File::open(&path)
            .with_context(|| OzonecErr::OpenFile(path.to_string_lossy().to_string()))?;
        let state = serde_json::from_reader(&state_file)?;
        Ok(state)
    }

    pub fn remove_dir(&self) -> Result<()> {
        let state_dir = &self.root.join(&self.id);
        fs::remove_dir_all(state_dir).with_context(|| "Failed to remove state directory")?;
        Ok(())
    }

    fn file_path(root: &Path, id: &str) -> PathBuf {
        root.join(id).join("state.json")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use fs::{create_dir_all, remove_dir_all};
    use nix::unistd::getpid;

    use crate::linux::container::tests::init_config;
    use oci_spec::{
        linux::{Namespace, NamespaceType},
        state::ContainerStatus,
    };

    use super::*;

    fn init_state(root: &Path, id: &str) -> State {
        let oci_state = OciState {
            ociVersion: String::from("1.2"),
            id: String::from(id),
            status: ContainerStatus::Created,
            pid: 100,
            bundle: root.to_string_lossy().to_string(),
            annotations: HashMap::new(),
        };
        State::new(root, root, oci_state, 0, SystemTime::now(), &init_config())
    }

    #[test]
    fn test_state_update() {
        let root = "/tmp/ozonec";
        remove_dir_all(root).unwrap_or_default();
        let mut state = init_state(Path::new(root), "test_state_update");
        state
            .config
            .as_mut()
            .unwrap()
            .linux
            .as_mut()
            .unwrap()
            .namespaces
            .push(Namespace {
                ns_type: NamespaceType::Mount,
                path: None,
            });
        state.pid = getpid().as_raw();
        state.update();

        for ns in &state
            .config
            .as_ref()
            .unwrap()
            .linux
            .as_ref()
            .unwrap()
            .namespaces
        {
            assert_eq!(
                ns.path.as_ref().unwrap().to_str().unwrap(),
                format!(
                    "/proc/{}/ns/{}",
                    state.pid,
                    <NamespaceType as Into<String>>::into(ns.ns_type)
                )
            );
        }
    }

    #[test]
    fn test_state_load() {
        let root = "/tmp/ozonec";
        remove_dir_all(root).unwrap_or_default();

        let state = init_state(Path::new(root), "test_state_load");
        let dir = PathBuf::from(String::from(root)).join("test_state_load");
        create_dir_all(&dir).unwrap();

        assert!(state.save().is_ok());
        assert!(dir.join("state.json").exists());
        let loaded_state = State::load(Path::new(root), "test_state_load").unwrap();
        assert_eq!(loaded_state.id, state.id);
        assert!(state.remove_dir().is_ok());
        assert!(State::load(Path::new(root), "test_state_load").is_err());
    }
}
