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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{builder::NonEmptyStringValueParser, Parser};
use serde::{Deserialize, Serialize};

use crate::{container::State as ContainerState, linux::LinuxContainer};

/// Request the container state
#[derive(Debug, Parser)]
pub struct State {
    /// Specify the container id
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RuntimeState {
    pub oci_version: String,
    pub id: String,
    pub status: String,
    pub pid: i32,
    pub bundle: PathBuf,
}

impl State {
    pub fn run(&self, root: &Path) -> Result<()> {
        let state = ContainerState::load(root, &self.container_id)?;
        let container = LinuxContainer::load_from_state(&state, &None)?;
        let runtime_state = RuntimeState {
            oci_version: state.oci_version,
            id: state.id,
            pid: state.pid,
            status: container.status()?.to_string(),
            bundle: state.bundle,
        };
        let json_data = &serde_json::to_string_pretty(&runtime_state)
            .with_context(|| "Failed to get json data of container state")?;

        println!("{}", json_data);
        Ok(())
    }
}
