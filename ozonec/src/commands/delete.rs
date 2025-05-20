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

use std::{fs, path::Path};

use anyhow::{bail, Result};
use clap::{builder::NonEmptyStringValueParser, Parser};

use crate::{
    container::{Container, State},
    linux::LinuxContainer,
};

/// Release container resources after the container process has exited
#[derive(Debug, Parser)]
pub struct Delete {
    /// Specify the container id
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// Force to delete the container (kill the container using SIGKILL)
    #[arg(short, long)]
    pub force: bool,
}

impl Delete {
    pub fn run(&self, root: &Path) -> Result<()> {
        let state_dir = root.join(&self.container_id);
        if !state_dir.exists() {
            bail!("{} doesn't exist", state_dir.display());
        }

        let state = if let Ok(s) = State::load(root, &self.container_id) {
            s
        } else {
            fs::remove_dir_all(state_dir)?;
            return Ok(());
        };

        let container = LinuxContainer::load_from_state(&state, &None)?;
        container.delete(&state, self.force)?;
        Ok(())
    }
}
