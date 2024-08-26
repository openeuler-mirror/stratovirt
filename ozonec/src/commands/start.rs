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

use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::Parser;
use oci_spec::state::ContainerStatus;

use crate::{
    container::{Action, Container, Launcher, State},
    linux::LinuxContainer,
    utils::OzonecErr,
};

/// Start the user-specified code from process
#[derive(Parser, Debug)]
pub struct Start {
    pub container_id: String,
}

impl Start {
    fn launcher(&self, root: &Path) -> Result<Launcher> {
        let container_state =
            State::load(root, &self.container_id).with_context(|| OzonecErr::LoadConState)?;
        let container = LinuxContainer::load_from_state(&container_state, &None)?;
        let oci_status = container
            .get_oci_state()
            .with_context(|| OzonecErr::GetOciState)?
            .status;

        if oci_status != ContainerStatus::Created {
            bail!("Can't start a container with {:?} status", oci_status);
        }

        Ok(Launcher::new(
            &container_state.bundle,
            root,
            false,
            Box::new(container),
            None,
        ))
    }

    pub fn run(&self, root: &Path) -> Result<()> {
        let mut launcher = self.launcher(root)?;
        launcher.launch(Action::Start)?;
        Ok(())
    }
}
