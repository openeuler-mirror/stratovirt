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

use core::str;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{builder::NonEmptyStringValueParser, Parser};
use oci_spec::state::ContainerStatus;

use crate::{
    container::{Action, Launcher, State},
    linux::LinuxContainer,
    utils::OzonecErr,
};

/// Execute a new process inside the container
#[derive(Debug, Parser)]
pub struct Exec {
    /// Path to an AF_UNIX socket which will receive a file descriptor of the master end
    /// of the console's pseudoterminal
    #[arg(long)]
    pub console_socket: Option<PathBuf>,
    /// Allocate a pseudio-TTY
    #[arg(short, long)]
    pub tty: bool,
    /// Current working directory in the container
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    /// Specify the file to write the process pid to
    #[arg(long)]
    pub pid_file: Option<PathBuf>,
    /// Specify environment variables
    #[arg(short, long, value_parser = parse_key_val::<String, String>, number_of_values = 1)]
    pub env: Vec<(String, String)>,
    /// Prevent the process from gaining additional privileges
    #[arg(long)]
    pub no_new_privs: bool,
    /// Specify the container id
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// Specify the command to execute in the container
    #[arg(required = false)]
    pub command: Vec<String>,
}

fn parse_key_val<T, U>(s: &str) -> Result<(T, U)>
where
    T: str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
    U: str::FromStr,
    U::Err: std::error::Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or(anyhow!("Invalid KEY=value: no '=' found in '{}'", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

impl Exec {
    fn launcher(&self, root: &Path) -> Result<Launcher> {
        let mut container_state =
            State::load(root, &self.container_id).with_context(|| OzonecErr::LoadConState)?;

        if let Some(config) = container_state.config.as_mut() {
            config.process.terminal = self.tty;
            config.process.cwd = if let Some(cwd) = &self.cwd {
                cwd.to_string_lossy().to_string()
            } else {
                String::from("/")
            };

            for (env_name, env_value) in &self.env {
                config
                    .process
                    .env
                    .as_mut()
                    .unwrap()
                    .push(format!("{}={}", env_name, env_value));
            }
            config.process.noNewPrivileges = Some(self.no_new_privs);
            config.process.args = Some(self.command.clone());
        }

        let container = LinuxContainer::load_from_state(&container_state, &self.console_socket)?;
        let status = container.status()?;
        if status != ContainerStatus::Created && status != ContainerStatus::Running {
            bail!("Can't exec in container with {:?} state", status);
        }

        Ok(Launcher::new(
            &container_state.bundle,
            root,
            false,
            Box::new(container),
            self.pid_file.clone(),
        ))
    }

    pub fn run(&self, root: &Path) -> Result<()> {
        let mut launcher = self.launcher(root)?;
        launcher.launch(Action::Exec)?;
        Ok(())
    }
}
