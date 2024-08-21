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

use anyhow::{Context, Ok, Result};
use clap::{builder::NonEmptyStringValueParser, Parser};

use crate::container::{Action, Container, Launcher};
use crate::linux::LinuxContainer;
use oci_spec::runtime::RuntimeConfig;

/// Create a container from a bundle directory
#[derive(Parser, Debug)]
pub struct Create {
    /// File to write the container PID to
    #[arg(short, long)]
    pub pid_file: Option<PathBuf>,
    /// Path to the bundle directory, defaults to the current working directory.
    #[arg(short, long, default_value = ".")]
    pub bundle: PathBuf,
    /// Path to an AF_UNIX socket which will receive the pseudoterminal master
    /// at a file descriptor.
    #[arg(short, long)]
    pub console_socket: Option<PathBuf>,
    /// Container ID to create.
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
}

impl Create {
    fn launcher(&self, root: &Path, exist: &mut bool) -> Result<Launcher> {
        let bundle_path = self
            .bundle
            .canonicalize()
            .with_context(|| "Failed to canonicalize bundle path")?;
        let config_path = bundle_path
            .join("config.json")
            .to_string_lossy()
            .to_string();
        let mut config = RuntimeConfig::from_file(&config_path)?;
        let mut rootfs_path = PathBuf::from(config.root.path);

        if !rootfs_path.is_absolute() {
            rootfs_path = bundle_path.join(rootfs_path);
        }
        config.root.path = rootfs_path.to_string_lossy().to_string();

        let container: Box<dyn Container> = Box::new(LinuxContainer::new(
            &self.container_id,
            &root.to_string_lossy().to_string(),
            &config,
            &self.console_socket,
            exist,
        )?);
        Ok(Launcher::new(
            &bundle_path,
            root,
            true,
            container,
            self.pid_file.clone(),
        ))
    }

    pub fn run(&self, root: &Path, exist: &mut bool) -> Result<()> {
        let mut launcher = self.launcher(root, exist)?;
        launcher.launch(Action::Create)?;
        Ok(())
    }
}
