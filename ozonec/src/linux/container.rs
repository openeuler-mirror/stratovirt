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
    collections::HashMap,
    fs::{canonicalize, create_dir_all},
    path::{Path, PathBuf},
    time::SystemTime,
};

use anyhow::{anyhow, bail, Context, Result};
use libc::pid_t;
use log::error;
use nix::{
    sys::signal::Signal,
    unistd::{chown, getegid, geteuid},
};
use procfs::process::ProcState;

use super::notify_socket::NOTIFY_SOCKET;
use crate::container::{Container, Process};
use oci_spec::{
    runtime::RuntimeConfig,
    state::{ContainerStatus, State},
};

pub struct LinuxContainer {
    pub id: String,
    pub root: String,
    pub config: RuntimeConfig,
    pub pid: pid_t,
    pub start_time: u64,
    pub created_time: SystemTime,
    pub console_socket: Option<PathBuf>,
}

impl LinuxContainer {
    pub fn new(
        id: &String,
        root: &String,
        config: &RuntimeConfig,
        console_socket: &Option<PathBuf>,
        exist: &mut bool,
    ) -> Result<Self> {
        let container_dir = format!("{}/{}", root, id);

        Self::validate_config(config)?;

        if Path::new(container_dir.as_str()).exists() {
            *exist = true;
            bail!("Container {} already exists", id);
        }
        create_dir_all(container_dir.as_str()).map_err(|e| {
            error!("Failed to create container directory: {}", e);
            anyhow!(e).context("Failed to create container directory")
        })?;
        chown(container_dir.as_str(), Some(geteuid()), Some(getegid()))
            .with_context(|| "Failed to chown container directory")?;

        Ok(Self {
            id: id.clone(),
            root: container_dir,
            config: config.clone(),
            pid: -1,
            start_time: 0,
            created_time: SystemTime::now(),
            console_socket: console_socket.clone(),
        })
    }

    fn validate_config(config: &RuntimeConfig) -> Result<()> {
        if config.linux.is_none() {
            bail!("There is no linux specific configuration in config.json for Linux container");
        }
        Ok(())
    }

    fn container_status(&self) -> Result<ContainerStatus> {
        if self.pid == -1 {
            return Ok(ContainerStatus::Creating);
        }

        let proc = procfs::process::Process::new(self.pid);
        // If error occurs when accessing /proc/<pid>, the process most likely has stopped.
        if proc.is_err() {
            return Ok(ContainerStatus::Stopped);
        }
        let proc_stat = proc
            .unwrap()
            .stat()
            .with_context(|| format!("Failed to read /proc/{}/stat", self.pid))?;
        // If starttime is not the same, then pid is reused, and the original process has stopped.
        if proc_stat.starttime != self.start_time {
            return Ok(ContainerStatus::Stopped);
        }

        match proc_stat.state()? {
            ProcState::Zombie | ProcState::Dead => Ok(ContainerStatus::Stopped),
            _ => {
                let notify_socket = PathBuf::from(&self.root).join(NOTIFY_SOCKET);
                if notify_socket.exists() {
                    return Ok(ContainerStatus::Created);
                }
                Ok(ContainerStatus::Running)
            }
        }
    }
}

impl Container for LinuxContainer {
    fn get_config(&self) -> &RuntimeConfig {
        &self.config
    }

    fn get_pid(&self) -> pid_t {
        self.pid
    }

    fn created_time(&self) -> &SystemTime {
        &self.created_time
    }

    fn get_oci_state(&self) -> Result<State> {
        let status = self.container_status()?;
        let pid = if status != ContainerStatus::Stopped {
            self.pid
        } else {
            0
        };

        let rootfs = canonicalize(&self.config.root.path.clone())
            .with_context(|| "Failed to canonicalize root path")?;
        let bundle = match rootfs.parent() {
            Some(p) => p
                .to_str()
                .ok_or(anyhow!("root path is not valid unicode"))?
                .to_string(),
            None => bail!("Failed to get bundle directory"),
        };
        let annotations = if let Some(a) = self.config.annotations.clone() {
            a
        } else {
            HashMap::new()
        };
        Ok(State {
            ociVersion: self.config.ociVersion.clone(),
            id: self.id.clone(),
            status,
            pid,
            bundle,
            annotations,
        })
    }

    fn create(&mut self, process: &mut Process) -> Result<()> {
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        Ok(())
    }

    fn exec(&mut self, process: &mut Process) -> Result<()> {
        Ok(())
    }

    fn kill(&mut self, sig: Signal) -> Result<()> {
        Ok(())
    }
}
