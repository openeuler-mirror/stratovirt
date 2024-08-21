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
use log::{debug, error, info};
use nix::{
    errno::Errno,
    sys::{
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{chown, getegid, geteuid},
};
use procfs::process::ProcState;

use super::{notify_socket::NOTIFY_SOCKET, process::clone_process, NotifyListener, Process};
use crate::{
    container::Container,
    utils::{Channel, Message, OzonecErr},
};
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
        if config.process.args.is_none() {
            bail!("args in process is not set in config.json.");
        }
        Ok(())
    }

    fn do_first_stage(
        &mut self,
        process: &mut Process,
        parent_channel: &Channel<Message>,
        fst_stage_channel: &Channel<Message>,
        notify_listener: Option<NotifyListener>,
    ) -> Result<()> {
        debug!("First stage process start");

        fst_stage_channel
            .receiver
            .close()
            .with_context(|| "Failed to close receiver end of first stage channel")?;

        // Spawn a child process to perform the second stage to initialize container.
        let init_pid = clone_process("ozonec:[2:INIT]", || {
            self.do_second_stage(process, parent_channel, notify_listener)
                .with_context(|| "Second stage process encounters errors")?;
            Ok(0)
        })?;

        // Send the final container pid to the parent process.
        parent_channel.send_init_pid(init_pid)?;

        debug!("First stage process exit");
        Ok(())
    }

    fn do_second_stage(
        &mut self,
        process: &mut Process,
        parent_channel: &Channel<Message>,
        notify_listener: Option<NotifyListener>,
    ) -> Result<()> {
        debug!("Second stage process start");

        // Tell the parent process that the init process has been cloned.
        parent_channel.send_container_created()?;
        parent_channel
            .sender
            .close()
            .with_context(|| "Failed to close sender of parent channel")?;

        // Listening on the notify socket to start container.
        if let Some(listener) = notify_listener {
            listener.wait_for_start_container()?;
            listener
                .close()
                .with_context(|| "Failed to close notify socket")?;
        }

        debug!("Container process exit");
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
            .with_context(|| OzonecErr::ReadProcStat(self.pid))?;
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
        // Create notify socket to notify the container process to start.
        let notify_listener = if process.init {
            Some(NotifyListener::new(PathBuf::from(&self.root))?)
        } else {
            None
        };

        // Create channels to communicate with child processes.
        let parent_channel = Channel::<Message>::new()
            .with_context(|| "Failed to create message channel for parent process")?;
        let fst_stage_channel = Channel::<Message>::new()?;
        // Set receivers timeout: 50ms.
        parent_channel.receiver.set_timeout(50000)?;
        fst_stage_channel.receiver.set_timeout(50000)?;

        // Spawn a child process to perform Stage 1.
        let fst_stage_pid = clone_process("ozonec:[1:CHILD]", || {
            self.do_first_stage(
                process,
                &parent_channel,
                &fst_stage_channel,
                notify_listener,
            )
            .with_context(|| "First stage process encounters errors")?;
            Ok(0)
        })?;

        let init_pid = parent_channel
            .recv_init_pid()
            .with_context(|| "Failed to receive init pid")?;
        parent_channel.recv_container_created()?;
        parent_channel
            .receiver
            .close()
            .with_context(|| "Failed to close receiver end of parent channel")?;

        self.pid = init_pid.as_raw();
        self.start_time = procfs::process::Process::new(self.pid)
            .with_context(|| OzonecErr::ReadProcPid(self.pid))?
            .stat()
            .with_context(|| OzonecErr::ReadProcStat(self.pid))?
            .starttime;

        match waitpid(fst_stage_pid, None) {
            Ok(WaitStatus::Exited(_, 0)) => (),
            Ok(WaitStatus::Exited(_, s)) => {
                info!("First stage process exits with status: {}", s);
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                info!("First stage process killed by signal: {}", sig)
            }
            Ok(_) => (),
            Err(Errno::ECHILD) => {
                info!("First stage process has already been reaped");
            }
            Err(e) => {
                bail!("Failed to waitpid for first stage process: {e}");
            }
        }
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
