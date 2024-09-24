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

// Linux container create flow:
//      ozonec create       |       State 1 process     |       Stage 2 process     |       ozonec start
//                          |                           |                           |
//      -> clone3 ->        |                           |                           |
//  <- mapping request <-   |                           |                           |
//  write uid/gid mappings  |                           |                           |
//  -> send mapping done -> |                           |                           |
//                          |       set uid/gid         |                           |
//                          |       set pid namespace   |                           |
//  <- send stage 2 pid     |                           |        -> clone3 ->       |
//                          |           exit            |     set rest namespaces   |
//                          |                           |      pivot_root/chroot    |
//                          |                           |       set capabilities    |
//                          |                           |       set seccomp         |
//          <             send ready          <-        |                           |
//                          |                           |   wait for start signal   |
//      update pid file     |                           |                           |     ozonec start $id
//          exit            |                           |                           |   <- send start signal
//                          |                           |         execvp cmd        |           exit

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{state::State, Container};
use crate::{linux::Process, utils::OzonecErr};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    Create,
    Start,
    Exec,
}

pub struct Launcher {
    pub bundle: PathBuf,
    pub root: PathBuf,
    /// init is set to true when creating a container.
    pub init: bool,
    pub runner: Box<dyn Container>,
    pub pid_file: Option<PathBuf>,
}

impl Launcher {
    pub fn new(
        bundle: &Path,
        root: &Path,
        init: bool,
        runner: Box<dyn Container>,
        pid_file: Option<PathBuf>,
    ) -> Self {
        Self {
            bundle: bundle.to_path_buf(),
            root: root.to_path_buf(),
            init,
            runner,
            pid_file,
        }
    }

    pub fn launch(&mut self, action: Action) -> Result<()> {
        if self.init {
            self.spawn_container()?;
        } else {
            self.spawn_process(action)?;
        }

        if let Some(pid_file) = self.pid_file.as_ref() {
            let pid = self.runner.get_pid();
            std::fs::write(pid_file, format!("{}", pid)).with_context(|| "Failed to write pid")?;
        }

        Ok(())
    }

    fn spawn_container(&mut self) -> Result<()> {
        self.spawn_process(Action::Create)?;

        let mut state = self
            .get_state()
            .with_context(|| "Failed to get container state")?;
        state.update();
        state.save().with_context(|| "Failed to save state")?;
        Ok(())
    }

    fn spawn_process(&mut self, action: Action) -> Result<()> {
        let mut process = self.get_process();
        match action {
            Action::Create => self.runner.create(&mut process),
            Action::Start => self.runner.start(),
            Action::Exec => self.runner.exec(&mut process),
        }
    }

    fn get_process(&self) -> Process {
        let config = self.runner.get_config();
        Process::new(&config.process, self.init)
    }

    fn get_state(&self) -> Result<State> {
        let state = self.runner.get_oci_state()?;
        let pid = self.runner.get_pid();
        let proc =
            procfs::process::Process::new(pid).with_context(|| OzonecErr::ReadProcPid(pid))?;
        let start_time = proc
            .stat()
            .with_context(|| OzonecErr::ReadProcStat(pid))?
            .starttime;

        Ok(State::new(
            &self.root,
            &self.bundle,
            state,
            start_time,
            *self.runner.created_time(),
            self.runner.get_config(),
        ))
    }
}
