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

mod launcher;
mod state;

pub use launcher::{Action, Launcher};
pub use state::State;

use std::time::SystemTime;

use anyhow::Result;
use libc::pid_t;
use nix::sys::signal::Signal;

use oci_spec::{runtime::RuntimeConfig, state::State as OciState};

use crate::linux::Process;

pub trait Container {
    fn get_config(&self) -> &RuntimeConfig;

    fn get_oci_state(&self) -> Result<OciState>;

    fn get_pid(&self) -> pid_t;

    fn created_time(&self) -> &SystemTime;

    fn create(&mut self, process: &mut Process) -> Result<()>;

    fn start(&mut self) -> Result<()>;

    fn exec(&mut self, process: &mut Process) -> Result<()>;

    fn kill(&mut self, sig: Signal) -> Result<()>;
}
