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

use std::{path::Path, str::FromStr};

use anyhow::{Context, Result};
use clap::{builder::NonEmptyStringValueParser, Parser};
use nix::sys::signal::Signal;

use crate::{
    container::{Container, State},
    linux::LinuxContainer,
};

/// Send a signal to the container process
#[derive(Parser, Debug)]
pub struct Kill {
    /// Specify the container id
    #[arg(value_parser = NonEmptyStringValueParser::new(), required = true)]
    pub container_id: String,
    /// The signal to send to the container process
    pub signal: String,
}

impl Kill {
    pub fn run(&self, root: &Path) -> Result<()> {
        let container_state = State::load(root, &self.container_id)?;
        let signal = parse_signal(&self.signal).with_context(|| "Invalid signal")?;
        let container = LinuxContainer::load_from_state(&container_state, &None)?;

        container.kill(signal)?;
        Ok(())
    }
}

fn parse_signal(signal: &str) -> Result<Signal> {
    if let Ok(num) = signal.parse::<i32>() {
        return Ok(Signal::try_from(num)?);
    }

    let mut uppercase_sig = signal.to_uppercase();
    if !uppercase_sig.starts_with("SIG") {
        uppercase_sig = format!("SIG{}", &uppercase_sig);
    }
    Ok(Signal::from_str(&uppercase_sig)?)
}
