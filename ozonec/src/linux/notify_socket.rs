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
    env,
    io::Read,
    os::{fd::AsRawFd, unix::net::UnixListener},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nix::unistd::{self, chdir};

pub const NOTIFY_SOCKET: &str = "notify.sock";

pub struct NotifyListener {
    socket: UnixListener,
}

impl NotifyListener {
    pub fn new(root: PathBuf) -> Result<Self> {
        // The length of path of Unix domain socket has the limit 108, which is smaller then
        // the maximum length of file on Linux (255).
        let cwd =
            env::current_dir().with_context(|| "Current working directory value is invalid")?;
        chdir(&root).with_context(|| "Failed to chdir to root directory")?;
        let listener =
            UnixListener::bind(NOTIFY_SOCKET).with_context(|| "Failed to bind notify socket")?;
        chdir(&cwd).with_context(|| "Failed to chdir to previous working directory")?;
        Ok(Self { socket: listener })
    }

    pub fn wait_for_start_container(&self) -> Result<()> {
        match self.socket.accept() {
            Ok((mut socket, _)) => {
                let mut response = String::new();
                socket
                    .read_to_string(&mut response)
                    .with_context(|| "Invalid response from notify socket")?;
            }
            Err(e) => {
                bail!("Failed to accept on notify socket: {}", e);
            }
        }
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        Ok(unistd::close(self.socket.as_raw_fd())?)
    }
}
