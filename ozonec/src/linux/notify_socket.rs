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
    io::{Read, Write},
    os::unix::{
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use nix::unistd::{self, chdir};

use crate::utils::OzonecErr;

pub const NOTIFY_SOCKET: &str = "notify.sock";

pub struct NotifyListener {
    socket: UnixListener,
}

impl NotifyListener {
    pub fn new(root: PathBuf) -> Result<Self> {
        // The length of path of Unix domain socket has the limit 108, which is smaller then
        // the maximum length of file on Linux (255).
        let cwd = env::current_dir().with_context(|| OzonecErr::GetCurDir)?;
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

pub struct NotifySocket {
    path: PathBuf,
}

impl NotifySocket {
    pub fn new(path: &PathBuf) -> Self {
        Self { path: path.into() }
    }

    pub fn notify_container_start(&mut self) -> Result<()> {
        let cwd = env::current_dir().with_context(|| OzonecErr::GetCurDir)?;
        let root_path = self
            .path
            .parent()
            .ok_or(anyhow!("Invalid notify socket path"))?;
        chdir(root_path).with_context(|| "Failed to chdir to root directory")?;

        let mut stream =
            UnixStream::connect(NOTIFY_SOCKET).with_context(|| "Failed to connect notify.sock")?;
        stream.write_all(b"start container")?;
        chdir(&cwd).with_context(|| "Failed to chdir to previous working directory")?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs::{create_dir_all, remove_dir_all};

    use nix::sys::wait::{waitpid, WaitStatus};

    use crate::linux::process::clone_process;

    use super::*;

    #[test]
    fn test_notify_socket() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let root = PathBuf::from("/tmp/ozonec/notify_socket");
        create_dir_all(&root).unwrap();

        let socket_path = root.join(NOTIFY_SOCKET);
        let mut socket = NotifySocket::new(&socket_path);
        let listener = NotifyListener::new(root.clone()).unwrap();
        let child = clone_process("notify_socket", || {
            listener.wait_for_start_container().unwrap();
            Ok(1)
        })
        .unwrap();
        socket.notify_container_start().unwrap();

        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, s)) => {
                assert_eq!(s, 1);
            }
            Ok(_) => (),
            Err(e) => {
                panic!("Failed to waitpid for child process: {e}");
            }
        }
    }
}
