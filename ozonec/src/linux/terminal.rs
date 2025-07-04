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
    fs::File,
    io::IoSlice,
    mem::ManuallyDrop,
    os::unix::io::{AsRawFd, RawFd},
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use nix::{
    errno::errno,
    fcntl::{open, OFlag},
    mount::MsFlags,
    pty::{posix_openpt, ptsname, unlockpt},
    sys::{
        socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr},
        stat::{fchmod, Mode},
    },
    unistd::{close, dup2},
};

use crate::utils::OzonecErr;

pub enum Stdio {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
}

pub fn setup_console(console_fd: &RawFd, mount: bool) -> Result<()> {
    let master_fd = posix_openpt(OFlag::O_RDWR).with_context(|| "openpt error")?;
    let pty_name: &[u8] = b"/dev/ptmx";
    let iov = [IoSlice::new(pty_name)];
    // Use ManuallyDrop to keep fds open.
    let master = ManuallyDrop::new(master_fd.as_raw_fd());
    let fds = [master.as_raw_fd()];
    let cmsg = ControlMessage::ScmRights(&fds);
    sendmsg::<UnixAddr>(
        console_fd.as_raw_fd(),
        &iov,
        &[cmsg],
        MsgFlags::empty(),
        None,
    )
    .with_context(|| "sendmsg error")?;

    // SAFETY: FFI call with valid arguments.
    let slave_name = unsafe { ptsname(&master_fd).with_context(|| "ptsname error")? };
    unlockpt(&master_fd).with_context(|| "unlockpt error")?;
    let slave_path = PathBuf::from(&slave_name);
    if mount {
        let file = File::create("/dev/console").with_context(|| "Failed to create /dev/console")?;
        fchmod(file.as_raw_fd(), Mode::from_bits_truncate(0o666u32))
            .with_context(|| "chmod error")?;
        nix::mount::mount(
            Some(&slave_path),
            "/dev/console",
            Some("bind"),
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| OzonecErr::Mount(slave_name.clone()))?;
    }

    let slave_fd = open(&slave_path, OFlag::O_RDWR, Mode::empty())
        .with_context(|| OzonecErr::OpenFile(slave_name.clone()))?;
    let slave = ManuallyDrop::new(slave_fd);
    // SAFETY: FFI call with valid arguments.
    if unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY) } != 0 {
        bail!("TIOCSCTTY error: {}", errno());
    }
    connect_stdio(&slave_fd, &slave_fd, &slave_fd)?;
    close(console_fd.as_raw_fd()).with_context(|| "Failed to close console socket")?;
    Ok(())
}

pub fn connect_stdio(stdin: &RawFd, stdout: &RawFd, stderr: &RawFd) -> Result<()> {
    dup2(*stdin, (Stdio::Stdin as i32).as_raw_fd())
        .with_context(|| OzonecErr::Dup2("stdin".to_string()))?;
    dup2(*stdout, (Stdio::Stdout as i32).as_raw_fd())
        .with_context(|| OzonecErr::Dup2("stdout".to_string()))?;
    dup2(*stderr, (Stdio::Stderr as i32).as_raw_fd())
        .with_context(|| OzonecErr::Dup2("stderr".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_stdio() {
        let stdin: RawFd = 0;
        let stdout: RawFd = 0;
        let stderr: RawFd = 0;

        assert!(connect_stdio(&stdin, &stdout, &stderr).is_ok());
    }
}
