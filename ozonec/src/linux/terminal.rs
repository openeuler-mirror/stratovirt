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
    io::IoSlice,
    mem::ManuallyDrop,
    os::fd::{AsRawFd, RawFd},
};

use anyhow::{Context, Result};
use nix::{
    pty::openpty,
    sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr},
    unistd::{close, dup2},
};

use crate::utils::OzonecErr;

pub enum Stdio {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
}

pub fn setup_console(console_fd: &RawFd) -> Result<()> {
    let ret = openpty(None, None).with_context(|| "openpty error")?;
    let pty_name: &[u8] = b"/dev/ptmx";
    let iov = [IoSlice::new(pty_name)];

    // Use ManuallyDrop to keep fds open.
    let master = ManuallyDrop::new(ret.master);
    let slave = ManuallyDrop::new(ret.slave);
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
    let slave_fd = slave.as_raw_fd();
    unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY) };
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
