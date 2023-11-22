// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
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

#![deny(missing_docs)]
//! This file implements a high level wrapper for daemonize
//!
//! # Daemonize Introduction
//!
//! [daemonize](https://linux.die.net/man/1/daemonize) to runs a command as a
//! Unix daemonize. A daemon is a process that executes in the background either
//! waiting for some event to occur, or waiting to perform some specified task
//! on a periodic basis. A typical daemon program will:
//! 1. Close all open file descriptors(especially standard input, standard
//! output and standard error).
//! 2. Change its working directory to the root filesystem, to ensure that it
//! doesn't tie up another filesystem and prevent it from being unmounted.
//! 3. Reset its umask value.
//! 4. Run in the background(i.e., fork).
//! 5. Ignore all terminal I/O signals.
//! 6. Disassociate from the control terminal.
//! 7. Disassociate from its process group, to insulate itself from signals
//! sent to the process group.
//! 8. Handle any `SIGCLD` signals.

use std::cmp::Ordering;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::RawFd;
use std::path::Path;
use std::process::exit;

use anyhow::{anyhow, Result};

use crate::UtilError;

/// Write process id to pid file.
fn create_pid_file(path: &str) -> Result<()> {
    let pid: u32 = std::process::id();

    let mut pid_file: File = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    write!(pid_file, "{}", pid)?;

    Ok(())
}

/// [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html)
/// fork() creates a new process by duplicating the calling process. The new
/// process is referred to as the child process. The calling process is referred
/// to as the parent process.
/// **libc::fork()** may have three kinds ret:
/// if ret > 0 : current process is parent process, it's not expected, so exit
/// if ret < 0 : error occurred in fork()
/// if ret = 0 : current process is child process, it's expected
///
/// # Errors
///
/// `DaemonFork` Error, the ret of `libc::fork()` is less than zero.
fn fork() -> Result<()> {
    // SAFETY: No input parameters in this system call.
    // and the return value have been verified later.
    let ret = unsafe { libc::fork() };

    match ret.cmp(&0) {
        Ordering::Less => Err(anyhow!(UtilError::DaemonFork)),
        Ordering::Greater => exit(0),
        Ordering::Equal => Ok(()),
    }
}

/// [setsid(2)](https://man7.org/linux/man-pages/man2/setsid.2.html)
/// setsid() creates a new session if the calling process is not a process group
/// leader. The calling process is the leader of the new session. The calling
/// process also becomes the process group leader or a new process group in the
/// session.
/// The calling process will be the only process in the new process group and in
/// the new session. New session has no controlling terminal.
///
/// # Errors
///
/// `DaemonSetsid` Error, the ret of `libc::setsid()` is -1
fn set_sid() -> Result<()> {
    // SAFETY: No input parameters in this system call.
    // and the return value have been verified later.
    let ret = unsafe { libc::setsid() };

    if ret == -1 {
        Err(anyhow!(UtilError::DaemonSetsid))
    } else {
        Ok(())
    }
}

/// Redirect stdio to `/dev/null`.
///
/// Use [dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html)
/// dup2(oldfd, newfd) creates a copy of the file descriptor `oldfd`, uses the
/// file descriptor number specified in `newfd`. If the file descriptor `newfd`
/// was previously open, it is silently closed before being reused. This
/// function use `dup2` to redirect file descriptor use to `/dev/null`.
///
/// # Errors
///
/// `DaemonRedirectStdio` Error, the ret of `libc::open()`, `libc::dup2()`,
/// `libc::close()`is -1
fn redirect_stdio(fd: RawFd) -> Result<()> {
    // SAFETY: the input parameter for systemctl are constant，and the return
    // value have been verified later.
    unsafe {
        let devnull_fd = libc::open(b"/dev/null\0" as *const [u8; 10] as _, libc::O_RDWR);

        if devnull_fd == -1 {
            return Err(anyhow!(UtilError::DaemonRedirectStdio));
        }

        if libc::dup2(devnull_fd, fd) == -1 {
            return Err(anyhow!(UtilError::DaemonRedirectStdio));
        }

        if libc::close(devnull_fd) == -1 {
            return Err(anyhow!(UtilError::DaemonRedirectStdio));
        }
    }

    Ok(())
}

/// Daemonize a process.
///
/// # Arguments
///
/// * `pid_file` - Path where will create pid file.
///
/// # Notes
/// This function do five things to daemonize a process:
/// 1. Reset its umask value.
/// 2. Run in the background use fork.
/// 3. Ignore all terminal I/O signals.
/// 4. Disassociate from the control terminal.
/// 5. Write pid to pidfile.
pub fn daemonize(pid_file: Option<String>) -> Result<()> {
    if let Some(path) = pid_file.as_ref() {
        if Path::new(path).exists() {
            return Err(anyhow!(UtilError::PidFileExist));
        }
    }

    // The first fork make parent process quit, child process inherit parent's
    // session ID and have a new process ID. It can guarantee child
    // process will not be the first process in a session.
    fork()?;
    // Create a new session for process. Now parent process quit will not
    // influence stratovirt process. But stratovirt becomes the first process in
    // new section.
    set_sid()?;
    // The second fork make stratovirt run as daemonize process. It won't be the
    // first process in this session and never get terminal control.
    fork()?;
    // Redirect stdio to `/dev/null`.
    redirect_stdio(libc::STDIN_FILENO)?;
    redirect_stdio(libc::STDOUT_FILENO)?;
    redirect_stdio(libc::STDERR_FILENO)?;

    // Now can record PID to file. It won't be changed again in stratovirt's
    // lifetime.
    if let Some(path) = pid_file {
        create_pid_file(&path)?;
    }

    Ok(())
}
