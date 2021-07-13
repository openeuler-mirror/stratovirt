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

use std::fs::{read_link, File, OpenOptions};
use std::io::{Stdin, Stdout};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use libc::{cfmakeraw, tcgetattr, tcsetattr, termios};
use machine_manager::{
    config::{ChardevConfig, ChardevType},
    temp_cleaner::TempCleaner,
};
use util::set_termi_raw_mode;
use util::unix::limit_permission;

use super::errors::{Result, ResultExt};

/// Provide input receiver method used by frontends.
pub trait InputReceiver: Send {
    fn input_handle(&mut self, buffer: &[u8]);
}

/// Character device structure.
pub struct Chardev {
    /// Type of backend device.
    pub backend: ChardevType,
    /// UnixListener for socket-type chardev.
    listener: Option<UnixListener>,
    /// Chardev input.
    pub input: Option<Arc<Mutex<dyn CommunicatInInterface>>>,
    /// Chardev output.
    pub output: Option<Arc<Mutex<dyn CommunicatOutInterface>>>,
}

impl Chardev {
    pub fn new(chardev_cfg: ChardevConfig) -> Self {
        Chardev {
            backend: chardev_cfg.backend,
            listener: None,
            input: None,
            output: None,
        }
    }

    pub fn realize(&mut self) -> Result<()> {
        match &self.backend {
            ChardevType::Stdio => {
                set_termi_raw_mode().chain_err(|| "Failed to set terminal to raw mode")?;
                self.input = Some(Arc::new(Mutex::new(std::io::stdin())));
                self.output = Some(Arc::new(Mutex::new(std::io::stdout())));
            }
            ChardevType::Pty => {
                let (master, path) =
                    set_pty_raw_mode().chain_err(|| "Failed to set pty to raw mode")?;
                info!("Pty path is: {:?}", path);
                // Safe because `master_arc` is the only one owner for the file descriptor.
                let master_arc = unsafe { Arc::new(Mutex::new(File::from_raw_fd(master))) };
                self.input = Some(master_arc.clone());
                self.output = Some(master_arc);
            }
            ChardevType::Socket(path) => {
                let sock = UnixListener::bind(path.clone())
                    .chain_err(|| format!("Failed to bind socket for chardev, path:{}", path))?;
                self.listener = Some(sock);
                // add file to temporary pool, so it could be cleaned when vm exit.
                TempCleaner::add_path(path.clone());
                limit_permission(path).chain_err(|| {
                    format!(
                        "Failed to change file permission for chardev, path:{}",
                        path
                    )
                })?;
            }
            ChardevType::File(path) => {
                let file = Arc::new(Mutex::new(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(path)?,
                ));
                self.output = Some(file);
            }
        };
        Ok(())
    }
}

fn set_pty_raw_mode() -> Result<(i32, PathBuf)> {
    let mut master: libc::c_int = 0;
    let master_ptr: *mut libc::c_int = &mut master;
    let mut slave: libc::c_int = 0;
    let slave_ptr: *mut libc::c_int = &mut slave;
    // Safe because this only create a new pseudoterminal and set the master and slave fd.
    let ret = {
        unsafe {
            libc::openpty(
                master_ptr,
                slave_ptr,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        }
    };
    if ret < 0 {
        bail!(
            "Failed to open pty, error is {}",
            std::io::Error::last_os_error()
        )
    }
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", slave));
    let path = read_link(proc_path).chain_err(|| "Failed to read slave pty link")?;
    // Safe because this only set the `old_termios` struct to zero.
    let mut old_termios: termios = unsafe { std::mem::zeroed() };
    // Safe because this only get the current mode of slave pty and save it.
    let ret = unsafe { tcgetattr(slave, &mut old_termios as *mut _) };
    if ret < 0 {
        bail!(
            "Failed to get mode of pty, error is {}",
            std::io::Error::last_os_error()
        );
    }
    let mut new_termios: termios = old_termios;
    // Safe because this function only change the `new_termios` argument.
    unsafe { cfmakeraw(&mut new_termios as *mut _) };
    // Safe because this function only set the slave pty to raw mode.
    let ret = unsafe { tcsetattr(slave, libc::TCSAFLUSH, &new_termios as *const _) };
    if ret < 0 {
        bail!(
            "Failed to set pty to raw mode, error is {}",
            std::io::Error::last_os_error()
        );
    }
    Ok((master, path))
}

/// Provide backend trait object receiving the input from the guest.
pub trait CommunicatInInterface:
    std::io::Read + std::marker::Send + std::os::unix::io::AsRawFd
{
}

/// Provide backend trait object processing the output from the guest.
pub trait CommunicatOutInterface: std::io::Write + std::marker::Send {}

impl CommunicatInInterface for UnixStream {}
impl CommunicatInInterface for File {}
impl CommunicatInInterface for Stdin {}

impl CommunicatOutInterface for UnixStream {}
impl CommunicatOutInterface for File {}
impl CommunicatOutInterface for Stdout {}
