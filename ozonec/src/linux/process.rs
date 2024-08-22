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
    ffi::CString,
    fs::read_to_string,
    io::{stderr, stdin, stdout},
    os::fd::{AsRawFd, RawFd},
};

use anyhow::{anyhow, bail, Context, Result};
use clone3::Clone3;
use libc::SIGCHLD;
use nix::unistd::{self, setresgid, setresuid, Gid, Pid, Uid};

use oci_spec::process::Process as OciProcess;

pub struct Process {
    pub stdin: Option<RawFd>,
    pub stdout: Option<RawFd>,
    pub stderr: Option<RawFd>,
    pub init: bool,
    pub tty: bool,
    pub oci: OciProcess,
}

impl Process {
    pub fn new(oci: &OciProcess, init: bool) -> Self {
        let mut p = Process {
            stdin: None,
            stdout: None,
            stderr: None,
            tty: oci.terminal,
            init,
            oci: oci.clone(),
        };

        if !p.tty {
            p.stdin = Some(stdin().as_raw_fd());
            p.stdout = Some(stdout().as_raw_fd());
            p.stderr = Some(stderr().as_raw_fd());
        }
        p
    }

    pub fn set_additional_gids(&self) -> Result<()> {
        if let Some(additional_gids) = &self.oci.user.additionalGids {
            let setgroups = read_to_string("proc/self/setgroups")
                .with_context(|| "Failed to read setgroups")?;
            if setgroups.trim() == "deny" {
                bail!("Cannot set additional gids as setgroup is desabled");
            }

            let gids: Vec<Gid> = additional_gids
                .iter()
                .map(|gid| Gid::from_raw(*gid))
                .collect();
            unistd::setgroups(&gids).with_context(|| "Failed to set additional gids")?;
        }
        Ok(())
    }

    pub fn set_id(&self, gid: Gid, uid: Uid) -> Result<()> {
        setresgid(gid, gid, gid).with_context(|| "Failed to setresgid")?;
        setresuid(uid, uid, uid).with_context(|| "Failed to setresuid")?;
        Ok(())
    }

    pub fn exec_program(&self) -> ! {
        // It has been make sure that args is not None in validate_config().
        let args = &self.oci.args.as_ref().unwrap();
        // args don't have 0 byte in the middle such as "hello\0world".
        let exec_bin = CString::new(args[0].as_str().as_bytes()).unwrap();
        let args: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
            .collect();

        let _ = unistd::execvp(&exec_bin, &args).map_err(|e| match e {
            nix::Error::UnknownErrno => std::process::exit(-2),
            _ => std::process::exit(e as i32),
        });

        unreachable!()
    }
}

// Clone a new child process.
pub fn clone_process<F: FnOnce() -> Result<i32>>(child_name: &str, cb: F) -> Result<Pid> {
    let mut clone3 = Clone3::default();
    clone3.exit_signal(SIGCHLD as u64);

    // SAFETY: FFI call with valid arguments.
    match unsafe { clone3.call().with_context(|| "Clone3() error")? } {
        0 => {
            prctl::set_name(child_name)
                .map_err(|e| anyhow!("Failed to set process name: errno {}", e))?;
            let ret = match cb() {
                Err(e) => {
                    eprintln!("Child process exit with errors: {:?}", e);
                    -1
                }
                Ok(exit_code) => exit_code,
            };
            std::process::exit(ret);
        }
        pid => Ok(Pid::from_raw(pid)),
    }
}
