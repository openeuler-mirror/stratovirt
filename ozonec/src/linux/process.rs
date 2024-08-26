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
    ffi::CString,
    fs::{self, read_to_string},
    io::{stderr, stdin, stdout},
    mem,
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use caps::{self, CapSet, Capability, CapsHashSet};
use clone3::Clone3;
use nix::unistd::{self, chdir, setresgid, setresuid, Gid, Pid, Uid};
use prctl::{set_keep_capabilities, set_no_new_privileges};
use rlimit::{setrlimit, Resource, Rlim};

use super::{
    apparmor,
    terminal::{connect_stdio, setup_console},
};
use crate::utils::OzonecErr;
use oci_spec::{linux::IoPriClass, process::Process as OciProcess};

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

    pub fn set_tty(&self, console_fd: Option<RawFd>) -> Result<()> {
        if self.tty && console_fd.is_some() {
            setup_console(&console_fd.unwrap()).with_context(|| "Failed to setup console")?;
        } else {
            connect_stdio(
                self.stdin.as_ref().unwrap(),
                self.stdout.as_ref().unwrap(),
                self.stderr.as_ref().unwrap(),
            )?;
            // SAFETY: FFI call with valid arguments.
            unsafe { libc::ioctl(0, libc::TIOCSCTTY) };
        }
        Ok(())
    }

    pub fn set_oom_score_adj(&self) -> Result<()> {
        if let Some(score) = self.oci.oomScoreAdj {
            fs::write("/proc/self/oom_score_adj", score.to_string().as_bytes())?;
        }
        Ok(())
    }

    pub fn set_rlimits(&self) -> Result<()> {
        if let Some(rlimits) = self.oci.rlimits.as_ref() {
            for rlimit in rlimits {
                setrlimit(
                    Resource::from_str(&rlimit.rlimit_type)
                        .with_context(|| "rlimit type is ill-formatted")?,
                    Rlim::from_raw(rlimit.soft),
                    Rlim::from_raw(rlimit.hard),
                )?;
            }
        }
        Ok(())
    }

    pub fn set_io_priority(&self) -> Result<()> {
        if let Some(io_prio) = &self.oci.ioPriority {
            let class = match io_prio.class {
                IoPriClass::IoprioClassRt => 1i64,
                IoPriClass::IoprioClassBe => 2i64,
                IoPriClass::IoprioClassIdle => 3i64,
            };
            // Who is a process id or thread id identifying a single process or
            // thread. If who is 0, then operate on the calling process or thread.
            let io_prio_who_process: libc::c_int = 1;
            let io_prio_who_pid = 0;
            // SAFETY: FFI call with valid arguments.
            match unsafe {
                libc::syscall(
                    libc::SYS_ioprio_set,
                    io_prio_who_process,
                    io_prio_who_pid,
                    (class << 13) | io_prio.priority,
                )
            } {
                0 => Ok(()),
                -1 => Err(nix::Error::last()),
                _ => Err(nix::Error::UnknownErrno),
            }?;
        }
        Ok(())
    }

    pub fn set_scheduler(&self) -> Result<()> {
        if let Some(scheduler) = &self.oci.scheduler {
            // SAFETY: FFI call with valid arguments.
            let mut param: libc::sched_param = unsafe { mem::zeroed() };
            param.sched_priority = scheduler.priority.unwrap_or_default();
            // SAFETY: FFI call with valid arguments.
            match unsafe { libc::sched_setscheduler(0, scheduler.policy.into(), &param) } {
                0 => Ok(()),
                -1 => Err(nix::Error::last()),
                _ => Err(nix::Error::UnknownErrno),
            }?;
        }
        Ok(())
    }

    pub fn no_new_privileges(&self) -> bool {
        self.oci.noNewPrivileges.is_some()
    }

    pub fn set_no_new_privileges(&self) -> Result<()> {
        if let Some(no_new_privileges) = self.oci.noNewPrivileges {
            if no_new_privileges {
                set_no_new_privileges(true)
                    .map_err(|e| anyhow!("Failed to set no new privileges: {}", e))?;
            }
        }
        Ok(())
    }

    pub fn chdir_cwd(&self) -> Result<()> {
        if !self.oci.cwd.is_empty() {
            chdir(&PathBuf::from(&self.oci.cwd))
                .with_context(|| format!("Failed to chdir to {}", &self.oci.cwd))?;
        }
        Ok(())
    }

    pub fn drop_capabilities(&self) -> Result<()> {
        if let Some(caps) = self.oci.capabilities.as_ref() {
            if let Some(bounding) = caps.bounding.as_ref() {
                let all_caps = caps::read(None, CapSet::Bounding)
                    .with_context(|| OzonecErr::GetAllCaps("Bounding".to_string()))?;
                let caps_hash_set = to_cap_set(bounding)?;
                for cap in all_caps.difference(&caps_hash_set) {
                    caps::drop(None, CapSet::Bounding, *cap).with_context(|| {
                        format!("Failed to drop {} from bonding set", cap.to_string())
                    })?;
                }
            }
            if let Some(effective) = caps.effective.as_ref() {
                caps::set(None, CapSet::Effective, &to_cap_set(effective)?)
                    .with_context(|| OzonecErr::SetCaps("Effective".to_string()))?;
            }
            if let Some(permitted) = caps.permitted.as_ref() {
                caps::set(None, CapSet::Permitted, &to_cap_set(permitted)?)
                    .with_context(|| OzonecErr::SetCaps("Permitted".to_string()))?;
            }
            if let Some(inheritable) = caps.inheritable.as_ref() {
                caps::set(None, CapSet::Inheritable, &to_cap_set(inheritable)?)
                    .with_context(|| OzonecErr::SetCaps("Inheritable".to_string()))?;
            }
            if let Some(ambient) = caps.ambient.as_ref() {
                caps::set(None, CapSet::Ambient, &to_cap_set(ambient)?)
                    .with_context(|| OzonecErr::SetCaps("Ambient".to_string()))?;
            }
        }
        Ok(())
    }

    pub fn set_apparmor(&self) -> Result<()> {
        if let Some(profile) = &self.oci.apparmorProfile {
            if !apparmor::is_enabled()? {
                bail!("Apparmor is disabled.");
            }
            apparmor::apply_profile(profile)?;
        }
        Ok(())
    }

    pub fn reset_capabilities(&self) -> Result<()> {
        let permitted = caps::read(None, CapSet::Permitted)
            .with_context(|| OzonecErr::GetAllCaps("Permitted".to_string()))?;
        caps::set(None, CapSet::Effective, &permitted)?;
        Ok(())
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

    pub fn set_process_id(&self) -> Result<()> {
        let gid = Gid::from(self.oci.user.gid);
        let uid = Uid::from(self.oci.user.uid);
        self.set_id(gid, uid)?;
        Ok(())
    }

    pub fn set_id(&self, gid: Gid, uid: Uid) -> Result<()> {
        set_keep_capabilities(true)
            .map_err(|e| anyhow!("Failed to enable keeping capabilities: {}", e))?;
        setresgid(gid, gid, gid).with_context(|| "Failed to setresgid")?;
        setresuid(uid, uid, uid).with_context(|| "Failed to setresuid")?;

        let permitted = caps::read(None, CapSet::Permitted)
            .with_context(|| OzonecErr::GetAllCaps("Permitted".to_string()))?;
        caps::set(None, CapSet::Effective, &permitted)
            .with_context(|| OzonecErr::SetCaps("Effective".to_string()))?;
        set_keep_capabilities(false)
            .map_err(|e| anyhow!("Failed to disable keeping capabilities: {}", e))?;
        Ok(())
    }

    // Check and reserve valid environment variables.
    // Invalid env vars may cause panic, refer to https://doc.rust-lang.org/std/env/fn.set_var.html#panics
    // Key should not :
    // * contain NULL character '\0'
    // * contain ASCII character '='
    // * be empty
    // Value should not:
    // * contain NULL character '\0'
    fn is_env_valid(env: &str) -> Option<(&str, &str)> {
        // Split the env var by '=' to ensure there is no '=' in key, and there is only one '='
        // in the whole env var.
        if let Some((key, value)) = env.split_once('=') {
            if !key.is_empty()
                && !key.as_bytes().contains(&b'\0')
                && !value.as_bytes().contains(&b'\0')
            {
                return Some((key.trim(), value.trim()));
            }
        }
        None
    }

    pub fn set_envs(&self) {
        if let Some(envs) = &self.oci.env {
            for env in envs {
                if let Some((key, value)) = Self::is_env_valid(env) {
                    env::set_var(key, value);
                }
            }
        }
    }

    pub fn clean_envs(&self) {
        env::vars().for_each(|(key, _value)| env::remove_var(key));
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
    clone3.exit_signal(libc::SIGCHLD as u64);

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

fn to_cap_set(caps: &Vec<String>) -> Result<CapsHashSet> {
    let mut caps_hash_set = CapsHashSet::new();

    for c in caps {
        let cap = to_cap(&c)?;
        caps_hash_set.insert(cap);
    }
    Ok(caps_hash_set)
}

fn to_cap(value: &str) -> Result<Capability> {
    let binding = value.to_uppercase();
    let stripped = binding.strip_prefix("CAP_").unwrap_or(&binding);

    match stripped {
        "AUDIT_CONTROL" => Ok(Capability::CAP_AUDIT_CONTROL),
        "AUDIT_READ" => Ok(Capability::CAP_AUDIT_READ),
        "AUDIT_WRITE" => Ok(Capability::CAP_AUDIT_WRITE),
        "BLOCK_SUSPEND" => Ok(Capability::CAP_BLOCK_SUSPEND),
        "BPF" => Ok(Capability::CAP_BPF),
        "CHECKPOINT_RESTORE" => Ok(Capability::CAP_CHECKPOINT_RESTORE),
        "CHOWN" => Ok(Capability::CAP_CHOWN),
        "DAC_OVERRIDE" => Ok(Capability::CAP_DAC_OVERRIDE),
        "DAC_READ_SEARCH" => Ok(Capability::CAP_DAC_READ_SEARCH),
        "FOWNER" => Ok(Capability::CAP_FOWNER),
        "FSETID" => Ok(Capability::CAP_FSETID),
        "IPC_LOCK" => Ok(Capability::CAP_IPC_LOCK),
        "IPC_OWNER" => Ok(Capability::CAP_IPC_OWNER),
        "KILL" => Ok(Capability::CAP_KILL),
        "LEASE" => Ok(Capability::CAP_LEASE),
        "LINUX_IMMUTABLE" => Ok(Capability::CAP_LINUX_IMMUTABLE),
        "MAC_ADMIN" => Ok(Capability::CAP_MAC_ADMIN),
        "MAC_OVERRIDE" => Ok(Capability::CAP_MAC_OVERRIDE),
        "MKNOD" => Ok(Capability::CAP_MKNOD),
        "NET_ADMIN" => Ok(Capability::CAP_NET_ADMIN),
        "NET_BIND_SERVICE" => Ok(Capability::CAP_NET_BIND_SERVICE),
        "NET_BROADCAST" => Ok(Capability::CAP_NET_BROADCAST),
        "NET_RAW" => Ok(Capability::CAP_NET_RAW),
        "PERFMON" => Ok(Capability::CAP_PERFMON),
        "SETGID" => Ok(Capability::CAP_SETGID),
        "SETFCAP" => Ok(Capability::CAP_SETFCAP),
        "SETPCAP" => Ok(Capability::CAP_SETPCAP),
        "SETUID" => Ok(Capability::CAP_SETUID),
        "SYS_ADMIN" => Ok(Capability::CAP_SYS_ADMIN),
        "SYS_BOOT" => Ok(Capability::CAP_SYS_BOOT),
        "SYS_CHROOT" => Ok(Capability::CAP_SYS_CHROOT),
        "SYS_MODULE" => Ok(Capability::CAP_SYS_MODULE),
        "SYS_NICE" => Ok(Capability::CAP_SYS_NICE),
        "SYS_PACCT" => Ok(Capability::CAP_SYS_PACCT),
        "SYS_PTRACE" => Ok(Capability::CAP_SYS_PTRACE),
        "SYS_RAWIO" => Ok(Capability::CAP_SYS_RAWIO),
        "SYS_RESOURCE" => Ok(Capability::CAP_SYS_RESOURCE),
        "SYS_TIME" => Ok(Capability::CAP_SYS_TIME),
        "SYS_TTY_CONFIG" => Ok(Capability::CAP_SYS_TTY_CONFIG),
        "SYSLOG" => Ok(Capability::CAP_SYSLOG),
        "WAKE_ALARM" => Ok(Capability::CAP_WAKE_ALARM),
        _ => bail!("Invalid capability: {}", value),
    }
}
