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
    os::unix::{
        io::{AsRawFd, RawFd},
        net::UnixStream,
    },
    path::PathBuf,
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use caps::{self, CapSet, Capability, CapsHashSet};
use libc::SIGCHLD;
use nix::{
    errno::Errno,
    sched::{clone, CloneFlags},
    unistd::{self, chdir, setresgid, setresuid, Gid, Pid, Uid},
};
use rlimit::{setrlimit, Resource, Rlim};

use super::{apparmor, terminal::setup_console};
use crate::utils::{prctl, Clone3, OzonecErr};
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

    pub fn set_tty(&self, console_fd: Option<UnixStream>, mount: bool) -> Result<()> {
        if self.tty {
            if console_fd.is_none() {
                bail!("Terminal is specified, but no console socket set");
            }
            setup_console(&console_fd.unwrap().as_raw_fd(), mount)
                .with_context(|| "Failed to setup console")?;
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
                prctl::set_no_new_privileges(true)
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
                    caps::drop(None, CapSet::Bounding, *cap)
                        .with_context(|| format!("Failed to drop {} from bonding set", cap))?;
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
        prctl::set_keep_capabilities(true)
            .map_err(|e| anyhow!("Failed to enable keeping capabilities: {}", e))?;
        setresgid(gid, gid, gid).with_context(|| "Failed to setresgid")?;
        setresuid(uid, uid, uid).with_context(|| "Failed to setresuid")?;

        let permitted = caps::read(None, CapSet::Permitted)
            .with_context(|| OzonecErr::GetAllCaps("Permitted".to_string()))?;
        caps::set(None, CapSet::Effective, &permitted)
            .with_context(|| OzonecErr::SetCaps("Effective".to_string()))?;
        prctl::set_keep_capabilities(false)
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
        let exec_bin = CString::new(args[0].as_bytes()).unwrap();
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

    pub fn getcwd() -> Result<()> {
        unistd::getcwd().map_err(|e| match e {
            Errno::ENOENT => anyhow!("Current working directory is out of container rootfs"),
            _ => anyhow!("Failed to getcwd"),
        })?;
        Ok(())
    }
}

// Clone a new child process.
pub fn clone_process<F: FnMut() -> Result<i32>>(child_name: &str, mut cb: F) -> Result<Pid> {
    let mut clone3 = Clone3::default();
    clone3.exit_signal(SIGCHLD as u64);

    let mut ret = clone3.call();
    if ret.is_err() {
        // clone3() may not be supported in the kernel, fallback to clone();
        let mut stack = [0; 1024 * 1024];
        ret = clone(
            Box::new(|| match cb() {
                Ok(r) => r as isize,
                Err(e) => {
                    eprintln!("{}", e);
                    -1
                }
            }),
            &mut stack,
            CloneFlags::empty(),
            Some(SIGCHLD),
        )
        .map_err(|e| anyhow!("Clone error: errno {}", e));
    }

    match ret {
        Ok(pid) => {
            if pid.as_raw() != 0 {
                return Ok(pid);
            }

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
        Err(e) => bail!(e),
    }
}

fn to_cap_set(caps: &Vec<String>) -> Result<CapsHashSet> {
    let mut caps_hash_set = CapsHashSet::new();

    for c in caps {
        let cap = to_cap(c)?;
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

#[cfg(test)]
pub mod tests {
    use std::path::Path;

    use nix::sys::resource::{getrlimit, Resource};
    use rusty_fork::rusty_fork_test;
    use unistd::getcwd;

    use oci_spec::{
        linux::{Capbilities, IoPriority, SchedPolicy, Scheduler},
        posix::{Rlimits, User},
    };

    use super::*;

    pub fn init_oci_process() -> OciProcess {
        let user = User {
            uid: 0,
            gid: 0,
            umask: None,
            additionalGids: None,
        };
        OciProcess {
            cwd: String::from("/"),
            args: Some(vec![String::from("bash")]),
            env: None,
            terminal: false,
            consoleSize: None,
            rlimits: None,
            apparmorProfile: None,
            capabilities: None,
            noNewPrivileges: None,
            oomScoreAdj: None,
            scheduler: None,
            selinuxLabel: None,
            ioPriority: None,
            execCPUAffinity: None,
            user,
        }
    }

    #[test]
    fn test_process_new() {
        let mut oci_process = init_oci_process();

        let process = Process::new(&oci_process, false);
        assert_eq!(process.stdin.unwrap(), stdin().as_raw_fd());
        assert_eq!(process.stdout.unwrap(), stdout().as_raw_fd());
        assert_eq!(process.stderr.unwrap(), stderr().as_raw_fd());

        oci_process.terminal = true;
        let process = Process::new(&oci_process, false);
        assert!(process.stdin.is_none());
        assert!(process.stdout.is_none());
        assert!(process.stderr.is_none());
    }

    #[test]
    fn test_set_tty() {
        let mut oci_process = init_oci_process();

        let process = Process::new(&oci_process, false);
        assert!(process.set_tty(None, false).is_ok());

        oci_process.terminal = true;
        let process = Process::new(&oci_process, false);
        assert!(process.set_tty(None, false).is_err());
    }

    #[test]
    fn test_chdir_cwd() {
        let oci_process = init_oci_process();
        let process = Process::new(&oci_process, false);

        assert!(process.chdir_cwd().is_ok());
        assert_eq!(getcwd().unwrap().to_str().unwrap(), "/");
    }

    #[test]
    fn test_set_envs() {
        let mut oci_process = init_oci_process();
        oci_process.env = Some(vec![
            String::from("OZONEC_ENV_1=1"),
            String::from("=OZONEC_ENV_2"),
            String::from("OZONEC_ENV"),
        ]);
        let process = Process::new(&oci_process, false);

        process.set_envs();
        for (key, value) in env::vars() {
            if key == "OZONEC_ENV_1" {
                assert_eq!(value, "1");
                continue;
            }
            assert_ne!(value, "OZONEC_ENV_2");
            assert_ne!(key, "OZONEC_ENV");
            assert_ne!(value, "OZONEC_ENV");
        }

        env::remove_var("OZONEC_ENV_1");
    }

    #[test]
    fn test_to_cap() {
        assert_eq!(
            to_cap("CAP_AUDIT_CONTROL").unwrap(),
            Capability::CAP_AUDIT_CONTROL
        );
        assert_eq!(
            to_cap("CAP_AUDIT_READ").unwrap(),
            Capability::CAP_AUDIT_READ
        );
        assert_eq!(
            to_cap("CAP_AUDIT_WRITE").unwrap(),
            Capability::CAP_AUDIT_WRITE
        );
        assert_eq!(
            to_cap("CAP_BLOCK_SUSPEND").unwrap(),
            Capability::CAP_BLOCK_SUSPEND
        );
        assert_eq!(to_cap("CAP_BPF").unwrap(), Capability::CAP_BPF);
        assert_eq!(
            to_cap("CAP_CHECKPOINT_RESTORE").unwrap(),
            Capability::CAP_CHECKPOINT_RESTORE
        );
        assert_eq!(to_cap("CAP_CHOWN").unwrap(), Capability::CAP_CHOWN);
        assert_eq!(
            to_cap("CAP_DAC_OVERRIDE").unwrap(),
            Capability::CAP_DAC_OVERRIDE
        );
        assert_eq!(
            to_cap("CAP_DAC_READ_SEARCH").unwrap(),
            Capability::CAP_DAC_READ_SEARCH
        );
        assert_eq!(to_cap("CAP_FOWNER").unwrap(), Capability::CAP_FOWNER);
        assert_eq!(to_cap("CAP_FSETID").unwrap(), Capability::CAP_FSETID);
        assert_eq!(to_cap("CAP_IPC_LOCK").unwrap(), Capability::CAP_IPC_LOCK);
        assert_eq!(to_cap("CAP_IPC_OWNER").unwrap(), Capability::CAP_IPC_OWNER);
        assert_eq!(to_cap("CAP_KILL").unwrap(), Capability::CAP_KILL);
        assert_eq!(to_cap("CAP_LEASE").unwrap(), Capability::CAP_LEASE);
        assert_eq!(
            to_cap("CAP_LINUX_IMMUTABLE").unwrap(),
            Capability::CAP_LINUX_IMMUTABLE
        );
        assert_eq!(to_cap("CAP_MAC_ADMIN").unwrap(), Capability::CAP_MAC_ADMIN);
        assert_eq!(
            to_cap("CAP_MAC_OVERRIDE").unwrap(),
            Capability::CAP_MAC_OVERRIDE
        );
        assert_eq!(to_cap("CAP_MKNOD").unwrap(), Capability::CAP_MKNOD);
        assert_eq!(to_cap("CAP_NET_ADMIN").unwrap(), Capability::CAP_NET_ADMIN);
        assert_eq!(
            to_cap("CAP_NET_BIND_SERVICE").unwrap(),
            Capability::CAP_NET_BIND_SERVICE
        );
        assert_eq!(
            to_cap("CAP_NET_BROADCAST").unwrap(),
            Capability::CAP_NET_BROADCAST
        );
        assert_eq!(to_cap("CAP_NET_RAW").unwrap(), Capability::CAP_NET_RAW);
        assert_eq!(to_cap("CAP_PERFMON").unwrap(), Capability::CAP_PERFMON);
        assert_eq!(to_cap("CAP_SETGID").unwrap(), Capability::CAP_SETGID);
        assert_eq!(to_cap("CAP_SETFCAP").unwrap(), Capability::CAP_SETFCAP);
        assert_eq!(to_cap("CAP_SETPCAP").unwrap(), Capability::CAP_SETPCAP);
        assert_eq!(to_cap("CAP_SETUID").unwrap(), Capability::CAP_SETUID);
        assert_eq!(to_cap("CAP_SYS_ADMIN").unwrap(), Capability::CAP_SYS_ADMIN);
        assert_eq!(to_cap("CAP_SYS_BOOT").unwrap(), Capability::CAP_SYS_BOOT);
        assert_eq!(
            to_cap("CAP_SYS_CHROOT").unwrap(),
            Capability::CAP_SYS_CHROOT
        );
        assert_eq!(
            to_cap("CAP_SYS_MODULE").unwrap(),
            Capability::CAP_SYS_MODULE
        );
        assert_eq!(to_cap("CAP_SYS_NICE").unwrap(), Capability::CAP_SYS_NICE);
        assert_eq!(to_cap("CAP_SYS_PACCT").unwrap(), Capability::CAP_SYS_PACCT);
        assert_eq!(
            to_cap("CAP_SYS_PTRACE").unwrap(),
            Capability::CAP_SYS_PTRACE
        );
        assert_eq!(to_cap("CAP_SYS_RAWIO").unwrap(), Capability::CAP_SYS_RAWIO);
        assert_eq!(
            to_cap("CAP_SYS_RESOURCE").unwrap(),
            Capability::CAP_SYS_RESOURCE
        );
        assert_eq!(to_cap("CAP_SYS_TIME").unwrap(), Capability::CAP_SYS_TIME);
        assert_eq!(
            to_cap("CAP_SYS_TTY_CONFIG").unwrap(),
            Capability::CAP_SYS_TTY_CONFIG
        );
        assert_eq!(to_cap("CAP_SYSLOG").unwrap(), Capability::CAP_SYSLOG);
        assert_eq!(
            to_cap("CAP_WAKE_ALARM").unwrap(),
            Capability::CAP_WAKE_ALARM
        );
        assert!(to_cap("CAP_TO_CAP").is_err());
    }

    rusty_fork_test! {
        #[test]
        #[ignore = "oom_score_adj may not be permitted to set"]
        fn test_set_oom_score_adj() {
            let mut oci_process = init_oci_process();
            oci_process.oomScoreAdj = Some(100);
            let process = Process::new(&oci_process, false);

            assert!(process.set_oom_score_adj().is_ok());
            assert_eq!(
                read_to_string(Path::new("/proc/self/oom_score_adj")).unwrap(),
                String::from("100\n")
            );
        }

        #[test]
        #[ignore = "setrlimit may not be permitted"]
        fn test_set_rlimits() {
            let mut oci_process = init_oci_process();
            let rlimits = Rlimits {
                rlimit_type: String::from("RLIMIT_CORE"),
                soft: 10,
                hard: 20,
            };
            oci_process.rlimits = Some(vec![rlimits]);
            let process = Process::new(&oci_process, false);

            assert!(process.set_rlimits().is_ok());
            assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap().0, 10);
            assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap().1, 20);
        }

        #[test]
        fn test_set_io_priority() {
            let mut oci_process = init_oci_process();
            let io_pri = IoPriority {
                class: IoPriClass::IoprioClassBe,
                priority: 7,
            };
            oci_process.ioPriority = Some(io_pri.clone());
            let process = Process::new(&oci_process, false);

            assert!(process.set_io_priority().is_ok());

            let io_prio_who_process: libc::c_int = 1;
            let io_prio_who_pid = 0;
            let ioprio = unsafe {
                libc::syscall(libc::SYS_ioprio_get, io_prio_who_process, io_prio_who_pid)
            };
            assert_eq!(ioprio, (2 as i64) << 13 | io_pri.priority);
        }

        #[test]
        fn test_set_scheduler() {
            let mut oci_process = init_oci_process();
            let scheduler = Scheduler {
                policy: SchedPolicy::SchedOther,
                nice: None,
                priority: None,
                flags: None,
                runtime: None,
                deadline: None,
                period: None,
            };
            oci_process.scheduler = Some(scheduler);
            let process = Process::new(&oci_process, false);

            assert!(process.set_scheduler().is_ok());
        }

        #[test]
        fn test_set_no_new_privileges() {
            let mut oci_process = init_oci_process();
            oci_process.noNewPrivileges = Some(true);
            let process = Process::new(&oci_process, false);

            assert!(process.set_no_new_privileges().is_ok());
        }

        #[test]
        #[ignore = "capset may not be permitted"]
        fn test_drop_capabilities() {
            let mut oci_process = init_oci_process();
            let caps = Capbilities {
                effective: Some(vec![
                    String::from("CAP_DAC_OVERRIDE"),
                    String::from("CAP_DAC_READ_SEARCH"),
                    String::from("CAP_SETFCAP"),
                ]),
                bounding: Some(vec![
                    String::from("CAP_DAC_OVERRIDE"),
                    String::from("CAP_DAC_READ_SEARCH"),
                ]),
                inheritable: Some(vec![String::from("CAP_DAC_READ_SEARCH")]),
                permitted: Some(vec![
                    String::from("CAP_DAC_OVERRIDE"),
                    String::from("CAP_DAC_READ_SEARCH"),
                    String::from("CAP_SETFCAP"),
                ]),
                ambient: Some(vec![String::from("CAP_DAC_READ_SEARCH")]),
            };
            oci_process.capabilities = Some(caps);
            let process = Process::new(&oci_process, false);

            assert!(process.drop_capabilities().is_ok());
            let mut caps = caps::read(None, CapSet::Bounding).unwrap();
            assert_eq!(caps.len(), 2);
            assert!(caps.get(&Capability::CAP_DAC_OVERRIDE).is_some());
            assert!(caps.get(&Capability::CAP_DAC_READ_SEARCH).is_some());
            caps = caps::read(None, CapSet::Effective).unwrap();
            assert_eq!(caps.len(), 3);
            assert!(caps.get(&Capability::CAP_DAC_OVERRIDE).is_some());
            assert!(caps.get(&Capability::CAP_DAC_READ_SEARCH).is_some());
            assert!(caps.get(&Capability::CAP_SETFCAP).is_some());
            caps = caps::read(None, CapSet::Inheritable).unwrap();
            assert_eq!(caps.len(), 1);
            assert!(caps.get(&Capability::CAP_DAC_READ_SEARCH).is_some());
            caps = caps::read(None, CapSet::Permitted).unwrap();
            assert_eq!(caps.len(), 3);
            assert!(caps.get(&Capability::CAP_DAC_OVERRIDE).is_some());
            assert!(caps.get(&Capability::CAP_DAC_READ_SEARCH).is_some());
            assert!(caps.get(&Capability::CAP_SETFCAP).is_some());
            caps = caps::read(None, CapSet::Ambient).unwrap();
            assert_eq!(caps.len(), 1);
            assert!(caps.get(&Capability::CAP_DAC_READ_SEARCH).is_some());
        }

        #[test]
        fn test_reset_capabilities() {
            let oci_process = init_oci_process();
            let process = Process::new(&oci_process, false);

            assert!(process.reset_capabilities().is_ok());
            let permit_caps = caps::read(None, CapSet::Permitted).unwrap();
            let eff_caps = caps::read(None, CapSet::Effective).unwrap();
            assert_eq!(permit_caps, eff_caps);
        }

        #[test]
        fn test_clean_envs() {
            let oci_process = init_oci_process();
            let process = Process::new(&oci_process, false);
            process.clean_envs();
            assert_eq!(env::vars().count(), 0);
        }
    }
}
