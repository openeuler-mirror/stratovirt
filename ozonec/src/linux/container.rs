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
    fs::{self, canonicalize, create_dir_all, OpenOptions},
    io::Write,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread::sleep,
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, bail, Context, Result};
use libc::{c_char, pid_t, setdomainname};
use log::{debug, info};
use nix::{
    errno::Errno,
    mount::MsFlags,
    sys::{
        signal::{kill, Signal},
        statfs::statfs,
        wait::{waitpid, WaitStatus},
    },
    unistd::{self, chown, getegid, geteuid, sethostname, unlink, Gid, Pid, Uid},
};
use procfs::process::ProcState;

use super::{
    namespace::NsController,
    notify_socket::{NotifySocket, NOTIFY_SOCKET},
    process::clone_process,
    NotifyListener, Process,
};
use crate::{
    container::{Container, State},
    linux::{rootfs::Rootfs, seccomp::set_seccomp},
    utils::{prctl, Channel, Message, OzonecErr},
};
use oci_spec::{
    linux::{Device as OciDevice, IdMapping, NamespaceType},
    runtime::RuntimeConfig,
    state::{ContainerStatus, State as OciState},
};

pub struct LinuxContainer {
    pub id: String,
    pub root: String,
    pub config: RuntimeConfig,
    pub pid: pid_t,
    pub start_time: u64,
    pub created_time: SystemTime,
    pub console_socket: Option<PathBuf>,
}

impl LinuxContainer {
    pub fn new(
        id: &String,
        root: &String,
        config: &RuntimeConfig,
        console_socket: &Option<PathBuf>,
        exist: &mut bool,
    ) -> Result<Self> {
        let container_dir = format!("{}/{}", root, id);

        Self::validate_config(config)?;

        if Path::new(container_dir.as_str()).exists() {
            *exist = true;
            bail!("Container {} already exists", id);
        }
        create_dir_all(container_dir.as_str())
            .with_context(|| OzonecErr::CreateDir(container_dir.clone()))?;
        chown(container_dir.as_str(), Some(geteuid()), Some(getegid()))
            .with_context(|| "Failed to chown container directory")?;

        Ok(Self {
            id: id.clone(),
            root: container_dir,
            config: config.clone(),
            pid: -1,
            start_time: 0,
            created_time: SystemTime::now(),
            console_socket: console_socket.clone(),
        })
    }

    pub fn load_from_state(state: &State, console_socket: &Option<PathBuf>) -> Result<Self> {
        let root_path = format!("{}/{}", state.root.to_string_lossy(), &state.id);
        let config = state
            .config
            .clone()
            .ok_or_else(|| anyhow!("Can't find config in state"))?;

        Ok(Self {
            id: state.id.clone(),
            root: root_path,
            config,
            pid: state.pid,
            start_time: state.start_time,
            created_time: state.created_time.into(),
            console_socket: console_socket.clone(),
        })
    }

    fn validate_config(config: &RuntimeConfig) -> Result<()> {
        if config.linux.is_none() {
            bail!("There is no linux specific configuration in config.json for Linux container");
        }
        if config.process.args.is_none() {
            bail!("args in process is not set in config.json.");
        }
        Ok(())
    }

    fn do_first_stage(
        &mut self,
        process: &mut Process,
        parent_channel: &Channel<Message>,
        fst_stage_channel: &Channel<Message>,
        notify_listener: &Option<NotifyListener>,
    ) -> Result<()> {
        debug!("First stage process start");

        fst_stage_channel
            .receiver
            .close()
            .with_context(|| "Failed to close receiver end of first stage channel")?;

        process
            .set_rlimits()
            .with_context(|| "Failed to set rlimit")?;
        self.set_user_namespace(parent_channel, fst_stage_channel, process)?;
        // New pid namespace goes intto effect in cloned child processes.
        self.set_pid_namespace()?;

        // Spawn a child process to perform the second stage to initialize container.
        let init_pid = clone_process("ozonec:[2:INIT]", || {
            self.do_second_stage(process, parent_channel, notify_listener)
                .with_context(|| "Second stage process encounters errors")?;
            Ok(0)
        })?;

        // Send the final container pid to the parent process.
        parent_channel.send_init_pid(init_pid)?;

        debug!("First stage process exit");
        Ok(())
    }

    fn do_second_stage(
        &mut self,
        process: &mut Process,
        parent_channel: &Channel<Message>,
        notify_listener: &Option<NotifyListener>,
    ) -> Result<()> {
        debug!("Second stage process start");

        unistd::setsid().with_context(|| "Failed to setsid")?;
        process
            .set_io_priority()
            .with_context(|| "Failed to set io priority")?;
        process
            .set_scheduler()
            .with_context(|| "Failed to set scheduler")?;

        let console_stream = match &self.console_socket {
            Some(cs) => {
                Some(UnixStream::connect(cs).with_context(|| "Failed to connect console socket")?)
            }
            None => None,
        };
        self.set_rest_namespaces()?;
        process.set_no_new_privileges()?;

        if process.init {
            let propagation = self
                .config
                .linux
                .as_ref()
                .unwrap()
                .rootfsPropagation
                .clone();
            // Container running in a user namespace is not allowed to do mknod.
            let mknod_device = !self.is_namespace_set(NamespaceType::User)?;
            let mut devices: Vec<OciDevice> = Vec::new();
            if let Some(devs) = self.config.linux.as_ref().unwrap().devices.as_ref() {
                devices = devs.clone()
            };
            let rootfs = Rootfs::new(
                self.config.root.path.clone().into(),
                propagation,
                self.config.mounts.clone(),
                mknod_device,
                devices,
            )?;
            rootfs.prepare_rootfs(&self.config)?;

            // Entering into rootfs jail. If mount namespace is specified, use pivot_root.
            // Otherwise use chroot.
            if self.is_namespace_set(NamespaceType::Mount)? {
                Rootfs::pivot_root(&rootfs.path).with_context(|| "Failed to pivot_root")?;
            } else {
                Rootfs::chroot(&rootfs.path).with_context(|| "Failed to chroot")?;
            }

            self.set_sysctl_parameters()?;
        } else if !self.is_namespace_set(NamespaceType::Mount)? {
            Rootfs::chroot(&PathBuf::from(self.config.root.path.clone()))
                .with_context(|| "Failed to chroot")?;
        }

        process
            .set_tty(console_stream, process.init)
            .with_context(|| "Failed to set tty")?;
        process.set_apparmor()?;
        if self.config.root.readonly {
            LinuxContainer::mount_rootfs_readonly()?;
        }
        self.set_readonly_paths()?;
        self.set_masked_paths()?;

        let chdir_cwd_ret = process.chdir_cwd().is_err();
        process.set_additional_gids()?;
        process.set_process_id()?;

        // Without setting no new privileges, setting seccomp is a privileged operation.
        if !process.no_new_privileges() {
            if let Some(seccomp) = &self.config.linux.as_ref().unwrap().seccomp {
                set_seccomp(seccomp).with_context(|| "Failed to set seccomp")?;
            }
        }
        process
            .reset_capabilities()
            .with_context(|| "Failed to reset capabilities")?;
        process
            .drop_capabilities()
            .with_context(|| "Failed to drop capabilities")?;
        if chdir_cwd_ret {
            process.chdir_cwd()?;
        }
        // Ensure that the current working directory is inside the mount namespace root
        // of the current container process.
        Process::getcwd()?;
        process.clean_envs();
        process.set_envs();
        if process.no_new_privileges() {
            if let Some(seccomp) = &self.config.linux.as_ref().unwrap().seccomp {
                set_seccomp(seccomp).with_context(|| "Failed to set seccomp")?;
            }
        }

        // Tell the parent process that the init process has been cloned.
        parent_channel.send_container_created()?;
        parent_channel
            .sender
            .close()
            .with_context(|| "Failed to close sender of parent channel")?;

        // Listening on the notify socket to start container.
        if let Some(listener) = notify_listener {
            listener.wait_for_start_container()?;
            listener
                .close()
                .with_context(|| "Failed to close notify socket")?;
        }
        process.exec_program();
    }

    fn mount_rootfs_readonly() -> Result<()> {
        let ms_flags = MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT | MsFlags::MS_BIND;
        let root_path = Path::new("/");
        let fs_flags = statfs(root_path)
            .with_context(|| "Statfs root directory error")?
            .flags()
            .bits();

        nix::mount::mount(
            None::<&str>,
            root_path,
            None::<&str>,
            ms_flags | MsFlags::from_bits_truncate(fs_flags),
            None::<&str>,
        )
        .with_context(|| "Failed to remount rootfs readonly")?;
        Ok(())
    }

    fn get_container_status(&self) -> Result<ContainerStatus> {
        if self.pid == -1 {
            return Ok(ContainerStatus::Creating);
        }

        let proc = procfs::process::Process::new(self.pid);
        // If error occurs when accessing /proc/<pid>, the process most likely has stopped.
        if proc.is_err() {
            return Ok(ContainerStatus::Stopped);
        }
        let proc_stat = proc
            .unwrap()
            .stat()
            .with_context(|| OzonecErr::ReadProcStat(self.pid))?;
        // If starttime is not the same, then pid is reused, and the original process has stopped.
        if proc_stat.starttime != self.start_time {
            return Ok(ContainerStatus::Stopped);
        }

        match proc_stat.state()? {
            ProcState::Zombie | ProcState::Dead => Ok(ContainerStatus::Stopped),
            _ => {
                let notify_socket = PathBuf::from(&self.root).join(NOTIFY_SOCKET);
                if notify_socket.exists() {
                    return Ok(ContainerStatus::Created);
                }
                Ok(ContainerStatus::Running)
            }
        }
    }

    pub fn status(&self) -> Result<ContainerStatus> {
        Ok(self
            .get_oci_state()
            .with_context(|| OzonecErr::GetOciState)?
            .status)
    }

    fn ns_controller(&self) -> Result<NsController> {
        self.config
            .linux
            .as_ref()
            .unwrap()
            .namespaces
            .clone()
            .try_into()
    }

    fn set_user_namespace(
        &self,
        parent_channel: &Channel<Message>,
        fst_stage_channel: &Channel<Message>,
        process: &Process,
    ) -> Result<()> {
        let ns_controller: NsController = self.ns_controller()?;

        if let Some(ns) = ns_controller.get(NamespaceType::User)? {
            ns_controller
                .set_namespace(NamespaceType::User)
                .with_context(|| "Failed to set user namespace")?;

            if ns.path.is_none() {
                // Child process needs to be dumpable, otherwise the parent process is not
                // allowed to write the uid/gid mappings.
                prctl::set_dumpable(true)
                    .map_err(|e| anyhow!("Failed to set process dumpable: {e}"))?;
                parent_channel
                    .send_id_mappings()
                    .with_context(|| "Failed to send id mappings")?;
                fst_stage_channel
                    .recv_id_mappings_done()
                    .with_context(|| "Failed to receive id mappings done")?;
                prctl::set_dumpable(false)
                    .map_err(|e| anyhow!("Failed to set process undumpable: {e}"))?;
            }

            // After UID/GID mappings are configured, ozonec wants to make sure continue as
            // the root user inside the new user namespace. This is required because the
            // process of configuring the container process will require root, even though
            // the root in the user namespace is likely mapped to an non-privileged user.
            process.set_id(Gid::from_raw(0), Uid::from_raw(0))?;
        }
        Ok(())
    }

    fn is_namespace_set(&self, ns_type: NamespaceType) -> Result<bool> {
        let ns_controller: NsController = self.ns_controller()?;
        Ok(ns_controller.get(ns_type)?.is_some())
    }

    fn set_pid_namespace(&self) -> Result<()> {
        let ns_controller = self.ns_controller()?;

        if ns_controller.get(NamespaceType::Pid)?.is_some() {
            ns_controller
                .set_namespace(NamespaceType::Pid)
                .with_context(|| "Failed to set pid namespace")?;
        }
        Ok(())
    }

    fn set_readonly_paths(&self) -> Result<()> {
        if let Some(readonly_paths) = self.config.linux.as_ref().unwrap().readonlyPaths.clone() {
            for p in readonly_paths {
                let path = Path::new(&p);
                if let Err(e) = nix::mount::mount(
                    Some(path),
                    path,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    None::<&str>,
                ) {
                    if matches!(e, Errno::ENOENT) {
                        return Ok(());
                    }
                    bail!("Failed to make {} as recursive bind mount", path.display());
                }

                nix::mount::mount(
                    Some(path),
                    path,
                    None::<&str>,
                    MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOEXEC
                        | MsFlags::MS_BIND
                        | MsFlags::MS_REMOUNT
                        | MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .with_context(|| format!("Failed to remount {} readonly", path.display()))?;
            }
        }
        Ok(())
    }

    fn set_masked_paths(&self) -> Result<()> {
        let linux = self.config.linux.as_ref().unwrap();
        if let Some(masked_paths) = linux.maskedPaths.clone() {
            for p in masked_paths {
                let path = Path::new(&p);
                if let Err(e) = nix::mount::mount(
                    Some(Path::new("/dev/null")),
                    path,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                ) {
                    match e {
                        // Ignore if path doesn't exists.
                        Errno::ENOENT => (),
                        Errno::ENOTDIR => {
                            let label = match linux.mountLabel.clone() {
                                Some(l) => format!("context=\"{}\"", l),
                                None => "".to_string(),
                            };
                            nix::mount::mount(
                                Some(Path::new("tmpfs")),
                                path,
                                Some("tmpfs"),
                                MsFlags::MS_RDONLY,
                                Some(label.as_str()),
                            )
                            .with_context(|| {
                                format!(
                                    "Failed to make {} as masked mount by tmpfs",
                                    path.display()
                                )
                            })?;
                        }
                        _ => bail!(
                            "Failed to make {} as masked mount by /dev/null",
                            path.display()
                        ),
                    }
                }
            }
        }
        Ok(())
    }

    fn set_rest_namespaces(&self) -> Result<()> {
        let ns_config = &self.config.linux.as_ref().unwrap().namespaces;
        let ns_controller: NsController = ns_config.clone().try_into()?;
        let mut mnt_ns = false;

        for ns in ns_config {
            match ns.ns_type {
                // User namespace and pid namespace have been set in the first stage.
                // Mount namespace is going to be set later to avoid failure with
                // existed namespaces.
                NamespaceType::User | NamespaceType::Pid => (),
                NamespaceType::Mount => mnt_ns = true,
                _ => ns_controller.set_namespace(ns.ns_type).with_context(|| {
                    format!(
                        "Failed to set {} namespace",
                        <NamespaceType as Into<String>>::into(ns.ns_type)
                    )
                })?,
            }

            if ns.ns_type == NamespaceType::Uts && ns.path.is_none() {
                if let Some(hostname) = &self.config.hostname {
                    sethostname(hostname).with_context(|| "Failed to set hostname")?;
                }
                if let Some(domainname) = &self.config.domainname {
                    // SAFETY: FFI call with valid arguments.
                    let errno = match unsafe {
                        setdomainname(
                            domainname.as_bytes().as_ptr() as *const c_char,
                            domainname.len(),
                        )
                    } {
                        0 => return Ok(()),
                        -1 => nix::Error::last(),
                        _ => nix::Error::UnknownErrno,
                    };
                    bail!("Failed to set domainname: {}", errno);
                }
            }
        }

        if mnt_ns {
            ns_controller
                .set_namespace(NamespaceType::Mount)
                .with_context(|| "Failed to set mount namespace")?;
        }
        Ok(())
    }

    fn set_id_mappings(
        &self,
        parent_channel: &Channel<Message>,
        fst_stage_channel: &Channel<Message>,
        fst_stage_pid: &Pid,
    ) -> Result<()> {
        parent_channel
            .recv_id_mappings()
            .with_context(|| "Failed to receive id mappings")?;
        LinuxContainer::set_groups(fst_stage_pid, false)
            .with_context(|| "Failed to disable setting groups")?;

        if let Some(linux) = self.config.linux.as_ref() {
            if let Some(uid_mappings) = linux.uidMappings.as_ref() {
                self.write_id_mapping(uid_mappings, fst_stage_pid, "uid_map")?;
            }
            if let Some(gid_mappings) = linux.gidMappings.as_ref() {
                self.write_id_mapping(gid_mappings, fst_stage_pid, "gid_map")?;
            }
        }

        fst_stage_channel
            .send_id_mappings_done()
            .with_context(|| "Failed to send id mapping done")?;
        fst_stage_channel
            .sender
            .close()
            .with_context(|| "Failed to close fst_stage_channel sender")?;
        Ok(())
    }

    fn write_id_mapping(&self, mappings: &Vec<IdMapping>, pid: &Pid, file: &str) -> Result<()> {
        let path = format!("/proc/{}/{}", pid.as_raw(), file);
        let mut opened_file = OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| OzonecErr::OpenFile(path))?;
        let mut id_mappings = String::from("");

        for m in mappings {
            let mapping = format!("{} {} {}\n", m.containerID, m.hostID, m.size);
            id_mappings = id_mappings + &mapping;
        }
        opened_file
            .write_all(id_mappings.as_bytes())
            .with_context(|| "Failed to write id mappings")?;
        Ok(())
    }

    fn set_groups(pid: &Pid, allow: bool) -> Result<()> {
        let path = format!("/proc/{}/setgroups", pid.as_raw());
        if allow {
            std::fs::write(&path, "allow")?
        } else {
            std::fs::write(&path, "deny")?
        }
        Ok(())
    }

    fn set_sysctl_parameters(&self) -> Result<()> {
        if let Some(sysctl_params) = self.config.linux.as_ref().unwrap().sysctl.clone() {
            let sys_path = PathBuf::from("/proc/sys");
            for (param, value) in sysctl_params {
                let path = sys_path.join(param.replace('.', "/"));
                fs::write(&path, value.as_bytes())
                    .with_context(|| format!("Failed to set {} to {}", path.display(), value))?;
            }
        }
        Ok(())
    }
}

impl Container for LinuxContainer {
    fn get_config(&self) -> &RuntimeConfig {
        &self.config
    }

    fn get_pid(&self) -> pid_t {
        self.pid
    }

    fn created_time(&self) -> &SystemTime {
        &self.created_time
    }

    fn get_oci_state(&self) -> Result<OciState> {
        let status = self.get_container_status()?;
        let pid = if status != ContainerStatus::Stopped {
            self.pid
        } else {
            0
        };

        let rootfs = canonicalize(self.config.root.path.clone())
            .with_context(|| "Failed to canonicalize root path")?;
        let bundle = match rootfs.parent() {
            Some(p) => p
                .to_str()
                .ok_or_else(|| anyhow!("root path is not valid unicode"))?
                .to_string(),
            None => bail!("Failed to get bundle directory"),
        };
        let annotations = self.config.annotations.clone().unwrap_or_default();
        Ok(OciState {
            ociVersion: self.config.ociVersion.clone(),
            id: self.id.clone(),
            status,
            pid,
            bundle,
            annotations,
        })
    }

    fn create(&mut self, process: &mut Process) -> Result<()> {
        // Create notify socket to notify the container process to start.
        let notify_listener = if process.init {
            Some(NotifyListener::new(PathBuf::from(&self.root))?)
        } else {
            None
        };

        // As /proc/self/oom_score_adj is not allowed to write unless privileged,
        // set oom_score_adj before setting process undumpable.
        process
            .set_oom_score_adj()
            .with_context(|| "Failed to set oom_score_adj")?;

        // Make the process undumpable to avoid various race conditions that could cause
        // processes in namespaces to join to access host resources (or execute code).
        if !self.config.linux.as_ref().unwrap().namespaces.is_empty() {
            prctl::set_dumpable(false)
                .map_err(|e| anyhow!("Failed to set process undumpable: errno {}", e))?;
        }

        // Create channels to communicate with child processes.
        let parent_channel = Channel::<Message>::new()
            .with_context(|| "Failed to create message channel for parent process")?;
        let fst_stage_channel = Channel::<Message>::new()?;
        // Set receivers timeout: 50ms.
        parent_channel.receiver.set_timeout(50000)?;
        fst_stage_channel.receiver.set_timeout(50000)?;

        // Spawn a child process to perform Stage 1.
        let fst_stage_pid = clone_process("ozonec:[1:CHILD]", || {
            self.do_first_stage(
                process,
                &parent_channel,
                &fst_stage_channel,
                &notify_listener,
            )
            .with_context(|| "First stage process encounters errors")?;
            Ok(0)
        })?;

        if self.is_namespace_set(NamespaceType::User)? {
            self.set_id_mappings(&parent_channel, &fst_stage_channel, &fst_stage_pid)?;
        }

        let init_pid = parent_channel
            .recv_init_pid()
            .with_context(|| "Failed to receive init pid")?;
        parent_channel.recv_container_created()?;
        parent_channel
            .receiver
            .close()
            .with_context(|| "Failed to close receiver end of parent channel")?;

        self.pid = init_pid.as_raw();
        self.start_time = procfs::process::Process::new(self.pid)
            .with_context(|| OzonecErr::ReadProcPid(self.pid))?
            .stat()
            .with_context(|| OzonecErr::ReadProcStat(self.pid))?
            .starttime;

        match waitpid(fst_stage_pid, None) {
            Ok(WaitStatus::Exited(_, 0)) => (),
            Ok(WaitStatus::Exited(_, s)) => {
                info!("First stage process exits with status: {}", s);
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                info!("First stage process killed by signal: {}", sig)
            }
            Ok(_) => (),
            Err(Errno::ECHILD) => {
                info!("First stage process has already been reaped");
            }
            Err(e) => {
                bail!("Failed to waitpid for first stage process: {e}");
            }
        }
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        let path = PathBuf::from(&self.root).join(NOTIFY_SOCKET);
        let mut notify_socket = NotifySocket::new(&path);

        notify_socket.notify_container_start()?;
        unlink(&path).with_context(|| "Failed to delete notify.sock")?;
        self.start_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .with_context(|| "Failed to get start time")?
            .as_secs();
        Ok(())
    }

    fn exec(&mut self, process: &mut Process) -> Result<()> {
        // process.init is false.
        self.create(process)?;
        Ok(())
    }

    fn kill(&self, sig: Signal) -> Result<()> {
        let mut status = self.status()?;
        if status == ContainerStatus::Stopped {
            bail!("The container is already stopped");
        }
        if status == ContainerStatus::Creating {
            bail!("The container has not been created");
        }

        let pid = Pid::from_raw(self.pid);
        match kill(pid, None) {
            Err(errno) => {
                if errno != Errno::ESRCH {
                    bail!("Failed to kill process {}: {:?}", pid, errno);
                }
            }
            Ok(_) => kill(pid, sig)?,
        }

        let mut _retry = 0;
        status = self.status()?;
        while status != ContainerStatus::Stopped {
            sleep(Duration::from_millis(1));
            if _retry > 3 {
                bail!("The container is still not stopped.");
            }
            status = self.status()?;
            _retry += 1;
        }
        Ok(())
    }

    fn delete(&self, state: &State, force: bool) -> Result<()> {
        match self.status()? {
            ContainerStatus::Stopped => state.remove_dir()?,
            _ => {
                if force {
                    self.kill(Signal::SIGKILL)
                        .with_context(|| "Failed to kill the container by force")?;
                    state.remove_dir()?;
                } else {
                    bail!(
                        "Failed to delete container {} which is not stopped",
                        &state.id
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::ffi::CStr;

    use chrono::DateTime;
    use fs::{read_to_string, remove_dir_all, File};
    use libc::getdomainname;
    use nix::sys::stat::stat;
    use rusty_fork::rusty_fork_test;
    use unistd::{gethostname, getpid};

    use crate::linux::{
        mount::Mount, namespace::tests::set_namespace, process::tests::init_oci_process,
    };
    use oci_spec::{
        linux::{LinuxPlatform, Namespace},
        posix::{Root, User},
        process::Process as OciProcess,
        runtime::Mount as OciMount,
    };

    use super::*;

    pub fn init_config() -> RuntimeConfig {
        let root = Root {
            path: String::from("/tmp/ozonec/bundle/rootfs"),
            readonly: true,
        };
        let user = User {
            uid: 0,
            gid: 0,
            umask: None,
            additionalGids: None,
        };
        let process = OciProcess {
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
        };
        let linux = LinuxPlatform {
            namespaces: Vec::new(),
            uidMappings: None,
            gidMappings: None,
            timeOffsets: None,
            devices: None,
            cgroupsPath: None,
            rootfsPropagation: None,
            maskedPaths: None,
            readonlyPaths: None,
            mountLabel: None,
            personality: None,
            resources: None,
            rdma: None,
            unified: None,
            sysctl: None,
            seccomp: None,
            #[cfg(target_arch = "x86_64")]
            intelRdt: None,
        };
        RuntimeConfig {
            ociVersion: String::from("1.2"),
            root,
            mounts: Vec::new(),
            process,
            hostname: None,
            domainname: None,
            linux: Some(linux),
            vm: None,
            hooks: None,
            annotations: None,
        }
    }

    #[test]
    fn test_linux_container_new() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let config = init_config();
        let mut exist: bool = false;
        let container = LinuxContainer::new(
            &String::from("LinuxContainer_new"),
            &String::from("/tmp/ozonec"),
            &config,
            &None,
            &mut exist,
        )
        .unwrap();

        let root = Path::new(&container.root);
        assert!(root.exists());
        let root_stat = stat(root).unwrap();
        assert_eq!(root_stat.st_uid, geteuid().as_raw());
        assert_eq!(root_stat.st_gid, getegid().as_raw());

        assert!(LinuxContainer::new(
            &String::from("LinuxContainer_new"),
            &String::from("/tmp/ozonec"),
            &config,
            &None,
            &mut exist,
        )
        .is_err());
        assert_eq!(exist, true);
    }

    #[test]
    fn test_validate_config() {
        let mut config = init_config();
        config.linux = None;
        assert!(LinuxContainer::validate_config(&config).is_err());

        let linux = LinuxPlatform {
            namespaces: Vec::new(),
            uidMappings: None,
            gidMappings: None,
            timeOffsets: None,
            devices: None,
            cgroupsPath: None,
            rootfsPropagation: None,
            maskedPaths: None,
            readonlyPaths: None,
            mountLabel: None,
            personality: None,
            resources: None,
            rdma: None,
            unified: None,
            sysctl: None,
            seccomp: None,
            #[cfg(target_arch = "x86_64")]
            intelRdt: None,
        };
        config.process.args = None;
        config.linux = Some(linux);
        assert!(LinuxContainer::validate_config(&config).is_err());
    }

    #[test]
    fn test_load_from_state() {
        let mut state = State {
            oci_version: String::from("1.2"),
            id: String::from("load_from_state"),
            pid: 0,
            root: PathBuf::from("/tmp/ozonec/root"),
            bundle: PathBuf::from("/tmp/ozonec/bundle"),
            rootfs: String::from("/tmp/ozonec/bundle/rootfs"),
            start_time: 0,
            created_time: DateTime::from(SystemTime::now()),
            config: None,
        };
        assert!(LinuxContainer::load_from_state(&state, &None).is_err());

        let config = init_config();
        state.config = Some(config);
        assert!(LinuxContainer::load_from_state(&state, &None).is_ok());
    }

    #[test]
    fn test_status() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let config = init_config();
        create_dir_all(&config.root.path).unwrap();
        let mut exist: bool = false;
        let mut container = LinuxContainer::new(
            &String::from("get_container_status"),
            &String::from("/tmp/ozonec"),
            &config,
            &None,
            &mut exist,
        )
        .unwrap();
        container.pid = -1;

        assert_eq!(container.status().unwrap(), ContainerStatus::Creating);

        container.pid = 0;
        assert_eq!(container.status().unwrap(), ContainerStatus::Stopped);

        container.pid = getpid().as_raw();
        assert_eq!(container.status().unwrap(), ContainerStatus::Stopped);

        let proc_stat = procfs::process::Process::new(container.pid)
            .unwrap()
            .stat()
            .unwrap();
        container.start_time = proc_stat.starttime;
        assert_eq!(container.status().unwrap(), ContainerStatus::Running);

        let notify_socket = PathBuf::from(&container.root).join(NOTIFY_SOCKET);
        File::create(&notify_socket).unwrap();
        assert_eq!(container.status().unwrap(), ContainerStatus::Created);
    }

    #[test]
    fn test_is_namespace_set() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let mut config = init_config();
        config.linux.as_mut().unwrap().namespaces.push(Namespace {
            ns_type: NamespaceType::Mount,
            path: None,
        });
        let mut exist = false;
        let container = LinuxContainer::new(
            &String::from("test_is_namespace_set"),
            &String::from("/tmp/ozonec/test_is_namespace_set"),
            &config,
            &None,
            &mut exist,
        )
        .unwrap();

        assert!(container.is_namespace_set(NamespaceType::Mount).unwrap());
        assert!(!container.is_namespace_set(NamespaceType::User).unwrap());
    }

    #[test]
    #[ignore = "unshare may not be permitted"]
    fn test_set_pid_namespace() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let mut config = init_config();
        config.linux.as_mut().unwrap().namespaces.push(Namespace {
            ns_type: NamespaceType::Pid,
            path: None,
        });
        let mut exist = false;
        let container = LinuxContainer::new(
            &String::from("test_set_pid_namespace"),
            &String::from("/tmp/ozonec/test_set_pid_namespace"),
            &config,
            &None,
            &mut exist,
        )
        .unwrap();

        assert!(container.set_pid_namespace().is_ok());
    }

    #[test]
    #[ignore = "unshare may not be permitted"]
    fn test_set_id_mappings() {
        remove_dir_all("/tmp/ozonec").unwrap_or_default();

        let mut config = init_config();
        let linux = config.linux.as_mut().unwrap();
        linux.namespaces = vec![Namespace {
            ns_type: NamespaceType::User,
            path: None,
        }];
        linux.uidMappings = Some(vec![IdMapping {
            containerID: 0,
            hostID: 0,
            size: 1000,
        }]);
        linux.gidMappings = Some(vec![IdMapping {
            containerID: 0,
            hostID: 0,
            size: 1000,
        }]);
        let mut exist = false;
        let container = LinuxContainer::new(
            &String::from("test_set_id_mappings"),
            &String::from("/tmp/ozonec/test_set_id_mappings"),
            &config,
            &None,
            &mut exist,
        )
        .unwrap();

        let fst_channel = Channel::<Message>::new().unwrap();
        let sec_channel = Channel::<Message>::new().unwrap();
        let child = clone_process("test_set_id_mappings", || {
            let process = Process::new(&init_oci_process(), false);
            assert!(container
                .set_user_namespace(&fst_channel, &sec_channel, &process)
                .is_ok());
            Ok(1)
        })
        .unwrap();

        assert!(container
            .set_id_mappings(&fst_channel, &sec_channel, &child)
            .is_ok());
        let path = format!("/proc/{}/setgroups", child.as_raw().to_string());
        let setgroups = fs::read_to_string(path).unwrap();
        assert_eq!(setgroups.trim(), "deny");
        let path = format!("/proc/{}/uid_map", child.as_raw().to_string());
        let uid_map = fs::read_to_string(path).unwrap();
        let mut iter = uid_map.split_ascii_whitespace();
        assert_eq!(iter.next(), Some("0"));
        assert_eq!(iter.next(), Some("0"));
        assert_eq!(iter.next(), Some("1000"));
        assert_eq!(iter.next(), None);
        let path = format!("/proc/{}/gid_map", child.as_raw().to_string());
        let gid_map = fs::read_to_string(path).unwrap();
        let mut iter = gid_map.split_ascii_whitespace();
        assert_eq!(iter.next(), Some("0"));
        assert_eq!(iter.next(), Some("0"));
        assert_eq!(iter.next(), Some("1000"));
        assert_eq!(iter.next(), None);

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

    rusty_fork_test! {
        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_set_readonly_paths() {
            remove_dir_all("/tmp/ozonec").unwrap_or_default();

            set_namespace(NamespaceType::Mount);
            let root = PathBuf::from("/tmp/ozonec/test_set_readonly_paths");
            let mut config = init_config();
            let path = root.to_string_lossy().to_string();
            config.linux.as_mut().unwrap().readonlyPaths = Some(vec![path.clone()]);
            let mut exist = false;
            let container = LinuxContainer::new(
                &String::from("test_set_readonly_paths"),
                &root.to_string_lossy().to_string(),
                &config,
                &None,
                &mut exist,
            )
            .unwrap();
            File::create(root.join("test")).unwrap();

            assert!(container.set_readonly_paths().is_ok());
            let path = PathBuf::from(path).join("test");
            assert!(File::create(&path).is_err());
        }

        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_set_masked_paths() {
            remove_dir_all("/tmp/ozonec").unwrap_or_default();

            set_namespace(NamespaceType::Mount);
            let root = PathBuf::from("/tmp/ozonec/test_set_masked_paths");
            let mut config = init_config();
            config.linux.as_mut().unwrap().maskedPaths = Some(vec![root.to_string_lossy().to_string()]);
            let mut exist = false;
            let container = LinuxContainer::new(
                &String::from("test_set_masked_paths"),
                &root.to_string_lossy().to_string(),
                &config,
                &None,
                &mut exist,
            )
            .unwrap();

            File::create(root.join("test")).unwrap();
            assert!(container.set_masked_paths().is_ok());
            assert!(!root.join("test").exists());
        }

        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_set_rest_namespaces() {
            remove_dir_all("/tmp/ozonec").unwrap_or_default();

            let root = PathBuf::from("/tmp/ozonec/test_set_rest_namespaces");
            let mut config = init_config();
            config.linux.as_mut().unwrap().namespaces = vec![
                Namespace {
                    ns_type: NamespaceType::User,
                    path: None,
                },
                Namespace {
                    ns_type: NamespaceType::Uts,
                    path: None,
                },
            ];
            config.hostname = Some(String::from("test_set_rest_namespaces"));
            config.domainname = Some(String::from("test_set_rest_namespaces"));
            let mut exist = false;
            let container = LinuxContainer::new(
                &String::from("test_set_rest_namespaces"),
                &root.to_string_lossy().to_string(),
                &config,
                &None,
                &mut exist,
            )
            .unwrap();

            assert!(container.set_rest_namespaces().is_ok());
            assert_eq!(
                gethostname().unwrap().to_str().unwrap(),
                "test_set_rest_namespaces"
            );
            let len = 100;
            let mut domain: Vec<u8> = Vec::with_capacity(len);
            unsafe {
                getdomainname(domain.as_mut_ptr().cast(), len);
                // Ensure always null-terminated.
                domain.as_mut_ptr().wrapping_add(len - 1).write(0);
                let len = CStr::from_ptr(domain.as_ptr().cast()).to_bytes().len();
                domain.set_len(len);
            }
            assert_eq!(String::from_utf8_lossy(&domain), "test_set_rest_namespaces");
        }

        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_set_sysctl_parameters() {
            remove_dir_all("/tmp/ozonec").unwrap_or_default();

            set_namespace(NamespaceType::Mount);
            let root = PathBuf::from("/tmp/ozonec/test_set_sysctl_parameters");
            let mut config = init_config();
            config.linux.as_mut().unwrap().sysctl = Some(HashMap::new());
            let sysctl = &mut config.linux.as_mut().unwrap().sysctl;
            sysctl
                .as_mut()
                .unwrap()
                .insert(String::from("vm.oom_dump_tasks"), String::from("0"));

            let mut exist = false;
            let container = LinuxContainer::new(
                &String::from("test_set_sysctl_parameters"),
                &root.to_string_lossy().to_string(),
                &config,
                &None,
                &mut exist,
            )
            .unwrap();

            let mounts = vec![OciMount {
                destination: String::from("/proc"),
                source: Some(String::from("proc")),
                options: None,
                fs_type: Some(String::from("proc")),
                uidMappings: None,
                gidMappings: None,
            }];
            let mnt = Mount::new(&root);
            mnt.do_mounts(&mounts, &None).unwrap();

            assert!(container.set_sysctl_parameters().is_ok());
            assert_eq!(read_to_string("/proc/sys/vm/oom_dump_tasks").unwrap().trim(), "0");
        }
    }
}
