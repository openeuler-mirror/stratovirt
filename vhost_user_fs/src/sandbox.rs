// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Result};
use log::error;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::os::unix::io::FromRawFd;

/// Sandbox mechanism to isolate process.
pub struct Sandbox {
    /// Source directory in host which can be accessed by guest.
    pub source_dir: String,
    /// File object for /proc/self/fd.
    pub proc_self_fd: Option<File>,
}

impl Sandbox {
    pub fn new(source_dir: String) -> Self {
        Sandbox {
            source_dir,
            proc_self_fd: None,
        }
    }

    /// In "chroot" sandbox mode.
    /// The program invokes chroot(2) to make the shared directory tree its root.
    pub fn enable_chroot(&mut self) -> Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("chroot/setgroups must be privileged user");
        }

        let cstr = CString::new("/proc/self/fd").unwrap();
        let open_ans = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH) };
        if open_ans == -1 {
            bail!("open /proc/self/fd failed");
        }
        self.proc_self_fd = Some(unsafe { File::from_raw_fd(open_ans) });

        drop_groups()?;

        let source_dir = CString::new(self.source_dir.clone()).unwrap();
        if unsafe { libc::chroot(source_dir.as_ptr()) } == -1 {
            bail!("change root fail");
        }
        let root_dir = CString::new("/").unwrap();
        if unsafe { libc::chdir(root_dir.as_ptr()) } == -1 {
            bail!("change root directory fail");
        }
        Ok(())
    }

    /// In "namespace" sandbox mode.
    /// The program switches into a new file system namespace and invokes pivot_root(2) to make the shared directory tree its root.
    pub fn enable_namespace(&mut self) -> Result<()> {
        let mut flags = libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWNET;
        let euid = unsafe { libc::geteuid() };
        let egid = unsafe { libc::getegid() };
        if euid == 0 {
            // An unprivileged user do not have permission to call setgroups.
            drop_groups()?;
        } else {
            flags |= libc::CLONE_NEWUSER;
        }

        if unsafe { libc::unshare(flags) } == -1 {
            bail!("unshare fail");
        }
        let pid = unsafe { libc::getpid() };
        // Get parent's pid and wrap it in file Object to ensure that is auto-closed.
        let pidfd_open = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as libc::c_int };
        if pidfd_open == -1 {
            bail!("pidfd_open fail");
        }
        struct PidFd(File);
        let _pidfd = unsafe { PidFd(File::from_raw_fd(pidfd_open)) };

        let fork_ans = unsafe { libc::fork() };
        match fork_ans {
            -1 => bail!("fork fail"),
            0 => self.do_namespace_in_child_process(euid, egid, pidfd_open)?,
            _ => self.parent_process_wait_child(fork_ans)?,
        }
        Ok(())
    }

    fn do_namespace_in_child_process(
        &mut self,
        euid: u32,
        egid: u32,
        pidfd_open: i32,
    ) -> Result<()> {
        // If vhost_user_fs/src/set_signal_handlers do not register SIGTERM.
        // Child process became orphan process when parent process died.
        // Beacuse child process can not receive signal notification from parent process.
        // This is the signal that the calling process will get when its parent died.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } == -1 {
            bail!("prctl fail");
        }
        // The parent maybe died before before prctl.
        let mut pollfd = libc::pollfd {
            fd: pidfd_open,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ans = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if poll_ans == -1 {
            bail!("pollfd fail");
        } else if poll_ans != 0 {
            bail!("original parent process died");
        }
        // An unprivileged user set uid/gid mapping in user namespace.
        if euid != 0 {
            self.id_mapping(euid, egid);
        }
        // Open fd to '/proc/self' so we can later open '/proc/self/mountinfo'.
        let cstr = CString::new("/proc/self").unwrap();
        let open_fd = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH) };
        if open_fd < 0 {
            bail!("open /proc/self fail");
        }
        // Changing into file object to ensure it will closed when this function returns.
        let _open_fd_file = unsafe { File::from_raw_fd(open_fd) };
        // Ensure changes in child mount namespace do not affect parent mount namespace.
        self.change_propagation()?;
        // mount /proc in this context.
        self.mount_proc()?;
        // Bind-mount '/proc/self/fd' onto '/proc' to preventing access to ancestor directories.
        self.proc_self_fd_bind_proc()?;
        // Bind-mount 'source_dir' on itself so we can use as new root on 'pivot_root'.
        self.bind_source_dir()?;
        // Get a fd to old root.
        let cstr = CString::new("/").unwrap();
        let root_dir_fd = unsafe {
            libc::open(
                cstr.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if root_dir_fd < 0 {
            bail!("open root_dir fail");
        }
        // Get a fd to new root.
        let cstr = CString::new(self.source_dir.as_str()).unwrap();
        let source_dir_fd = unsafe {
            libc::open(
                cstr.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if source_dir_fd < 0 {
            bail!("open source_dir fail");
        }
        // Switch to new root then call pivot_root.
        if unsafe { libc::fchdir(source_dir_fd) } == -1 {
            bail!("fchdir fail");
        }
        // Use '.' as both old and new root.
        let cstr = CString::new(".").unwrap();
        if unsafe { libc::syscall(libc::SYS_pivot_root, cstr.as_ptr(), cstr.as_ptr()) } == -1 {
            bail!("pivot_root fail");
        }
        // Switch to old root then umount it.
        if unsafe { libc::fchdir(root_dir_fd) } == -1 {
            bail!("change to root_dir fail");
        }
        // Clean up old root to avoid mount namespace propagation.
        self.clean_old_root()?;
        // Umount old root.
        let cstr = CString::new(".").unwrap();
        if unsafe { libc::umount2(cstr.as_ptr(), libc::MNT_DETACH) } == -1 {
            bail!("umount2 old root fail");
        }
        if unsafe { libc::fchdir(source_dir_fd) } == -1 {
            bail!("change to root_dir fail");
        }
        if unsafe { libc::close(source_dir_fd) } == -1 {
            bail!("close source_dir fail");
        }
        if unsafe { libc::close(root_dir_fd) } == -1 {
            bail!("close root_dir fail");
        }
        Ok(())
    }

    pub fn parent_process_wait_child(&self, fork_ans: i32) -> Result<()> {
        capng::clear(capng::Set::BOTH);
        if let Err(err) = capng::apply(capng::Set::BOTH) {
            error!("apply fail {}", err);
        }

        let mut wstatus = 0;
        if fork_ans != unsafe { libc::waitpid(fork_ans, &mut wstatus, 0) } {
            bail!("waitpid fail");
        }
        let exit_code = if libc::WIFEXITED(wstatus) {
            // The child terminated normally return true.
            libc::WEXITSTATUS(wstatus)
        } else if libc::WIFSIGNALED(wstatus) {
            // Child process was terminated by a signal return true.
            let signal = libc::WTERMSIG(wstatus);
            error!("Child process was terminated by a signal: {}", signal);
            -signal
        } else {
            error!("exit failed: {:#X}", wstatus);
            libc::EXIT_FAILURE
        };
        bail!("exit_code {}", exit_code);
    }

    pub fn clean_old_root(&self) -> Result<()> {
        let cstr = CString::new("").unwrap();
        let cstr2 = CString::new(".").unwrap();
        if unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr2.as_ptr(),
                cstr.as_ptr(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        } == -1
        {
            bail!("changing the propagation type of mounts in the new namespace fail");
        }
        Ok(())
    }

    pub fn bind_source_dir(&self) -> Result<()> {
        let cstr = CString::new(self.source_dir.as_str()).unwrap();
        let cstr2 = CString::new("").unwrap();
        if unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr.as_ptr(),
                cstr2.as_ptr(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        } == -1
        {
            bail!("mount --bind source_dir source_dir fail");
        }
        Ok(())
    }

    fn proc_self_fd_bind_proc(&mut self) -> Result<()> {
        let cstr = CString::new("/proc/self/fd").unwrap();
        let cstr2 = CString::new("/proc").unwrap();
        let cstr3 = CString::new("").unwrap();
        if unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr2.as_ptr(),
                cstr3.as_ptr(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } == -1
        {
            bail!("mount --bind /proc/self/fd /proc fail");
        }

        let cstr = CString::new("/proc").unwrap();
        let open_ans = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH) };
        if open_ans == -1 {
            bail!("open /proc failed");
        }
        self.proc_self_fd = Some(unsafe { File::from_raw_fd(open_ans) });
        Ok(())
    }

    fn mount_proc(&self) -> Result<()> {
        let cstr = CString::new("proc").unwrap();
        let cstr2 = CString::new("/proc").unwrap();
        let cstr3 = CString::new("proc").unwrap();
        if unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr2.as_ptr(),
                cstr3.as_ptr(),
                libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID | libc::MS_RELATIME,
                std::ptr::null(),
            )
        } == -1
        {
            bail!("mount /proc fail");
        }
        Ok(())
    }

    fn change_propagation(&self) -> Result<()> {
        let cstr = CString::new("").unwrap();
        let cstr2 = CString::new("/").unwrap();
        if unsafe {
            libc::mount(
                cstr.as_ptr(),
                cstr2.as_ptr(),
                cstr.as_ptr(),
                libc::MS_SLAVE | libc::MS_REC,
                std::ptr::null(),
            )
        } == -1
        {
            bail!("changing the propagation type of mounts in the new namespace fail");
        }
        Ok(())
    }

    fn id_mapping(&self, euid: u32, egid: u32) {
        // The setgroups file can only be written to before the group-ID mapping has been set.
        let _result1 = fs::write("/proc/self/setgroups", "deny");
        // Format: id_in_namespace id_out_namespace length.
        let uid_map_string = format!("{} {} {}", euid, euid, 1);
        let gid_map_string = format!("{} {} {}", egid, egid, 1);
        let _result2 = fs::write("/proc/self/uid_map", uid_map_string);
        let _result3 = fs::write("/proc/self/gid_map", gid_map_string);
    }
}

pub fn drop_groups() -> Result<()> {
    // The total number of supplementary group IDs for the process is returned.
    let group_num = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if group_num == -1 {
        bail!("getgroups fail");
    } else if group_num > 0 {
        // Sets the supplementary group IDs for the calling process. Appropriate privileges are required.
        // A process can drop all of its supplementary groups with the call:setgroups(0, NULL).
        if unsafe { libc::setgroups(0, std::ptr::null()) } == -1 {
            bail!("setgroups fail");
        }
    }
    Ok(())
}
