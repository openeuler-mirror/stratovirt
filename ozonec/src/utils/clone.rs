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

use std::os::unix::io::{AsRawFd, RawFd};

use anyhow::{bail, Context, Result};
use libc::pid_t;
use nix::{errno::errno, unistd::Pid};

bitflags::bitflags! {
    #[derive(Default)]
    pub struct Flags: u64 {
        const CHILD_CLEARTID = 0x00200000;
        const CHILD_SETTID = 0x01000000;
        const FILES = 0x00000400;
        const FS = 0x00000200;
        const INTO_CGROUP = 0x200000000;
        const IO = 0x80000000;
        const NEWCGROUP = 0x02000000;
        const NEWIPC = 0x08000000;
        const NEWNET = 0x40000000;
        const NEWNS = 0x00020000;
        const NEWPID = 0x20000000;
        const NEWTIME = 0x00000080;
        const NEWUSER = 0x10000000;
        const NEWUTS = 0x04000000;
        const PARENT = 0x00008000;
        const PARENT_SETTID = 0x00100000;
        const PIDFD = 0x00001000;
        const PTRACE = 0x00002000;
        const SETTLS = 0x00080000;
        const SIGHAND = 0x00000800;
        const SYSVSEM = 0x00040000;
        const THREAD = 0x00010000;
        const UNTRACED = 0x00800000;
        const VFORK = 0x00004000;
        const VM = 0x00000100;
    }
}

#[repr(C, align(8))]
#[derive(Debug, Default)]
pub struct CloneArgs {
    pub flags: u64,
    pub pid_fd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub cgroup: u64,
}

#[derive(Default)]
pub struct Clone3<'a> {
    flags: Flags,
    pidfd: Option<&'a mut RawFd>,
    child_tid: Option<&'a mut libc::pid_t>,
    parent_tid: Option<&'a mut libc::pid_t>,
    exit_signal: u64,
    stack: Option<&'a mut [u8]>,
    tls: Option<u64>,
    cgroup: Option<&'a dyn AsRawFd>,
}

fn option_as_mut_ptr<T>(o: &mut Option<&mut T>) -> *mut T {
    match o {
        Some(inner) => *inner as *mut T,
        None => std::ptr::null_mut(),
    }
}

fn option_slice_as_mut_ptr<T>(o: &mut Option<&mut [T]>) -> *mut T {
    match o {
        Some(inner) => inner.as_mut_ptr(),
        None => std::ptr::null_mut(),
    }
}

impl<'a> Clone3<'a> {
    pub fn exit_signal(&mut self, exit_signal: u64) -> &mut Self {
        self.exit_signal = exit_signal;
        self
    }

    pub fn call(&mut self) -> Result<Pid> {
        let clone_args = CloneArgs {
            flags: self.flags.bits(),
            pid_fd: option_as_mut_ptr(&mut self.pidfd) as u64,
            child_tid: option_as_mut_ptr(&mut self.child_tid) as u64,
            parent_tid: option_as_mut_ptr(&mut self.parent_tid) as u64,
            exit_signal: self.exit_signal,
            stack: option_slice_as_mut_ptr(&mut self.stack) as u64,
            stack_size: self.stack.as_ref().map(|stack| stack.len()).unwrap_or(0) as u64,
            tls: self.tls.unwrap_or(0),
            cgroup: self.cgroup.map(AsRawFd::as_raw_fd).unwrap_or(0) as u64,
        };

        // SAFETY: FFI call with valid arguments.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &clone_args as *const CloneArgs,
                core::mem::size_of::<CloneArgs>(),
            )
        };
        if ret == -1 {
            bail!("clone3 error: errno {}", errno());
        }

        Ok(Pid::from_raw(
            pid_t::try_from(ret).with_context(|| "Invalid pid")?,
        ))
    }
}
