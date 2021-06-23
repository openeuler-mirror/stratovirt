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

extern crate libc;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate vmm_sys_util;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod aio;
pub mod arg_parser;
pub mod bitmap;
pub mod byte_code;
pub mod checksum;
pub mod daemonize;
#[cfg(target_arch = "aarch64")]
pub mod device_tree;
#[cfg(target_arch = "aarch64")]
pub mod fdt;
pub mod leak_bucket;
mod link_list;
pub mod loop_context;
pub mod num_ops;
pub mod reader;
pub mod seccomp;
pub mod tap;
pub mod unix;
#[macro_use]
pub mod logger;
#[macro_use]
pub mod offsetof;

pub mod errors {
    error_chain! {
        foreign_links {
            KvmIoctl(kvm_ioctls::Error);
            Io(std::io::Error);
            Nul(std::ffi::NulError);
        }
        errors {
            // arg_parser submodule error
            MissingArgument(t: String) {
                description("The required argument was not provided.")
                display("Argument '{}' required, but not found. Use \'-h\' or \'-help\' to get usage.", t)
            }
            MissingValue(t: String) {
                description("A value for args was not provided.")
                display("The argument '{}' requires a value, but none was supplied. Use \'-h\' or \'-help\' to get usage.", t)
            }
            IllegelValue(t1: String, t2: String) {
                description("A value is illegel for args.")
                display("The value '{}' is illegel for argument '{}'. Use \'-h\' or \'-help\' to get usage.", t1, t2)
            }
            ValueOutOfPossible(t1: String, t2: String) {
                description("A value for args is out of possile values.")
                display("The value of argument '{}' must be in '{}'. Use \'-h\' or \'-help\' to get usage.", t1, t2)
            }
            UnexpectedArguments(t: String) {
                description("The provided argument was not expected.")
                display("Found argument '{}' which wasn't expected, or isn't valid in the context. Use \'-h\' or \'-help\' to get usage.", t)
            }
            DuplicateArgument(t: String) {
                description("The argument was provided more than once.")
                display("The argument '{}' was provided more than once. Use \'-h\' or \'-help\' to get usage.", t)
            }
            DuplicateValue(t: String) {
                description("The argument value was provided more than once.")
                display("The argument '{}' only need one value. Use \'-h\' or \'-help\' to get usage.", t)
            }
            // daemonize submodule error
            DaemonFork {
                description("Unable to fork.")
                display("Unable to fork.")
            }
            DaemonSetsid {
                description("Unable to create new session.")
                display("Unable to create new session.")
            }
            DaemonRedirectStdio {
                description("Unable to redirect standard streams to /dev/null.")
                display("Unable to redirect standard streams to /dev/null.")
            }
            PidFileExist {
                description("Pidfile path is existed yet.")
                display("Pidfile path is existed yet.")
            }
            // epoll_context error
            BadSyscall(err: std::io::Error) {
                description("Return a bad syscall.")
                display("Found bad syscall, error is {} .", err)
            }
            UnExpectedOperationType {
                description("Unsupported notifier operation type.")
                display("Unsupported Epoll notifier operation type.")
            }
            EpollWait(err: std::io::Error) {
                description("Failed to execute epoll_wait syscall.")
                display("Failed to execute epoll_wait syscall: {} .", err)
            }
            NoRegisterFd(t: i32) {
                description("The fd is not registered in epoll.")
                display("The fd {} is not registered in epoll.", t)
            }
            NoParkedFd(t: i32) {
                description("Found no parked fd in registered.")
                display("Found no parked fd {}.", t)
            }
            RemoveParked(t: i32) {
                description("Remove parked event.")
                display("Remove parked event whose fd is {}.", t)
            }
            BadNotifierOperation {
                description("Bad Notifier Operation.")
                display("Notifier Operation non allowed.")
            }
            ChmodFailed(e: i32) {
                description("Chmod command failed.")
                display("Chmod command failed, os error {}", e)
            }
            OutOfBound(index: u64, bound: u64) {
                description("Index out of bound of array")
                display("Index :{} out of bound :{}", index, bound)
            }
            NodeDepthMismatch(target_dep: u32, real_dep: u32) {
                description("Fdt structure nested node depth mismatch")
                display("Desired node depth :{}, current node depth :{}", target_dep, real_dep)
            }
            NodeUnclosed(unclose: u32) {
                description("Fdt structure block node unclose")
                display("Still have {} node open when terminating the fdt", unclose)
            }
            IllegelPropertyPos {
                description("Cann't add property outside the node")
                display("Failed to add property because there is no open node")
            }
            IllegalString(s: String) {
                description("The string for fdt should not contain null")
                display("Failed to add string to fdt because of null character inside \"{}\"", s)
            }
            MemReserveOverlap {
                description("The mem reserve entry should not overlap")
                display("Failed to add overlapped mem reserve entries to fdt")
            }
            SetPropertyErr(s: String) {
                description("Cann't set property for fdt node")
                display("Failed to set {} property", s)
            }
        }
    }
}

use libc::{tcgetattr, tcsetattr, termios, OPOST, TCSANOW};
use std::sync::{Arc, Mutex};
use vmm_sys_util::terminal::Terminal;

lazy_static! {
    pub static ref TERMINAL_MODE: Arc<Mutex<Option<termios>>> = Arc::new(Mutex::new(None));
}

pub fn set_termi_raw_mode() -> std::io::Result<()> {
    let tty_fd = std::io::stdin().lock().tty_fd();

    // Safe because this only set the `old_term_mode` struct to zero.
    let mut old_term_mode: termios = unsafe { std::mem::zeroed() };
    // Safe because this only get stdin's current mode and save it.
    let ret = unsafe { tcgetattr(tty_fd, &mut old_term_mode as *mut _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    *TERMINAL_MODE.lock().unwrap() = Some(old_term_mode);

    let mut new_term_mode: termios = old_term_mode;
    // Safe because this function only change the `new_term_mode` argument.
    unsafe { libc::cfmakeraw(&mut new_term_mode as *mut _) };
    new_term_mode.c_oflag |= OPOST;
    // Safe because this function only set the stdin to raw mode.
    let ret = unsafe { tcsetattr(tty_fd, TCSANOW, &new_term_mode as *const _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

pub fn set_termi_canon_mode() -> std::io::Result<()> {
    let tty_fd = std::io::stdin().lock().tty_fd();
    if let Some(old_term_mode) = TERMINAL_MODE.lock().unwrap().as_ref() {
        // Safe because this only recover the stdin's mode.
        let ret = unsafe { tcsetattr(tty_fd, TCSANOW, old_term_mode as *const _) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        debug!("stdin's mode is not initialized: please check the config");
    }

    Ok(())
}
