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
extern crate kvm_bindings;
extern crate kvm_ioctls;

pub mod aio;
pub mod arg_parser;
pub mod byte_code;
pub mod checksum;
pub mod daemonize;
#[cfg(target_arch = "aarch64")]
pub mod device_tree;
pub mod epoll_context;
mod link_list;
pub mod num_ops;
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
                display("Argument '{}' required, but not found.", t)
            }
            MissingValue(t: String) {
                description("A value for args was not provided.")
                display("The argument '{}' requires a value, but none was supplied.", t)
            }
            IllegelValue(t1: String, t2: String) {
                description("A value is illegel for args.")
                display("The value '{}' is illegel for argument '{}'.", t1, t2)
            }
            ValueOutOfPossible(t1: String, t2: String) {
                description("A value for args is out of possile values.")
                display("The value of argument '{}' must be in '{}'.", t1, t2)
            }
            UnexpectedArguments(t: String) {
                description("The provided argument was not expected.")
                display("Found argument '{}' which wasn't expected, or isn't valid in the context.", t)
            }
            DuplicateArgument(t: String) {
                description("The argument was provided more than once.")
                display("The argument '{}' was provided more than once.", t)
            }
            DuplicateValue(t: String) {
                description("The argument value was provided more than once.")
                display("The argument '{}' only need one value.", t)
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
        }
    }
}
