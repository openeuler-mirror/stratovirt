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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum UtilError {
    #[error("Nul")]
    Nul {
        #[from]
        source: std::ffi::NulError,
    },
    // arg_parser submodule error
    #[error("Argument '{0}' required, but not found. Use \'-h\' or \'-help\' to get usage.")]
    MissingArgument(String),
    #[error("The argument '{0}' requires a value, but none was supplied. Use \'-h\' or \'-help\' to get usage.")]
    MissingValue(String),
    #[error(
        "The value '{0}' is illegel for argument '{1}'. Use \'-h\' or \'-help\' to get usage."
    )]
    IllegelValue(String, String),
    #[error("The value of argument '{0}' must be in '{1}'. Use \'-h\' or \'-help\' to get usage.")]
    ValueOutOfPossible(String, String),
    #[error("Found argument '{0}' which wasn't expected, or isn't valid in the context. Use \'-h\' or \'-help\' to get usage.")]
    UnexpectedArguments(String),
    #[error(
        "The argument '{0}' was provided more than once. Use \'-h\' or \'-help\' to get usage."
    )]
    DuplicateArgument(String),
    #[error("The argument '{0}' only need one value. Use \'-h\' or \'-help\' to get usage.")]
    DuplicateValue(String),
    // daemonize submodule error
    #[error("Unable to fork.")]
    DaemonFork,
    #[error("Unable to create new session.")]
    DaemonSetsid,
    #[error("Unable to redirect standard streams to /dev/null.")]
    DaemonRedirectStdio,
    #[error("Pidfile path is existed yet.")]
    PidFileExist,
    // epoll_context error
    #[error("Found bad syscall, error is {0} .")]
    BadSyscall(std::io::Error),
    #[error("Unsupported Epoll notifier operation type.")]
    UnExpectedOperationType,
    #[error("Failed to execute epoll_wait syscall: {0} .")]
    EpollWait(std::io::Error),
    #[error("The fd {0} is not registered in epoll.")]
    NoRegisterFd(i32),
    #[error("Found no parked fd {0}.")]
    NoParkedFd(i32),
    #[error("Notifier Operation non allowed.")]
    BadNotifierOperation,
    #[error("Chmod command failed, os error {0}")]
    ChmodFailed(i32),
    #[error("Index :{0} out of bound :{1}")]
    OutOfBound(u64, u64),
    #[error("Desired node depth :{0}, current node depth :{1}")]
    NodeDepthMismatch(u32, u32),
    #[error("Still have {0} node open when terminating the fdt")]
    NodeUnclosed(u32),
    #[error("Failed to add property because there is no open node")]
    IllegelPropertyPos,
    #[error("Failed to add string to fdt because of null character inside \"{0}\"")]
    IllegalString(String),
    #[error("Failed to add overlapped mem reserve entries to fdt")]
    MemReserveOverlap,
    #[error("Failed to set {0} property")]
    SetPropertyErr(String),
}
