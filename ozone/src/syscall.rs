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

use std::convert::Into;
use std::io::Result;
use std::os::raw::c_int;

/// Wrapper to syscall exit codes and transfer them into "io::Result"
pub struct SyscallResult {
    ret: c_int,
}

impl From<SyscallResult> for Result<c_int> {
    /// Transfer exit codes to "io::Result"
    fn from(res: SyscallResult) -> Self {
        if res.ret == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res.ret)
        }
    }
}

impl From<SyscallResult> for Result<()> {
    /// Transfer exit codes to "io::Result"
    fn from(res: SyscallResult) -> Self {
        let return_code: Result<c_int> = res.into();
        return_code.map(|_| ())
    }
}
