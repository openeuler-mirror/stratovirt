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

use super::errors::{ErrorKind, Result};

/// This function returns the caller's thread ID(TID).
pub fn gettid() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid) as u64 }
}

/// This function used to remove group and others permission using libc::chmod.
pub fn limit_permission(path: &str) -> Result<()> {
    let file_path = path.as_bytes().to_vec();
    let cstr_file_path = std::ffi::CString::new(file_path).unwrap();
    let ret = unsafe { libc::chmod(cstr_file_path.as_ptr(), 0o600) };

    if ret == 0 {
        Ok(())
    } else {
        Err(ErrorKind::ChmodFailed(ret).into())
    }
}
