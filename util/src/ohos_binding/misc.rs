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

use std::fs::OpenOptions;

use anyhow::{bail, Context, Result};
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

const ACCESS_TOKEN_ID_IOCTL_BASE: u32 = b'A' as u32;
const GET_FTOKEN_ID: u32 = 3;
const SET_FTOKEN_ID: u32 = 4;
const ACCESS_TOKEN_ID_DEV: &str = "/dev/access_token_id";

ioctl_iow_nr!(
    ACCESS_TOKENID_SET_FTOKENID,
    ACCESS_TOKEN_ID_IOCTL_BASE,
    SET_FTOKEN_ID,
    ::std::os::raw::c_ulonglong
);
ioctl_ior_nr!(
    ACCESS_TOKENID_GET_FTOKENID,
    ACCESS_TOKEN_ID_IOCTL_BASE,
    GET_FTOKEN_ID,
    ::std::os::raw::c_ulonglong
);

pub fn set_firstcaller_tokenid(id: u64) -> Result<()> {
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(ACCESS_TOKEN_ID_DEV)
        .with_context(|| {
            format!(
                "Failed to open {} for set_firstcaller_tokenid.",
                ACCESS_TOKEN_ID_DEV
            )
        })?;
    // SAFETY: ioctl is safe. called file is '/dev/access_token_id' fd and we check the return.
    let ret = unsafe { ioctl_with_ref(&fd, ACCESS_TOKENID_SET_FTOKENID(), &id) };
    if ret != 0 {
        bail!(
            "Failed to set first caller tokenid: {ret}, error info: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

pub fn get_firstcaller_tokenid() -> Result<u64> {
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(ACCESS_TOKEN_ID_DEV)
        .with_context(|| {
            format!(
                "Failed to open {} for get_firstcaller_tokenid.",
                ACCESS_TOKEN_ID_DEV
            )
        })?;
    let mut id: u64 = 0;
    // SAFETY: ioctl is safe. called file is '/dev/access_token_id' fd and we check the return.
    let ret = unsafe { ioctl_with_mut_ref(&fd, ACCESS_TOKENID_GET_FTOKENID(), &mut id) };
    if ret != 0 {
        bail!(
            "Failed to get first caller tokenid: {ret}, error info: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(id)
}
