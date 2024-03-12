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

use anyhow::{bail, Result};

#[link(name = "token_setproc")]
extern "C" {
    fn SetFirstCallerTokenID(id: u64) -> i32;
    fn GetFirstCallerTokenID() -> u64;
}

pub fn set_firstcaller_tokenid(id: u64) -> Result<()> {
    // SAFETY: This function is only applied on this thread.
    unsafe {
        if SetFirstCallerTokenID(id) != 0 {
            bail!("Set first caller failed");
        }
    }
    Ok(())
}

pub fn get_firstcaller_tokenid() -> u64 {
    // SAFETY: This function is only applied on this thread.
    unsafe { GetFirstCallerTokenID() }
}
