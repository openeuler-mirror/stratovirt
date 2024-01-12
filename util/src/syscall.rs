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
use libc::{c_void, syscall, SYS_mbind};

/// This function set memory policy for host NUMA node memory range.
///
/// * Arguments
///
/// * `addr` - The memory range starting with addr.
/// * `len` - Length of the memory range.
/// * `mode` - Memory policy mode.
/// * `node_mask` - node_mask specifies physical node ID.
/// * `max_node` - The max node.
/// * `flags` - Mode flags.
pub fn mbind(
    addr: u64,
    len: u64,
    mode: u32,
    node_mask: Vec<u64>,
    max_node: u64,
    flags: u32,
) -> Result<()> {
    // SAFETY:
    // 1. addr is managed by memory mapping, it can be guaranteed legal.
    // 2. node_mask was created in function of set_host_memory_policy.
    // 3. Upper limit of max_node is MAX_NODES.
    let res = unsafe {
        syscall(
            SYS_mbind,
            addr as *mut c_void,
            len,
            mode,
            node_mask.as_ptr(),
            max_node + 1,
            flags,
        )
    };
    if res < 0 {
        bail!(
            "Failed to apply host numa node policy, error is {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}
