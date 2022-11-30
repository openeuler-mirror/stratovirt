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

//! Remove all capability for ozone when uid is 0, use -capability cap_* to add capability.

use crate::syscall;
use crate::OzoneError;
use anyhow::{anyhow, bail, Context, Result};
use std::{collections::HashMap, io::Write};

const CAPS_V3: u32 = 0x20080522;
const NR_ALL_CAP: u8 = 41;

fn init_cap() -> HashMap<&'static str, (u8, bool)> {
    [
        ("CAP_CHOWN", (0, true)),
        ("CAP_DAC_OVERRIDE", (1, true)),
        ("CAP_DAC_READ_SEARCH", (2, false)),
        ("CAP_FOWNER", (3, true)),
        ("CAP_FSETID", (4, true)),
        ("CAP_KILL", (5, true)),
        ("CAP_SETGID", (6, true)),
        ("CAP_SETUID", (7, true)),
        ("CAP_SETPCAP", (8, true)),
        ("CAP_LINUX_IMMUTABLE", (9, false)),
        ("CAP_NET_BIND_SERVICE", (10, true)),
        ("CAP_NET_BROADCAST", (11, false)),
        ("CAP_NET_ADMIN", (12, false)),
        ("CAP_NET_RAW", (13, true)),
        ("CAP_IPC_LOCK", (14, false)),
        ("CAP_IPC_OWNER", (15, false)),
        ("CAP_SYS_MODULE", (16, false)),
        ("CAP_SYS_RAWIO", (17, false)),
        ("CAP_SYS_CHROOT", (18, true)),
        ("CAP_SYS_PTRACE", (19, false)),
        ("CAP_SYS_PACCT", (20, false)),
        ("CAP_SYS_ADMIN", (21, false)),
        ("CAP_SYS_BOOT", (22, false)),
        ("CAP_SYS_NICE", (23, false)),
        ("CAP_SYS_RESOURCE", (24, false)),
        ("CAP_SYS_TIME", (25, false)),
        ("CAP_SYS_TTY_CONFIG", (26, false)),
        ("CAP_MKNOD", (27, true)),
        ("CAP_LEASE", (28, false)),
        ("CAP_AUDIT_WRITE", (29, true)),
        ("CAP_AUDIT_CONTROL", (30, false)),
        ("CAP_SETFCAP", (31, true)),
        ("CAP_AUDIT_WRITE", (29, true)),
        ("CAP_AUDIT_CONTROL", (30, false)),
        ("CAP_SETFCAP", (31, true)),
        ("CAP_MAC_OVERRIDE", (32, false)),
        ("CAP_MAC_ADMIN", (33, false)),
        ("CAP_SYSLOG", (34, false)),
        ("CAP_WAKE_ALARM", (35, false)),
        ("CAP_BLOCK_SUSPEND", (36, false)),
        ("CAP_AUDIT_READ", (37, false)),
        ("CAP_PERFMON", (38, false)),
        ("CAP_BPF", (39, false)),
        ("CAP_CHECKPOINT_RESTORE", (40, false)),
    ]
    .iter()
    .map(|(name, (index, is_safe_capability))| (*name, (*index, *is_safe_capability)))
    .collect::<HashMap<&'static str, (u8, bool)>>()
}

#[repr(C)]
pub struct CapUserHeader {
    // Linux capabilities version (runtime kernel support)
    version: u32,
    // Process ID (thread)
    pid: i32,
}

#[derive(Default)]
#[repr(C)]
pub struct CapUserData {
    effective_s0: u32,
    permitted_s0: u32,
    inheritable_s0: u32,
    effective_s1: u32,
    permitted_s1: u32,
    inheritable_s1: u32,
}

fn has_cap(cap: u8) -> Result<bool> {
    let mut hdr = CapUserHeader {
        version: CAPS_V3,
        pid: 0,
    };
    let mut data: CapUserData = Default::default();
    syscall::capget(&mut hdr, &mut data)?;
    let caps: u64 = (u64::from(data.permitted_s1) << 32) + u64::from(data.permitted_s0);
    let has_cap = (caps & (1u64 << cap)) != 0;
    Ok(has_cap)
}

// Remove all capability when uid is 0.
// when uid is 0 , the child process capability is :
// P'(permitted)   = P(inheritable) | P(bounding)
// P'(effective)   = P'(permitted)
// so we set Bounding to limit child process.
pub fn clear_all_capabilities() -> Result<()> {
    for cap in 0..NR_ALL_CAP {
        if has_cap(cap).with_context(|| anyhow!(OzoneError::CapsError("CAPGET")))? {
            syscall::drop_bounding_caps(cap)
                .with_context(|| anyhow!(OzoneError::CapsError("PR_CAPBSET_DROP")))?;
        }
    }

    Ok(())
}

// set_capability_for_ozone , you can use -capability cap_* to obtain a capability
pub fn set_capability_for_ozone(capability: &str) -> Result<()> {
    let cap_str = capability.to_uppercase();
    let cap_add_arr: Vec<&str> = cap_str.split(',').collect();
    let all_caps = init_cap();

    for cap in cap_add_arr.iter() {
        if let Some(val) = all_caps.get(cap) {
            if !val.1 {
                let warning = format!("Alert! Adding dangerous capability {:?} to ozone , it might cause risk of escape!\n", cap);
                std::io::stdout()
                    .write(warning.as_bytes())
                    .with_context(|| "Failed to write warnings")?;
                std::io::stdout()
                    .flush()
                    .with_context(|| "Failed to flush stdout")?;
            }
        } else {
            bail!("Invalid capability argument: {:?}", cap);
        }
    }

    for item in all_caps.iter() {
        if cap_add_arr.contains(item.0) {
            continue;
        }
        if has_cap(item.1 .0).with_context(|| anyhow!(OzoneError::CapsError("CAPGET")))? {
            syscall::drop_bounding_caps(item.1 .0)
                .with_context(|| anyhow!(OzoneError::CapsError("PR_CAPBSET_DROP")))?;
        }
    }
    Ok(())
}
