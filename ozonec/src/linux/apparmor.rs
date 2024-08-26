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

use std::{fs, path::Path};

use anyhow::{Context, Result};

const APPARMOR_ENABLED_PATH: &str = "/sys/module/apparmor/parameters/enabled";
const APPARMOR_INTERFACE: &str = "/proc/self/attr/apparmor/exec";
const APPARMOR_LEGACY_INTERFACE: &str = "/proc/self/attr/exec";

pub fn is_enabled() -> Result<bool> {
    let enabled = fs::read_to_string(APPARMOR_ENABLED_PATH)
        .with_context(|| format!("Failed to read {}", APPARMOR_ENABLED_PATH))?;
    Ok(enabled.starts_with('Y'))
}

pub fn apply_profile(profile: &str) -> Result<()> {
    if profile.is_empty() {
        return Ok(());
    }

    // Try the module specific subdirectory. This is recommended to configure LSMs
    // since Linux kernel 5.1. AppArmor has such a directory since Linux kernel 5.8.
    match activate_profile(Path::new(APPARMOR_INTERFACE), profile) {
        Ok(_) => Ok(()),
        Err(_) => activate_profile(Path::new(APPARMOR_LEGACY_INTERFACE), profile)
            .with_context(|| "Failed to apply apparmor profile"),
    }
}

fn activate_profile(path: &Path, profile: &str) -> Result<()> {
    fs::write(path, format!("exec {}", profile))?;
    Ok(())
}
