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

use std::fs::File;
use std::os::unix::prelude::IntoRawFd;

use crate::syscall;
use anyhow::{Context, Result};

const ROOT_DIR_NAME: &str = "/";
const OLD_ROOT_DIR_NAME: &str = "old_root";
const CURRENT_DIR_NAME: &str = ".";

/// Set namespace for uts.
///
/// # Arguments
///
/// * `hostname` - Host name.
pub fn set_uts_namespace(hostname: &str) -> Result<()> {
    syscall::unshare(libc::CLONE_NEWUTS)
        .with_context(|| "Failed to unshare into a new namespace")?;
    syscall::set_host_name(hostname).with_context(|| "Failed to set new hostname")?;
    Ok(())
}

/// Set namespace for ipc.
pub fn set_ipc_namespace() -> Result<()> {
    syscall::unshare(libc::CLONE_NEWIPC)
        .with_context(|| "Failed to share into a new ipc namespace")?;
    Ok(())
}

/// Set namespace for network.
///
/// # Arguments
///
/// * `path` - Path of network namespace.
pub fn set_network_namespace(path: &str) -> Result<()> {
    let network_ns_fd = File::open(path)
        .with_context(|| format!("Failed to open netns path: {}", path))?
        .into_raw_fd();
    syscall::setns(network_ns_fd, libc::CLONE_NEWNET)
        .with_context(|| "Failed to set network namespace")?;
    syscall::close(network_ns_fd)?;
    Ok(())
}

/// Set namespace for mount directory.
///
/// # Arguments
///
/// * `mount_dir` - Path of mount directory .
pub fn set_mount_namespace(mount_dir: &str) -> Result<()> {
    syscall::unshare(libc::CLONE_NEWNS)
        .with_context(|| "Failed to unshare into a new namespace")?;
    syscall::mount(None, ROOT_DIR_NAME, libc::MS_SLAVE | libc::MS_REC)
        .with_context(|| "Failed to mount root path as slave and rec")?;

    syscall::mount(Some(mount_dir), mount_dir, libc::MS_BIND | libc::MS_REC)
        .with_context(|| "Failed to mount target path as bind and rec")?;

    std::env::set_current_dir(mount_dir)
        .with_context(|| "Failed to change current dir to mount dir path")?;

    syscall::mkdir(OLD_ROOT_DIR_NAME).with_context(|| "Failed to create old root dir")?;

    syscall::pivot_root(CURRENT_DIR_NAME, OLD_ROOT_DIR_NAME)
        .with_context(|| "Failed to call pivot_root")?;

    syscall::chdir(ROOT_DIR_NAME).with_context(|| "Failed to call chdir to change dir")?;

    syscall::umount(OLD_ROOT_DIR_NAME).with_context(|| "Failed to umount old root path dir")?;

    std::fs::remove_dir(OLD_ROOT_DIR_NAME).with_context(|| "Failed to remove old root path dir")?;
    Ok(())
}
