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

pub mod logger;
pub mod prctl;

mod channel;
mod clone;
mod error;

pub use channel::{Channel, Message};
pub use clone::Clone3;
pub use error::OzonecErr;

use std::{
    fs::create_dir_all,
    mem,
    os::unix::io::{AsRawFd, RawFd},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nix::{
    errno::errno,
    fcntl::{open, OFlag},
    sys::stat::Mode,
    NixPath,
};

struct OpenHow(libc::open_how);

bitflags::bitflags! {
    struct ResolveFlag: libc::c_ulonglong {
        const RESOLVE_BENEATH = libc::RESOLVE_BENEATH;
        const RESOLVE_IN_ROOT = libc::RESOLVE_IN_ROOT;
        const RESOLVE_NO_MAGICLINKS = libc::RESOLVE_NO_MAGICLINKS;
        const RESOLVE_NO_SYMLINKS = libc::RESOLVE_NO_SYMLINKS;
        const RESOLVE_NO_XDEV = libc::RESOLVE_NO_XDEV;
    }
}

impl OpenHow {
    fn new() -> Self {
        // SAFETY: FFI call with valid arguments.
        unsafe { mem::zeroed() }
    }

    fn flags(mut self, flags: OFlag) -> Self {
        let flags = flags.bits() as libc::c_ulonglong;
        self.0.flags = flags;
        self
    }

    fn mode(mut self, mode: Mode) -> Self {
        let mode = mode.bits() as libc::c_ulonglong;
        self.0.mode = mode;
        self
    }

    fn resolve(mut self, resolve: ResolveFlag) -> Self {
        let resolve = resolve.bits() as libc::c_ulonglong;
        self.0.resolve = resolve;
        self
    }
}

/// Get a file descriptor by openat2 with `root` path, relative `target` path in `root`
/// and whether is director or not. If the target directory or file doesn't exist, create
/// automatically.
pub fn openat2_in_root(root: &Path, target: &Path, is_dir: bool) -> Result<RawFd> {
    let mut flags = OFlag::O_CLOEXEC;
    let mode;
    if is_dir {
        flags |= OFlag::O_DIRECTORY | OFlag::O_PATH;
        mode = Mode::empty();
        create_dir_all(root.join(target))
            .with_context(|| OzonecErr::CreateDir(target.to_string_lossy().to_string()))?;
    } else {
        flags |= OFlag::O_CREAT;
        mode = Mode::S_IRWXU;
    };

    let mut open_how = OpenHow::new()
        .flags(flags)
        .mode(mode)
        .resolve(ResolveFlag::RESOLVE_IN_ROOT);
    let dirfd = open(root, flags & !OFlag::O_CREAT, Mode::empty())
        .with_context(|| OzonecErr::OpenFile(root.to_string_lossy().to_string()))?;
    let fd = target
        // SAFETY: FFI call with valid arguments.
        .with_nix_path(|p| unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd.as_raw_fd(),
                p.as_ptr(),
                &mut open_how as *mut OpenHow,
                mem::size_of::<libc::open_how>(),
            )
        })
        .with_context(|| "with_nix_path error")?;
    if fd < 0 {
        bail!(
            "openat2 {} error with RESOLVE_IN_ROOT: {}",
            target.display(),
            errno()
        );
    }
    Ok(RawFd::try_from(fd)?)
}

/// Build path "/proc/self/fd/{}" with an opened file descriptor.
pub fn proc_fd_path(dirfd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dirfd))
}
