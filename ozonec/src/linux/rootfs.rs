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

use std::{
    fs::remove_file,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use nix::{
    fcntl::{open, OFlag},
    mount::{umount2, MntFlags, MsFlags},
    sys::stat::{umask, Mode},
    unistd::{chroot, fchdir, pivot_root},
    NixPath,
};
use procfs::process::Process;

use super::{device::Device, mount::Mount};
use crate::utils::OzonecErr;
use oci_spec::{
    linux::Device as OciDevice,
    runtime::{Mount as OciMount, RuntimeConfig},
};

pub struct Rootfs {
    pub path: PathBuf,
    propagation_flags: MsFlags,
    mounts: Vec<OciMount>,
    // Should we mknod the device or bind one.
    mknod_device: bool,
    devices: Vec<OciDevice>,
}

impl Rootfs {
    pub fn new(
        path: PathBuf,
        propagation: Option<String>,
        mounts: Vec<OciMount>,
        mknod_device: bool,
        devices: Vec<OciDevice>,
    ) -> Result<Self> {
        if !path.exists() {
            bail!("Rootfs directory not exist");
        }

        let propagation_flags = Self::get_mount_flags(propagation)?;
        Ok(Self {
            path,
            propagation_flags,
            mounts,
            mknod_device,
            devices,
        })
    }

    fn get_mount_flags(propagation: Option<String>) -> Result<MsFlags> {
        let flags = match propagation.as_deref() {
            Some("shared") => MsFlags::MS_SHARED,
            Some("private") => MsFlags::MS_PRIVATE,
            Some("slave") => MsFlags::MS_SLAVE,
            Some("unbindable") => MsFlags::MS_UNBINDABLE,
            Some(_) => bail!("Invalid rootfsPropagation"),
            None => MsFlags::MS_REC | MsFlags::MS_SLAVE,
        };
        Ok(flags)
    }

    fn set_propagation(&self) -> Result<()> {
        nix::mount::mount(
            None::<&str>,
            Path::new("/"),
            None::<&str>,
            self.propagation_flags,
            None::<&str>,
        )
        .with_context(|| "Failed to set rootfs mount propagation")?;
        Ok(())
    }

    fn mount(&self) -> Result<()> {
        nix::mount::mount(
            Some(&self.path),
            &self.path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )?;
        Ok(())
    }

    fn make_parent_mount_private(&self) -> Result<()> {
        let process = Process::myself().with_context(|| OzonecErr::AccessProcSelf)?;
        let mount_info = process.mountinfo().with_context(|| OzonecErr::GetMntInfo)?;

        match mount_info
            .into_iter()
            .filter(|m| self.path.starts_with(&m.mount_point) && m.mount_point != self.path)
            .map(|m| m.mount_point)
            .max_by_key(|m| m.len())
            .as_ref()
        {
            Some(m) => {
                nix::mount::mount(Some(m), m, None::<&str>, MsFlags::MS_PRIVATE, None::<&str>)?
            }
            None => (),
        }
        Ok(())
    }

    // OCI spec requires runtime MUST create the following symlinks if the source file exists after
    // processing mounts:
    // dev/fd -> /proc/self/fd
    // dev/stdin -> /proc/self/fd/0
    // dev/stdout -> /proc/self/fd/1
    // dev/stderr -> /proc/self/fd/2
    fn set_default_symlinks(&self) -> Result<()> {
        let link_pairs = vec![
            ((&self.path).join("dev/fd"), "/proc/self/fd"),
            ((&self.path).join("dev/stdin"), "/proc/self/fd/0"),
            ((&self.path).join("dev/stdout"), "/proc/self/fd/1"),
            ((&self.path).join("dev/stderr"), "/proc/self/fd/2"),
        ];

        for pair in link_pairs {
            let cloned_pair = pair.clone();
            symlink(pair.1, pair.0).with_context(|| {
                format!(
                    "Failed to create symlink {} -> {}",
                    cloned_pair.0.display(),
                    cloned_pair.1
                )
            })?;
        }
        Ok(())
    }

    fn do_mounts(&self, config: &RuntimeConfig) -> Result<()> {
        let mount = Mount::new(&self.path);
        mount
            .do_mounts(&self.mounts, &config.linux.as_ref().unwrap().mountLabel)
            .with_context(|| "Failed to do mounts")?;
        Ok(())
    }

    fn link_ptmx(&self) -> Result<()> {
        let ptmx = self.path.clone().join("dev/ptmx");
        if ptmx.exists() {
            remove_file(&ptmx).with_context(|| "Failed to delete ptmx")?;
        }
        symlink("pts/ptmx", &ptmx)
            .with_context(|| format!("Failed to create symlink {} -> pts/ptmx", ptmx.display()))?;
        Ok(())
    }

    fn create_default_devices(&self, mknod: bool) -> Result<()> {
        let dev = Device::new(self.path.clone());
        dev.create_default_devices(mknod)?;
        Ok(())
    }

    fn create_devices(&self, devices: &Vec<OciDevice>, mknod: bool) -> Result<()> {
        let dev = Device::new(self.path.clone());
        for d in devices {
            if dev.is_default_device(d) {
                dev.delete_device(d)?;
            }
            dev.create_device(d, mknod)
                .with_context(|| format!("Failed to create device {}", d.path))?;
        }
        Ok(())
    }

    pub fn prepare_rootfs(&self, config: &RuntimeConfig) -> Result<()> {
        self.set_propagation()?;
        self.mount().with_context(|| "Failed to mount rootfs")?;
        self.make_parent_mount_private()
            .with_context(|| "Failed to make parent mount private")?;
        self.do_mounts(config)?;
        self.set_default_symlinks()?;

        let old_mode = umask(Mode::from_bits_truncate(0o000));
        self.create_default_devices(self.mknod_device)?;
        self.create_devices(&self.devices, self.mknod_device)?;
        umask(old_mode);

        self.link_ptmx()?;
        Ok(())
    }

    pub fn chroot(path: &Path) -> Result<()> {
        let new_root = open(path, OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())
            .with_context(|| OzonecErr::OpenFile(path.to_string_lossy().to_string()))?;
        chroot(path)?;
        fchdir(new_root).with_context(|| "Failed to chdir to new root directory")?;
        Ok(())
    }

    pub fn pivot_root(path: &Path) -> Result<()> {
        let new_root = open(path, OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())
            .with_context(|| OzonecErr::OpenFile(path.to_string_lossy().to_string()))?;
        let old_root = open("/", OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())
            .with_context(|| OzonecErr::OpenFile("/".to_string()))?;

        pivot_root(path, path)?;
        nix::mount::mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_SLAVE | MsFlags::MS_REC,
            None::<&str>,
        )
        .with_context(|| OzonecErr::Mount("/".to_string()))?;

        fchdir(old_root).with_context(|| "Failed to chdir to old root directory")?;
        umount2(".", MntFlags::MNT_DETACH)
            .with_context(|| "Failed to umount old root directory")?;
        fchdir(new_root).with_context(|| "Failed to chdir to new root directory")?;
        Ok(())
    }
}
