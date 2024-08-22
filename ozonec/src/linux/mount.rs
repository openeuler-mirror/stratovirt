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
    fs::{self, canonicalize, create_dir_all, read_to_string, File},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use nix::mount::MsFlags;

use oci_spec::runtime::Mount as OciMount;

use crate::utils::OzonecErr;

pub struct Mount {
    rootfs: PathBuf,
}

impl Mount {
    pub fn new(rootfs: &PathBuf) -> Self {
        Self {
            rootfs: rootfs.clone(),
        }
    }

    fn get_mount_flag_data(&self, mount: &OciMount) -> (MsFlags, String) {
        let mut ms_flags = MsFlags::empty();
        let mut data = Vec::new();

        if let Some(options) = &mount.options {
            for option in options {
                if let Some((clear, flag)) = match option.as_str() {
                    "defaults" => Some((false, MsFlags::empty())),
                    "ro" => Some((false, MsFlags::MS_RDONLY)),
                    "rw" => Some((true, MsFlags::MS_RDONLY)),
                    "suid" => Some((true, MsFlags::MS_NOSUID)),
                    "nosuid" => Some((false, MsFlags::MS_NOSUID)),
                    "dev" => Some((true, MsFlags::MS_NODEV)),
                    "nodev" => Some((false, MsFlags::MS_NODEV)),
                    "exec" => Some((true, MsFlags::MS_NOEXEC)),
                    "noexec" => Some((false, MsFlags::MS_NOEXEC)),
                    "sync" => Some((false, MsFlags::MS_SYNCHRONOUS)),
                    "async" => Some((true, MsFlags::MS_SYNCHRONOUS)),
                    "dirsync" => Some((false, MsFlags::MS_DIRSYNC)),
                    "remount" => Some((false, MsFlags::MS_REMOUNT)),
                    "mand" => Some((false, MsFlags::MS_MANDLOCK)),
                    "nomand" => Some((true, MsFlags::MS_MANDLOCK)),
                    "atime" => Some((true, MsFlags::MS_NOATIME)),
                    "noatime" => Some((false, MsFlags::MS_NOATIME)),
                    "diratime" => Some((true, MsFlags::MS_NODIRATIME)),
                    "nodiratime" => Some((false, MsFlags::MS_NODIRATIME)),
                    "bind" => Some((false, MsFlags::MS_BIND)),
                    "rbind" => Some((false, MsFlags::MS_BIND | MsFlags::MS_REC)),
                    "unbindable" => Some((false, MsFlags::MS_UNBINDABLE)),
                    "runbindable" => Some((false, MsFlags::MS_UNBINDABLE | MsFlags::MS_REC)),
                    "private" => Some((false, MsFlags::MS_PRIVATE)),
                    "rprivate" => Some((false, MsFlags::MS_PRIVATE | MsFlags::MS_REC)),
                    "shared" => Some((false, MsFlags::MS_SHARED)),
                    "rshared" => Some((false, MsFlags::MS_SHARED | MsFlags::MS_REC)),
                    "slave" => Some((false, MsFlags::MS_SLAVE)),
                    "rslave" => Some((false, MsFlags::MS_SLAVE | MsFlags::MS_REC)),
                    "relatime" => Some((false, MsFlags::MS_RELATIME)),
                    "norelatime" => Some((true, MsFlags::MS_RELATIME)),
                    "strictatime" => Some((false, MsFlags::MS_STRICTATIME)),
                    "nostrictatime" => Some((true, MsFlags::MS_STRICTATIME)),
                    _ => None,
                } {
                    if clear {
                        ms_flags &= !flag;
                    } else {
                        ms_flags |= flag;
                    }
                    continue;
                }
                data.push(option.as_str());
            }
        }
        (ms_flags, data.join(","))
    }

    fn do_one_mount(&self, mount: &OciMount, label: &Option<String>) -> Result<()> {
        let fs_type = mount.fs_type.as_deref();
        let (flag, mut data) = self.get_mount_flag_data(mount);

        if let Some(label) = label {
            if fs_type != Some("proc") && fs_type != Some("sysfs") {
                match data.is_empty() {
                    true => data = format!("context=\"{}\"", label),
                    false => data = format!("{},context=\"{}\"", data, label),
                }
            }
        }

        // If destination begins with "/", then ignore the first "/".
        let binding = self.rootfs.join(&mount.destination[1..]);
        let dest_path = Path::new(&binding);
        let binding = &mount
            .source
            .clone()
            .ok_or(anyhow!("Mount source not set"))?;
        let source = Path::new(&binding);
        let canonicalized;
        let src_path = match fs_type {
            Some("bind") => {
                canonicalized = canonicalize(source)
                    .with_context(|| format!("Failed to canonicalize {}", source.display()))?;
                canonicalized.as_path()
            }
            _ => source,
        };

        match fs_type {
            Some("bind") => {
                let dir = if src_path.is_file() {
                    dest_path.parent().ok_or(anyhow!(
                        "Failed to get parent directory: {}",
                        dest_path.display()
                    ))?
                } else {
                    dest_path
                };

                create_dir_all(dir)
                    .with_context(|| OzonecErr::CreateDir(dir.to_string_lossy().to_string()))?;
                if src_path.is_file() && !dest_path.exists() {
                    File::create(dest_path)
                        .with_context(|| format!("Failed to create {}", dest_path.display()))?;
                }

                nix::mount::mount(
                    Some(src_path),
                    dest_path,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    Some(data.as_str()),
                )?;
            }
            _ => {
                create_dir_all(&dest_path).with_context(|| {
                    OzonecErr::CreateDir(dest_path.to_string_lossy().to_string())
                })?;
                // Sysfs doesn't support duplicate mounting to one directory.
                if self.is_mounted_sysfs_dir(&dest_path.to_string_lossy().to_string()) {
                    nix::mount::umount(dest_path)
                        .with_context(|| format!("Failed to umount {}", dest_path.display()))?;
                }
                nix::mount::mount(
                    Some(src_path),
                    dest_path,
                    fs_type,
                    flag,
                    Some(data.as_str()),
                )?;
            }
        }

        Ok(())
    }

    fn is_mounted_sysfs_dir(&self, path: &str) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.file_type().is_dir() {
                if let Ok(mounts) = read_to_string("/proc/mounts") {
                    for line in mounts.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 && parts[1] == path && parts[2] == "sysfs" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn do_mounts(&self, mounts: &Vec<OciMount>, label: &Option<String>) -> Result<()> {
        for mount in mounts {
            match mount.fs_type.as_deref() {
                Some("cgroup") => (),
                _ => self.do_one_mount(mount, label)?,
            }
        }
        Ok(())
    }
}
