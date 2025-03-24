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
    collections::HashMap,
    fs::{self, canonicalize, create_dir_all, read_to_string},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use nix::{
    mount::MsFlags,
    sys::statfs::{statfs, CGROUP2_SUPER_MAGIC},
    unistd::close,
};
use procfs::process::{MountInfo, Process};

use crate::utils::{openat2_in_root, proc_fd_path, OzonecErr};
use oci_spec::runtime::Mount as OciMount;

#[derive(PartialEq, Debug)]
enum CgroupType {
    CgroupV1,
    CgroupV2,
}

pub struct Mount {
    rootfs: PathBuf,
}

impl Mount {
    pub fn new(rootfs: &Path) -> Self {
        Self {
            rootfs: rootfs.to_path_buf(),
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
        let mut fs_type = mount.fs_type.as_deref();
        let (mnt_flags, mut data) = self.get_mount_flag_data(mount);
        if let Some(label) = label {
            if fs_type != Some("proc") && fs_type != Some("sysfs") {
                match data.is_empty() {
                    true => data = format!("context=\"{}\"", label),
                    false => data = format!("{},context=\"{}\"", data, label),
                }
            }
        }

        let src_binding = mount
            .source
            .clone()
            .ok_or_else(|| anyhow!("Mount source not set"))?;
        let mut source = Path::new(&src_binding);
        let canonicalized;
        // Strip the first "/".
        let target_binding = self.rootfs.join(&mount.destination[1..]);
        let target = Path::new(&target_binding);

        if !(mnt_flags & MsFlags::MS_BIND).is_empty() {
            canonicalized = canonicalize(source)
                .with_context(|| format!("Failed to canonicalize {}", source.display()))?;
            source = canonicalized.as_path();
            let dir = if source.is_file() {
                target.parent().ok_or_else(|| {
                    anyhow!("Failed to get parent directory: {}", target.display())
                })?
            } else {
                target
            };
            create_dir_all(dir)
                .with_context(|| OzonecErr::CreateDir(dir.to_string_lossy().to_string()))?;
            // Actually when MS_BIND is set, filesystemtype is ignored by mount syscall.
            fs_type = Some("bind");
        } else {
            // Sysfs doesn't support duplicate mounting to one directory.
            if self.is_mounted_sysfs_dir(&target.to_string_lossy()) {
                nix::mount::umount(target)
                    .with_context(|| format!("Failed to umount {}", target.display()))?;
            }
        }

        let target_fd = openat2_in_root(
            Path::new(&self.rootfs),
            Path::new(&mount.destination[1..]),
            !source.is_file(),
        )?;
        nix::mount::mount(
            Some(source),
            &proc_fd_path(target_fd),
            fs_type,
            mnt_flags,
            Some(data.as_str()),
        )
        .with_context(|| OzonecErr::Mount(source.to_string_lossy().to_string()))?;
        close(target_fd).with_context(|| OzonecErr::CloseFd)?;
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
                Some("cgroup") => match self.cgroup_type()? {
                    CgroupType::CgroupV1 => self
                        .do_cgroup_mount(mount)
                        .with_context(|| "Failed to do cgroup mount")?,
                    CgroupType::CgroupV2 => bail!("Cgroup V2 is not supported now"),
                },
                _ => self.do_one_mount(mount, label)?,
            }
        }
        Ok(())
    }

    fn do_cgroup_mount(&self, mount: &OciMount) -> Result<()> {
        // Strip the first "/".
        let rel_target = Path::new(&mount.destination[1..]);
        let target_fd = openat2_in_root(Path::new(&self.rootfs), rel_target, true)?;
        nix::mount::mount(
            Some("tmpfs"),
            &proc_fd_path(target_fd),
            Some("tmpfs"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .with_context(|| OzonecErr::Mount(String::from("tmpfs")))?;
        close(target_fd).with_context(|| OzonecErr::CloseFd)?;

        let process = Process::myself().with_context(|| OzonecErr::AccessProcSelf)?;
        let mnt_info: Vec<MountInfo> =
            process.mountinfo().with_context(|| OzonecErr::GetMntInfo)?;
        let proc_cgroups: HashMap<String, String> = process
            .cgroups()
            .with_context(|| "Failed to get cgroups belong to")?
            .into_iter()
            .map(|cgroup| (cgroup.controllers.join(","), cgroup.pathname))
            .collect();
        // Get all of available cgroup mount points.
        let host_cgroups: Vec<PathBuf> = mnt_info
            .into_iter()
            .filter(|m| m.fs_type == "cgroup")
            .map(|m| m.mount_point)
            .collect();
        for cg_path in host_cgroups {
            let cg = cg_path
                .file_name()
                .ok_or_else(|| anyhow!("Failed to get controller file"))?
                .to_str()
                .ok_or_else(|| {
                    anyhow!("Convert {:?} to string error", cg_path.file_name().unwrap())
                })?;
            let proc_cg_key = if cg == "systemd" {
                String::from("systemd")
            } else {
                cg.to_string()
            };

            if let Some(src) = proc_cgroups.get(&proc_cg_key) {
                let source = cg_path.join(&src[1..]);
                let rel_target = cg_path
                    .strip_prefix("/")
                    .with_context(|| format!("{} doesn't start with '/'", cg_path.display()))?;
                let target_fd = openat2_in_root(Path::new(&self.rootfs), rel_target, true)?;

                nix::mount::mount(
                    Some(&source),
                    &proc_fd_path(target_fd),
                    Some("bind"),
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    None::<&str>,
                )
                .with_context(|| OzonecErr::Mount(source.to_string_lossy().to_string()))?;
                close(target_fd).with_context(|| OzonecErr::CloseFd)?;
            }
        }

        Ok(())
    }

    fn cgroup_type(&self) -> Result<CgroupType> {
        let cgroup_path = Path::new("/sys/fs/cgroup");
        if !cgroup_path.exists() {
            bail!("/sys/fs/cgroup doesn't exist.");
        }

        let st = statfs(cgroup_path).with_context(|| "statfs /sys/fs/cgroup error")?;
        if st.filesystem_type() == CGROUP2_SUPER_MAGIC {
            return Ok(CgroupType::CgroupV2);
        }
        Ok(CgroupType::CgroupV1)
    }
}

#[cfg(test)]
mod tests {
    use rusty_fork::rusty_fork_test;

    use crate::linux::namespace::tests::set_namespace;
    use oci_spec::linux::NamespaceType;

    use super::*;

    fn init_mount(rootfs: &str) -> Mount {
        let path = PathBuf::from(rootfs);
        create_dir_all(&path).unwrap();
        Mount::new(&path)
    }

    #[test]
    fn test_is_mounted_sysfs_dir() {
        let mut path = PathBuf::from("/test");
        let mut mnt = Mount::new(&path);
        assert!(!mnt.is_mounted_sysfs_dir(path.to_str().unwrap()));

        path = PathBuf::from("/sys");
        mnt = Mount::new(&path);
        assert!(mnt.is_mounted_sysfs_dir(path.to_str().unwrap()));
    }

    #[test]
    fn test_cgroup_type() {
        let rootfs = PathBuf::from("/tmp/ozonec/test_cgroup_type");
        let mnt = Mount::new(&rootfs);
        let cgroup_path = Path::new("/sys/fs/cgroup");

        if !cgroup_path.exists() {
            assert!(mnt.cgroup_type().is_err());
        } else {
            let st = statfs(cgroup_path).unwrap();
            if st.filesystem_type() == CGROUP2_SUPER_MAGIC {
                assert_eq!(mnt.cgroup_type().unwrap(), CgroupType::CgroupV2);
            } else {
                assert_eq!(mnt.cgroup_type().unwrap(), CgroupType::CgroupV1);
            }
        }
    }

    #[test]
    fn test_get_mount_flag_data() {
        let rootfs = PathBuf::from("/test_get_mount_flag_data");
        let mnt = Mount::new(&rootfs);
        let mut oci_mnt = OciMount {
            destination: String::new(),
            source: None,
            options: Some(vec![
                String::from("defaults"),
                String::from("rw"),
                String::from("suid"),
                String::from("dev"),
                String::from("exec"),
                String::from("async"),
                String::from("nomand"),
                String::from("atime"),
                String::from("diratime"),
                String::from("norelatime"),
                String::from("nostrictatime"),
            ]),
            fs_type: None,
            uidMappings: None,
            gidMappings: None,
        };

        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::empty());

        oci_mnt.options = Some(vec![
            String::from("ro"),
            String::from("nosuid"),
            String::from("nodev"),
            String::from("noexec"),
            String::from("sync"),
            String::from("dirsync"),
            String::from("remount"),
            String::from("mand"),
            String::from("noatime"),
            String::from("nodiratime"),
            String::from("bind"),
            String::from("unbindable"),
            String::from("private"),
            String::from("shared"),
            String::from("slave"),
            String::from("relatime"),
            String::from("strictatime"),
        ]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(
            flags,
            MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC
                | MsFlags::MS_SYNCHRONOUS
                | MsFlags::MS_DIRSYNC
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_MANDLOCK
                | MsFlags::MS_NOATIME
                | MsFlags::MS_NODIRATIME
                | MsFlags::MS_BIND
                | MsFlags::MS_UNBINDABLE
                | MsFlags::MS_PRIVATE
                | MsFlags::MS_SHARED
                | MsFlags::MS_SLAVE
                | MsFlags::MS_RELATIME
                | MsFlags::MS_STRICTATIME
        );

        oci_mnt.options = Some(vec![String::from("rbind")]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::MS_BIND | MsFlags::MS_REC);
        oci_mnt.options = Some(vec![String::from("runbindable")]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::MS_UNBINDABLE | MsFlags::MS_REC);
        oci_mnt.options = Some(vec![String::from("rprivate")]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::MS_PRIVATE | MsFlags::MS_REC);
        oci_mnt.options = Some(vec![String::from("rshared")]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::MS_SHARED | MsFlags::MS_REC);
        oci_mnt.options = Some(vec![String::from("rslave")]);
        let (flags, _data) = mnt.get_mount_flag_data(&oci_mnt);
        assert_eq!(flags, MsFlags::MS_SLAVE | MsFlags::MS_REC);
    }

    rusty_fork_test! {
        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_do_mounts_cgroup() {
            set_namespace(NamespaceType::Mount);

            let mounts = vec![OciMount {
                destination: String::from("/sys/fs/cgroup"),
                source: Some(String::from("cgroup")),
                options: Some(vec![
                    String::from("nosuid"),
                    String::from("noexec"),
                    String::from("nodev"),
                    String::from("relatime"),
                    String::from("ro"),
                ]),
                fs_type: Some(String::from("cgroup")),
                uidMappings: None,
                gidMappings: None,
            }];
            let mnt = init_mount("/tmp/ozonec/test_do_mounts_cgroup");

            assert!(mnt.do_mounts(&mounts, &None).is_ok());
            assert!(mnt.rootfs.join("sys/fs/cgroup").exists());
        }

        #[test]
        #[ignore = "unshare may not be permitted"]
        fn test_do_mounts_bind() {
            set_namespace(NamespaceType::Mount);

            let mounts = vec![OciMount {
                destination: String::from("/dest"),
                source: Some(String::from("/tmp/ozonec/test_do_mounts_bind/source")),
                options: Some(vec![
                    String::from("rbind")
                ]),
                fs_type: None,
                uidMappings: None,
                gidMappings: None,
            }];
            let mnt = init_mount("/tmp/ozonec/test_do_mounts_bind");
            create_dir_all(&mnt.rootfs.join("source")).unwrap();

            assert!(mnt.do_mounts(&mounts, &None).is_ok());
            assert!(mnt.rootfs.join("dest").exists());
        }
    }
}
