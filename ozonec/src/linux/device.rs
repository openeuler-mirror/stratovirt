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
    fs::{create_dir_all, remove_file, File},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use nix::{
    mount::MsFlags,
    sys::stat::{makedev, mknod, Mode, SFlag},
    unistd::{chown, Gid, Uid},
};
use oci_spec::linux::Device as OciDevice;

use crate::utils::OzonecErr;

pub struct Device {
    rootfs: PathBuf,
}

impl Device {
    pub fn new(rootfs: PathBuf) -> Self {
        Self { rootfs }
    }

    pub fn default_devices(&self) -> Vec<DeviceInfo> {
        vec![
            DeviceInfo {
                path: self.rootfs.join("dev/null"),
                dev_type: "c".to_string(),
                major: 1,
                minor: 3,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
            DeviceInfo {
                path: self.rootfs.join("dev/zero"),
                dev_type: "c".to_string(),
                major: 1,
                minor: 5,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
            DeviceInfo {
                path: self.rootfs.join("dev/full"),
                dev_type: "c".to_string(),
                major: 1,
                minor: 7,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
            DeviceInfo {
                path: self.rootfs.join("dev/random"),
                dev_type: "c".to_string(),
                major: 1,
                minor: 8,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
            DeviceInfo {
                path: self.rootfs.join("dev/urandom"),
                dev_type: "c".to_string(),
                major: 1,
                minor: 9,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
            DeviceInfo {
                path: self.rootfs.join("dev/tty"),
                dev_type: "c".to_string(),
                major: 5,
                minor: 0,
                file_mode: Some(0o666u32),
                uid: None,
                gid: None,
            },
        ]
    }

    fn create_device_dir(&self, path: &PathBuf) -> Result<()> {
        let dir = Path::new(path)
            .parent()
            .ok_or_else(|| anyhow!("Failed to get parent directory: {}", path.display()))?;
        if !dir.exists() {
            create_dir_all(dir)
                .with_context(|| OzonecErr::CreateDir(dir.to_string_lossy().to_string()))?;
        }
        Ok(())
    }

    fn get_sflag(&self, dev_type: &str) -> Result<SFlag> {
        let sflag = match dev_type {
            "c" => SFlag::S_IFCHR,
            "b" => SFlag::S_IFBLK,
            "u" => SFlag::S_IFCHR,
            "p" => SFlag::S_IFIFO,
            _ => bail!("Not supported device type: {}", dev_type),
        };
        Ok(sflag)
    }

    fn bind_device(&self, dev: &DeviceInfo) -> Result<()> {
        self.create_device_dir(&dev.path)?;

        let binding = dev.path.to_string_lossy().to_string();
        let stripped_path = binding
            .strip_prefix(&self.rootfs.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("Invalid device path"))?;
        let src_path = PathBuf::from(stripped_path);

        if !dev.path.exists() {
            File::create(&dev.path)
                .with_context(|| format!("Failed to create {}", dev.path.display()))?;
        }
        nix::mount::mount(
            Some(&src_path),
            &dev.path,
            Some("bind"),
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| OzonecErr::Mount(stripped_path.to_string()))?;

        Ok(())
    }

    fn mknod_device(&self, dev: &DeviceInfo) -> Result<()> {
        self.create_device_dir(&dev.path)?;

        let sflag = self.get_sflag(&dev.dev_type)?;
        let device = makedev(dev.major as u64, dev.minor as u64);
        mknod(
            &dev.path,
            sflag,
            Mode::from_bits_truncate(dev.file_mode.unwrap_or(0)),
            device,
        )?;
        chown(
            &dev.path,
            dev.uid.map(Uid::from_raw),
            dev.gid.map(Gid::from_raw),
        )
        .with_context(|| "Failed to chown")?;

        Ok(())
    }

    pub fn create_default_devices(&self, mknod: bool) -> Result<()> {
        let default_devs = self.default_devices();
        for dev in default_devs {
            if mknod {
                if self.mknod_device(&dev).is_err() {
                    self.bind_device(&dev).with_context(|| {
                        OzonecErr::BindDev(dev.path.to_string_lossy().to_string())
                    })?;
                }
            } else {
                self.bind_device(&dev)
                    .with_context(|| OzonecErr::BindDev(dev.path.to_string_lossy().to_string()))?;
            }
        }
        Ok(())
    }

    pub fn is_default_device(&self, dev: &OciDevice) -> bool {
        for d in &self.default_devices() {
            let path = self.rootfs.join(&dev.path.clone()[1..]);
            if path == d.path {
                return true;
            }
        }
        false
    }

    pub fn delete_device(&self, dev: &OciDevice) -> Result<()> {
        let path = self.rootfs.join(&dev.path.clone()[1..]);
        remove_file(&path).with_context(|| format!("Failed to delete {}", path.display()))?;
        Ok(())
    }

    pub fn create_device(&self, dev: &OciDevice, mknod: bool) -> Result<()> {
        let path = self.rootfs.join(&dev.path.clone()[1..]);
        let major = dev
            .major
            .ok_or_else(|| anyhow!("major not set for device {}", dev.path))?;
        let minor = dev
            .minor
            .ok_or_else(|| anyhow!("minor not set for device {}", dev.path))?;
        let dev_info = DeviceInfo {
            path,
            dev_type: dev.dev_type.clone(),
            major,
            minor,
            file_mode: dev.fileMode,
            uid: dev.uid,
            gid: dev.gid,
        };

        if mknod {
            if self.mknod_device(&dev_info).is_err() {
                self.bind_device(&dev_info).with_context(|| {
                    OzonecErr::BindDev(dev_info.path.to_string_lossy().to_string())
                })?;
            }
        } else {
            self.bind_device(&dev_info)
                .with_context(|| OzonecErr::BindDev(dev_info.path.to_string_lossy().to_string()))?;
        }
        Ok(())
    }
}

pub struct DeviceInfo {
    pub path: PathBuf,
    dev_type: String,
    major: i64,
    minor: i64,
    file_mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };

    use nix::mount::umount;

    use super::*;

    #[test]
    #[ignore = "mount may not be permitted"]
    fn test_mknod_dev() {
        let rootfs = PathBuf::from("/tmp/ozonec/mknod_dev");
        create_dir_all(&rootfs).unwrap();
        let dev = Device::new(rootfs.clone());
        let path = rootfs.join("mknod_dev");
        if path.exists() {
            remove_file(&path).unwrap();
        }
        let dev_info = DeviceInfo {
            path: path.clone(),
            dev_type: "c".to_string(),
            major: 1,
            minor: 3,
            file_mode: Some(0o644u32),
            uid: Some(1000u32),
            gid: Some(1000u32),
        };

        assert!(dev.mknod_device(&dev_info).is_ok());
        assert!(path.exists());

        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_char_device());
        let major = (metadata.rdev() >> 8) as u32;
        let minor = (metadata.rdev() & 0xff) as u32;
        assert_eq!(major, 1);
        assert_eq!(minor, 3);
        let file_mode = metadata.permissions().mode();
        assert_eq!(file_mode & 0o777, 0o644u32);
        assert_eq!(metadata.uid(), 1000);
        assert_eq!(metadata.gid(), 1000);

        fs::remove_dir_all("/tmp/ozonec").unwrap();
    }

    #[test]
    #[ignore = "mount may not be permitted"]
    fn test_bind_dev() {
        let rootfs = PathBuf::from("/tmp/ozonec/bind_dev");
        create_dir_all(&rootfs).unwrap();
        let dev_path = PathBuf::from("/mknod_dev");
        if dev_path.exists() {
            remove_file(&dev_path).unwrap();
        }
        let dev = makedev(1, 3);
        mknod(
            &dev_path,
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(0o644u32),
            dev,
        )
        .unwrap();
        let dev_to_bind = Device::new(rootfs.clone());
        let binded_path = rootfs.join("mknod_dev");
        if binded_path.exists() {
            umount(&binded_path).unwrap();
            remove_file(&binded_path).unwrap();
        }
        let dev_info = DeviceInfo {
            path: binded_path.clone(),
            dev_type: "c".to_string(),
            major: 1,
            minor: 3,
            file_mode: Some(0o644u32),
            uid: Some(1000u32),
            gid: Some(1000u32),
        };

        assert!(dev_to_bind.bind_device(&dev_info).is_ok());

        let metadata = fs::metadata(&dev_path).unwrap();
        let binded_metadata = fs::metadata(&binded_path).unwrap();
        assert_eq!(binded_metadata.file_type(), metadata.file_type());
        assert_eq!(binded_metadata.rdev(), metadata.rdev());
        assert_eq!(binded_metadata.permissions(), metadata.permissions());
        assert_eq!(binded_metadata.uid(), metadata.uid());
        assert_eq!(binded_metadata.gid(), metadata.gid());

        umount(&binded_path).unwrap();
        fs::remove_dir_all("/tmp/ozonec").unwrap();
        fs::remove_file(dev_path).unwrap();
    }

    #[test]
    #[ignore = "mknod may not be permitted"]
    fn test_create_device() {
        let oci_dev = OciDevice {
            dev_type: "c".to_string(),
            path: "/mknod_dev".to_string(),
            major: Some(1),
            minor: Some(3),
            fileMode: Some(0o644u32),
            uid: Some(1000),
            gid: Some(1000),
        };
        let rootfs = PathBuf::from("/tmp/ozonec/create_device");
        create_dir_all(&rootfs).unwrap();
        let path = rootfs.join("mknod_dev");
        if path.exists() {
            remove_file(&path).unwrap();
        }
        let dev = Device::new(rootfs.clone());

        assert!(dev.create_device(&oci_dev, true).is_ok());
        assert!(path.exists());

        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.file_type().is_char_device());
        let major = (metadata.rdev() >> 8) as u32;
        let minor = (metadata.rdev() & 0xff) as u32;
        assert_eq!(major, 1);
        assert_eq!(minor, 3);
        let file_mode = metadata.permissions().mode();
        assert_eq!(file_mode & 0o777, 0o644u32);
        assert_eq!(metadata.uid(), 1000);
        assert_eq!(metadata.gid(), 1000);

        fs::remove_dir_all("/tmp/ozonec").unwrap();
    }

    #[test]
    #[ignore = "mount may not be permitted"]
    fn test_delete_device() {
        let oci_dev = OciDevice {
            dev_type: "c".to_string(),
            path: "/mknod_dev".to_string(),
            major: Some(1),
            minor: Some(3),
            fileMode: Some(0o644u32),
            uid: Some(1000),
            gid: Some(1000),
        };
        let rootfs = PathBuf::from("/tmp/ozonec/delete_device");
        create_dir_all(&rootfs).unwrap();
        let path = rootfs.join("mknod_dev");
        if path.exists() {
            remove_file(&path).unwrap();
        }
        let dev = Device::new(rootfs.clone());
        dev.create_device(&oci_dev, true).unwrap();

        assert!(dev.delete_device(&oci_dev).is_ok());
        assert!(!path.exists());

        fs::remove_dir_all("/tmp/ozonec").unwrap();
    }

    #[test]
    fn test_default_device() {
        let rootfs = PathBuf::from("/tmp/ozonec/default_device");
        let dev = Device::new(rootfs.clone());

        let mut oci_dev = OciDevice {
            dev_type: "c".to_string(),
            path: "mknod_dev".to_string(),
            major: Some(1),
            minor: Some(3),
            fileMode: Some(0o644u32),
            uid: Some(1000),
            gid: Some(1000),
        };
        assert!(!dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/null".to_string();
        assert!(dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/zero".to_string();
        assert!(dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/full".to_string();
        assert!(dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/random".to_string();
        assert!(dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/urandom".to_string();
        assert!(dev.is_default_device(&oci_dev));
        oci_dev.path = "/dev/tty".to_string();
        assert!(dev.is_default_device(&oci_dev));
    }

    #[test]
    fn test_get_sflag() {
        let rootfs = PathBuf::from("/tmp/ozonec/test_get_sflag");
        let dev = Device::new(rootfs.clone());

        assert_eq!(dev.get_sflag("c").unwrap(), SFlag::S_IFCHR);
        assert_eq!(dev.get_sflag("b").unwrap(), SFlag::S_IFBLK);
        assert_eq!(dev.get_sflag("p").unwrap(), SFlag::S_IFIFO);
        assert_eq!(dev.get_sflag("u").unwrap(), SFlag::S_IFCHR);
    }
}
