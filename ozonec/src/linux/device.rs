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

    fn default_devices(&self) -> Vec<DeviceInfo> {
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
        let dir = Path::new(path).parent().ok_or(anyhow!(
            "Failed to get parent directory: {}",
            path.display()
        ))?;
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
            .ok_or(anyhow!("Invalid device path"))?;
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
        return false;
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
            .ok_or(anyhow!("major not set for device {}", dev.path))?;
        let minor = dev
            .minor
            .ok_or(anyhow!("minor not set for device {}", dev.path))?;
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

struct DeviceInfo {
    path: PathBuf,
    dev_type: String,
    major: i64,
    minor: i64,
    file_mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}
