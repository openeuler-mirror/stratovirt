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

use crate::cgroup::{self, init_cgroup, parse_cgroup, CgroupCfg};
use crate::OzoneError;
use crate::{capability, namespace, syscall};
use anyhow::{anyhow, bail, Context, Result};

use std::process::Command;
use std::{
    fs::{canonicalize, read_dir},
    os::unix::prelude::CommandExt,
    path::{Path, PathBuf},
    process::Stdio,
};

use util::arg_parser::ArgMatches;

const BASE_OZONE_PATH: &str = "/srv/ozone";
const SELF_FD: &str = "/proc/self/fd";
const MAX_STRING_LENGTH: usize = 255;
const MAX_ID_NUMBER: u32 = 65535;
const NEWROOT_FOLDERS: [&str; 3] = ["/", "/dev", "/dev/net"];
const NEWROOT_DEVICE_NR: usize = 6;
const NEWROOT_DEVICES: [&str; NEWROOT_DEVICE_NR] = [
    "/dev/kvm",
    "/dev/net/tun",
    "/dev/vhost-net",
    "/dev/vhost-vsock",
    "/dev/urandom",
    "/dev/null",
];
const NEWROOT_DEVICES_PERMISSION: [[u32; 3]; NEWROOT_DEVICE_NR] = [
    [10, 232, 0o660],
    [10, 200, 0o666],
    [10, 238, 0o600],
    [10, 241, 0o600],
    [1, 9, 0o666],
    [1, 3, 0o666],
];

/// OzoneHandler is used to handle data.
#[derive(Default)]
pub struct OzoneHandler {
    name: String,
    uid: u32,
    gid: u32,
    node: Option<String>,
    cgroup: Option<CgroupCfg>,
    netns_path: Option<String>,
    capability: Option<String>,
    exec_file_path: PathBuf,
    chroot_dir: PathBuf,
    source_file_paths: Vec<PathBuf>,
    extra_args: Vec<String>,
}

impl OzoneHandler {
    /// Create "OzoneHandler" from cmdline arguments.
    ///
    /// # Arguments
    ///
    /// * `args` - args parser.
    pub fn new(args: &ArgMatches) -> Result<Self> {
        let mut handler = OzoneHandler::default();
        if let Some(name) = args.value_of("name") {
            if name.len() > MAX_STRING_LENGTH {
                bail!("Input name's length must be no more than 255");
            }
            handler.name = name;
        }
        if let Some(uid) = args.value_of("uid") {
            let user_id = (uid)
                .parse::<u32>()
                .map_err(|_| anyhow!(OzoneError::DigitalParseError("uid", uid)))?;
            if user_id > MAX_ID_NUMBER {
                bail!("Input uid should be no more than 65535");
            }
            handler.uid = user_id;
        }
        if let Some(gid) = args.value_of("gid") {
            let group_id = (gid)
                .parse::<u32>()
                .map_err(|_| anyhow!(OzoneError::DigitalParseError("gid", gid)))?;
            if group_id > MAX_ID_NUMBER {
                bail!("Input gid should be no more than 65535");
            }
            handler.gid = group_id;
        }
        if let Some(exec_file) = args.value_of("exec_file") {
            handler.exec_file_path = canonicalize(exec_file)
                .with_context(|| "Failed to parse exec file path to PathBuf")?;
        }
        if let Some(source_paths) = args.values_of("source_files") {
            for path in source_paths.iter() {
                handler
                    .source_file_paths
                    .push(canonicalize(path).with_context(|| {
                        format!("Failed to parse source path {:?} to PathBuf", &path)
                    })?);
            }
        }
        if let Some(node) = args.value_of("numa") {
            handler.node = Some(
                (node)
                    .parse::<String>()
                    .map_err(|_| anyhow!(OzoneError::DigitalParseError("numa", node)))?,
            );
        }
        if let Some(config) = args.values_of("cgroup") {
            let mut cgroup_cfg = init_cgroup();
            for cfg in config {
                parse_cgroup(&mut cgroup_cfg, &cfg).with_context(|| "Failed to parse cgroup")?
            }
            handler.cgroup = Some(cgroup_cfg);
        }
        handler.extra_args = args.extra_args();
        handler.netns_path = args.value_of("network namespace");
        handler.capability = args.value_of("capability");
        handler.chroot_dir = PathBuf::from(BASE_OZONE_PATH);
        handler.chroot_dir.push(handler.exec_file_name()?);
        handler.chroot_dir.push(Path::new(&handler.name));

        Ok(handler)
    }

    /// Create directory for chroot.
    fn create_chroot_dir(&self) -> Result<()> {
        if self.chroot_dir.as_path().exists() {
            bail!(
                "Process name for {} in path {:?} has already exists",
                self.exec_file_name()?,
                &self.chroot_dir.as_path()
            );
        }
        std::fs::create_dir_all(&self.chroot_dir)
            .with_context(|| format!("Failed to create folder {:?}", &self.chroot_dir))?;
        Ok(())
    }

    /// Copy input executable binary file to chroot directory.
    fn copy_exec_file(&self) -> Result<()> {
        let exec_file_name = self.exec_file_name()?;
        let mut chroot_dir = self.chroot_dir.clone();
        chroot_dir.push(&exec_file_name);
        std::fs::copy(&self.exec_file_path, chroot_dir)
            .with_context(|| format!("Failed to copy {:?} to new chroot dir", exec_file_name))?;
        Ok(())
    }

    /// Bind mount 'file_path' into chroot directory.
    ///
    /// # Arguments
    ///
    /// * `file_path` - args parser.
    fn bind_mount_file(&self, file_path: &Path) -> Result<()> {
        let file_name = if let Some(file) = file_path.file_name() {
            file
        } else {
            bail!("Empty file path");
        };
        let mut new_root_dir = self.chroot_dir.clone();
        new_root_dir.push(file_name);
        if file_path.is_dir() {
            std::fs::create_dir_all(&new_root_dir)
                .with_context(|| format!("Failed to create directory: {:?}", &new_root_dir))?;
        } else {
            std::fs::File::create(&new_root_dir)
                .with_context(|| format!("Failed to create file: {:?}", &new_root_dir))?;
        }
        // new_root_dir.to_str().unwrap() is safe, because new_root_dir is not empty.
        syscall::mount(
            file_path.to_str(),
            new_root_dir.to_str().unwrap(),
            libc::MS_BIND | libc::MS_SLAVE,
        )
        .with_context(|| format!("Failed to mount file: {:?}", &file_path))?;

        let data = std::fs::metadata(&new_root_dir)?;
        if !file_path.is_dir() && data.len() == 0 {
            bail!("File: {:?} is empty", &new_root_dir);
        }

        syscall::chown(new_root_dir.to_str().unwrap(), self.uid, self.gid)
            .with_context(|| format!("Failed to change owner for source: {:?}", &file_path))?;
        Ok(())
    }

    /// Get  exec file name.
    fn exec_file_name(&self) -> Result<String> {
        if let Some(file_name) = self.exec_file_path.file_name() {
            return Ok(file_name.to_string_lossy().into());
        } else {
            bail!("Failed to exec file name")
        }
    }

    fn create_newroot_folder(&self, folder: &str) -> Result<()> {
        std::fs::create_dir_all(folder)
            .with_context(|| format!("Failed to create folder: {:?}", &folder))?;
        syscall::chmod(folder, 0o700)
            .with_context(|| format!("Failed to chmod to 0o700 for folder: {:?}", &folder))?;
        syscall::chown(folder, self.uid, self.gid)
            .with_context(|| format!("Failed to change owner for folder: {:?}", &folder))?;
        Ok(())
    }

    fn create_newroot_device(
        &self,
        dev_path: &str,
        dev_major: u32,
        dev_minor: u32,
        mode: u32,
    ) -> Result<()> {
        let dev = syscall::makedev(dev_major, dev_minor)?;
        syscall::mknod(dev_path, libc::S_IFCHR | libc::S_IWUSR | libc::S_IRUSR, dev)
            .with_context(|| format!("Failed to call mknod for device: {:?}", &dev_path))?;
        syscall::chmod(dev_path, mode)
            .with_context(|| format!("Failed to change mode for device: {:?}", &dev_path))?;
        syscall::chown(dev_path, self.uid, self.gid)
            .with_context(|| format!("Failed to change owner for device: {:?}", &dev_path))?;

        Ok(())
    }

    /// Realize OzoneHandler.
    pub fn realize(&self) -> Result<()> {
        // First, disinfect the process.
        disinfect_process().with_context(|| "Failed to disinfect process")?;

        self.create_chroot_dir()?;
        self.copy_exec_file()?;
        for source_file_path in self.source_file_paths.iter() {
            self.bind_mount_file(source_file_path)?;
        }

        let exec_file = self.exec_file_name()?;
        if let Some(node) = self.node.clone() {
            cgroup::set_numa_node(&node, &exec_file, &self.name)
                .with_context(|| "Failed to set numa node")?;
        }
        if let Some(cgroup) = &self.cgroup {
            cgroup::realize_cgroup(cgroup, exec_file, self.name.clone())
                .with_context(|| "Failed to realize cgroup")?;
        }

        namespace::set_uts_namespace("Ozone")?;
        namespace::set_ipc_namespace()?;
        if let Some(netns_path) = &self.netns_path {
            namespace::set_network_namespace(netns_path)?;
        }
        namespace::set_mount_namespace(self.chroot_dir.to_str().unwrap())?;

        for folder in NEWROOT_FOLDERS.iter() {
            self.create_newroot_folder(folder)?;
        }

        for index in 0..NEWROOT_DEVICE_NR {
            self.create_newroot_device(
                NEWROOT_DEVICES[index],
                NEWROOT_DEVICES_PERMISSION[index][0],
                NEWROOT_DEVICES_PERMISSION[index][1],
                NEWROOT_DEVICES_PERMISSION[index][2],
            )?;
        }
        if let Some(capability) = &self.capability {
            capability::set_capability_for_ozone(capability)
                .with_context(|| "Failed to set capability for ozone.")?;
        } else {
            capability::clear_all_capabilities()
                .with_context(|| "Failed to clean all capability for ozone.")?;
        }

        let mut chroot_exec_file = PathBuf::from("/");
        chroot_exec_file.push(self.exec_file_name()?);
        Err(anyhow!(OzoneError::ExecError(
            Command::new(chroot_exec_file)
                .gid(self.gid)
                .uid(self.uid)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .args(&self.extra_args)
                .exec(),
        )))
    }

    /// Clean the environment.
    pub fn teardown(&self) -> Result<()> {
        // Unmount source file in chroot dir path.
        for source_file_path in self.source_file_paths.clone().into_iter() {
            let mut chroot_path = self.chroot_dir.clone();
            let source_file_name = source_file_path.file_name();
            let file_name = if let Some(file_name) = source_file_name {
                file_name
            } else {
                bail!("Source file is empty")
            };
            chroot_path.push(file_name);

            if chroot_path.exists() {
                syscall::umount(chroot_path.to_str().unwrap())
                    .with_context(|| format!("Failed to umount resource: {:?}", file_name))?
            }
        }

        std::fs::remove_dir_all(&self.chroot_dir)
            .with_context(|| "Failed to remove chroot dir path")?;
        if self.node.is_some() {
            cgroup::clean_node(self.exec_file_name()?, self.name.clone())
                .with_context(|| "Failed to clean numa node")?;
        }
        if let Some(cgroup) = &self.cgroup {
            cgroup::clean_cgroup(cgroup, self.exec_file_name()?, self.name.clone())
                .with_context(|| "Failed to remove cgroup directory")?;
        }
        Ok(())
    }
}

/// Disinfect the process before launching the ozone process.
fn disinfect_process() -> Result<()> {
    let fd_entries = read_dir(SELF_FD).with_context(|| "Failed to open process fd proc")?;
    let mut open_fds = vec![];
    for entry in fd_entries {
        if entry.is_err() {
            break;
        }
        let file_name = entry.unwrap().file_name();
        let file_name = file_name.to_str().unwrap_or("0");
        let fd = file_name.parse::<libc::c_int>().unwrap_or(0);

        if fd > 2 {
            open_fds.push(fd);
        }
    }

    for fd in open_fds {
        let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if ret != -1 {
            syscall::close(fd).with_context(|| format!("Failed to close fd: {}", fd))?
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    pub use super::*;

    fn create_handler() -> OzoneHandler {
        let mut dir = env::temp_dir();
        dir.push("test_ozone_example");
        dir.push("stratovirt");
        let exec_file_path = dir.clone();
        dir.pop();
        let chroot_dir = PathBuf::from("/srv/ozone/ozone");
        let mut source_file_paths = Vec::new();
        dir.push("rootfs");
        source_file_paths.push(dir.clone());
        dir.pop();
        dir.push("vmlinux.bin");
        source_file_paths.push(dir);
        OzoneHandler {
            name: "ozone".to_string(),
            uid: 100,
            gid: 100,
            exec_file_path,
            netns_path: None,
            chroot_dir,
            source_file_paths,
            extra_args: Vec::new(),
            capability: None,
            node: None,
            cgroup: None,
        }
    }

    #[test]
    fn test_disinfect_process() {
        assert!(disinfect_process().is_ok());
    }

    #[test]
    fn test_exec_file_name() {
        let handler = create_handler();
        let exec_file = handler.exec_file_name();
        assert!(exec_file.is_ok());
        let exec_file = exec_file.unwrap();
        assert_eq!(exec_file, "stratovirt");
    }
}
