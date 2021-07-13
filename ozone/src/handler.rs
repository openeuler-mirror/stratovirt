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

use crate::{namespace, syscall, ErrorKind, Result, ResultExt};
use std::{
    fs::{canonicalize, read_dir},
    path::{Path, PathBuf},
};

use util::arg_parser::ArgMatches;

const BASE_OZONE_PATH: &str = "/srv/ozone";
const SELF_FD: &str = "/proc/self/fd";
const MAX_STRING_LENGTH: usize = 255;
const MAX_ID_NUMBER: u32 = 65535;

/// OzoneHandler is used to handle data.
#[derive(Default)]
pub struct OzoneHandler {
    name: String,
    uid: u32,
    gid: u32,
    netns_path: Option<String>,
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
            let user_id = (&uid)
                .parse::<u32>()
                .map_err(|_| ErrorKind::DigitalParseError("uid", uid))?;
            if user_id > MAX_ID_NUMBER {
                bail!("Input uid should be no more than 65535");
            }
            handler.uid = user_id;
        }
        if let Some(gid) = args.value_of("gid") {
            let group_id = (&gid)
                .parse::<u32>()
                .map_err(|_| ErrorKind::DigitalParseError("gid", gid))?;
            if group_id > MAX_ID_NUMBER {
                bail!("Input gid should be no more than 65535");
            }
            handler.gid = group_id;
        }
        if let Some(exec_file) = args.value_of("exec_file") {
            handler.exec_file_path = canonicalize(exec_file)
                .chain_err(|| "Failed to parse exec file path to PathBuf")?;
        }
        if let Some(source_paths) = args.values_of("source_files") {
            for path in source_paths.iter() {
                handler.source_file_paths.push(
                    canonicalize(path).chain_err(|| {
                        format!("Failed to parse source path {:?} to PathBuf", &path)
                    })?,
                );
            }
        }
        handler.extra_args = args.extra_args();
        handler.netns_path = args.value_of("network namespace");
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
            .chain_err(|| format!("Failed to create folder {:?}", &self.chroot_dir))?;
        Ok(())
    }

    /// Copy input executable binary file to chroot directory.
    fn copy_exec_file(&self) -> Result<()> {
        let exec_file_name = self.exec_file_name()?;
        let mut chroot_dir = self.chroot_dir.clone();
        chroot_dir.push(&exec_file_name);
        std::fs::copy(&self.exec_file_path, chroot_dir)
            .chain_err(|| format!("Failed to copy {:?} to new chroot dir", exec_file_name))?;
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
                .chain_err(|| format!("Failed to create directory: {:?}", &new_root_dir))?;
        } else {
            std::fs::File::create(&new_root_dir)
                .chain_err(|| format!("Failed to create file: {:?}", &new_root_dir))?;
        }
        // new_root_dir.to_str().unwrap() is safe, because new_root_dir is not empty.
        syscall::mount(
            file_path.to_str(),
            new_root_dir.to_str().unwrap(),
            libc::MS_BIND | libc::MS_SLAVE,
        )
        .chain_err(|| format!("Failed to mount file: {:?}", &file_path))?;

        let data = std::fs::metadata(&new_root_dir)?;
        if !file_path.is_dir() && data.len() == 0 {
            bail!("File: {:?} is empty", &new_root_dir);
        }

        syscall::chown(new_root_dir.to_str().unwrap(), self.uid, self.gid)
            .chain_err(|| format!("Failed to change owner for source: {:?}", &file_path))?;
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

    /// Realize OzoneHandler.
    pub fn realize(&self) -> Result<()> {
        // First, disinfect the process.
        disinfect_process().chain_err(|| "Failed to disinfect process")?;
        self.create_chroot_dir()?;
        self.copy_exec_file()?;
        for source_file_path in self.source_file_paths.iter() {
            self.bind_mount_file(source_file_path)?;
        }

        namespace::set_uts_namespace("Ozone")?;
        namespace::set_ipc_namespace()?;
        if let Some(netns_path) = &self.netns_path {
            namespace::set_network_namespace(netns_path)?;
        }
        namespace::set_mount_namespace(self.chroot_dir.to_str().unwrap())?;
        Ok(())
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
                    .chain_err(|| format!("Failed to umount resource: {:?}", file_name))?
            }
        }

        std::fs::remove_dir_all(&self.chroot_dir)
            .chain_err(|| "Failed to remove chroot dir path")?;
        Ok(())
    }
}

/// Disinfect the process before launching the ozone process.
fn disinfect_process() -> Result<()> {
    let fd_entries = read_dir(SELF_FD).chain_err(|| "Failed to open process fd proc")?;
    for entry in fd_entries {
        if entry.is_err() {
            continue;
        }
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_str().unwrap_or("0");
        let fd = file_name.parse::<libc::c_int>().unwrap_or(0);

        if fd > 2 {
            syscall::close(fd).chain_err(|| format!("Failed to close fd: {}", fd))?;
        }
    }
    Ok(())
}
