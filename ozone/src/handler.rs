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

use std::{
    fs::canonicalize,
    path::{Path, PathBuf},
};

use crate::{ErrorKind, Result, ResultExt};

use util::arg_parser::ArgMatches;

const BASE_OZONE_PATH: &str = "/srv/ozone";
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

    /// Get  exec file name.
    fn exec_file_name(&self) -> Result<String> {
        if let Some(file_name) = self.exec_file_path.file_name() {
            return Ok(file_name.to_string_lossy().into());
        } else {
            bail!("Failed to exec file name")
        }
    }
}
