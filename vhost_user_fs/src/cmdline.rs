// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

// Read the programe version in `Cargo.toml`.
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
const MAX_PATH_LENGTH: usize = 4096;
// Maximum length of the socket path is restricted by linux.
const MAX_SOCK_PATH_LENGTH: usize = 108;

use crate::fs_ops::open;
use crate::fuse_msg::FUSE_OK;
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::File;
use std::{fs, path::PathBuf};
use util::arg_parser::{Arg, ArgMatches, ArgParser};

/// This function is to define all command line arguments.
pub fn create_args_parser<'a>() -> ArgParser<'a> {
    ArgParser::new("VhostUserFs")
        .version(VERSION.unwrap_or("unknown"))
        .author("Huawei Technologies Co., Ltd")
        .about("The process of Virtio fs for StratoVirt.")
        .arg(
            Arg::with_name("source dir")
                .long("source")
                .value_name("shared_path")
                .help("set source shared directory in host")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("socket path")
                .long("socket-path")
                .value_name("socket_path")
                .help("vhost-user socket path which communicates with StratoVirt")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("rlimit nofile")
                .long("rlimit-nofile")
                .value_name("num")
                .help("set file resource limits for the process")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("display log")
                .long("D")
                .value_name("log_path")
                .help("output log to logfile")
                .takes_value(true)
                .can_no_value(true),
        )
        .arg(
            Arg::with_name("seccomp")
                .long("seccomp")
                .value_name("[allow | kill | log | trap]")
                .help("limit syscall(allow, kill, log, trap) eg: -seccomp kill")
                .takes_value(true)
                .possible_values(vec!["allow", "kill", "log", "trap"]),
        )
        .arg(
            Arg::with_name("sandbox")
                .long("sandbox")
                .value_name("[chroot | namespace]")
                .help("isolate the daemon process(chroot, namespace). eg: -sandbox namespace")
                .takes_value(true)
                .possible_values(vec!["namespace", "chroot"]),
        )
        .arg(
            Arg::with_name("modcaps")
                .opt_long("modcaps")
                .value_name("capabilities_list")
                .help("modify the list of capabilities. eg: --modcaps=-LEASE,+KILL")
                .takes_value(true),
        )
}

/// Filesystem configuration parsed from command line for the process.
#[derive(Debug, Default)]
pub struct FsConfig {
    /// Source directory in host which can be accessed by guest.
    pub source_dir: String,
    /// The path of socket file which communicates with StratoVirt.
    pub sock_path: String,
    /// The limit of file resources which can be opened for the process.
    pub rlimit_nofile: Option<u64>,
    /// The path of root directory.
    pub root_dir: String,
    /// File object for /proc/self/fd.
    pub proc_dir_opt: Option<File>,
}

impl FsConfig {
    fn check_config(&self) -> Result<()> {
        if self.source_dir.len() > MAX_PATH_LENGTH {
            bail!(
                "The length of source directory is too long {}",
                self.source_dir.len()
            );
        }

        if self.sock_path.len() > MAX_SOCK_PATH_LENGTH {
            bail!(
                "The length of socket file path is too long {}",
                self.sock_path.len()
            );
        }

        if fs::metadata(&self.source_dir).is_err() {
            bail!("Failed to stat source directory {}", self.source_dir);
        }
        let source_dir = PathBuf::from(&self.source_dir);
        if !source_dir.is_dir() {
            bail!(
                "The source directory {} is not a directory",
                self.source_dir
            );
        }

        Ok(())
    }
}

/// Construct a filesystem configuration parsed from command line.
///
/// # Arguments
/// * `args` - The collection of information about the arguments from command line.
pub fn create_fs_config(args: &ArgMatches) -> Result<FsConfig> {
    let mut fs_config = FsConfig::default();

    if let Some(source_dir) = args.value_of("source dir") {
        fs_config.source_dir = source_dir;
    }

    if let Some(sock_path) = args.value_of("socket path") {
        fs_config.sock_path = sock_path;
    }

    if let Some(rlimit_nofile) = args.value_of("rlimit nofile") {
        let limit = rlimit_nofile
            .parse::<u64>()
            .with_context(|| "Failed to parse rlimit nofile")?;
        fs_config.rlimit_nofile = Some(limit);
    }

    let (proc_dir_opt, ret) = open(CString::new("/proc/self/fd").unwrap(), libc::O_PATH);
    if ret != FUSE_OK {
        bail!("Failed to open proc dir");
    }
    fs_config.proc_dir_opt = proc_dir_opt;

    fs_config.root_dir = fs_config.source_dir.clone();
    if args.value_of("sandbox").is_some() {
        fs_config.root_dir = "/".to_string();
    }

    fs_config
        .check_config()
        .with_context(|| "Precheck failed, Config is unhealthy, stop running")?;

    Ok(fs_config)
}
