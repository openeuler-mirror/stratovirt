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
const MAX_STRING_LENGTH: usize = 255;

use crate::errors::{Result, ResultExt};
use std::path::PathBuf;
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
                .value_name("source directory in host")
                .help("set source directory in host")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("socket path")
                .long("socket-path")
                .value_name("sock path which communicates with StratoVirt")
                .help("sock path which communicates with StratoVirt")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("rlimit nofile")
                .long("rlimit-nofile")
                .value_name("file resource limits for the process")
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
}

/// Filesystem configuration parsed from command line for the process.
#[derive(Clone, Default, Debug)]
pub struct FsConfig {
    /// Source directory in host which can be accessed by guest.
    pub source_dir: String,
    /// The path of socket file which communicates with StratoVirt.
    pub sock_path: String,
    /// The limit of file resources which can be opened for the process.
    pub rlimit_nofile: Option<u64>,
}

impl FsConfig {
    fn check_config(&self) -> Result<()> {
        if self.source_dir.len() > MAX_STRING_LENGTH {
            bail!(
                "The length of source directory is too long {}",
                self.source_dir.len()
            );
        }

        if self.sock_path.len() > MAX_STRING_LENGTH {
            bail!(
                "The length of socket file path is too long {}",
                self.sock_path.len()
            );
        }

        let source_dir = PathBuf::from(&self.source_dir);
        if !source_dir.is_dir() {
            bail!(
                "The source directory is not a directory {}",
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
            .chain_err(|| "Failed to parse rlimit nofile")?;
        fs_config.rlimit_nofile = Some(limit);
    }

    fs_config
        .check_config()
        .chain_err(|| "Precheck failed, Config is unhealthy, stop running")?;

    Ok(fs_config)
}
