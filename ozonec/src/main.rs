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

mod commands;
mod container;
mod linux;
mod utils;

use std::{
    fs::remove_dir_all,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::{anyhow, Context, Result};
use clap::{crate_description, Args, Parser, Subcommand};
use commands::{Delete, Exec, Kill, Start, State};
use log::info;
use nix::unistd::geteuid;

use crate::{commands::Create, utils::logger};

// Global options which are not binded to any specific command.
#[derive(Args, Debug)]
struct GlobalOpts {
    /// Root directory to store container state.
    #[arg(short, long)]
    root: Option<PathBuf>,
    /// Path of log file.
    #[arg(short, long)]
    log: Option<PathBuf>,
    /// Enable debug log level.
    #[arg(short, long)]
    debug: bool,
}

// Standard commands supported by [OCI runtime-spec]
// (https://github.com/opencontainers/runtime-spec/blob/master/runtime.md)
// and [OCI Command Line Interface]
// (https://github.com/opencontainers/runtime-tools/blob/master/docs/command-line-interface.md).
#[derive(Subcommand, Debug)]
enum StandardCmd {
    Create(Create),
    Start(Start),
    State(State),
    Kill(Kill),
    Delete(Delete),
}

// Extended commands not documented in [OCI Command Line Interface].
#[derive(Subcommand, Debug)]
enum ExtendCmd {
    Exec(Exec),
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(flatten)]
    Standard(StandardCmd),
    #[command(flatten)]
    Extend(ExtendCmd),
}

#[derive(Parser, Debug)]
#[command(version, author, about = crate_description!())]
#[command(propagate_version = true)]
struct Cli {
    #[command(flatten)]
    global: GlobalOpts,
    #[command(subcommand)]
    cmd: Command,
}

fn cmd_run(command: Command, root: &Path) -> Result<()> {
    match command {
        Command::Standard(cmd) => match cmd {
            StandardCmd::Create(create) => {
                info!("Run command: {:?}", create);

                let mut root_exist = false;
                create.run(root, &mut root_exist).map_err(|e| {
                    if !root_exist {
                        let _ = remove_dir_all(root);
                    }
                    anyhow!(e)
                })?
            }
            StandardCmd::Start(start) => {
                info!("Run command: {:?}", start);
                start.run(root)?
            }
            StandardCmd::Kill(kill) => {
                info!("Run command: {:?}", kill);
                kill.run(root)?
            }
            StandardCmd::Delete(delete) => {
                info!("Run command: {:?}", delete);
                delete.run(root)?
            }
            StandardCmd::State(state) => {
                info!("Run command: {:?}", state);
                state.run(root)?
            }
        },
        Command::Extend(cmd) => match cmd {
            ExtendCmd::Exec(exec) => {
                info!("Run command: {:?}", exec);
                exec.run(root)?
            }
        },
    }
    Ok(())
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();

    logger::init(&cli.global.log, cli.global.debug).with_context(|| "Failed to init logger")?;

    let root_path = if let Some(root) = cli.global.root {
        root
    } else {
        let euid = geteuid();
        PathBuf::from(format!("/var/run/user/{}/ozonec", euid))
    };
    cmd_run(cli.cmd, &root_path)
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {:?}", e);
        exit(1);
    }
    exit(0);
}
