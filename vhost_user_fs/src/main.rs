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

#[macro_use]
extern crate log;
extern crate vhost_user_fs;
use anyhow::{Context, Result};
use machine_manager::event_loop::EventLoop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use util::{arg_parser, logger};
use vhost_user_fs::cmdline::{create_args_parser, create_fs_config, FsConfig};
use vhost_user_fs::vhost_user_fs::VhostUserFs;

#[derive(Error, Debug)]
pub enum MainError {
    #[error("VhostUserFs")]
    VhostUserFs {
        #[from]
        source: vhost_user_fs::error::VhostUserFsError,
    },
    #[error("Util")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
}

pub trait ExitCode {
    /// Returns the value to use as the exit status.
    fn code(self) -> i32;
}

impl ExitCode for i32 {
    fn code(self) -> i32 {
        self
    }
}

impl ExitCode for () {
    fn code(self) -> i32 {
        0
    }
}

fn main() {
    ::std::process::exit(match run() {
        Ok(ret) => ExitCode::code(ret),
        Err(ref e) => {
            write!(&mut ::std::io::stderr(), "{}", format!("{:?}", e))
                .expect("Error writing to stderr");

            1
        }
    });
}

fn run() -> Result<()> {
    let cmd_args = create_args_parser().get_matches()?;

    if let Some(logfile_path) = cmd_args.value_of("display log") {
        init_log(logfile_path)?;
    }
    set_panic_hook();
    match real_main(&cmd_args) {
        Ok(()) => info!("EventLoop over, Vm exit"),
        Err(ref e) => {
            error!("{:?}", e);
        }
    }

    Ok(())
}

fn real_main(cmd_args: &arg_parser::ArgMatches) -> Result<()> {
    let fsconfig: FsConfig = create_fs_config(cmd_args)?;
    info!("FsConfig is {:?}", fsconfig);

    EventLoop::object_init(&None)?;

    let vhost_user_fs = Arc::new(Mutex::new(
        VhostUserFs::new(fsconfig).with_context(|| "Failed to create vhost use fs")?,
    ));
    EventLoop::set_manager(vhost_user_fs.clone(), None);

    vhost_user_fs
        .lock()
        .unwrap()
        .add_event_notifier()
        .with_context(|| "Failed to add event")?;

    EventLoop::loop_run().with_context(|| "EventLoop exits unexpectedly: error occurs")?;
    Ok(())
}

fn init_log(logfile_path: String) -> Result<()> {
    if logfile_path.is_empty() {
        logger::init_logger_with_env(Some(Box::new(std::io::stdout())))
            .with_context(|| "Failed to init logger")?;
    } else {
        let logfile = std::fs::OpenOptions::new()
            .read(false)
            .write(true)
            .append(true)
            .create(true)
            .mode(0o640)
            .open(logfile_path.clone())
            .with_context(|| format!("Failed to open log file {}", logfile_path))?;
        logger::init_logger_with_env(Some(Box::new(logfile)))
            .with_context(|| format!("Failed to init logger {}", logfile_path))?;
    }

    Ok(())
}

fn set_panic_hook() {
    std::panic::set_hook(Box::new(|panic_msg| {
        let panic_file = panic_msg.location().map_or("", |loc| loc.file());
        let panic_line = panic_msg.location().map_or(0, |loc| loc.line());
        if let Some(msg) = panic_msg.payload().downcast_ref::<&str>() {
            error!("Panic at [{}: {}]: {}.", panic_file, panic_line, msg);
        } else {
            error!("Panic at [{}: {}].", panic_file, panic_line);
        }
    }));
}
