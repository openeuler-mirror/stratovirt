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

use anyhow::{bail, Context, Result};
use log::{error, info};
use machine_manager::event_loop::EventLoop;
use machine_manager::signal_handler;
use machine_manager::temp_cleaner::TempCleaner;
use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use util::arg_parser::ArgMatches;
use util::{arg_parser, logger};
use vhost_user_fs::cmdline::{create_args_parser, create_fs_config, FsConfig};
use vhost_user_fs::sandbox::Sandbox;
use vhost_user_fs::securecomputing::{seccomp_filter, string_to_seccompopt, SeccompOpt};
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
            write!(&mut ::std::io::stderr(), "{}", format_args!("{:?}\r\n", e))
                .expect("Error writing to stderr");

            1
        }
    });
}

fn parse_capabilities(cmd_args: &arg_parser::ArgMatches) -> Result<HashSet<String>> {
    let mut add_caps = HashSet::new();

    add_caps.insert("CHOWN".to_string());
    add_caps.insert("DAC_OVERRIDE".to_string());
    add_caps.insert("FOWNER".to_string());
    add_caps.insert("FSETID".to_string());
    add_caps.insert("SETGID".to_string());
    add_caps.insert("SETUID".to_string());
    add_caps.insert("MKNOD".to_string());
    add_caps.insert("SETFCAP".to_string());

    if let Some(capabilities_str) = cmd_args.value_of("modcaps") {
        let cut = &capabilities_str;
        for s in cut.split(',').map(str::to_string) {
            if s.is_empty() {
                bail!("empty capability");
            }
            let (addorsub, capability_literal) = s.split_at(1);
            let capability = capability_literal.to_uppercase().to_string();
            if capng::name_to_capability(capability.as_str()).is_err() {
                bail!("invalid capability {}", s);
            }
            match addorsub {
                "+" => {
                    info!("add capability:{}", &capability);
                    add_caps.insert(capability);
                }
                "-" => {
                    info!("del capability:{}", &capability);
                    add_caps.remove(&capability);
                }
                _ => bail!("The first char before capability name must be + or - "),
            }
        }
    }
    Ok(add_caps)
}

fn run() -> Result<()> {
    let cmd_args = create_args_parser().get_matches()?;

    if let Some(logfile_path) = cmd_args.value_of("display log") {
        init_log(logfile_path)?;
    }
    signal_handler::register_kill_signal();
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
    TempCleaner::object_init();

    let mut fsconfig: FsConfig = create_fs_config(cmd_args)?;
    info!("FsConfig is {:?}", fsconfig);

    let source_dir = cmd_args.value_of("source dir").unwrap();
    let mut sandbox = Sandbox::new(source_dir);
    if let Some(sandbox_value) = cmd_args.value_of("sandbox") {
        match sandbox_value.as_str() {
            "chroot" => sandbox.enable_chroot(),
            "namespace" => sandbox.enable_namespace(),
            _ => Ok(()),
        }?;
    };
    if sandbox.proc_self_fd.is_some() {
        fsconfig.proc_dir_opt = sandbox.proc_self_fd;
    }

    if let Some(seccomp) = cmd_args.value_of("seccomp") {
        let seccomp_opt = string_to_seccompopt(seccomp);
        match seccomp_opt {
            SeccompOpt::Allow => {}
            _ => seccomp_filter(seccomp_opt).unwrap(),
        }
    }
    update_capabilities(cmd_args)?;
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

fn update_capabilities(cmd_args: &ArgMatches) -> Result<()> {
    let add = parse_capabilities(cmd_args)?;
    capng::clear(capng::Set::BOTH);
    if let Err(e) = capng::updatev(
        capng::Action::ADD,
        capng::Type::PERMITTED | capng::Type::EFFECTIVE,
        add.iter().map(String::as_str).collect(),
    ) {
        bail!("can't set up the child capabilities: {}", e);
    }
    if let Err(e) = capng::apply(capng::Set::BOTH) {
        bail!("can't apply the child capabilities: {}", e);
    }
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
        TempCleaner::clean();
        let panic_file = panic_msg.location().map_or("", |loc| loc.file());
        let panic_line = panic_msg.location().map_or(0, |loc| loc.line());
        if let Some(msg) = panic_msg.payload().downcast_ref::<&str>() {
            error!("Panic at [{}: {}]: {}.", panic_file, panic_line, msg);
        } else {
            error!("Panic at [{}: {}].", panic_file, panic_line);
        }
    }));
}
