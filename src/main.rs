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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use vmm_sys_util::terminal::Terminal;

use device_model::{balloon_allow_list, register_seccomp, syscall_allow_list, LightMachine};
use machine_manager::qmp::QmpChannel;
use machine_manager::socket::Socket;
use machine_manager::{
    cmdline::{check_api_channel, create_args_parser, create_vmconfig},
    event_loop::EventLoop,
    temp_cleaner::TempCleaner,
};
use machine_manager::{config::VmConfig, signal_handler::register_kill_signal};
use util::loop_context::EventNotifierHelper;
use util::unix::limit_permission;
use util::{arg_parser, daemonize::daemonize, logger};

error_chain! {
    links {
       Manager(machine_manager::errors::Error, machine_manager::errors::ErrorKind);
       Vm(device_model::errors::Error, device_model::errors::ErrorKind);
       Util(util::errors::Error, util::errors::ErrorKind);
    }
    foreign_links {
        Io(std::io::Error);
    }
}

quick_main!(run);

fn run() -> Result<()> {
    let cmd_args = create_args_parser().get_matches()?;

    if let Some(logfile_path) = cmd_args.value_of("display log") {
        if logfile_path.is_empty() {
            logger::init_logger_with_env(Some(Box::new(std::io::stdout())))
                .chain_err(|| "Failed to init logger.")?;
        } else {
            let logfile = std::fs::OpenOptions::new()
                .read(false)
                .write(true)
                .append(true)
                .create(true)
                .mode(0o640)
                .open(logfile_path)
                .chain_err(|| "Failed to open log file")?;
            logger::init_logger_with_env(Some(Box::new(logfile)))
                .chain_err(|| "Failed to init logger.")?;
        }
    }

    std::panic::set_hook(Box::new(|panic_msg| {
        std::io::stdin()
            .lock()
            .set_canon_mode()
            .expect("Failed to set terminal to canon mode.");

        let panic_file = panic_msg.location().map_or("", |loc| loc.file());
        let panic_line = panic_msg.location().map_or(0, |loc| loc.line());
        if let Some(msg) = panic_msg.payload().downcast_ref::<&str>() {
            error!("Panic at [{}: {}]: {}.", panic_file, panic_line, msg);
        } else {
            error!("Panic at [{}: {}].", panic_file, panic_line);
        }

        // clean temporary file
        TempCleaner::clean();
    }));

    let vm_config: VmConfig = create_vmconfig(&cmd_args)?;
    info!("VmConfig is {:?}", vm_config);

    match real_main(&cmd_args, vm_config) {
        Ok(()) => info!("MainLoop over, Vm exit"),
        Err(ref e) => {
            std::io::stdin()
                .lock()
                .set_canon_mode()
                .chain_err(|| "Failed to set terminal to canon mode.")?;
            if cmd_args.is_present("display log") {
                error!("{}", error_chain::ChainedError::display_chain(e));
            } else {
                write!(
                    &mut std::io::stderr(),
                    "{}",
                    error_chain::ChainedError::display_chain(e)
                )
                .expect("Failed to write to stderr");
            }
        }
    }

    // clean temporary file
    TempCleaner::clean();

    Ok(())
}

fn real_main(cmd_args: &arg_parser::ArgMatches, vm_config: VmConfig) -> Result<()> {
    let balloon_switch_on = vm_config.balloon.is_some();

    if cmd_args.is_present("daemonize") {
        match daemonize(cmd_args.value_of("pidfile")) {
            Ok(()) => info!("Daemonize mode start!"),
            Err(e) => error!("Daemonize start failed: {}", e),
        }
    } else {
        std::io::stdin()
            .lock()
            .set_raw_mode()
            .chain_err(|| "Failed to set terminal to raw mode.")?;
    }

    TempCleaner::object_init();
    QmpChannel::object_init();
    EventLoop::object_init(&vm_config.iothreads)?;
    register_kill_signal();

    let vm = LightMachine::new(vm_config)?;
    EventLoop::set_manager(vm.clone(), None);

    let api_socket = {
        let (api_path, _) = check_api_channel(&cmd_args)?;
        let listener = UnixListener::bind(&api_path)
            .chain_err(|| format!("Failed to bind api socket {}", &api_path))?;

        // add file to temporary pool, so it could be clean when vm exit.
        TempCleaner::add_path(api_path.clone());

        limit_permission(&api_path)
            .chain_err(|| format!("Failed to limit permission for api socket {}", &api_path))?;
        Socket::from_unix_listener(listener, Some(vm.clone()))
    };

    EventLoop::update_event(
        EventNotifierHelper::internal_notifiers(Arc::new(Mutex::new(api_socket))),
        None,
    )
    .chain_err(|| "Failed to add api event to MainLoop")?;

    vm.realize()?;
    vm.vm_start(cmd_args.is_present("freeze_cpu"))?;

    if !cmd_args.is_present("disable-seccomp") {
        let mut allow_list = syscall_allow_list();
        if balloon_switch_on {
            balloon_allow_list(&mut allow_list);
        }
        register_seccomp(allow_list)?;
    }

    EventLoop::loop_run().chain_err(|| "MainLoop exits unexpectedly: error occurs")?;

    Ok(())
}
