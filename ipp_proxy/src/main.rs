// Copyright (c) 2025 Huawei Technologies Co.,Ltd. All rights reserved.
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

mod proxy_client;

use std::{os::unix::net::UnixStream, process, sync::Arc};

use clap::Parser;
use libc::{EFD_NONBLOCK, EFD_SEMAPHORE};
use log::*;
use proxy_client::*;
use util::logger;
use vmm_sys_util::eventfd::EventFd;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "ipp-proxy",
    about = "IPP Proxy for virtual machines shared printers",
    args_override_self = true
)]
struct Opt {
    #[arg(long, short = 'D', default_value = "")]
    log_file: String,
    #[arg(long = "log-level", default_value = "info")]
    log_level: Level,
    #[arg(long = "state-socket", required = true)]
    state_socket_path: String,
    #[arg(long = "data-socket", required = true)]
    data_socket_path: String,
    #[arg(long = "spool-dir", required = true)]
    spool_dir: String,
}

fn initialize_logging(opt: &Opt) {
    let log_env_string = match opt.log_level {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    };
    std::env::set_var("STRATOVIRT_LOG_LEVEL", log_env_string);
    if let Err(e) = logger::init_log(opt.log_file.clone()) {
        println!("can't enable logger: {}", e);
    }
}

fn main() {
    let opt = Opt::parse();

    initialize_logging(&opt);

    let exit_evt = Arc::new(
        EventFd::new(EFD_NONBLOCK | EFD_SEMAPHORE).unwrap_or_else(|_| {
            error!("killevent create failed");
            process::exit(1);
        }),
    );

    // SAFETY: sets signal-handler via signal_hook crate. Just signal the exit_evt in handler.
    let _ = unsafe {
        let exit_evt = exit_evt.clone();
        signal_hook_registry::register(signal_hook::consts::SIGTERM, move || {
            exit_evt.write(0xffffffff).unwrap()
        })
    }
    .unwrap_or_else(|error| {
        error!("Error setup signals: {}", error);
        process::exit(1);
    });

    let proxy_state_stream = UnixStream::connect(&opt.state_socket_path).unwrap();
    let proxy_data_stream = UnixStream::connect(&opt.data_socket_path).unwrap();
    let mut proxy_client = ProxyClient::new(
        proxy_state_stream,
        proxy_data_stream,
        &opt.spool_dir,
        exit_evt,
    )
    .unwrap_or_else(|error| {
        error!("Error initializing proxy: {}", error);
        process::exit(1);
    });

    match proxy_client.run() {
        Ok(ret) => {
            info!("ProxyClient stopped with ret {:?}", ret);
        }
        Err(ref e) => {
            error!("Error at ProxyClient::run(): {e}");
            process::exit(1);
        }
    }
}
