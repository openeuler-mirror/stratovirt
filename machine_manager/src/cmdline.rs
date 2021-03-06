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

use std::fs::File;
use std::io::Read;

use error_chain::bail;
use util::arg_parser::{Arg, ArgMatches, ArgParser};

use crate::{
    config::VmConfig,
    errors::{Result, ResultExt},
    socket::SocketType,
};

// Read the programe version in `Cargo.toml`.
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// This macro is to run struct $z 's function $s whose arg is $x 's inner member.
/// There is a multi-macro-cast in cases of vec and bool.
///
/// # Examples
///
/// ```text
/// update_args_to_config!(name, vm_cfg, update_name);
/// update_args_to_config!(name, vm_cfg, update_name, vec);
/// update_args_to_config!(name, vm_cfg, update_name, bool);
/// ```
macro_rules! update_args_to_config {
    ( $x:tt, $z:expr, $s:tt ) => {
        if let Some(temp) = &$x {
            $z.$s(temp)?;
        }
    };
    ( $x:tt, $z:expr, $s:tt, vec ) => {
        if let Some(temp) = &$x {
            $z.$s(&temp)
        }
    };
    ( $x:tt, $z:expr, $s:tt, bool ) => {
        if $x {
            $z.$s()
        }
    };
}

/// This macro is to run struct $z 's function $s whose arg is $x 's every inner
/// member.
///
/// # Examples
///
/// ```text
/// update_args_to_config_multi!(drive, vm_cfg, update_drive);
/// ```
macro_rules! update_args_to_config_multi {
    ( $x:tt, $z:expr, $s:tt ) => {
        if let Some(temps) = &$x {
            for temp in temps {
                $z.$s(temp)?;
            }
        }
    };
}

/// This function is to define all commandline arguments.
pub fn create_args_parser<'a>() -> ArgParser<'a> {
    ArgParser::new("StratoVirt")
        .version(VERSION.unwrap_or("unknown"))
        .author("Huawei Technologies Co., Ltd")
        .about("A light kvm-based hypervisor.")
        .arg(
            Arg::with_name("name")
                .long("name")
                .value_name("vm_name")
                .help("set the name of the guest.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("machine")
                .long("machine")
                .value_name("[type=]name[,dump_guest_core=on|off][,mem-share=on|off]")
                .help("selects emulated machine and set properties")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("smp")
                .long("smp")
                .value_name("[cpus=]n")
                .help("set the number of CPUs to 'n' (default: 1)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("memory")
                .long("m")
                .value_name("[size=]megs[m|M|g|G]")
                .help("configure guest RAM")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mem-path")
                .long("mem-path")
                .value_name("filebackend file path")
                .help("configure file path that backs guest memory.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config-file")
                .long("config")
                .value_name("json file path")
                .help("Sets a config file for vmm.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kernel")
                .long("kernel")
                .value_name("kernel_path")
                .help("use uncompressed kernel image")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kernel-cmdline")
                .multiple(true)
                .long("append")
                .value_name("kernel cmdline parameters")
                .help("use 'cmdline' as kernel command line")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("initrd-file")
                .long("initrd")
                .value_name("initrd_path")
                .help("use 'initrd-file' as initial ram disk")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api-channel")
                .long("api-channel")
                .value_name("unix:socket_path")
                .help("set api-channel's unixsocket path")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("drive")
                .multiple(true)
                .long("drive")
                .value_name("file=path,id=str[,readonly=][,direct=][,serial=][,iothread=][iops=]")
                .help("use 'file' as a drive image")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("netdev")
                .multiple(true)
                .long("netdev")
                .value_name(
                    "id=str,netdev=str[,mac=][,fds=][,vhost=on|off][,vhostfds=][,iothread=]",
                )
                .help("configure a host TAP network with ID 'str'")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("chardev")
                .multiple(true)
                .long("chardev")
                .value_name("id=str,path=socket_path")
                .help("set char device virtio console for vm")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("device")
                .multiple(true)
                .long("device")
                .value_name("vsock,id=str,guest-cid=u32[,vhostfd=]")
                .help("add virtio vsock device and sets properties")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("serial")
                .long("serial")
                .value_name("[stdio]")
                .help("add serial and set chardev [stdio] for it")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("display log")
                .long("D")
                .value_name("log path")
                .help("output log to logfile (default stderr)")
                .takes_value(true)
                .can_no_value(true),
        )
        .arg(
            Arg::with_name("pidfile")
                .long("pidfile")
                .value_name("pidfile path")
                .help("write PID to 'file'")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("daemonize")
                .long("daemonize")
                .help("daemonize StratoVirt after initializing")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("disable-seccomp")
                .long("disable-seccomp")
                .help("not use seccomp sandbox for StratoVirt")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("freeze_cpu")
                .short("S")
                .long("freeze")
                .help("Freeze CPU at startup")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("iothread")
                .multiple(true)
                .long("iothread")
                .value_name("id=str")
                .help("configure a iothread ID 'str'")
                .takes_values(true),
        )
        .arg(
            Arg::with_name("balloon")
                .long("balloon")
                .value_name("[deflate_on_oom=bool]")
                .help("add balloon device")
                .can_no_value(true)
                .takes_value(true),
        )
}

/// Create `VmConfig` from `ArgMatches`'s arg.
///
/// When accepted cmdline arguments, `StratoVirt` will parse useful arguments and
/// transform them to VM's configuration structure -- `VmConfig`.
///
/// # Arguments
///
/// - * `args` - The structure accepted input cmdline arguments.
///
/// # Errors
///
/// Input arguments is illegal for `VmConfig` or `VmConfig`'s health check
/// failed -- with this unhealthy `VmConfig`, VM will not boot successfully.
pub fn create_vmconfig(args: &ArgMatches) -> Result<VmConfig> {
    // Parse config-file json.
    // VmConfig can be transformed by json file which described VmConfig
    // directly.
    let mut vm_cfg = VmConfig::default();
    if let Some(config_file) = args.value_of("config-file") {
        let config_value = match File::open(&config_file) {
            Ok(mut f) => {
                let mut data = String::new();
                f.read_to_string(&mut data)
                    .chain_err(|| format!("Failed to read from file:{}", &config_file))?;
                if config_file.contains("json") {
                    serde_json::from_str(&data)?
                } else {
                    bail!("Only support \'json\' format config-file");
                }
            }
            Err(e) => {
                bail!("Failed to open config file by: {}", e);
            }
        };
        vm_cfg = VmConfig::create_from_value(config_value)
            .chain_err(|| "Failed to parse config file to VmConfig")?;
    }

    // Parse cmdline args which need to set in VmConfig
    update_args_to_config!((args.value_of("name")), vm_cfg, update_name);
    update_args_to_config!((args.value_of("machine")), vm_cfg, update_machine);
    update_args_to_config!((args.value_of("memory")), vm_cfg, update_memory);
    update_args_to_config!((args.value_of("mem-path")), vm_cfg, update_mem_path);
    update_args_to_config!((args.value_of("smp")), vm_cfg, update_cpu);
    update_args_to_config!((args.value_of("kernel")), vm_cfg, update_kernel);
    update_args_to_config!((args.value_of("initrd-file")), vm_cfg, update_initrd);
    update_args_to_config!((args.value_of("serial")), vm_cfg, update_serial);
    update_args_to_config!((args.value_of("balloon")), vm_cfg, update_balloon);
    update_args_to_config!(
        (args.values_of("kernel-cmdline")),
        vm_cfg,
        update_kernel_cmdline,
        vec
    );
    update_args_to_config_multi!((args.values_of("drive")), vm_cfg, update_drive);
    update_args_to_config_multi!((args.values_of("device")), vm_cfg, update_vsock);
    update_args_to_config_multi!((args.values_of("netdev")), vm_cfg, update_net);
    update_args_to_config_multi!((args.values_of("chardev")), vm_cfg, update_console);
    update_args_to_config_multi!((args.values_of("iothread")), vm_cfg, update_iothread);

    // Check the mini-set for Vm to start is ok
    vm_cfg
        .check_vmconfig(args.is_present("daemonize"))
        .chain_err(|| "Precheck failed, VmConfig is unhealthy, stop running")?;

    Ok(vm_cfg)
}

/// This function is to parse api-channel socket path and type.
///
/// # Arguments
///
/// * `args` - The structure accepted input cmdline arguments.
///
/// # Errors
///
/// The value of `api-channel` is illegel.
pub fn check_api_channel(args: &ArgMatches) -> Result<(String, SocketType)> {
    if let Some(api) = args.value_of("api-channel") {
        let (api_path, api_type) = parse_path(&api)
            .map(|(path, type_)| (path, type_))
            .chain_err(|| "Failed to parse api-channel socket path")?;
        Ok((api_path, api_type))
    } else {
        bail!("Please use \'-api-channel\' to give a api-channel path for Unix socket");
    }
}

/// This function is to parse a `String` to socket path string and socket type.
///
/// # Arguments
///
/// * `args_str` - The arguments `String` would be parsed.
///
/// # Errors
///
/// The arguments `String` is illegal.
fn parse_path(args_str: &str) -> Result<(String, SocketType)> {
    let arg: Vec<&str> = args_str.split(',').collect();
    let item = arg[0].to_string();
    let path_vec: Vec<&str> = item.split(':').collect();
    if path_vec.len() > 1 {
        if path_vec[0] == "unix" {
            let unix_path = String::from(path_vec[1]);
            Ok((unix_path, SocketType::Unix))
        } else {
            bail!("{} type is not support yet!", path_vec[0]);
        }
    } else {
        bail!("Failed to parse path: {}", args_str);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path() {
        let test_path = "unix:/tmp/stratovirt.sock";
        assert_eq!(
            parse_path(test_path).unwrap(),
            ("/tmp/stratovirt.sock".to_string(), SocketType::Unix)
        );

        let test_path = "unix:/tmp/stratovirt.sock,nowait,server";
        assert_eq!(
            parse_path(test_path).unwrap(),
            ("/tmp/stratovirt.sock".to_string(), SocketType::Unix)
        );

        let test_path = "tcp:127.0.0.1:8080,nowait,server";
        assert!(parse_path(test_path).is_err());

        let test_path = "file:/tmp/stratovirt-file";
        assert!(parse_path(test_path).is_err());
    }
}
