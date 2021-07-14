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

use error_chain::bail;

use crate::{
    config::{MachineType, VmConfig},
    errors::{Result, ResultExt},
};
use util::arg_parser::{Arg, ArgMatches, ArgParser};
use util::unix::{parse_uri, UnixPath};

// Read the programe version in `Cargo.toml`.
const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");

/// This macro is to run struct $z 's function $s whose arg is $x 's inner member.
/// There is a multi-macro-cast in cases of vec and bool.
///
/// # Examples
///
/// ```text
/// add_args_to_config!(name, vm_cfg, update_name);
/// add_args_to_config!(name, vm_cfg, update_name, vec);
/// add_args_to_config!(name, vm_cfg, update_name, bool);
/// ```
macro_rules! add_args_to_config {
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
/// add_args_to_config_multi!(drive, vm_cfg, update_drive);
/// ```
macro_rules! add_args_to_config_multi {
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
            Arg::with_name("qmp")
                .long("qmp")
                .value_name("unix:socket_path")
                .help("set qmp's unixsocket path")
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
            Arg::with_name("incoming")
                .long("incoming")
                .help("wait for the URI to be specified via migrate_incoming")
                .value_name("incoming")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("balloon")
                .long("balloon")
                .value_name("[deflate_on_oom=bool]")
                .help("add balloon device")
                .can_no_value(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("object")
                .multiple(true)
                .long("object")
                .value_name("-object virtio-rng-device,rng=rng_name,max-bytes=1234,period=1000")
                .help("add object")
                .takes_values(true),
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

    // Parse cmdline args which need to set in VmConfig
    add_args_to_config!((args.value_of("name")), vm_cfg, add_name);
    add_args_to_config!((args.value_of("machine")), vm_cfg, add_machine);
    add_args_to_config!((args.value_of("memory")), vm_cfg, add_memory);
    add_args_to_config!((args.value_of("mem-path")), vm_cfg, add_mem_path);
    add_args_to_config!((args.value_of("smp")), vm_cfg, add_cpu);
    add_args_to_config!((args.value_of("kernel")), vm_cfg, add_kernel);
    add_args_to_config!((args.value_of("initrd-file")), vm_cfg, add_initrd);
    add_args_to_config!((args.value_of("serial")), vm_cfg, add_serial);
    add_args_to_config!((args.value_of("object")), vm_cfg, add_object);
    add_args_to_config!(
        (args.values_of("kernel-cmdline")),
        vm_cfg,
        add_kernel_cmdline,
        vec
    );
    add_args_to_config_multi!((args.values_of("drive")), vm_cfg, add_drive);
    add_args_to_config_multi!((args.values_of("netdev")), vm_cfg, add_netdev);
    add_args_to_config_multi!((args.values_of("chardev")), vm_cfg, add_chardev);
    add_args_to_config_multi!((args.values_of("iothread")), vm_cfg, add_iothread);
    add_args_to_config_multi!((args.values_of("device")), vm_cfg, add_devices);

    // Check the mini-set for Vm to start is ok
    if vm_cfg.machine_config.mach_type != MachineType::None {
        vm_cfg
            .check_vmconfig(args.is_present("daemonize"))
            .chain_err(|| "Precheck failed, VmConfig is unhealthy, stop running")?;
    }
    Ok(vm_cfg)
}

/// This function is to parse qmp socket path and type.
///
/// # Arguments
///
/// * `args` - The structure accepted input cmdline arguments.
///
/// # Errors
///
/// The value of `qmp` is illegel.
pub fn check_api_channel(args: &ArgMatches) -> Result<(String, UnixPath)> {
    if let Some(api) = args.value_of("qmp") {
        let (api_type, api_path) =
            parse_uri(&api).chain_err(|| "Failed to parse qmp socket path")?;
        Ok((api_path, api_type))
    } else {
        bail!("Please use \'-qmp\' to give a qmp path for Unix socket");
    }
}
