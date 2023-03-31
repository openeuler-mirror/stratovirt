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

use std::os::unix::net::UnixListener;

use anyhow::{bail, Context, Result};
use util::arg_parser::{Arg, ArgMatches, ArgParser};
use util::unix::{limit_permission, parse_unix_uri};

use crate::{
    config::{add_trace_events, ChardevType, CmdParser, MachineType, VmConfig},
    temp_cleaner::TempCleaner,
};

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
        if ($x) {
            $z.$s();
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
        .author("The StratoVirt Project Developers")
        .about("A light kvm-based hypervisor.")
        .arg(
            Arg::with_name("name")
            .long("name")
            .value_name("[vm_name]")
            .help("set the name of the guest.")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("machine")
            .long("machine")
            .value_name("[type=]<name>[,dump_guest_core=on|off][,mem-share=on|off]")
            .help("'type' selects emulated machine type and set properties. \
                   'dump_guest_core' includes guest memory in a core dump. \
                   'mem-share' sets guest memory is shareable.")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("accel")
            .long("accel")
            .value_name("[accel]")
            .help("select accelerator, only 'kvm' is supported now.")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("smp")
            .long("smp")
            .value_name("[cpus=]<n>[,maxcpus=<cpus>][,sockets=<sockets>][,dies=<dies>][,clusters=<clusters>][,cores=<cores>][,threads=<threads>]")
            .help("'cpus' sets the number of CPUs to 'n' (default: 1). 'maxcpus' sets number of total CPUs, including online and offline CPUs. \
                   'sockets' is the number of sockets on the machine. \
                   'dies' is the number of dies in one socket. \
                   'clusters' is the number of clusters in one die. \
                   'cores' is the number of cores in one cluster. \
                   'threads' is the number of threads in one core")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("cpu")
            .long("cpu")
            .value_name("host[,pmu=on|off]")
            .help("set CPU model and features.")
            .can_no_value(false)
            .takes_value(true)
        )
        .arg(
            Arg::with_name("freeze_cpu")
            .short("S")
            .long("freeze")
            .help("freeze CPU at startup")
            .takes_value(false)
            .required(false),
        )
        .arg(
            Arg::with_name("memory")
            .long("m")
            .value_name("[size=]<megs>[m|M|g|G]")
            .help("configure guest RAM(default unit: MiB).")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("mem-path")
            .long("mem-path")
            .value_name("<filebackend file path>")
            .help("configure file path that backs guest memory.")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("mem-prealloc")
            .long("mem-prealloc")
            .help("Prealloc memory for VM")
            .takes_value(false)
            .required(false),
        )
        .arg(
            Arg::with_name("numa")
            .multiple(true)
            .long("numa")
            .value_name("<parameters>")
            .help("\n\t\tset numa node: -numa node,nodeid=<0>,cpus=<0-1>,memdev=<mem0>; \
                   \n\t\tset numa distance: -numa dist,src=<0>,dst=<1>,val=<20> ")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("kernel")
            .long("kernel")
            .value_name("<kernel_path>")
            .help("use uncompressed kernel image")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("kernel-cmdline")
            .multiple(true)
            .long("append")
            .value_name("<kernel cmdline parameters>")
            .help("use 'cmdline' as kernel command line")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("initrd-file")
            .long("initrd")
            .value_name("<initrd_path>")
            .help("use 'initrd-file' as initial ram disk")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("qmp")
            .long("qmp")
            .value_name("unix:<socket_path>")
            .help("set QMP's unix socket path")
            .takes_value(true)
        )
        .arg(
            Arg::with_name("mod-test")
            .long("mod-test")
            .value_name("unix:socket_path")
            .help("set module test's unixsocket path")
            .takes_value(true)
        )
        .arg(
            Arg::with_name("drive")
            .multiple(true)
            .long("drive")
            .value_name("<parameters>")
            .help("\n\t\tset block drive image: -drive id=<drive_id>,file=<path_on_host>[,readonly=on|off][,direct=on|off][,throttling.iops-total=<200>]; \
                   \n\t\tset pflash drive image: -drive file=<pflash_path>,if=pflash,unit=0|1[,readonly=true|false]; \
                   \n\t\tset scsi drive image: -drive id=<drive-scsi0-0-0-0>,file=<path_on_host>[,readonly=true|false]")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("netdev")
            .multiple(true)
            .long("netdev")
            .value_name(
                "tap,id=<str>,ifname=<tap_name>[,vhost=on|off][,queue=<N>]",
            )
            .help("configure a host TAP network with ID 'str'")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("chardev")
            .multiple(true)
            .long("chardev")
            .value_name("socket,id=<str>,path=<socket_path>")
            .help("set char device virtio console for vm")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("device")
            .multiple(true)
            .long("device")
            .value_name("<parameters>")
            .help("\n\t\tadd virtio mmio block: -device virtio-blk-device,id=<blk_id>,drive=<drive_id>[,iothread=<iothread1>][,serial=<serial_num>]; \
                   \n\t\tadd virtio pci block: -device virtio-blk-pci,id=<blk_id>,drive=<drive_id>,bus=<pcie.0>,addr=<0x3>[,multifunction=on|off][,iothread=<iothread1>][,serial=<serial_num>][,num-queues=<N>][,bootindex=<N>]; \
                   \n\t\tadd vhost user pci block: -device vhost-user-blk-pci,id=<blk_id>,chardev=<chardev_id>,bus=<pcie.0>,addr=<0x3>[,num-queues=<N>][,bootindex=<N>]; \
                   \n\t\tadd virtio mmio net: -device virtio-net-device,id=<net_id>,netdev=<netdev_id>[,iothread=<iothread1>][,mac=<12:34:56:78:9A:BC>]; \
                   \n\t\tadd virtio pci net: -device virtio-net-pci,id=<net_id>,netdev=<netdev_id>,bus=<pcie.0>,addr=<0x2>[,multifunction=on|off][,iothread=<iothread1>][,mac=<12:34:56:78:9A:BC>][,mq=on|off]; \
                   \n\t\tadd vhost mmio net: -device virtio-net-device,id=<net_id>,netdev=<netdev_id>[,iothread=<iothread1>][,mac=<12:34:56:78:9A:BC>]; \
                   \n\t\tadd vhost pci net: -device virtio-net-pci,id=<net_id>,netdev=<netdev_id>,bus=<pcie.0>,addr=<0x2>[,multifunction=on|off][,iothread=<iothread1>][,mac=<12:34:56:78:9A:BC>][,mq=on|off]; \
                   \n\t\tadd virtio mmio console: -device virtio-serial-device[,id=<virtio-serial0>] -device virtconsole,id=console_id,chardev=<virtioconsole1>; \
                   \n\t\tadd virtio pci console: -device virtio-serial-pci,id=<virtio-serial0>,bus=<pcie.0>,addr=<0x3>[,multifunction=on|off] -device virtconsole,id=<console_id>,chardev=<virtioconsole1>; \
                   \n\t\tadd vhost mmio vsock: -device vhost-vsock-device,id=<vsock_id>,guest-cid=<N>; \
                   \n\t\tadd vhost pci vsock: -device vhost-vsock-pci,id=<vsock_id>,guest-cid=<N>,bus=<pcie.0>,addr=<0x3>[,multifunction=on|off]; \
                   \n\t\tadd virtio mmio balloon: -device virtio-balloon-device[,deflate-on-oom=true|false][,free-page-reporting=true|false]; \
                   \n\t\tadd virtio pci balloon: -device virtio-balloon-pci,id=<balloon_id>,bus=<pcie.0>,addr=<0x4>[,deflate-on-oom=true|false][,free-page-reporting=true|false][,multifunction=on|off]; \
                   \n\t\tadd virtio mmio rng: -device virtio-rng-device,rng=<objrng0>,max-bytes=<1234>,period=<1000>; \
                   \n\t\tadd virtio pci rng: -device virtio-rng-pci,id=<rng_id>,rng=<objrng0>,max-bytes=<1234>,period=<1000>,bus=<pcie.0>,addr=<0x1>[,multifunction=on|off]; \
                   \n\t\tadd pcie root port: -device pcie-root-port,id=<pcie.1>,port=<0x1>,bus=<pcie.0>,addr=<0x1>[,multifunction=on|off]; \
                   \n\t\tadd vfio pci: -device vfio-pci,id=<vfio_id>,host=<0000:1a:00.3>,bus=<pcie.0>,addr=<0x03>[,multifunction=on|off]; \
                   \n\t\tadd usb controller: -device nec-usb-xhci,id=<xhci>,bus=<pcie.0>,addr=<0xa>; \
                   \n\t\tadd usb keyboard: -device usb-kbd,id=<kbd>; \
                   \n\t\tadd usb tablet: -device usb-tablet,id=<tablet>; \
                   \n\t\tadd usb storage: -device usb-storage,id=<storage>,drive=<drive_id>; \
                   \n\t\tadd scsi controller: -device virtio-scsi-pci,id=<scsi_id>,bus=<pcie.0>,addr=<0x3>[,multifunction=on|off][,iothread=<iothread1>][,num-queues=<N>]; \
                   \n\t\tadd scsi hard disk: -device scsi-hd,scsi-id=<0>,bus=<scsi0.0>,lun=<0>,drive=<drive-scsi0-0-0-0>,id=<scsi0-0-0-0>; \
                   \n\t\tadd vhost user fs: -device vhost-user-fs-pci,id=<device_id>,chardev=<chardev_id>,tag=<mount_tag>")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("serial")
            .long("serial")
            .value_name("backend[,path=<str>,server,nowait] or chardev:<char_id>")
            .help("add serial and set chardev for it")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("display log")
            .long("D")
            .value_name("[log path]")
            .help("output log to logfile (default stderr)")
            .takes_value(true)
            .can_no_value(true),
        )
        .arg(
            Arg::with_name("pidfile")
            .long("pidfile")
            .value_name("<pidfile path>")
            .help("write PID to 'file'")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("daemonize")
            .long("daemonize")
            .value_name("")
            .help("daemonize StratoVirt after initializing")
            .takes_value(false)
            .required(false),
        )
        .arg(
            Arg::with_name("disable-seccomp")
            .long("disable-seccomp")
            .value_name("")
            .help("not use seccomp sandbox for StratoVirt")
            .takes_value(false)
            .required(false),
        )
        .arg(
            Arg::with_name("incoming")
            .long("incoming")
            .value_name("<parameters>")
            .help("\n\t\tdo the migration using tcp socket: -incoming tcp:<ip>:<port>; \
                   \n\t\tdo the migration using unix socket: -incoming unix:<socket path>; \
                   \n\t\tdo the virtual machine snapshot: -incoming file:<file path>")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("object")
            .multiple(true)
            .long("object")
            .value_name("<parameters>")
            .help("\n\t\tadd memory backend ram object: -object memory-backend-ram,id=<memid>,size=<2G>,host-nodes=<0-1>,policy=<bind>; \
                   \n\t\tadd iothread object: -object iothread,id=<iothread_id>; \
                   \n\t\tadd rng object: -object rng-random,id=<rng_id>,filename=<file_path>; \
                   \n\t\tadd vnc tls object: -object tls-creds-x509,id=<vnc_id>,dir=</etc/pki/vnc>; \
                   \n\t\tadd authz object: -object authz-simple,id=<authz_id>,identity=<username>")
            .takes_values(true),
        )
        .arg(
            Arg::with_name("mon")
            .long("mon")
            .value_name("chardev=<chardev_id>,id=<mon_id>[,mode=control]")
            .help("-mon is another way to create qmp channel. To use it, the chardev should be specified")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("overcommit")
            .long("overcommit")
            .value_name("[mem-lock=off]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("uuid")
            .long("uuid")
            .value_name("[uuid]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("no-user-config")
            .long("no-user-config")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("nodefaults")
            .long("nodefaults")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("sandbox")
            .long("sandbox")
            .value_name("[on,obsolete=deny]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("msg")
            .long("msg")
            .value_name("[timestamp=on]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("rtc")
            .long("rtc")
            .value_name("[base=utc]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("no-shutdown")
            .long("no-shutdown")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("boot")
            .long("boot")
            .value_name("[strict=on]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("nographic")
            .long("nographic")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("realtime")
            .long("realtime")
            .value_name("[malock=off]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("display")
            .long("display")
            .value_name("[none]")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("usb")
            .long("usb")
            .hidden(true)
            .can_no_value(true)
            .takes_value(true),
        )
        .arg(
            Arg::with_name("trace")
            .multiple(false)
            .long("trace")
            .value_name("events=<file>")
            .help("specify the file lists trace events to enable")
            .takes_value(true),
        )
        .arg(
            Arg::with_name("global")
            .multiple(true)
            .long("global")
            .value_name("[key=<value>]")
            .help("set global config")
            .takes_values(true)
            .required(false),
        )
        .arg(
            Arg::with_name("vnc")
            .multiple(false)
            .long("vnc")
            .value_name("ip:port")
            .help("specify the ip and port for vnc")
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

    // Parse cmdline args which need to set in VmConfig
    add_args_to_config!((args.value_of("name")), vm_cfg, add_name);
    add_args_to_config!((args.value_of("machine")), vm_cfg, add_machine);
    add_args_to_config!((args.value_of("accel")), vm_cfg, add_accel);
    add_args_to_config!((args.value_of("memory")), vm_cfg, add_memory);
    add_args_to_config!((args.value_of("mem-path")), vm_cfg, add_mem_path);
    add_args_to_config!((args.value_of("smp")), vm_cfg, add_cpu);
    add_args_to_config!((args.value_of("cpu")), vm_cfg, add_cpu_feature);
    add_args_to_config!((args.value_of("kernel")), vm_cfg, add_kernel);
    add_args_to_config!((args.value_of("initrd-file")), vm_cfg, add_initrd);
    add_args_to_config!((args.value_of("serial")), vm_cfg, add_serial);
    add_args_to_config!((args.value_of("incoming")), vm_cfg, add_incoming);
    add_args_to_config!((args.value_of("vnc")), vm_cfg, add_vnc);
    add_args_to_config!(
        (args.is_present("no-shutdown")),
        vm_cfg,
        add_no_shutdown,
        bool
    );
    add_args_to_config!(
        (args.is_present("mem-prealloc")),
        vm_cfg,
        enable_mem_prealloc,
        bool
    );
    add_args_to_config!(
        (args.values_of("kernel-cmdline")),
        vm_cfg,
        add_kernel_cmdline,
        vec
    );
    add_args_to_config_multi!((args.values_of("drive")), vm_cfg, add_drive);
    add_args_to_config_multi!((args.values_of("object")), vm_cfg, add_object);
    add_args_to_config_multi!((args.values_of("netdev")), vm_cfg, add_netdev);
    add_args_to_config_multi!((args.values_of("chardev")), vm_cfg, add_chardev);
    add_args_to_config_multi!((args.values_of("device")), vm_cfg, add_device);
    add_args_to_config_multi!((args.values_of("global")), vm_cfg, add_global_config);
    add_args_to_config_multi!((args.values_of("numa")), vm_cfg, add_numa);

    if let Some(s) = args.value_of("trace") {
        add_trace_events(&s)?;
    }

    // Check the mini-set for Vm to start is ok
    if vm_cfg.machine_config.mach_type != MachineType::None {
        vm_cfg
            .check_vmconfig(args.is_present("daemonize"))
            .with_context(|| "Precheck failed, VmConfig is unhealthy, stop running")?;
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
pub fn check_api_channel(args: &ArgMatches, vm_config: &mut VmConfig) -> Result<Vec<UnixListener>> {
    let mut sock_paths = Vec::new();
    if let Some(qmp_config) = args.value_of("qmp") {
        let mut cmd_parser = CmdParser::new("qmp");
        cmd_parser.push("").push("server").push("nowait");

        cmd_parser.parse(&qmp_config)?;
        if let Some(uri) = cmd_parser.get_value::<String>("")? {
            let api_path =
                parse_unix_uri(&uri).with_context(|| "Failed to parse qmp socket path")?;
            sock_paths.push(api_path);
        } else {
            bail!("No uri found for qmp");
        }
        if cmd_parser.get_value::<String>("server")?.is_none() {
            bail!("Argument \'server\' is needed for qmp");
        }
        if cmd_parser.get_value::<String>("nowait")?.is_none() {
            bail!("Argument \'nowait\' is needed for qmp");
        }
    }
    if let Some(mon_config) = args.value_of("mon") {
        let mut cmd_parser = CmdParser::new("monitor");
        cmd_parser.push("id").push("mode").push("chardev");

        cmd_parser.parse(&mon_config)?;

        let chardev = if let Some(dev) = cmd_parser.get_value::<String>("chardev")? {
            dev
        } else {
            bail!("Argument \'chardev\'  is missing for \'mon\'");
        };

        if let Some(mode) = cmd_parser.get_value::<String>("mode")? {
            if mode != *"control" {
                bail!("Invalid \'mode\' parameter: {:?} for monitor", &mode);
            }
        } else {
            bail!("Argument \'mode\' of \'mon\' should be set to \'control\'.");
        }

        if let Some(cfg) = vm_config.chardev.remove(&chardev) {
            if let ChardevType::Socket {
                path,
                server,
                nowait,
            } = cfg.backend
            {
                if !server || !nowait {
                    bail!(
                        "Argument \'server\' and \'nowait\' are both required for chardev \'{}\'",
                        path
                    );
                }
                sock_paths.push(path);
            } else {
                bail!("Only socket-type of chardev can be used for monitor");
            }
        } else {
            bail!("No chardev found: {}", &chardev);
        }
    }

    if sock_paths.is_empty() {
        bail!("Please use \'-qmp\' or \'-mon\' to give a qmp path for Unix socket");
    }
    let mut listeners = Vec::new();
    for path in sock_paths {
        listeners.push(
            bind_socket(path.clone())
                .with_context(|| format!("Failed to bind socket for path: {:?}", &path))?,
        )
    }

    Ok(listeners)
}

fn bind_socket(path: String) -> Result<UnixListener> {
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("Failed to bind socket file {}", &path))?;
    // Add file to temporary pool, so it could be cleaned when vm exits.
    TempCleaner::add_path(path.clone());
    limit_permission(&path)
        .with_context(|| format!("Failed to limit permission for socket file {}", &path))?;
    Ok(listener)
}
