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

#[cfg(feature = "usb_camera")]
pub mod camera;
#[cfg(any(feature = "gtk", feature = "ohui_srv"))]
pub mod display;
pub mod error;
#[cfg(feature = "vnc")]
pub mod vnc;

mod boot_source;
mod chardev;
mod devices;
mod drive;
mod incoming;
mod iothread;
mod machine_config;
mod network;
mod numa;
mod pci;
mod rng;
#[cfg(feature = "vnc_auth")]
mod sasl_auth;
mod smbios;
#[cfg(feature = "vnc_auth")]
mod tls_creds;

pub use boot_source::*;
#[cfg(feature = "usb_camera")]
pub use camera::*;
pub use chardev::*;
#[cfg(any(feature = "gtk", feature = "ohui_srv"))]
pub use display::*;
pub use drive::*;
pub use error::ConfigError;
pub use incoming::*;
pub use iothread::*;
pub use machine_config::*;
pub use network::*;
pub use numa::*;
pub use pci::*;
pub use rng::*;
#[cfg(feature = "vnc_auth")]
pub use sasl_auth::*;
pub use smbios::*;
#[cfg(feature = "vnc_auth")]
pub use tls_creds::*;
#[cfg(feature = "vnc")]
pub use vnc::*;

use std::collections::HashMap;
use std::fs::{canonicalize, File};
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use log::error;
use serde::{Deserialize, Serialize};

use trace::{enable_state_by_type, set_state_by_pattern, TraceType};
#[cfg(target_arch = "aarch64")]
use util::device_tree::{self, FdtBuilder};
use util::{
    file::{get_file_alignment, open_file},
    num_ops::str_to_num,
    test_helper::is_test_enabled,
    AsAny,
};

pub const MAX_STRING_LENGTH: usize = 255;
pub const MAX_PATH_LENGTH: usize = 4096;
// Maximum length of the socket path is restricted by linux.
pub const MAX_SOCK_PATH_LENGTH: usize = 108;
// FIXME: `queue_config` len in `VirtioPciState` struct needs to be modified together.
pub const MAX_VIRTIO_QUEUE: usize = 32;
pub const FAST_UNPLUG_ON: &str = "1";
pub const FAST_UNPLUG_OFF: &str = "0";
pub const MAX_NODES: u32 = 128;
/// Default virtqueue size for virtio devices excepts virtio-fs.
pub const DEFAULT_VIRTQUEUE_SIZE: u16 = 256;
// Seg_max = queue_size - 2. So, size of each virtqueue for virtio-scsi/virtio-blk should be larger than 2.
pub const MIN_QUEUE_SIZE_BLOCK_DEVICE: u64 = 2;
// Max size of each virtqueue for virtio-scsi/virtio-blk.
pub const MAX_QUEUE_SIZE_BLOCK_DEVICE: u64 = 1024;
/// The bar0 size of enable_bar0 features
pub const VIRTIO_GPU_ENABLE_BAR0_SIZE: u64 = 64 * M;

#[derive(Parser)]
#[command(no_binary_name(true))]
struct GlobalConfig {
    #[arg(long, alias = "pcie-root-port.fast-unplug", value_parser = ["0", "1"])]
    fast_unplug: Option<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct ObjectConfig {
    pub rng_object: HashMap<String, RngObjConfig>,
    pub mem_object: HashMap<String, MemZoneConfig>,
    #[cfg(feature = "vnc_auth")]
    pub tls_object: HashMap<String, TlsCredObjConfig>,
    #[cfg(feature = "vnc_auth")]
    pub sasl_object: HashMap<String, SaslAuthObjConfig>,
}

/// This main config structure for Vm, contains Vm's basic configuration and devices.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct VmConfig {
    pub guest_name: String,
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: HashMap<String, DriveConfig>,
    pub netdevs: HashMap<String, NetDevcfg>,
    pub chardev: HashMap<String, ChardevConfig>,
    pub virtio_serial: Option<VirtioSerialInfo>,
    pub devices: Vec<(String, String)>,
    pub serial: Option<SerialConfig>,
    pub iothreads: Option<Vec<IothreadConfig>>,
    pub object: ObjectConfig,
    pub pflashs: Option<Vec<DriveConfig>>,
    pub dev_name: HashMap<String, u8>,
    pub global_config: HashMap<String, String>,
    pub numa_nodes: Vec<(String, String)>,
    pub incoming: Option<Incoming>,
    pub hardware_signature: Option<u32>,
    #[cfg(feature = "vnc")]
    pub vnc: Option<VncConfig>,
    #[cfg(any(feature = "gtk", all(target_env = "ohos", feature = "ohui_srv")))]
    pub display: Option<DisplayConfig>,
    #[cfg(feature = "usb_camera")]
    pub camera_backend: HashMap<String, CameraDevConfig>,
    #[cfg(feature = "windows_emu_pid")]
    pub emulator_pid: Option<String>,
    pub smbios: SmbiosConfig,
}

impl VmConfig {
    /// Healthy check for `VmConfig`
    pub fn check_vmconfig(&self, is_daemonize: bool) -> Result<()> {
        self.boot_source.check()?;
        self.machine_config.check()?;

        check_arg_too_long(&self.guest_name, "name")?;

        if self.boot_source.kernel_file.is_none()
            && self.machine_config.mach_type == MachineType::MicroVm
        {
            bail!("kernel file is required for microvm machine type, which is not provided");
        }

        if self.boot_source.initrd.is_none()
            && self.drives.is_empty()
            && self.chardev.is_empty()
            && !is_test_enabled()
        {
            bail!("Before Vm start, set a initrd or drive_file or vhost-user blk as rootfs");
        }

        let mut stdio_count = 0;
        if let Some(serial) = self.serial.as_ref() {
            if let ChardevType::Stdio { .. } = serial.chardev.classtype {
                stdio_count += 1;
            }
        }
        for (_, char_dev) in self.chardev.clone() {
            if let ChardevType::Stdio { .. } = char_dev.classtype {
                stdio_count += 1;
            }
        }
        if stdio_count > 0 && is_daemonize {
            bail!("Device redirected to stdio and daemonize can't be set together");
        }
        if stdio_count > 1 {
            bail!("Can't set multiple devices redirected to stdio");
        }

        Ok(())
    }

    /// Add argument `name` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name `String` updated to `VmConfig`.
    pub fn add_name(&mut self, name: &str) -> Result<()> {
        self.guest_name = name.to_string();
        Ok(())
    }

    /// Add argument `object` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `object_args` - The args of object.
    pub fn add_object(&mut self, object_args: &str) -> Result<()> {
        let object_type =
            get_class_type(object_args).with_context(|| "Object type not specified")?;
        match object_type.as_str() {
            "iothread" => {
                self.add_iothread(object_args)
                    .with_context(|| "Failed to add iothread")?;
            }
            "rng-random" => {
                let rng_cfg =
                    RngObjConfig::try_parse_from(str_slip_to_clap(object_args, true, false))?;
                let id = rng_cfg.id.clone();
                if self.object.rng_object.contains_key(&id) {
                    bail!("Object: {} has been added", id);
                }
                self.object.rng_object.insert(id, rng_cfg);
            }
            "memory-backend-ram" | "memory-backend-file" | "memory-backend-memfd" => {
                self.add_mem_zone(object_args)?;
            }
            #[cfg(feature = "vnc_auth")]
            "tls-creds-x509" => {
                self.add_tlscred(object_args)?;
            }
            #[cfg(feature = "vnc_auth")]
            "authz-simple" => {
                self.add_saslauth(object_args)?;
            }
            _ => {
                bail!("Unknow object type: {:?}", &object_type);
            }
        }

        Ok(())
    }

    /// Add argument `global` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `global_config` - The args of global config.
    pub fn add_global_config(&mut self, global_config: &str) -> Result<()> {
        let global_config =
            GlobalConfig::try_parse_from(str_slip_to_clap(global_config, false, false))?;

        if let Some(fast_unplug_value) = global_config.fast_unplug {
            let fast_unplug_key = String::from("pcie-root-port.fast-unplug");
            if self.global_config.contains_key(&fast_unplug_key) {
                bail!("Global config {} has been added", fast_unplug_key);
            }
            self.global_config
                .insert(fast_unplug_key, fast_unplug_value);
        }

        Ok(())
    }

    /// Add argument `windows_emu_pid` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `windows_emu_pid` - The args of windows_emu_pid.
    #[cfg(feature = "windows_emu_pid")]
    pub fn add_windows_emu_pid(&mut self, windows_emu_pid: &str) -> Result<()> {
        if windows_emu_pid.is_empty() {
            bail!("The arg of emulator_pid is empty!");
        }
        self.emulator_pid = Some(windows_emu_pid.to_string());
        Ok(())
    }

    /// Add a file to drive file store.
    pub fn add_drive_file(
        drive_files: &mut HashMap<String, DriveFile>,
        id: &str,
        path: &str,
        read_only: bool,
        direct: bool,
    ) -> Result<()> {
        if let Some(drive_file) = drive_files.get_mut(path) {
            if drive_file.read_only && read_only {
                // File can be shared with read_only.
                drive_file.count += 1;
                return Ok(());
            } else {
                return Err(anyhow!(
                    "Failed to add drive {}, file can only be shared with read_only. \
                    Is it used more than once or another process using the same file?",
                    path
                ));
            }
        }
        let file = open_file(path, read_only, direct)?;
        let (req_align, buf_align) = get_file_alignment(&file, direct);
        if req_align == 0 || buf_align == 0 {
            bail!(
                "Failed to detect alignment requirement of drive file {}.",
                path
            );
        }
        let drive_file = DriveFile {
            id: id.to_string(),
            file: Arc::new(file),
            count: 1,
            read_only,
            path: path.to_string(),
            locked: false,
            req_align,
            buf_align,
        };
        drive_files.insert(path.to_string(), drive_file);
        Ok(())
    }

    /// Remove a file from drive file store.
    pub fn remove_drive_file(
        drive_files: &mut HashMap<String, DriveFile>,
        path: &str,
    ) -> Result<()> {
        if let Some(drive_file) = drive_files.get_mut(path) {
            drive_file.count -= 1;
            if drive_file.count == 0 {
                drive_files.remove(path);
            }
        } else {
            return Err(anyhow!(
                "Failed to remove drive {}, it does not exist",
                path
            ));
        }
        Ok(())
    }

    /// Get a file from drive file store.
    pub fn fetch_drive_file(
        drive_files: &HashMap<String, DriveFile>,
        path: &str,
    ) -> Result<Arc<File>> {
        match drive_files.get(path) {
            Some(drive_file) => Ok(drive_file.file.clone()),
            None => Err(anyhow!("The file {} is not in drive backend", path)),
        }
    }

    /// Get drive id from drive file store.
    pub fn get_drive_id(drive_files: &HashMap<String, DriveFile>, path: &str) -> Result<String> {
        match drive_files.get(path) {
            Some(drive_file) => Ok(drive_file.id.clone()),
            None => Err(anyhow!("The file {} is not in drive backend", path)),
        }
    }

    /// Get alignment requirement from drive file store.
    pub fn fetch_drive_align(
        drive_files: &HashMap<String, DriveFile>,
        path: &str,
    ) -> Result<(u32, u32)> {
        match drive_files.get(path) {
            Some(drive_file) => Ok((drive_file.req_align, drive_file.buf_align)),
            None => Err(anyhow!("The file {} is not in drive backend", path)),
        }
    }

    /// Create initial drive file store from cmdline drive.
    pub fn init_drive_files(&self) -> Result<HashMap<String, DriveFile>> {
        let mut drive_files: HashMap<String, DriveFile> = HashMap::new();
        for drive in self.drives.values() {
            Self::add_drive_file(
                &mut drive_files,
                &drive.id,
                &drive.path_on_host,
                drive.readonly,
                drive.direct,
            )?;
        }
        if let Some(pflashs) = self.pflashs.as_ref() {
            for pflash in pflashs {
                Self::add_drive_file(
                    &mut drive_files,
                    "",
                    &pflash.path_on_host,
                    pflash.readonly,
                    false,
                )?;
            }
        }
        Ok(drive_files)
    }
}

#[cfg(target_arch = "aarch64")]
impl device_tree::CompileFDT for VmConfig {
    fn generate_fdt_node(&self, _fdt: &mut FdtBuilder) -> Result<()> {
        Ok(())
    }
}

/// This trait is to check the legality of Config structure.
pub trait ConfigCheck: AsAny + Send + Sync + std::fmt::Debug {
    /// To check the legality of Config structure.
    ///
    /// # Errors
    ///
    /// * `StringLengthTooLong` - Limit the length of String.
    /// * `NrcpusError` - Limit the number of vcpu in StratoVirt.
    /// * `MemsizeError` - Limit the size of memory in StratoVirt.
    /// * `GuestCidError` - Vsock guest-cid is illegel.
    /// * `MacFormatError` - Mac address is illegel.
    /// * `UnRegularFile` - File is illegel.
    fn check(&self) -> Result<()>;
}

/// This struct is a wrapper for `bool`.
/// More switch string can be transferred to this structure.
pub struct ExBool {
    inner: bool,
}

impl FromStr for ExBool {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "true" | "on" | "yes" | "unmap" => Ok(ExBool { inner: true }),
            "false" | "off" | "no" | "ignore" => Ok(ExBool { inner: false }),
            _ => Err(anyhow!("Unknown Exbool value {}", s)),
        }
    }
}

impl From<ExBool> for bool {
    fn from(item: ExBool) -> Self {
        item.inner
    }
}

pub fn parse_bool(s: &str) -> Result<bool> {
    match s {
        "true" | "on" | "yes" | "unmap" => Ok(true),
        "false" | "off" | "no" | "ignore" => Ok(false),
        _ => Err(anyhow!("Unknow bool value {s}")),
    }
}

fn enable_trace_state_from_file(path: &str) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("Failed to open {}", path))?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .with_context(|| format!("Failed to read {}", path))?;

    let state: Vec<&str> = buf.split('\n').filter(|&s| !s.is_empty()).collect();
    for s in state {
        set_state_by_pattern(s.trim().to_string(), true).with_context(|| {
            format!(
                "Unable to set the state of {} according to {}",
                s.trim(),
                path
            )
        })?;
    }
    Ok(())
}

fn enable_trace_state_from_type(type_str: &str) -> Result<()> {
    match type_str {
        "events" => enable_state_by_type(TraceType::Event)?,
        "scopes" => enable_state_by_type(TraceType::Scope)?,
        "all" => {
            enable_state_by_type(TraceType::Event)?;
            enable_state_by_type(TraceType::Scope)?;
        }
        _ => bail!("Unknown trace type {}", type_str),
    };

    Ok(())
}

#[derive(Parser)]
#[command(no_binary_name(true))]
struct TraceConfig {
    #[arg(long)]
    file: Option<String>,
    #[arg(long, alias = "type")]
    type_str: Option<String>,
}

pub fn add_trace(opt: &str) -> Result<()> {
    let trace_cfg = TraceConfig::try_parse_from(str_slip_to_clap(opt, false, false))?;
    if trace_cfg.type_str.is_none() && trace_cfg.file.is_none() {
        bail!("No type or file after -trace");
    }

    if let Some(type_str) = trace_cfg.type_str {
        enable_trace_state_from_type(&type_str)?;
    }
    if let Some(file) = trace_cfg.file {
        enable_trace_state_from_file(&file)?;
    }
    Ok(())
}

/// This struct is a wrapper for `usize`.
/// Hexadecimal string can be converted to integers by this structure method.
pub struct UnsignedInteger(pub usize);

impl FromStr for UnsignedInteger {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let value =
            str_to_num::<usize>(s).map_err(|e| error!("Invalid value {}, error is {:?}", s, e))?;
        Ok(UnsignedInteger(value))
    }
}

pub struct IntegerList(pub Vec<u64>);

impl FromStr for IntegerList {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut integer_list = Vec::new();
        let lists: Vec<&str> = s
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .split(':')
            .collect();
        for list in lists.iter() {
            let items: Vec<&str> = list.split('-').collect();
            if items.len() > 2 {
                return Err(anyhow!(
                    "{} parameters connected by -, should be no more than 2.",
                    items.len()
                ));
            }

            let start = items[0]
                .parse::<u64>()
                .map_err(|e| anyhow!("Invalid value {}, error is {:?}", items[0], e))?;
            integer_list.push(start);
            if items.len() == 2 {
                let end = items[1]
                    .parse::<u64>()
                    .map_err(|e| anyhow!("Invalid value {}, error is {:?}", items[1], e))?;
                if start >= end {
                    return Err(anyhow!("start {} is bigger than end {}.", start, end));
                }

                for i in start..end {
                    integer_list.push(i + 1);
                }
            }
        }

        Ok(IntegerList(integer_list))
    }
}

pub fn check_arg_too_long(arg: &str, name: &str) -> Result<()> {
    if arg.len() > MAX_STRING_LENGTH {
        bail!(ConfigError::StringLengthTooLong(
            name.to_string(),
            MAX_STRING_LENGTH
        ));
    }
    Ok(())
}

pub fn check_path_too_long(arg: &str, name: &str) -> Result<()> {
    if arg.len() > MAX_PATH_LENGTH {
        bail!(ConfigError::StringLengthTooLong(
            name.to_string(),
            MAX_PATH_LENGTH
        ));
    }
    Ok(())
}

/// Make sure args are existed.
///
///   arg_name: Name of arg.
///   arg_value: Value of arg. Should be Option<> class.
/// Eg:
///   check_arg_exist!(("id", id));
///   check_arg_exist!(("bus", bus), ("addr", addr));
#[macro_export]
macro_rules! check_arg_exist{
    ($(($arg_name:tt, $arg_value:expr)),*) => {
        $($arg_value.clone().with_context(|| format!("Should set {}.", $arg_name))?;)*
    }
}

/// Make sure args are existed.
///
///   arg_name: Name of arg.
///   arg_value: Value of arg. Should be Option<> class.
/// Eg:
///   check_arg_nonexist!(("id", id));
///   check_arg_nonexist!(("bus", bus), ("addr", addr));
#[macro_export]
macro_rules! check_arg_nonexist{
    ($(($arg_name:tt, $arg_value:expr)),*) => {
        $($arg_value.clone().map_or(Some(0), |_| None).with_context(|| format!("Should not set {}", $arg_name))?;)*
    }
}

fn concat_classtype(args: &str, concat: bool) -> String {
    if concat {
        format!("classtype={}", args)
    } else {
        args.to_string()
    }
}

/// Configure StratoVirt parameters in clap format.
///
/// The first parameter will be parsed as the `binary name` unless Command::no_binary_name is used when using `clap`.
/// Stratovirt command line may use the first parameter as class type.
/// Eg:
/// 1. drive config: "-drive file=<your file path>,if=pflash,unit=0"
///   This cmdline has no class type.
/// 2. device config: "-device virtio-balloon-pci,id=<balloon_id>,bus=<pcie.0>,addr=<0x4>"
///   This cmdline sets device type `virtio-balloon-pci` as the first parameter.
///
/// Use first_pos_is_type to indicate whether the first parameter is a type class which needs a separate analysis.
/// Eg:
/// 1. drive config: "-drive file=<your file path>,if=pflash,unit=0"
///   Set first_pos_is_type false for this cmdline has no class type.
/// 2. device config: "-device virtio-balloon-pci,id=<balloon_id>,bus=<pcie.0>,addr=<0x4>"
///   Set first_pos_is_type true for this cmdline has device type "virtio-balloon-pci" as the first parameter.
///
/// Use first_pos_is_subcommand to indicate whether the first parameter is a subclass.
/// Eg:
/// Chardev has stdio/unix-socket/tcp-socket/pty/file classes. These classes have different configurations but will be stored
/// in the same `ChardevConfig` structure by using `enum`. So, we will use class type as a subcommand to indicate which subtype
/// will be used to store the configuration in enumeration type. Subcommand in `clap` doesn't need `--` in parameter.
/// 1. -serial file,path=<file_path>
///   Set first_pos_is_subcommand true for first parameter `file` is the subclass type for chardev.
pub fn str_slip_to_clap(
    args: &str,
    first_pos_is_type: bool,
    first_pos_is_subcommand: bool,
) -> Vec<String> {
    let mut subcommand = first_pos_is_subcommand;
    let args_str = concat_classtype(args, first_pos_is_type && !subcommand);
    let args_vecs = args_str.split([',']).collect::<Vec<&str>>();
    let mut itr: Vec<String> = Vec::with_capacity(args_vecs.len() * 2);
    for params in args_vecs {
        let key_value = params.split(['=']).collect::<Vec<&str>>();
        // Command line like "key=value" will be converted to "--key value".
        // Command line like "key" will be converted to "--key".
        for (cnt, param) in key_value.iter().enumerate() {
            if cnt % 2 == 0 {
                if subcommand {
                    itr.push(param.to_string());
                    subcommand = false;
                } else {
                    itr.push(format!("--{}", param));
                }
            } else {
                itr.push(param.to_string());
            }
        }
    }
    itr
}

/// Retrieve the value of the specified parameter from a string in the format "key=value".
pub fn get_value_of_parameter(parameter: &str, args_str: &str) -> Result<String> {
    let args_vecs = args_str.split([',']).collect::<Vec<&str>>();

    for args in args_vecs {
        let key_value = args.split(['=']).collect::<Vec<&str>>();
        if key_value.len() != 2 || key_value[0] != parameter {
            continue;
        }
        if key_value[1].is_empty() {
            bail!("Find empty arg {} in string {}.", key_value[0], args_str);
        }
        return Ok(key_value[1].to_string());
    }

    bail!("Cannot find {}'s value from string {}", parameter, args_str);
}

pub fn get_class_type(args: &str) -> Result<String> {
    let args_str = concat_classtype(args, true);
    get_value_of_parameter("classtype", &args_str)
}

pub fn valid_id(id: &str) -> Result<String> {
    check_arg_too_long(id, "id")?;
    Ok(id.to_string())
}

// Virtio queue size must be power of 2 and in range [min_size, max_size].
pub fn valid_virtqueue_size(size: u64, min_size: u64, max_size: u64) -> Result<()> {
    if size < min_size || size > max_size {
        return Err(anyhow!(ConfigError::IllegalValue(
            "virtqueue size".to_string(),
            min_size,
            true,
            max_size,
            true
        )));
    }

    if size & (size - 1) != 0 {
        bail!("Virtqueue size should be power of 2!");
    }

    Ok(())
}

pub fn valid_path(path: &str) -> Result<String> {
    if path.len() > MAX_PATH_LENGTH {
        return Err(anyhow!(ConfigError::StringLengthTooLong(
            "path".to_string(),
            MAX_PATH_LENGTH,
        )));
    }

    let canonical_path = canonicalize(path).map_or(path.to_string(), |pathbuf| {
        String::from(pathbuf.to_str().unwrap())
    });

    Ok(canonical_path)
}

pub fn valid_socket_path(sock_path: &str) -> Result<String> {
    if sock_path.len() > MAX_SOCK_PATH_LENGTH {
        return Err(anyhow!(ConfigError::StringLengthTooLong(
            "socket path".to_string(),
            MAX_SOCK_PATH_LENGTH,
        )));
    }
    valid_path(sock_path)
}

pub fn valid_dir(d: &str) -> Result<String> {
    let dir = String::from(d);
    if !Path::new(&dir).is_dir() {
        return Err(anyhow!(ConfigError::DirNotExist(dir)));
    }
    Ok(dir)
}

pub fn valid_block_device_virtqueue_size(s: &str) -> Result<u16> {
    let size: u64 = s.parse()?;
    valid_virtqueue_size(
        size,
        MIN_QUEUE_SIZE_BLOCK_DEVICE + 1,
        MAX_QUEUE_SIZE_BLOCK_DEVICE,
    )?;

    Ok(size as u16)
}

pub fn parse_size(s: &str) -> Result<u64> {
    let size = memory_unit_conversion(s, M).with_context(|| format!("Invalid size: {}", s))?;
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_trace() {
        assert!(std::fs::File::create("/tmp/trace_file").is_ok());

        assert!(add_trace("file=/tmp/trace_file,type=all").is_ok());
        assert!(add_trace("fil=test_trace").is_err());
        assert!(add_trace("file").is_err());
        assert!(add_trace("file=test_trace").is_err());

        assert!(add_trace("type=events").is_ok());
        assert!(add_trace("type=scopes").is_ok());
        assert!(add_trace("type=all").is_ok());
        assert!(add_trace("type=xxxxx").is_err());

        assert!(add_trace("").is_err());
        assert!(add_trace("file=/tmp/trace_file,type=all").is_ok());

        assert!(std::fs::remove_file("/tmp/trace_file").is_ok());
    }

    #[test]
    fn test_add_global_config() {
        let mut vm_config = VmConfig::default();
        vm_config
            .add_global_config("pcie-root-port.fast-unplug=1")
            .unwrap();
        let fast_unplug = vm_config.global_config.get("pcie-root-port.fast-unplug");
        assert!(fast_unplug.is_some());
        assert_eq!(fast_unplug.unwrap(), FAST_UNPLUG_ON);

        let mut vm_config = VmConfig::default();
        vm_config
            .add_global_config("pcie-root-port.fast-unplug=0")
            .unwrap();
        let fast_unplug = vm_config.global_config.get("pcie-root-port.fast-unplug");
        assert!(fast_unplug.is_some());
        assert_eq!(fast_unplug.unwrap(), FAST_UNPLUG_OFF);

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug");
        assert!(res.is_err());

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=2");
        assert!(res.is_err());

        let mut vm_config = VmConfig::default();
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=0");
        assert!(res.is_ok());
        let res = vm_config.add_global_config("pcie-root-port.fast-unplug=1");
        assert!(res.is_err());
    }

    #[test]
    fn test_get_value_of_parameter() {
        let cmd = "scsi-hd,id=disk1,drive=scsi-drive-0";
        let id = get_value_of_parameter("id", cmd).unwrap();
        assert_eq!(id, "disk1");

        let cmd = "id=";
        assert!(get_value_of_parameter("id", cmd).is_err());

        let cmd = "id";
        assert!(get_value_of_parameter("id", cmd).is_err());

        let cmd = "scsi-hd,idxxx=disk1";
        assert!(get_value_of_parameter("id", cmd).is_err());
    }
}
