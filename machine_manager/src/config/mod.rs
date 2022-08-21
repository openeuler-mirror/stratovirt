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

pub mod errors {
    use error_chain::error_chain;

    error_chain! {
        links {
            Util(util::errors::Error, util::errors::ErrorKind);
        }
        foreign_links {
            JsonSerde(serde_json::Error);
        }
        errors {
            InvalidJsonField(field: String) {
                display("Invalid json field \'{}\'", field)
            }
            InvalidParam(param: String, name: String) {
                display("Invalid parameter \'{}\' for \'{}\'", param, name)
            }
            ConvertValueFailed(param: String, value: String) {
                display("Unable to parse \'{}\' for \'{}\'", value, param)
            }
            StringLengthTooLong(t: String, len: usize) {
                display("Input {} string's length must be no more than {}.", t, len)
            }
            FieldRepeat(param: String, field: String) {
                display("Input field \'{}\' in {} is offered more than once.", field, param)
            }
            IdRepeat(param: String, id: String) {
                display("Input id \'{}\' for {} repeat.", id, param)
            }
            IntegerOverflow(item: String) {
                display("Integer overflow occurred during parse {}!", item)
            }
            UnknownDeviceType(item: String) {
                display("Unknown device type: {}!", item)
            }
            FieldIsMissing(field: &'static str, device: &'static str) {
                display("\'{}\' is missing for \'{}\' device.", field, device)
            }
            IllegalValue(name: String, min: u64, min_include: bool, max: u64, max_include: bool) {
                display(
                    "{} must >{} {} and <{} {}.",
                    name,
                    if *min_include {"="} else {""},
                    min,
                    if *max_include {"="} else {""},
                    max
                )
            }
            MacFormatError {
                display("Mac address is illegal.")
            }
            UnknownVhostType {
                display("Unknown vhost type.")
            }
            UnRegularFile(t: String) {
                display("{} is not a regular File.", t)
            }
            Unaligned(param: String, value: u64, align: u64) {
                display("Input value {} is unaligned with {} for {}.", value, align, param)
            }
            UnitIdError(id: usize, max: usize){
                description("Check unit id of pflash device.")
                display("PFlash unit id given {} should not be more than {}", id, max)
            }
        }
    }
}

pub use self::errors::{ErrorKind, Result, ResultExt};
pub use balloon::*;
pub use boot_source::*;
pub use chardev::*;
pub use devices::*;
pub use drive::*;
pub use incoming::*;
pub use iothread::*;
pub use machine_config::*;
pub use network::*;
pub use numa::*;
pub use pci::*;
pub use rng::*;
pub use usb::*;
pub use vfio::*;

mod balloon;
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
mod usb;
mod vfio;

use std::any::Any;
use std::collections::HashMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use error_chain::bail;
use log::error;
#[cfg(target_arch = "aarch64")]
use util::device_tree::{self, FdtBuilder};
use util::trace::enable_trace_events;

pub const MAX_STRING_LENGTH: usize = 255;
pub const MAX_PATH_LENGTH: usize = 4096;
// FIXME: `queue_config` len in `VirtioPciState` struct needs to be modified together.
pub const MAX_VIRTIO_QUEUE: usize = 32;
pub const FAST_UNPLUG_ON: &str = "1";
pub const FAST_UNPLUG_OFF: &str = "0";
pub const MAX_NODES: u32 = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjConfig {
    Rng(RngObjConfig),
    Zone(MemZoneConfig),
}

fn parse_rng_obj(object_args: &str) -> Result<RngObjConfig> {
    let mut cmd_params = CmdParser::new("rng-object");
    cmd_params.push("").push("id").push("filename");

    cmd_params.parse(object_args)?;
    let id = if let Some(obj_id) = cmd_params.get_value::<String>("id")? {
        obj_id
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "rng-object").into());
    };
    let filename = if let Some(name) = cmd_params.get_value::<String>("filename")? {
        name
    } else {
        return Err(ErrorKind::FieldIsMissing("filename", "rng-object").into());
    };
    let rng_obj_cfg = RngObjConfig { id, filename };

    Ok(rng_obj_cfg)
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
    pub object: HashMap<String, ObjConfig>,
    pub pflashs: Option<Vec<PFlashConfig>>,
    pub dev_name: HashMap<String, u8>,
    pub global_config: HashMap<String, String>,
    pub numa_nodes: Vec<(String, String)>,
    pub incoming: Option<Incoming>,
}

impl VmConfig {
    /// Healthy check for `VmConfig`
    pub fn check_vmconfig(&self, is_daemonize: bool) -> Result<()> {
        self.boot_source.check()?;
        self.machine_config.check()?;

        if self.guest_name.len() > MAX_STRING_LENGTH {
            return Err(self::errors::ErrorKind::StringLengthTooLong(
                "name".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }
        if self.boot_source.kernel_file.is_none()
            && self.machine_config.mach_type == MachineType::MicroVm
        {
            bail!("kernel file is required for microvm machine type, which is not provided");
        }

        if self.boot_source.initrd.is_none() && self.drives.is_empty() {
            bail!("Before Vm start, set a initrd or drive_file as rootfs");
        }

        let mut stdio_count = 0;
        if let Some(serial) = self.serial.as_ref() {
            if serial.chardev.backend == ChardevType::Stdio {
                stdio_count += 1;
            }
        }
        for (_, char_dev) in self.chardev.clone() {
            if char_dev.backend == ChardevType::Stdio {
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
        let mut cmd_params = CmdParser::new("object");
        cmd_params.push("");

        cmd_params.get_parameters(object_args)?;
        let obj_type = cmd_params.get_value::<String>("")?;
        if obj_type.is_none() {
            bail!("Object type not specified");
        }
        let device_type = obj_type.unwrap();
        match device_type.as_str() {
            "iothread" => {
                self.add_iothread(object_args)
                    .chain_err(|| "Failed to add iothread")?;
            }
            "rng-random" => {
                let rng_cfg = parse_rng_obj(object_args)?;
                let id = rng_cfg.id.clone();
                let object_config = ObjConfig::Rng(rng_cfg);
                if self.object.get(&id).is_none() {
                    self.object.insert(id, object_config);
                } else {
                    bail!("Object: {} has been added", id);
                }
            }
            "memory-backend-ram" => {
                let zone_config = self.add_mem_zone(object_args)?;
                let id = zone_config.id.clone();
                let object_config = ObjConfig::Zone(zone_config);
                if self.object.get(&id).is_none() {
                    self.object.insert(id, object_config);
                } else {
                    bail!("Object: {} has been added", id);
                }
            }
            _ => {
                bail!("Unknow object type: {:?}", &device_type);
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
        let mut cmd_parser = CmdParser::new("global");
        cmd_parser.push("pcie-root-port.fast-unplug");
        cmd_parser.parse(global_config)?;

        if let Some(fast_unplug_value) =
            cmd_parser.get_value::<String>("pcie-root-port.fast-unplug")?
        {
            if fast_unplug_value != FAST_UNPLUG_ON && fast_unplug_value != FAST_UNPLUG_OFF {
                bail!("The value of fast-unplug is invalid: {}", fast_unplug_value);
            }
            let fast_unplug_key = String::from("pcie-root-port.fast-unplug");
            if self.global_config.get(&fast_unplug_key).is_none() {
                self.global_config
                    .insert(fast_unplug_key, fast_unplug_value);
            } else {
                bail!("Global config {} has been added", fast_unplug_key);
            }
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
impl device_tree::CompileFDT for VmConfig {
    fn generate_fdt_node(&self, _fdt: &mut FdtBuilder) -> util::errors::Result<()> {
        Ok(())
    }
}

/// This trait is to cast trait object to struct.
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// This trait is to check the legality of Config structure.
pub trait ConfigCheck: AsAny + Send + Sync {
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

/// Struct `CmdParser` used to parse and check cmdline parameters to vm config.
pub struct CmdParser {
    name: String,
    params: HashMap<String, Option<String>>,
}

impl CmdParser {
    /// Allocates an empty `CmdParser`.
    pub fn new(name: &str) -> Self {
        CmdParser {
            name: name.to_string(),
            params: HashMap::<String, Option<String>>::new(),
        }
    }

    /// Push a new param field into `params`.
    ///
    /// # Arguments
    ///
    /// * `param_field`: The cmdline parameter field name.
    pub fn push(&mut self, param_field: &str) -> &mut Self {
        self.params.insert(param_field.to_string(), None);

        self
    }

    /// Parse cmdline parameters string into `params`.
    ///
    /// # Arguments
    ///
    /// * `cmd_param`: The whole cmdline parameter string.
    pub fn parse(&mut self, cmd_param: &str) -> Result<()> {
        if cmd_param.starts_with(',') || cmd_param.ends_with(',') {
            return Err(ErrorKind::InvalidParam(cmd_param.to_string(), self.name.clone()).into());
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for (i, param_item) in param_items.iter().enumerate() {
            if param_item.starts_with('=') || param_item.ends_with('=') {
                return Err(
                    ErrorKind::InvalidParam(param_item.to_string(), self.name.clone()).into(),
                );
            }
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => {
                    if i == 0 {
                        ("", param[0])
                    } else {
                        (param[0], "")
                    }
                }
                2 => (param[0], param[1]),
                _ => {
                    return Err(
                        ErrorKind::InvalidParam(param_item.to_string(), self.name.clone()).into(),
                    );
                }
            };

            if self.params.contains_key(param_key) {
                let field_value = self.params.get_mut(param_key).unwrap();
                if field_value.is_none() {
                    *field_value = Some(String::from(param_value));
                } else {
                    return Err(
                        ErrorKind::FieldRepeat(self.name.clone(), param_key.to_string()).into(),
                    );
                }
            } else {
                return Err(
                    ErrorKind::InvalidParam(param[0].to_string(), self.name.clone()).into(),
                );
            }
        }

        Ok(())
    }

    /// Parse all cmdline parameters string into `params`.
    ///
    /// # Arguments
    ///
    /// * `cmd_param`: The whole cmdline parameter string.
    fn get_parameters(&mut self, cmd_param: &str) -> Result<()> {
        if cmd_param.starts_with(',') || cmd_param.ends_with(',') {
            return Err(ErrorKind::InvalidParam(cmd_param.to_string(), self.name.clone()).into());
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for param_item in param_items {
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => ("", param[0]),
                2 => (param[0], param[1]),
                _ => {
                    return Err(
                        ErrorKind::InvalidParam(param_item.to_string(), self.name.clone()).into(),
                    );
                }
            };

            if self.params.contains_key(param_key) {
                let field_value = self.params.get_mut(param_key).unwrap();
                if field_value.is_none() {
                    *field_value = Some(String::from(param_value));
                } else {
                    return Err(
                        ErrorKind::FieldRepeat(self.name.clone(), param_key.to_string()).into(),
                    );
                }
            }
        }

        Ok(())
    }

    /// Get cmdline parameters value from param field name.
    ///
    /// # Arguments
    ///
    /// * `param_field`: The cmdline parameter field name.
    pub fn get_value<T: FromStr>(&self, param_field: &str) -> Result<Option<T>> {
        match self.params.get(param_field) {
            Some(value) => {
                let field_msg = if param_field.is_empty() {
                    &self.name
                } else {
                    param_field
                };

                if let Some(raw_value) = value {
                    Ok(Some(raw_value.parse().map_err(|_| {
                        ErrorKind::ConvertValueFailed(field_msg.to_string(), raw_value.clone())
                    })?))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

/// This struct is a wrapper for `bool`.
/// More switch string can be transferred to this structure.
pub struct ExBool {
    inner: bool,
}

impl FromStr for ExBool {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "true" | "on" | "yes" => Ok(ExBool { inner: true }),
            "false" | "off" | "no" => Ok(ExBool { inner: false }),
            _ => Err(()),
        }
    }
}

impl From<ExBool> for bool {
    fn from(item: ExBool) -> Self {
        item.inner
    }
}

pub fn add_trace_events(config: &str) -> Result<()> {
    let mut cmd_parser = CmdParser::new("trace");
    cmd_parser.push("events");
    cmd_parser.get_parameters(config)?;

    if let Some(file) = cmd_parser.get_value::<String>("events")? {
        enable_trace_events(&file)?;
        return Ok(());
    }
    bail!("trace: events file must be set.");
}

pub struct IntegerList(pub Vec<u64>);

impl FromStr for IntegerList {
    type Err = ();

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
                return Err(());
            }

            let start = items[0]
                .parse::<u64>()
                .map_err(|_| error!("Invalid value {}", items[0]))?;
            integer_list.push(start);
            if items.len() == 2 {
                let end = items[1]
                    .parse::<u64>()
                    .map_err(|_| error!("Invalid value {}", items[1]))?;
                if start >= end {
                    return Err(());
                }

                for i in start..end {
                    integer_list.push(i + 1);
                }
            }
        }

        Ok(IntegerList(integer_list))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_parser() {
        let mut cmd_parser = CmdParser::new("test");
        cmd_parser
            .push("")
            .push("id")
            .push("path")
            .push("num")
            .push("test1")
            .push("test2")
            .push("test3")
            .push("test4")
            .push("test5")
            .push("test6")
            .push("test7");
        assert!(cmd_parser
            .parse("socket,id=charconsole0,path=/tmp/console.sock,num=1,test1=true,test2=on,test3=yes,test4=false,test5=off,test6=no,test7=random")
            .is_ok());
        assert_eq!(
            cmd_parser.get_value::<String>("").unwrap().unwrap(),
            "socket".to_string()
        );
        assert_eq!(
            cmd_parser.get_value::<String>("id").unwrap().unwrap(),
            "charconsole0".to_string()
        );
        assert_eq!(
            cmd_parser.get_value::<String>("path").unwrap().unwrap(),
            "/tmp/console.sock".to_string()
        );
        assert_eq!(cmd_parser.get_value::<u64>("num").unwrap().unwrap(), 1_u64);
        assert_eq!(cmd_parser.get_value::<u32>("num").unwrap().unwrap(), 1_u32);
        assert_eq!(cmd_parser.get_value::<u16>("num").unwrap().unwrap(), 1_u16);
        assert_eq!(cmd_parser.get_value::<u8>("num").unwrap().unwrap(), 1_u8);
        assert_eq!(cmd_parser.get_value::<i64>("num").unwrap().unwrap(), 1_i64);
        assert_eq!(cmd_parser.get_value::<i32>("num").unwrap().unwrap(), 1_i32);
        assert_eq!(cmd_parser.get_value::<i16>("num").unwrap().unwrap(), 1_i16);
        assert_eq!(cmd_parser.get_value::<i8>("num").unwrap().unwrap(), 1_i8);
        assert!(cmd_parser.get_value::<bool>("test1").unwrap().unwrap());
        assert!(
            cmd_parser
                .get_value::<ExBool>("test1")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            cmd_parser
                .get_value::<ExBool>("test2")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            cmd_parser
                .get_value::<ExBool>("test3")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(!cmd_parser.get_value::<bool>("test4").unwrap().unwrap());
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test4")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test5")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(
            !cmd_parser
                .get_value::<ExBool>("test6")
                .unwrap()
                .unwrap()
                .inner
        );
        assert!(cmd_parser.get_value::<bool>("test7").is_err());
        assert!(cmd_parser.get_value::<ExBool>("test7").is_err());
        assert!(cmd_parser.get_value::<String>("random").unwrap().is_none());
        assert!(cmd_parser.parse("random=false").is_err());
    }

    #[test]
    fn test_add_trace_events_01() {
        assert!(add_trace_events("event=test_trace_events").is_err());
        assert!(add_trace_events("events").is_err());
        assert!(add_trace_events("events=test_trace_events").is_err());
    }

    #[test]
    fn test_add_trace_events_02() {
        use std::fs::File;
        use std::io::Write;
        use util::trace::is_trace_event_enabled;

        let file = "/tmp/test_trace_events";
        let mut fd = File::create(file).unwrap();
        let event = "add_trace_events";
        fd.write(event.as_bytes()).unwrap();
        add_trace_events(format!("events={}", file).as_str()).unwrap();

        assert!(is_trace_event_enabled(event));
        std::fs::remove_file(file).unwrap();
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
}
