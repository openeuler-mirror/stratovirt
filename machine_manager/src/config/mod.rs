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

extern crate serde;
extern crate serde_json;

mod balloon;
mod boot_source;
mod chardev;
mod devices;
mod fs;
mod iothread;
mod machine_config;
mod network;
mod pci;
mod pflash;
mod rng;

use std::any::Any;
use std::collections::HashMap;
use std::str::FromStr;

#[cfg(target_arch = "aarch64")]
use util::device_tree;

pub use self::errors::{ErrorKind, Result};
pub use balloon::*;
pub use boot_source::*;
pub use chardev::*;
pub use devices::*;
pub use fs::*;
pub use iothread::*;
pub use machine_config::*;
pub use network::*;
pub use pci::*;
pub use pflash::*;
pub use rng::*;

pub mod errors {
    error_chain! {
        foreign_links {
            JsonSerde(serde_json::Error);
        }
        errors {
            InvalidJsonField(field: String) {
                display("Invalid json field \'{}\'", field)
            }
            InvalidParam(param: String) {
                display("Invalid parameter \'{}\'", param)
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

pub const MAX_STRING_LENGTH: usize = 255;

/// This main config structure for Vm, contains Vm's basic configuration and devices.
#[derive(Clone, Default, Debug)]
pub struct VmConfig {
    pub guest_name: String,
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: Option<Vec<DriveConfig>>,
    pub nets: Option<Vec<NetworkInterfaceConfig>>,
    pub consoles: Option<Vec<ConsoleConfig>>,
    pub devices: Vec<(String, String)>,
    pub serial: Option<SerialConfig>,
    pub iothreads: Option<Vec<IothreadConfig>>,
    pub balloon: Option<BalloonConfig>,
    pub rng: Option<RngConfig>,
    pub pflashs: Option<Vec<PFlashConfig>>,
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

        if self.drives.is_some() {
            for drive in self.drives.as_ref().unwrap() {
                drive.check()?;
            }
        }

        if self.nets.is_some() {
            for net in self.nets.as_ref().unwrap() {
                net.check()?;
            }
        }

        if self.consoles.is_some() {
            for console in self.consoles.as_ref().unwrap() {
                console.check()?;
            }
        }

        if self.rng.is_some() {
            self.rng.as_ref().unwrap().check()?;
        }

        if self.boot_source.initrd.is_none() && self.drives.is_none() {
            bail!("Before Vm start, set a initrd or drive_file as rootfs");
        }

        if self.serial.is_some() && self.serial.as_ref().unwrap().stdio && is_daemonize {
            bail!("Serial with stdio and daemonize can't be set together");
        }

        if self.iothreads.is_some() {
            for iothread in self.iothreads.as_ref().unwrap() {
                iothread.check()?;
            }
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
}

#[cfg(target_arch = "aarch64")]
impl device_tree::CompileFDT for VmConfig {
    fn generate_fdt_node(&self, _fdt: &mut Vec<u8>) -> util::errors::Result<()> {
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
    fn new(name: &str) -> Self {
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
    fn push(&mut self, param_field: &str) -> &mut Self {
        self.params.insert(param_field.to_string(), None);

        self
    }

    /// Parse cmdline parameters string into `params`.
    ///
    /// # Arguments
    ///
    /// * `cmd_param`: The whole cmdline parameter string.
    fn parse(&mut self, cmd_param: &str) -> Result<()> {
        if cmd_param.starts_with(',') || cmd_param.ends_with(',') {
            return Err(ErrorKind::InvalidParam(cmd_param.to_string()).into());
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for param_item in param_items {
            if param_item.starts_with('=') || param_item.ends_with('=') {
                return Err(ErrorKind::InvalidParam(param_item.to_string()).into());
            }
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => ("", param[0]),
                2 => (param[0], param[1]),
                _ => {
                    return Err(ErrorKind::InvalidParam(param_item.to_string()).into());
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
                return Err(ErrorKind::InvalidParam(param[0].to_string()).into());
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
            return Err(ErrorKind::InvalidParam(cmd_param.to_string()).into());
        }
        let param_items = cmd_param.split(',').collect::<Vec<&str>>();
        for param_item in param_items {
            let param = param_item.splitn(2, '=').collect::<Vec<&str>>();
            let (param_key, param_value) = match param.len() {
                1 => ("", param[0]),
                2 => (param[0], param[1]),
                _ => {
                    return Err(ErrorKind::InvalidParam(param_item.to_string()).into());
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
    fn get_value<T: FromStr>(&self, param_field: &str) -> Result<Option<T>> {
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
}
