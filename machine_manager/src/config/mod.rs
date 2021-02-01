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
mod fs;
mod machine_config;
mod network;

use std::any::Any;
use std::collections::HashMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "aarch64")]
use util::device_tree;

pub use self::errors::{ErrorKind, Result};
pub use balloon::*;
pub use boot_source::*;
pub use chardev::*;
pub use fs::*;
pub use machine_config::*;
pub use network::*;

pub mod errors {
    error_chain! {
        errors {
            InvalidParam(param: String) {
                display("Invalid parameter \'{}\'", param)
            }
            ConvertValueFailed(param: String, value: String) {
                display("Unable to parse \'{}\' for \'{}\'", value, param)
            }
            StringLengthTooLong(t: String, len: usize) {
                display("Input {} string's length must be no more than {}.", t, len)
            }
            FieldRepeat(field: String, name: String) {
                display("\'{}\' in {} is offerred more than once.", field, name)
            }
            IntegerOverflow(item: &'static str) {
                display("Integer overflow occurred during parse {}!", item)
            }
            NrcpusError {
                display("Number of vcpu should be more than 0 and less than 255.")
            }
            MemsizeError {
                display("Size of memory should be less than 512G and more than 128M.")
            }
            GuestCidError {
                display("Vsock guest-cid should be more than 3 and less than 4294967296.")
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
        }
    }
}

/// `MAX_VCPUS`: the most cpu number Vm support.
pub static MAX_VCPUS: u8 = 128_u8;
const MAX_STRING_LENGTH: usize = 255;

/// Macro: From serde_json: Value $y to get member $z, use $s's from_value
/// function to convert.
///
/// # Example
///
/// ```text
/// config_parse!(machine_config, value, "machine-config", MachineConfig);
/// ```
macro_rules! config_parse {
    ( $x:expr, $y:expr, $z:expr, $s:tt ) => {
        if let Some(tmp_value) = $y.get($z) {
            $x = $s::from_value(tmp_value);
        }
    };
}

/// This main config structure for Vm, contains Vm's basic configuration and devices.
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct VmConfig {
    pub guest_name: String,
    pub machine_config: MachineConfig,
    pub boot_source: BootSource,
    pub drives: Option<Vec<DriveConfig>>,
    pub nets: Option<Vec<NetworkInterfaceConfig>>,
    pub consoles: Option<Vec<ConsoleConfig>>,
    pub vsock: Option<VsockConfig>,
    pub serial: Option<SerialConfig>,
    pub balloon: Option<BalloonConfig>,
}

impl VmConfig {
    /// Create the `VmConfig` from `Value`.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn create_from_value(value: serde_json::Value) -> Result<VmConfig> {
        let mut machine_config = MachineConfig::default();
        let mut boot_source = BootSource::default();
        let mut drives = None;
        let mut nets = None;
        let mut consoles = None;
        let mut vsock = None;
        let mut serial = None;
        let mut balloon = None;

        // Use macro to use from_value function for every member
        config_parse!(machine_config, value, "machine-config", MachineConfig);
        config_parse!(boot_source, value, "boot-source", BootSource);
        config_parse!(drives, value, "drive", DriveConfig);
        config_parse!(nets, value, "net", NetworkInterfaceConfig);
        config_parse!(consoles, value, "console", ConsoleConfig);
        config_parse!(vsock, value, "vsock", VsockConfig);
        config_parse!(serial, value, "serial", SerialConfig);
        config_parse!(balloon, value, "balloon", BalloonConfig);

        Ok(VmConfig {
            guest_name: "StratoVirt".to_string(),
            machine_config,
            boot_source,
            drives,
            nets,
            consoles,
            vsock,
            serial,
            balloon,
        })
    }

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

        if self.vsock.is_some() {
            self.vsock.as_ref().unwrap().check()?;
        }

        if self.boot_source.initrd.is_none() && self.drives.is_none() {
            bail!("Before Vm start, set a initrd or drive_file as rootfs");
        }

        if self.serial.is_some() && self.serial.as_ref().unwrap().stdio && is_daemonize {
            bail!("Serial with stdio and daemonize can't be set together");
        }

        Ok(())
    }

    /// Update argument `name` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name `String` updated to `VmConfig`.
    pub fn update_name(&mut self, name: &str) -> Result<()> {
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
            if param_item.starts_with('=') || cmd_param.ends_with('=') {
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
                        ErrorKind::FieldRepeat(param_key.to_string(), self.name.clone()).into(),
                    );
                }
            } else {
                return Err(ErrorKind::InvalidParam(param[0].to_string()).into());
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
                let field_msg = if param_field == "" {
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

impl Into<bool> for ExBool {
    fn into(self) -> bool {
        self.inner
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
    fn test_vmcfg_json_parser() {
        let kernel_path = String::from("test_vmlinux.bin");
        let kernel_file = std::fs::File::create(&kernel_path).unwrap();
        kernel_file.set_len(100_u64).unwrap();
        let basic_json = r#"
        {
            "boot-source": {
              "kernel_image_path": "test_vmlinux.bin",
              "boot_args": "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1 root=/dev/vda"
            },
            "machine-config": {
              "vcpu_count": 1,
              "mem_size": 268435456
            },
            "drive": [
              {
                "drive_id": "rootfs",
                "path_on_host": "/path/to/rootfs/image",
                "direct": false,
                "read_only": false
              }
            ],
            "serial": {
              "stdio": true
            }
        }
        "#;
        let value = serde_json::from_str(basic_json).unwrap();
        let vm_config_rst = VmConfig::create_from_value(value);
        assert!(vm_config_rst.is_ok());
        let vm_config = vm_config_rst.unwrap();
        assert_eq!(vm_config.guest_name, "StratoVirt");
        assert!(vm_config.check_vmconfig(false).is_ok());
        assert!(vm_config.check_vmconfig(true).is_err());
        std::fs::remove_file(&kernel_path).unwrap();
    }
}
