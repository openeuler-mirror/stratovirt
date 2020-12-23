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
use std::fmt;

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "aarch64")]
use util::device_tree;

pub use self::errors::Result;
pub use balloon::*;
pub use boot_source::*;
pub use chardev::*;
pub use fs::*;
pub use machine_config::*;
pub use network::*;

pub mod errors {
    error_chain! {
        errors {
            StringLengthTooLong(t: String, len: usize) {
                description("Limit the length of String.")
                display("Input {} string's length must be no more than {}.", t, len)
            }
            NrcpusError {
                description("Limit the number of vcpu in StratoVirt.")
                display("Number of vcpu should be more than 0 and less than 255.")
            }
            MemsizeError {
                description("Limit the size of memory in StratoVirt.")
                display("Size of memory should be less than 512G and more than 128M.")
            }
            GuestCidError {
                description("Check legality of vsock guest-cid.")
                display("Vsock guest-cid should be more than 3 and less than 4294967296.")
            }
            MacFormatError {
                description("Check legality of vsock mac address.")
                display("Mac address is illegal.")
            }
            UnknownVhostType {
                description("Unknown vhost type.")
                display("Unknown vhost type.")
            }
            UnRegularFile(t: String) {
                description("Check legality of file.")
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
    pub fn update_name(&mut self, name: String) {
        self.guest_name = name;
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

/// The basic structure to parse arguments to config.
///
/// # Notes
///
/// The attr format such as `param_type=value` can be treated as a `Param`
/// Single attr such as `quiet` can also be treated as Param
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Param {
    /// The item on the left of `=`, if no `=`, param_type is ""
    pub param_type: String,
    /// The item on the right of `=`, if no `=`, the whole is value
    pub value: String,
}

impl Param {
    /// Converts from `&str`.
    ///
    /// # Arguments
    ///
    /// * `item` - The `str` transformed to `Param`.
    fn from_str(item: &str) -> Self {
        let split = item.split('=');
        let vec = split.collect::<Vec<&str>>();
        if vec.len() == 1 {
            Param {
                param_type: String::new(),
                value: String::from(vec[0]),
            }
        } else {
            Param {
                param_type: String::from(vec[0]),
                value: String::from(vec[1]),
            }
        }
    }

    /// Converts `value` in `Param` to `u64`.
    pub fn value_to_u64(&self) -> u64 {
        self.value
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("Unrecognized value to u64: {}", &self.value))
    }

    /// Converts `value` in `Param` to `u32`.
    pub fn value_to_u32(&self) -> u32 {
        self.value
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("Unrecognized value to u32: {}", &self.value))
    }

    /// Converts `value` in `Param` to `u8`.
    pub fn value_to_u8(&self) -> u8 {
        self.value
            .parse::<u8>()
            .unwrap_or_else(|_| panic!("Unrecognized value to u8: {}", &self.value))
    }

    /// Replace `value`'s `str` in `Param` by blank.
    ///
    /// # Arguments
    ///
    /// * `s` - The `str` in `Param` will be replaced.
    pub fn value_replace_blank(&mut self, s: &str) -> bool {
        if self.value.contains(s) {
            self.value = self.value.replace(s, "");
            true
        } else {
            false
        }
    }

    /// Converts `yes`,`on`,`true`,`no`,`off`,`false` in `value` to `bool`.
    pub fn to_bool(&self) -> bool {
        match self.value.as_ref() {
            "yes" | "on" | "true" => true,
            "no" | "off" | "false" => false,
            _ => panic!("Can only give `yes`,`on`,`true`,`no`,`off`,`false` for boolean."),
        }
    }
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut str1 = String::from(&self.param_type);
        let param_str = if str1.is_empty() {
            String::from(&self.value)
        } else {
            str1 += "=";
            str1 + &self.value
        };
        write!(f, "{}", param_str)
    }
}

/// `Operation` for `Param`.
///
/// The trait `ParamOperation` define two function: `new()` and `from_str()`.
pub trait ParamOperation {
    fn new() -> Self;
    fn from_str(s: String) -> Self;
}

/// Struct `CmdParams` used to parse arguments to config.
/// Contains a `Vec<Param>` and its `len()`.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CmdParams {
    /// A `Vec` to restore `Param`s, each item in `Vec` is a basic Param,
    /// such as `isrootfs=on`.
    pub params: Vec<Param>,
    /// The length of the whole cmdline, a basic param is simple one.
    pub length: usize,
}

impl ParamOperation for CmdParams {
    /// Allocates an empty `CmdParams`.
    fn new() -> Self {
        let params: Vec<Param> = Vec::new();
        let length: usize = 0;
        CmdParams { params, length }
    }

    /// Created `CmdParams` from `String`.
    ///
    /// # Arguments
    ///
    /// * `cmdline_args`: The args `String` to be transformed.
    fn from_str(cmdline_args: String) -> Self {
        let split = cmdline_args.split(',');
        let vec = split.collect::<Vec<&str>>();
        let mut params: Vec<Param> = Vec::new();
        let mut length: usize = 0;

        for item in vec {
            params.push(Param::from_str(item));
            length += 1;
        }
        CmdParams { params, length }
    }
}

impl CmdParams {
    /// Input the `Param`'s `param_type`, get its `value`.
    ///
    /// # Arguments
    ///
    /// * `item` - The item name `str` to get `Param`.
    pub fn get(&self, item: &str) -> Option<Param> {
        for i in 0..self.length {
            if self.params[i].param_type == item {
                return Some(self.params[i].clone());
            }
        }
        None
    }

    /// Input the `Param`'s `param_type`, get its value.
    ///
    /// # Arguments
    ///
    /// * `item` - The item name `str` to get `Param`'s value `String`.
    pub fn get_value_str(&self, item: &str) -> Option<String> {
        if let Some(param) = self.get(item) {
            Some(param.value)
        } else {
            None
        }
    }

    /// Input the `Param`'s `param_type`, get its value to u32.
    ///
    /// # Arguments
    ///
    /// * `item` - The item name `str` to get `Param`'s value `i32`.
    pub fn get_value_i32(&self, item: &str) -> Option<i32> {
        if let Some(param) = self.get(item) {
            Some(param.value_to_u32() as i32)
        } else {
            None
        }
    }

    /// Input the `Param`'s `param_type`, get its value to u32.
    ///
    /// # Arguments
    ///
    /// * `item` - The item name `str` to get `Param`'s value `u32`.
    pub fn get_value_u64(&self, item: &str) -> Option<u64> {
        if let Some(param) = self.get(item) {
            Some(param.value_to_u64())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_param() {
        let test_param_str = "isrootfs=on";
        let mut test_param: Param = Param::from_str(&test_param_str);

        assert_eq!(test_param.to_string(), "isrootfs=on".to_string());
        assert_eq!(test_param.to_bool(), true);

        test_param.value = "off".to_string();
        assert_eq!(test_param.to_bool(), false);

        let test_param_str = "quiet";
        let mut test_param: Param = Param::from_str(&test_param_str);

        assert_eq!(test_param.to_string(), "quiet".to_string());
        test_param.value_replace_blank("et");
        assert_eq!(test_param.to_string(), "qui".to_string());

        let test_param_str = "max_vcpu=8";
        let test_param: Param = Param::from_str(&test_param_str);

        assert_eq!(test_param.value_to_u8(), 8u8);
        assert_eq!(test_param.value_to_u32(), 8u32);
        assert_eq!(test_param.value_to_u64(), 8u64);
    }

    #[test]
    fn test_cmd_param() {
        let test_cmdline = "socket,id=charconsole0,path=/tmp/console.sock";
        let test_cmdline_param = CmdParams::from_str(test_cmdline.to_string());

        assert_eq!(
            test_cmdline_param.get("id").unwrap().to_string(),
            "id=charconsole0".to_string()
        );
        assert_eq!(
            test_cmdline_param.get("").unwrap().to_string(),
            "socket".to_string()
        );
    }
}
