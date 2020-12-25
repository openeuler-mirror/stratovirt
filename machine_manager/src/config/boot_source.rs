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

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{ConfigCheck, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;

/// Config struct for boot-source.
/// Contains `kernel_file`, `kernel_cmdline` and `initrd`.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BootSource {
    /// Path of the kernel image.
    pub kernel_file: PathBuf,
    /// Kernel boot arguments.
    pub kernel_cmdline: KernelParams,
    /// Config of initrd.
    pub initrd: Option<InitrdConfig>,
}

impl BootSource {
    /// Create `BootSource` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let mut boot_source = BootSource::default();
        if let serde_json::Value::Object(items) = value {
            for (name, item) in items {
                let item_str = item.to_string().replace("\"", "");
                match name.as_str() {
                    "kernel_image_path" => boot_source.kernel_file = PathBuf::from(&item_str),
                    "boot_args" => boot_source.kernel_cmdline = KernelParams::from_str(item_str),
                    "initrd_fs_path" => boot_source.initrd = Some(InitrdConfig::new(&item_str)),
                    _ => return Err(ErrorKind::InvalidJsonField(name.to_string()).into()),
                }
            }
        }

        Ok(boot_source)
    }

    /// Move all the elements of `other` into `Self.kernel_cmdline`.
    pub fn append_kernel_cmdline(&mut self, other: &mut Vec<Param>) {
        self.kernel_cmdline.append(other);
    }
}

impl ConfigCheck for BootSource {
    fn check(&self) -> Result<()> {
        if self.kernel_file.to_str().unwrap().len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "kernel_file path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if !self.kernel_file.is_file() {
            return Err(ErrorKind::UnRegularFile("Input kernel_file".to_string()).into());
        }

        self.kernel_cmdline.check()?;
        if self.initrd.is_some() {
            self.initrd.as_ref().unwrap().check()?;
        }

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct InitrdConfig {
    /// Path of the initrd image
    pub initrd_file: PathBuf,
    pub initrd_addr: u64,
    pub initrd_size: u64,
}

impl InitrdConfig {
    pub fn new(initrd: &str) -> Self {
        InitrdConfig {
            initrd_file: PathBuf::from(initrd),
            initrd_addr: 0,
            initrd_size: 0,
        }
    }
}

impl ConfigCheck for InitrdConfig {
    fn check(&self) -> Result<()> {
        if self.initrd_file.to_str().unwrap().len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "initrd_file".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if !self.initrd_file.is_file() {
            return Err(ErrorKind::UnRegularFile("Input initrd_file".to_string()).into());
        }

        Ok(())
    }
}

/// Struct `KernelParams` used to parse kernel cmdline to config.
/// Contains a `Vec<Param>` and its `len()`.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct KernelParams {
    pub params: Vec<Param>,
    pub length: usize,
}

impl ConfigCheck for KernelParams {
    fn check(&self) -> Result<()> {
        for param in self.params.clone() {
            if param.value.len() > MAX_STRING_LENGTH {
                return Err(ErrorKind::StringLengthTooLong(
                    "kernel params".to_string(),
                    MAX_STRING_LENGTH,
                )
                .into());
            }
        }

        Ok(())
    }
}

impl KernelParams {
    /// Created `Kernel` from `String`.
    fn from_str(kernel_cmdline: String) -> Self {
        let split = kernel_cmdline.split(' ');
        let vec = split.collect::<Vec<&str>>();
        let mut params: Vec<Param> = Vec::new();
        let mut length: usize = 0;
        for item in vec {
            params.push(Param::from_str(item));
            length += 1;
        }
        KernelParams { params, length }
    }

    /// Push new `Param` to `KernelParams`.
    pub fn push(&mut self, item: Param) {
        self.params.push(item);
        self.length = self
            .length
            .checked_add(1)
            .unwrap_or_else(|| panic!("Kernel params length is too long: {}", self.length));
    }

    /// Move all the `Param` into `KernelParams`.
    pub fn append(&mut self, items: &mut Vec<Param>) {
        self.length = self
            .length
            .checked_add(items.len())
            .unwrap_or_else(|| panic!("Kernel params length is too long: {}", self.length));
        self.params.append(items);
    }

    /// Check `KernelParam` whether contains `item` or not.
    pub fn contains(&self, item: &str) -> bool {
        for i in 0..self.length {
            if self.params[i].param_type == item {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for KernelParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut vec: Vec<String> = Vec::with_capacity(self.length);
        for i in 0..self.length {
            vec.push(self.params[i].to_string());
        }
        write!(f, "{}", vec.join(" "))
    }
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

impl VmConfig {
    /// Update `-kernel kernel_file` config to `VmConfig`
    pub fn update_kernel(&mut self, kernel_image: &str) -> Result<()> {
        self.boot_source.kernel_file = PathBuf::from(kernel_image);
        Ok(())
    }

    /// Update  `-append kernel_cmdline` config to `VmConfig`
    pub fn update_kernel_cmdline(&mut self, cmdline: &[String]) {
        let cmdline: String = cmdline.join(" ");
        self.boot_source.kernel_cmdline = KernelParams::from_str(cmdline);
    }

    /// Update `-initrd initrd_path` config to `VmConfig`
    pub fn update_initrd(&mut self, initrd: &str) -> Result<()> {
        self.boot_source.initrd = Some(InitrdConfig::new(initrd));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn test_kernel_params() {
        let test_kernel = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0";
        let mut test_kernel_param = KernelParams::from_str(test_kernel.to_string());

        assert_eq!(test_kernel_param.length, 5);

        test_kernel_param.push(Param::from_str("maxcpus=8"));
        assert_eq!(test_kernel_param.length, 6);
        assert_eq!(test_kernel_param.contains("maxcpus"), true);
        assert_eq!(test_kernel_param.contains("cpus"), false);
        assert_eq!(
            test_kernel_param.to_string(),
            "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 maxcpus=8"
        );
    }

    #[test]
    fn test_bootsource_json_parser() {
        let json = r#"
        {
            "kernel_image_path": "/path/to/vmlinux",
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let boot_source = BootSource::from_value(&value).unwrap();
        assert_eq!(boot_source.kernel_file, PathBuf::from("/path/to/vmlinux"));
        assert_eq!(
            boot_source.kernel_cmdline.to_string(),
            "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1"
        );
        assert!(boot_source.initrd.is_none());
    }

    #[test]
    fn test_bootsource_cmdline_parser() {
        let kernel_path = String::from("vmlinux.bin");
        let initrd_path = String::from("initrd.img");
        let kernel_file = File::create(&kernel_path).unwrap();
        kernel_file.set_len(100_u64).unwrap();
        let initrd_file = File::create(&initrd_path).unwrap();
        initrd_file.set_len(100_u64).unwrap();
        let mut vm_config = VmConfig::default();
        assert!(vm_config.update_kernel(&kernel_path).is_ok());
        vm_config.update_kernel_cmdline(&vec![
            String::from("console=ttyS0"),
            String::from("reboot=k"),
            String::from("panic=1"),
            String::from("pci=off"),
            String::from("tsc=reliable"),
            String::from("ipv6.disable=1"),
        ]);
        let boot_source = vm_config.clone().boot_source;
        assert_eq!(boot_source.kernel_file, PathBuf::from(&kernel_path));
        assert_eq!(
            boot_source.kernel_cmdline.to_string(),
            "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1"
        );
        assert!(boot_source.initrd.is_none());
        assert!(boot_source.check().is_ok());
        assert!(vm_config.update_initrd(&initrd_path).is_ok());
        let boot_source = vm_config.clone().boot_source;
        assert!(boot_source.initrd.is_some());
        assert!(boot_source.check().is_ok());
        let initrd_config = boot_source.initrd.unwrap();
        assert_eq!(initrd_config.initrd_file, PathBuf::from(&initrd_path));
        assert_eq!(initrd_config.initrd_size, 0);
        assert_eq!(initrd_config.initrd_addr, 0);
        std::fs::remove_file(&kernel_path).unwrap();
        std::fs::remove_file(&initrd_path).unwrap();
    }
}
