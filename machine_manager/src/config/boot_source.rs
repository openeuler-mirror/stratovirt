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

use std::fmt;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use crate::config::{check_arg_too_long, ConfigCheck, VmConfig, MAX_PATH_LENGTH};

/// Config struct for boot-source.
/// Contains `kernel_file`, `kernel_cmdline` and `initrd`.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct BootSource {
    /// Path of the kernel image.
    pub kernel_file: Option<PathBuf>,
    /// Kernel boot arguments.
    pub kernel_cmdline: KernelParams,
    /// Config of initrd.
    pub initrd: Option<InitrdConfig>,
}

impl BootSource {
    /// Move all the elements of `other` into `Self.kernel_cmdline`.
    pub fn append_kernel_cmdline(&mut self, other: &mut Vec<Param>) {
        self.kernel_cmdline.append(other);
    }
}

impl ConfigCheck for BootSource {
    fn check(&self) -> Result<()> {
        if let Some(kernel_file) = &self.kernel_file {
            if kernel_file.to_str().unwrap().len() > MAX_PATH_LENGTH {
                return Err(anyhow!(ConfigError::StringLengthTooLong(
                    "kernel_file path".to_string(),
                    MAX_PATH_LENGTH,
                )));
            }
            if !kernel_file.is_file() {
                return Err(anyhow!(ConfigError::UnRegularFile(
                    "Input kernel_file".to_string()
                )));
            }
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
        check_arg_too_long(self.initrd_file.to_str().unwrap(), "initrd_file")?;

        if !self.initrd_file.is_file() {
            return Err(anyhow!(ConfigError::UnRegularFile(
                "Input initrd_file".to_string()
            )));
        }

        Ok(())
    }
}

/// Struct `KernelParams` used to parse kernel cmdline to config.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct KernelParams {
    pub params: Vec<Param>,
}

impl ConfigCheck for KernelParams {
    fn check(&self) -> Result<()> {
        for param in self.params.iter() {
            check_arg_too_long(&param.value, "kernel params")?;
        }

        Ok(())
    }
}

impl KernelParams {
    /// Created `Kernel` from `String`.
    fn from_str(kernel_cmdline: String) -> Self {
        let split = kernel_cmdline.split(' ');
        let vec = split.collect::<Vec<&str>>();
        let mut params: Vec<Param> = Vec::with_capacity(vec.len());
        for item in vec {
            params.push(Param::from_str(item));
        }
        KernelParams { params }
    }

    /// Push new `Param` to `KernelParams`.
    pub fn push(&mut self, item: Param) {
        self.params.push(item);
    }

    /// Move all the `Param` into `KernelParams`.
    pub fn append(&mut self, items: &mut Vec<Param>) {
        self.params.append(items);
    }

    /// Check `KernelParam` whether contains `item` or not.
    pub fn contains(&self, item: &str) -> bool {
        for param in self.params.iter() {
            if param.param_type == item {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for KernelParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut vec: Vec<String> = Vec::with_capacity(self.params.len());
        for param in self.params.iter() {
            vec.push(param.to_string());
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
        let split = item.splitn(2, '=');
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
    /// Add `-kernel kernel_file` config to `VmConfig`
    pub fn add_kernel(&mut self, kernel_image: &str) -> Result<()> {
        self.boot_source.kernel_file = Some(PathBuf::from(kernel_image));
        Ok(())
    }

    /// Add  `-append kernel_cmdline` config to `VmConfig`
    pub fn add_kernel_cmdline(&mut self, cmdline: &[String]) {
        let cmdline: String = cmdline.join(" ");
        self.boot_source.kernel_cmdline = KernelParams::from_str(cmdline);
    }

    /// Add `-initrd initrd_path` config to `VmConfig`
    pub fn add_initrd(&mut self, initrd: &str) -> Result<()> {
        self.boot_source.initrd = Some(InitrdConfig::new(initrd));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[test]
    fn test_kernel_params() {
        let test_kernel = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0";
        let mut test_kernel_param = KernelParams::from_str(test_kernel.to_string());

        assert_eq!(test_kernel_param.params.len(), 5);

        test_kernel_param.push(Param::from_str("maxcpus=8"));
        assert_eq!(test_kernel_param.params.len(), 6);
        assert_eq!(test_kernel_param.contains("maxcpus"), true);
        assert_eq!(test_kernel_param.contains("cpus"), false);
        assert_eq!(
            test_kernel_param.to_string(),
            "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 maxcpus=8"
        );
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
        assert!(vm_config.add_kernel(&kernel_path).is_ok());
        vm_config.add_kernel_cmdline(&vec![
            String::from("console=ttyS0"),
            String::from("reboot=k"),
            String::from("panic=1"),
            String::from("pci=off"),
            String::from("tsc=reliable"),
            String::from("ipv6.disable=1"),
        ]);
        let boot_source = vm_config.clone().boot_source;
        assert_eq!(boot_source.kernel_file, Some(PathBuf::from(&kernel_path)));
        assert_eq!(
            boot_source.kernel_cmdline.to_string(),
            "console=ttyS0 reboot=k panic=1 pci=off tsc=reliable ipv6.disable=1"
        );
        assert!(boot_source.initrd.is_none());
        assert!(boot_source.check().is_ok());
        assert!(vm_config.add_initrd(&initrd_path).is_ok());
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
