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
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{ConfigCheck, Param, ParamOperation, VmConfig};

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
    pub fn from_value(value: &serde_json::Value) -> Self {
        let mut boot_source = BootSource::default();
        if value.get("kernel_image_path") != None {
            boot_source.kernel_file =
                PathBuf::from(&(value["kernel_image_path"].to_string().replace("\"", "")));
        }
        if value.get("boot_args") != None {
            boot_source.kernel_cmdline =
                KernelParams::from_str((value["boot_args"]).to_string().replace("\"", ""))
        }
        if value.get("initrd_fs_path") != None {
            boot_source.initrd = Some(InitrdConfig::new(
                &(value["initrd_fs_path"].to_string().replace("\"", "")),
            ))
        }
        boot_source
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

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct InitrdConfig {
    /// Path of the initrd image
    pub initrd_file: PathBuf,
    /// Size of initrd image
    pub initrd_size: u64,
    pub initrd_addr: Mutex<u64>,
}

impl InitrdConfig {
    pub fn new(initrd: &str) -> Self {
        let initrd_size = match std::fs::metadata(initrd) {
            Ok(meta) => meta.len() as u64,
            _ => panic!("initrd file init failed {:?}!", initrd),
        };
        InitrdConfig {
            initrd_file: PathBuf::from(initrd),
            initrd_size,
            initrd_addr: Mutex::new(0),
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

impl Clone for InitrdConfig {
    fn clone(&self) -> Self {
        InitrdConfig {
            initrd_file: self.initrd_file.to_path_buf(),
            initrd_size: self.initrd_size,
            initrd_addr: Mutex::new(0),
        }
    }
}

/// Struct `KernelParams` used to parse kernel cmdline to config.
/// Contains a `Vec<Param>` and its `len()`.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct KernelParams {
    pub params: Vec<Param>,
    pub length: usize,
}

impl ParamOperation for KernelParams {
    /// Allocates an empty `KernelParams`
    fn new() -> Self {
        let params: Vec<Param> = Vec::new();
        let length: usize = 0;
        KernelParams { params, length }
    }

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

impl VmConfig {
    /// Update `-kernel kernel_file` config to `VmConfig`
    pub fn update_kernel(&mut self, kernel_image: String) {
        self.boot_source.kernel_file = PathBuf::from(kernel_image);
    }

    /// Update  `-append kernel_cmdline` config to `VmConfig`
    pub fn update_kernel_cmdline(&mut self, cmdline: &[String]) {
        let cmdline: String = cmdline.join(" ");
        self.boot_source.kernel_cmdline = KernelParams::from_str(cmdline);
    }

    /// Update `-initrd initrd_path` config to `VmConfig`
    pub fn update_initrd(&mut self, initrd: String) {
        self.boot_source.initrd = Some(InitrdConfig::new(&initrd));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Param, ParamOperation};
    use super::KernelParams;

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
}
