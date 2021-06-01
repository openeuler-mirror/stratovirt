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

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result, ResultExt};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};
use util::num_ops::round_down;

const DEFAULT_CPUS: u8 = 1;
const DEFAULT_MEMSIZE: u64 = 256;
const MAX_NR_CPUS: u64 = 254;
const MIN_NR_CPUS: u64 = 1;
const MAX_MEMSIZE: u64 = 549_755_813_888;
const MIN_MEMSIZE: u64 = 268_435_456;
const M: u64 = 1024 * 1024;
const G: u64 = 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MachineType {
    MicroVm,
    StandardVm,
}

impl FromStr for MachineType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "microvm" => Ok(MachineType::MicroVm),
            "standard_vm" => Ok(MachineType::StandardVm),
            _ => Err(()),
        }
    }
}

/// Config that contains machine's memory information config.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineMemConfig {
    pub mem_size: u64,
    pub mem_path: Option<String>,
    pub dump_guest_core: bool,
    pub mem_share: bool,
}

impl Default for MachineMemConfig {
    fn default() -> Self {
        MachineMemConfig {
            mem_size: DEFAULT_MEMSIZE * M,
            mem_path: None,
            dump_guest_core: true,
            mem_share: false,
        }
    }
}

/// Config struct for machine-config.
/// Contains some basic Vm config about cpu, memory, name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineConfig {
    pub mach_type: MachineType,
    pub nr_cpus: u8,
    pub mem_config: MachineMemConfig,
}

impl Default for MachineConfig {
    /// Set default config for `machine-config`.
    fn default() -> Self {
        MachineConfig {
            mach_type: MachineType::MicroVm,
            nr_cpus: DEFAULT_CPUS,
            mem_config: MachineMemConfig::default(),
        }
    }
}

impl MachineConfig {
    /// Create `MachineConfig` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let mut machine_config = MachineConfig::default();
        if let serde_json::Value::Object(items) = value {
            for (name, item) in items {
                let item_str = item.to_string().replace("\"", "");
                match name.as_str() {
                    "type" => {
                        machine_config.mach_type =
                            item_str.parse::<MachineType>().map_err(|_| {
                                ErrorKind::ConvertValueFailed("MachineType".to_string(), item_str)
                            })?
                    }
                    "vcpu_count" => {
                        let cpu = item_str.parse::<u64>().map_err(|_| {
                            ErrorKind::ConvertValueFailed("vcpu_count".to_string(), item_str)
                        })?;
                        // limit cpu count
                        if !(MIN_NR_CPUS..=MAX_NR_CPUS).contains(&cpu) {
                            return Err(ErrorKind::IllegalValue(
                                "CPU number".to_string(),
                                MIN_NR_CPUS,
                                true,
                                MAX_NR_CPUS,
                                true,
                            )
                            .into());
                        }

                        machine_config.nr_cpus = cpu as u8;
                    }
                    "mem_size" => {
                        machine_config.mem_config.mem_size = memory_unit_conversion(&item_str)
                            .map_err(|_| {
                                ErrorKind::ConvertValueFailed("mem_size".to_string(), item_str)
                            })?
                    }
                    "mem_path" => machine_config.mem_config.mem_path = Some(item_str),
                    "mem_share" => {
                        machine_config.mem_config.mem_share =
                            item_str.parse::<bool>().map_err(|_| {
                                ErrorKind::ConvertValueFailed("mem_share".to_string(), item_str)
                            })?
                    }
                    "dump_guest_core" => {
                        machine_config.mem_config.dump_guest_core =
                            item_str.parse::<bool>().map_err(|_| {
                                ErrorKind::ConvertValueFailed(
                                    "dump_guest_core".to_string(),
                                    item_str,
                                )
                            })?
                    }
                    _ => return Err(ErrorKind::InvalidJsonField(name.to_string()).into()),
                }
            }
        }

        Ok(machine_config)
    }
}

impl ConfigCheck for MachineConfig {
    fn check(&self) -> Result<()> {
        if self.mem_config.mem_size < MIN_MEMSIZE || self.mem_config.mem_size > MAX_MEMSIZE {
            return Err(ErrorKind::IllegalValue(
                "Memory size".to_string(),
                MIN_MEMSIZE,
                true,
                MAX_MEMSIZE,
                true,
            )
            .into());
        }

        Ok(())
    }
}

impl VmConfig {
    /// Update argument `name` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name `String` updated to `VmConfig`.
    pub fn update_machine(&mut self, mach_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("machine");
        cmd_parser
            .push("")
            .push("type")
            .push("dump-guest-core")
            .push("mem-share");

        cmd_parser.parse(mach_config)?;

        if let Some(mach_type) = cmd_parser
            .get_value::<MachineType>("")
            .chain_err(|| "Unrecognized machine type")?
        {
            self.machine_config.mach_type = mach_type;
        }
        if let Some(mach_type) = cmd_parser
            .get_value::<MachineType>("type")
            .chain_err(|| "Unrecognized machine type")?
        {
            self.machine_config.mach_type = mach_type;
        }
        if let Some(dump_guest) = cmd_parser.get_value::<ExBool>("dump-guest-core")? {
            self.machine_config.mem_config.dump_guest_core = dump_guest.into();
        }
        if let Some(mem_share) = cmd_parser.get_value::<ExBool>("mem-share")? {
            self.machine_config.mem_config.mem_share = mem_share.into();
        }

        Ok(())
    }

    /// Update '-m' memory config to `VmConfig`.
    pub fn update_memory(&mut self, mem_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("m");
        cmd_parser.push("").push("size");

        cmd_parser.parse(mem_config)?;

        let mem = if let Some(mem_size) = cmd_parser.get_value::<String>("")? {
            memory_unit_conversion(&mem_size)?
        } else if let Some(mem_size) = cmd_parser.get_value::<String>("size")? {
            memory_unit_conversion(&mem_size)?
        } else {
            return Err(ErrorKind::FieldIsMissing("size", "memory").into());
        };

        self.machine_config.mem_config.mem_size = mem;

        Ok(())
    }

    /// Update '-smp' cpu config to `VmConfig`.
    pub fn update_cpu(&mut self, cpu_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("smp");
        cmd_parser.push("").push("cpus");

        cmd_parser.parse(cpu_config)?;

        let cpu = if let Some(cpu) = cmd_parser.get_value::<u64>("")? {
            cpu
        } else if let Some(cpu) = cmd_parser.get_value::<u64>("cpus")? {
            cpu
        } else {
            return Err(ErrorKind::FieldIsMissing("cpus", "smp").into());
        };

        // limit cpu count
        if !(MIN_NR_CPUS..=MAX_NR_CPUS).contains(&cpu) {
            return Err(ErrorKind::IllegalValue(
                "CPU number".to_string(),
                MIN_NR_CPUS,
                true,
                MAX_NR_CPUS,
                true,
            )
            .into());
        }

        // it is safe, as value limited before
        self.machine_config.nr_cpus = cpu as u8;

        Ok(())
    }

    pub fn update_mem_path(&mut self, mem_path: &str) -> Result<()> {
        self.machine_config.mem_config.mem_path = Some(mem_path.replace("\"", ""));
        Ok(())
    }
}

fn memory_unit_conversion(origin_value: &str) -> Result<u64> {
    if origin_value.contains('M') ^ origin_value.contains('m') {
        let value = origin_value.replacen("M", "", 1);
        let value = value.replacen("m", "", 1);
        get_inner(
            value
                .parse::<u64>()
                .map_err(|_| {
                    ErrorKind::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
                })?
                .checked_mul(M),
        )
    } else if origin_value.contains('G') ^ origin_value.contains('g') {
        let value = origin_value.replacen("G", "", 1);
        let value = value.replacen("g", "", 1);
        get_inner(
            value
                .parse::<u64>()
                .map_err(|_| {
                    ErrorKind::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
                })?
                .checked_mul(G),
        )
    } else {
        let size = origin_value.parse::<u64>().map_err(|_| {
            ErrorKind::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
        })?;

        if let Some(round) = round_down(size, M) {
            if size != round {
                return Err(ErrorKind::Unaligned("memory".to_string(), size, M).into());
            }
        }

        get_inner(Some(size))
    }
}

fn get_inner<T>(outer: Option<T>) -> Result<T> {
    if let Some(x) = outer {
        Ok(x)
    } else {
        Err(ErrorKind::IntegerOverflow("-m".to_string()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_json_parser() {
        let json = r#"
        {
            "vcpu_count": 1,
            "mem_size": 268435456,
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);
        assert!(machine_config.is_ok());
        let machine_config = machine_config.unwrap();

        assert_eq!(machine_config.nr_cpus, 1);
        assert_eq!(machine_config.mem_config.mem_size, 268_435_456);
        assert_eq!(machine_config.mem_config.dump_guest_core, false);
    }

    #[test]
    fn test_config_json_parser_unit() {
        // Unit 'M'
        let json = r#"
        {
            "mem_size": "1024M"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value).unwrap();
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'm'
        let json = r#"
        {
            "mem_size": "1024m"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value).unwrap();
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'G'
        let json = r#"
        {
            "mem_size": "1G"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value).unwrap();
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'g'
        let json = r#"
        {
            "mem_size": "1g"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value).unwrap();
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Round down
        let json = r#"
        {
            "mem_size": "1073741900"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        assert!(MachineConfig::from_value(&value).is_err());
    }

    #[test]
    fn test_config_cmdline_parser() {
        let json = r#"
        {
            "vcpu_count": 1,
            "mem_size": 268435456,
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);

        let mut vm_config = VmConfig::default();
        vm_config.machine_config = machine_config.unwrap();

        assert!(vm_config.update_cpu("8").is_ok());
        assert_eq!(vm_config.machine_config.nr_cpus, 8);
        assert!(vm_config.update_cpu("cpus=16").is_ok());
        assert_eq!(vm_config.machine_config.nr_cpus, 16);
        assert!(vm_config.update_cpu("nr_cpus=32").is_err());
        assert_eq!(vm_config.machine_config.nr_cpus, 16);

        assert!(vm_config.update_memory("256m").is_ok());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 268_435_456);
        assert!(vm_config.update_memory("512M").is_ok());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 536_870_912);
        assert!(vm_config.update_memory("size=1G").is_ok());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 1_073_741_824);

        assert!(!vm_config.machine_config.mem_config.dump_guest_core);
        assert!(vm_config.update_machine("dump-guest-core=true").is_ok());
        assert!(vm_config.machine_config.mem_config.dump_guest_core);
    }

    #[test]
    fn test_health_check() {
        let memory_config = MachineMemConfig {
            mem_size: MIN_MEMSIZE,
            mem_path: None,
            mem_share: false,
            dump_guest_core: false,
        };
        let mut machine_config = MachineConfig {
            mach_type: MachineType::MicroVm,
            nr_cpus: MIN_NR_CPUS as u8,
            mem_config: memory_config,
        };
        assert!(machine_config.check().is_ok());

        machine_config.nr_cpus = MAX_NR_CPUS as u8;
        machine_config.mem_config.mem_size = MAX_MEMSIZE;
        assert!(machine_config.check().is_ok());

        machine_config.nr_cpus = MIN_NR_CPUS as u8;
        machine_config.mem_config.mem_size = MIN_MEMSIZE - 1;
        assert!(!machine_config.check().is_ok());
        machine_config.mem_config.mem_size = MAX_MEMSIZE + 1;
        assert!(!machine_config.check().is_ok());
        machine_config.mem_config.mem_size = MIN_MEMSIZE;

        assert!(machine_config.check().is_ok());
    }
}
