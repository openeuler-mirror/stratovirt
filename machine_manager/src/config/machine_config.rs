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
const DEFAULT_MEMSIZE: u64 = 128;
const MAX_NR_CPUS: u8 = 254;
const MIN_NR_CPUS: u8 = 1;
const MAX_MEMSIZE: u64 = 549_755_813_888;
const MIN_MEMSIZE: u64 = 134_217_728;
const M: u64 = 1024 * 1024;
const G: u64 = 1024 * 1024 * 1024;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum MachineType {
    MicroVm,
}

impl FromStr for MachineType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "microvm" => Ok(MachineType::MicroVm),
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
    pub fn from_value(value: &serde_json::Value) -> Self {
        let mut machine_config = MachineConfig::default();
        if value.get("type") != None {
            machine_config.mach_type = value["type"]
                .to_string()
                .parse::<MachineType>()
                .expect("Unrecognized machine type");
        }
        if value.get("vcpu_count") != None {
            machine_config.nr_cpus = value["vcpu_count"].to_string().parse::<u8>().unwrap();
        }
        if value.get("mem_size") != None {
            machine_config.mem_config.mem_size =
                memory_unit_conversion(&value["mem_size"].to_string().replace("\"", ""))
                    .unwrap_or_else(|_| panic!("Unrecognized value to u64: {}", value["mem_size"]));
        }
        if value.get("mem_path") != None {
            machine_config.mem_config.mem_path =
                Some(value["mem_path"].to_string().replace("\"", ""));
        }
        if value.get("mem_share") != None {
            machine_config.mem_config.mem_share =
                value["mem_share"].to_string().parse::<bool>().unwrap();
        }
        if value.get("dump_guest_core") != None {
            machine_config.mem_config.dump_guest_core = value["dump_guest_core"]
                .to_string()
                .parse::<bool>()
                .unwrap();
        }
        machine_config
    }
}

impl ConfigCheck for MachineConfig {
    fn check(&self) -> Result<()> {
        if self.nr_cpus < MIN_NR_CPUS || self.nr_cpus > MAX_NR_CPUS {
            return Err(ErrorKind::NrcpusError.into());
        }

        if self.mem_config.mem_size < MIN_MEMSIZE || self.mem_config.mem_size > MAX_MEMSIZE {
            return Err(ErrorKind::MemsizeError.into());
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

        if let Some(mem_size) = cmd_parser.get_value::<String>("")? {
            self.machine_config.mem_config.mem_size = memory_unit_conversion(&mem_size)?;
        } else if let Some(mem_size) = cmd_parser.get_value::<String>("size")? {
            self.machine_config.mem_config.mem_size = memory_unit_conversion(&mem_size)?;
        }

        Ok(())
    }

    /// Update '-smp' cpu config to `VmConfig`.
    pub fn update_cpu(&mut self, cpu_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("smp");
        cmd_parser.push("").push("cpus");

        cmd_parser.parse(cpu_config)?;

        if let Some(cpu_num) = cmd_parser.get_value::<u8>("")? {
            self.machine_config.nr_cpus = cpu_num;
        } else if let Some(cpu_num) = cmd_parser.get_value::<u8>("cpus")? {
            self.machine_config.nr_cpus = cpu_num;
        }

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
                    ErrorKind::ConvertValueFailed(String::from("u64"), origin_value.to_string())
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
                    ErrorKind::ConvertValueFailed(String::from("u64"), origin_value.to_string())
                })?
                .checked_mul(G),
        )
    } else {
        get_inner(round_down(
            origin_value.parse::<u64>().map_err(|_| {
                ErrorKind::ConvertValueFailed(String::from("u64"), origin_value.to_string())
            })?,
            M,
        ))
    }
}

fn get_inner<T>(outer: Option<T>) -> Result<T> {
    if let Some(x) = outer {
        Ok(x)
    } else {
        Err(ErrorKind::IntegerOverflow("-m").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_json_parser() {
        let json = r#"
        {
            "name": "test_stratovirt",
            "vcpu_count": 1,
            "mem_size": 268435456,
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);

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
        let machine_config = MachineConfig::from_value(&value);
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'm'
        let json = r#"
        {
            "mem_size": "1024m"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'G'
        let json = r#"
        {
            "mem_size": "1G"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Unit 'g'
        let json = r#"
        {
            "mem_size": "1g"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);

        // Round down
        let json = r#"
        {
            "mem_size": "1073741900"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);
        assert_eq!(machine_config.mem_config.mem_size, 1_073_741_824);
    }

    #[test]
    fn test_config_cmdline_parser() {
        let json = r#"
        {
            "name": "test_stratovirt",
            "vcpu_count": 1,
            "mem_size": 268435456,
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let machine_config = MachineConfig::from_value(&value);

        let mut vm_config = VmConfig::default();
        vm_config.machine_config = machine_config;

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
            nr_cpus: MIN_NR_CPUS,
            mem_config: memory_config,
        };
        assert!(machine_config.check().is_ok());

        machine_config.nr_cpus = MAX_NR_CPUS;
        machine_config.mem_config.mem_size = MAX_MEMSIZE;
        assert!(machine_config.check().is_ok());

        machine_config.nr_cpus = MIN_NR_CPUS - 1;
        assert!(!machine_config.check().is_ok());
        machine_config.nr_cpus = MAX_NR_CPUS + 1;
        assert!(!machine_config.check().is_ok());
        machine_config.nr_cpus = MIN_NR_CPUS;

        machine_config.mem_config.mem_size = MIN_MEMSIZE - 1;
        assert!(!machine_config.check().is_ok());
        machine_config.mem_config.mem_size = MAX_MEMSIZE + 1;
        assert!(!machine_config.check().is_ok());
        machine_config.mem_config.mem_size = MIN_MEMSIZE;

        assert!(machine_config.check().is_ok());
    }
}
