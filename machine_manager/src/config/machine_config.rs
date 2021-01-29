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

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParams, ConfigCheck, Param, ParamOperation, VmConfig};
use util::num_ops::round_down;

const DEFAULT_CPUS: u8 = 1;
const DEFAULT_MEMSIZE: u64 = 128;
const MAX_NR_CPUS: u8 = 254;
const MIN_NR_CPUS: u8 = 1;
const MAX_MEMSIZE: u64 = 549_755_813_888;
const MIN_MEMSIZE: u64 = 134_217_728;
const M: u64 = 1024 * 1024;
const G: u64 = 1024 * 1024 * 1024;

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
    pub mach_type: String,
    pub nr_cpus: u8,
    pub mem_config: MachineMemConfig,
}

impl Default for MachineConfig {
    /// Set default config for `machine-config`.
    fn default() -> Self {
        MachineConfig {
            mach_type: "MicroVm".to_string(),
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
            machine_config.mach_type = value["type"].to_string();
        }
        if value.get("vcpu_count") != None {
            machine_config.nr_cpus = value["vcpu_count"].to_string().parse::<u8>().unwrap();
        }
        if value.get("mem_size") != None {
            let mut param = Param {
                param_type: String::new(),
                value: value["mem_size"].to_string().replace("\"", ""),
            };
            machine_config.mem_config.mem_size = unit_conversion(&mut param);
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
    pub fn update_machine(&mut self, mach_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(mach_config);
        if let Some(mach_type) = cmd_params.get("type") {
            self.machine_config.mach_type = mach_type.value;
        }
        if let Some(dump_guest) = cmd_params.get("dump-guest-core") {
            self.machine_config.mem_config.dump_guest_core = dump_guest.to_bool();
        }
        if let Some(mem_share) = cmd_params.get("mem-share") {
            self.machine_config.mem_config.mem_share = mem_share.to_bool();
        }
    }
    /// Update '-m' memory config to `VmConfig`.
    pub fn update_memory(&mut self, mem_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(mem_config);
        if let Some(mut mem_size) = cmd_params.get("") {
            self.machine_config.mem_config.mem_size = unit_conversion(&mut mem_size)
        } else if let Some(mut mem_size) = cmd_params.get("size") {
            self.machine_config.mem_config.mem_size = unit_conversion(&mut mem_size)
        }
    }

    /// Update '-smp' cpu config to `VmConfig`.
    pub fn update_cpu(&mut self, cpu_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(cpu_config);
        if let Some(cpu_num) = cmd_params.get("") {
            self.machine_config.nr_cpus = cpu_num.value_to_u8();
        } else if let Some(cpu_num) = cmd_params.get("cpus") {
            self.machine_config.nr_cpus = cpu_num.value_to_u8();
        }
    }

    pub fn update_mem_path(&mut self, mem_path: String) {
        self.machine_config.mem_config.mem_path = Some(mem_path.replace("\"", ""));
    }
}

fn unit_conversion(origin_param: &mut Param) -> u64 {
    if origin_param.value_replace_blank("M") || origin_param.value_replace_blank("m") {
        get_inner(origin_param.value_to_u64().checked_mul(M))
    } else if origin_param.value_replace_blank("G") || origin_param.value_replace_blank("g") {
        get_inner(origin_param.value_to_u64().checked_mul(G))
    } else {
        get_inner(round_down(origin_param.value_to_u64(), M))
    }
}

fn get_inner<T>(outer: Option<T>) -> T {
    if let Some(x) = outer {
        x
    } else {
        panic!("Integer overflow occurred!");
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

        vm_config.update_cpu("8".to_string());
        assert_eq!(vm_config.machine_config.nr_cpus, 8);
        vm_config.update_cpu("cpus=16".to_string());
        assert_eq!(vm_config.machine_config.nr_cpus, 16);
        vm_config.update_cpu("nrcpus=32".to_string());
        assert_eq!(vm_config.machine_config.nr_cpus, 16);

        vm_config.update_memory("256m".to_string());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 268_435_456);
        vm_config.update_memory("512M".to_string());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 536_870_912);
        vm_config.update_memory("size=1G".to_string());
        assert_eq!(vm_config.machine_config.mem_config.mem_size, 1_073_741_824);

        assert!(!vm_config.machine_config.mem_config.dump_guest_core);
        vm_config.update_machine(String::from("dump-guest-core=on"));
        assert!(vm_config.machine_config.mem_config.dump_guest_core);
    }

    #[test]
    #[should_panic(expected = "Unrecognized value to u64: 268435456N")]
    fn test_invaild_json_01() {
        let json = r#"
        {
            "name": "test_stratovirt",
            "vcpu_count": 1,
            "mem_size": "268435456MN",
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        MachineConfig::from_value(&value);
    }

    #[test]
    #[should_panic(expected = "Unrecognized value to u64: ABCDEF")]
    fn test_invaild_json_02() {
        let json = r#"
        {
            "name": "test_stratovirt",
            "vcpu_count": 1,
            "mem_size": "ABCDEF",
            "dump_guest_core": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        MachineConfig::from_value(&value);
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
            mach_type: String::from("MicroVm"),
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
