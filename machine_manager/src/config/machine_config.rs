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
use crate::config::{CmdParams, ConfigCheck, ParamOperation, VmConfig};

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
            machine_config.mem_config.mem_size =
                value["mem_size"].to_string().parse::<u64>().unwrap();
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
            if mem_size.value_replace_blank("M") || mem_size.value_replace_blank("m") {
                self.machine_config.mem_config.mem_size =
                    get_inner(mem_size.value_to_u64().checked_mul(M));
            } else if mem_size.value_replace_blank("G") || mem_size.value_replace_blank("g") {
                self.machine_config.mem_config.mem_size =
                    get_inner(mem_size.value_to_u64().checked_mul(G));
            } else {
                self.machine_config.mem_config.mem_size = mem_size.value_to_u64();
            }
        } else if let Some(mut mem_size) = cmd_params.get("size") {
            if mem_size.value_replace_blank("M") || mem_size.value_replace_blank("m") {
                self.machine_config.mem_config.mem_size =
                    get_inner(mem_size.value_to_u64().checked_mul(M));
            } else if mem_size.value_replace_blank("G") || mem_size.value_replace_blank("g") {
                self.machine_config.mem_config.mem_size =
                    get_inner(mem_size.value_to_u64().checked_mul(G));
            } else {
                self.machine_config.mem_config.mem_size = mem_size.value_to_u64();
            }
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

fn get_inner<T>(outer: Option<T>) -> T {
    if let Some(x) = outer {
        x
    } else {
        panic!("Integer overflow occurred!");
    }
}
