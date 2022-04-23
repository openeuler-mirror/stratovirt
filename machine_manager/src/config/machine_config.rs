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

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result, ResultExt};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

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
    None,
    MicroVm,
    StandardVm,
}

impl FromStr for MachineType {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(MachineType::None),
            "microvm" => Ok(MachineType::MicroVm),
            #[cfg(target_arch = "x86_64")]
            "q35" => Ok(MachineType::StandardVm),
            #[cfg(target_arch = "aarch64")]
            "virt" => Ok(MachineType::StandardVm),
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
    pub mem_prealloc: bool,
}

impl Default for MachineMemConfig {
    fn default() -> Self {
        MachineMemConfig {
            mem_size: DEFAULT_MEMSIZE * M,
            mem_path: None,
            dump_guest_core: true,
            mem_share: false,
            mem_prealloc: false,
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

impl ConfigCheck for MachineConfig {
    fn check(&self) -> Result<()> {
        if self.mem_config.mem_size < MIN_MEMSIZE || self.mem_config.mem_size > MAX_MEMSIZE {
            bail!("Memory size must >= 256MiB and <= 512GiB, default unit: MiB, current memory size: {:?} bytes", 
            &self.mem_config.mem_size);
        }

        Ok(())
    }
}

impl VmConfig {
    /// Add argument `name` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `name` - The name `String` added to `VmConfig`.
    pub fn add_machine(&mut self, mach_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("machine");
        cmd_parser
            .push("")
            .push("type")
            .push("accel")
            .push("usb")
            .push("dump-guest-core")
            .push("mem-share");
        #[cfg(target_arch = "aarch64")]
        cmd_parser.push("gic-version");
        cmd_parser.parse(mach_config)?;

        #[cfg(target_arch = "aarch64")]
        if let Some(gic_version) = cmd_parser.get_value::<u8>("gic-version")? {
            if gic_version != 3 {
                bail!("Unsupported gic version, only gicv3 is supported");
            }
        }

        if let Some(accel) = cmd_parser.get_value::<String>("accel")? {
            if accel.ne("kvm:tcg") && accel.ne("tcg") && accel.ne("kvm") {
                bail!("Only \'kvm\', \'kvm:tcg\' and \'tcg\' are supported for \'accel\' of \'machine\'");
            }
        }
        if let Some(usb) = cmd_parser.get_value::<ExBool>("usb")? {
            if usb.into() {
                bail!("Argument \'usb\' should be set to \'off\'");
            }
        }
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

    /// Add '-m' memory config to `VmConfig`.
    pub fn add_memory(&mut self, mem_config: &str) -> Result<()> {
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

    /// Add '-smp' cpu config to `VmConfig`.
    pub fn add_cpu(&mut self, cpu_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("smp");
        cmd_parser
            .push("")
            .push("sockets")
            .push("cores")
            .push("threads")
            .push("cpus");

        cmd_parser.parse(cpu_config)?;

        let cpu = if let Some(cpu) = cmd_parser.get_value::<u64>("")? {
            cpu
        } else if let Some(cpu) = cmd_parser.get_value::<u64>("cpus")? {
            cpu
        } else {
            return Err(ErrorKind::FieldIsMissing("cpus", "smp").into());
        };

        if let Some(sockets) = cmd_parser.get_value::<u64>("sockets")? {
            if sockets.ne(&cpu) {
                bail!("Invalid \'sockets\' arguments for \'smp\', it should equal to the number of cpus");
            }
        }
        if let Some(cores) = cmd_parser.get_value::<u64>("cores")? {
            if cores.ne(&1) {
                bail!("Invalid \'cores\' arguments for \'smp\', it should be \'1\'");
            }
        }
        if let Some(threads) = cmd_parser.get_value::<u64>("threads")? {
            if threads.ne(&1) {
                bail!("Invalid \'threads\' arguments for \'smp\', it should be \'1\'");
            }
        }

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

    pub fn add_mem_path(&mut self, mem_path: &str) -> Result<()> {
        self.machine_config.mem_config.mem_path = Some(mem_path.replace('\"', ""));
        Ok(())
    }

    pub fn enable_mem_prealloc(&mut self) {
        self.machine_config.mem_config.mem_prealloc = true;
    }
}

fn memory_unit_conversion(origin_value: &str) -> Result<u64> {
    if (origin_value.ends_with('M') | origin_value.ends_with('m'))
        && (origin_value.contains('M') ^ origin_value.contains('m'))
    {
        let value = origin_value.replacen('M', "", 1);
        let value = value.replacen('m', "", 1);
        get_inner(
            value
                .parse::<u64>()
                .map_err(|_| {
                    ErrorKind::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
                })?
                .checked_mul(M),
        )
    } else if (origin_value.ends_with('G') | origin_value.ends_with('g'))
        && (origin_value.contains('G') ^ origin_value.contains('g'))
    {
        let value = origin_value.replacen('G', "", 1);
        let value = value.replacen('g', "", 1);
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

        let memory_size = size.checked_mul(M);

        get_inner(memory_size)
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
    fn test_health_check() {
        let memory_config = MachineMemConfig {
            mem_size: MIN_MEMSIZE,
            mem_path: None,
            mem_share: false,
            dump_guest_core: false,
            mem_prealloc: false,
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

    #[test]
    fn test_memory_unit_conversion() {
        let test_string = "6G";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024 * 1024);

        let test_string = "6g";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024 * 1024);

        let test_string = "6M";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        let test_string = "6m";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        // default unit is MiB
        let test_string = "6";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        let test_string = "G6";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "G6G";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "6Gg";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "6gG";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "g6G";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "G6g";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "M6";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "M6M";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "6Mm";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "6mM";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "m6M";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());

        let test_string = "M6m";
        let ret = memory_unit_conversion(test_string);
        assert!(ret.is_err());
    }

    #[test]
    fn test_machine_type() {
        let test_string = "none";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_ok());
        let machine_type = machine_type.unwrap();
        assert_eq!(machine_type, MachineType::None);

        let test_string = "None";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_ok());
        let machine_type = machine_type.unwrap();
        assert_eq!(machine_type, MachineType::None);

        let test_string = "NONE";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_ok());
        let machine_type = machine_type.unwrap();
        assert_eq!(machine_type, MachineType::None);

        let test_string = "no";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_err());

        let test_string = "microvm";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_ok());
        let machine_type = machine_type.unwrap();
        assert_eq!(machine_type, MachineType::MicroVm);

        let test_string = "MICROVM";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_ok());
        let machine_type = machine_type.unwrap();
        assert_eq!(machine_type, MachineType::MicroVm);

        let test_string = "machine";
        let machine_type = MachineType::from_str(test_string);
        assert!(machine_type.is_err());

        #[cfg(target_arch = "x86_64")]
        {
            let test_string = "q35";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_ok());
            let machine_type = machine_type.unwrap();
            assert_eq!(machine_type, MachineType::StandardVm);

            let test_string = "Q35";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_ok());
            let machine_type = machine_type.unwrap();
            assert_eq!(machine_type, MachineType::StandardVm);

            let test_string = "virt";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_err());
        }

        #[cfg(target_arch = "aarch64")]
        {
            let test_string = "virt";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_ok());
            let machine_type = machine_type.unwrap();
            assert_eq!(machine_type, MachineType::StandardVm);

            let test_string = "VIRT";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_ok());
            let machine_type = machine_type.unwrap();
            assert_eq!(machine_type, MachineType::StandardVm);

            let test_string = "q35";
            let machine_type = MachineType::from_str(test_string);
            assert!(machine_type.is_err());
        }
    }
}
