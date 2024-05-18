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

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::{parse_bool, parse_size, str_slip_to_clap, valid_id, valid_path};
use crate::config::{CmdParser, ConfigCheck, ExBool, IntegerList, VmConfig, MAX_NODES};
use crate::machine::HypervisorType;

const DEFAULT_CPUS: u8 = 1;
const DEFAULT_THREADS: u8 = 1;
const DEFAULT_CORES: u8 = 1;
const DEFAULT_DIES: u8 = 1;
const DEFAULT_CLUSTERS: u8 = 1;
const DEFAULT_SOCKETS: u8 = 1;
const DEFAULT_MAX_CPUS: u8 = 1;
const DEFAULT_MEMSIZE: u64 = 256;
const MAX_NR_CPUS: u64 = 254;
const MIN_NR_CPUS: u64 = 1;
const MAX_MEMSIZE: u64 = 549_755_813_888;
const MIN_MEMSIZE: u64 = 134_217_728;
pub const K: u64 = 1024;
pub const M: u64 = 1024 * 1024;
pub const G: u64 = 1024 * 1024 * 1024;

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

#[repr(u32)]
#[derive(PartialEq, Eq)]
pub enum HostMemPolicy {
    Default = 0,
    Preferred = 1,
    Bind = 2,
    Interleave = 3,
    NotSupported = 4,
}

impl From<String> for HostMemPolicy {
    fn from(str: String) -> HostMemPolicy {
        match str.to_lowercase().as_str() {
            "default" => HostMemPolicy::Default,
            "preferred" => HostMemPolicy::Preferred,
            "bind" => HostMemPolicy::Bind,
            "interleave" => HostMemPolicy::Interleave,
            _ => HostMemPolicy::NotSupported,
        }
    }
}

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct MemZoneConfig {
    #[arg(long, alias = "classtype", value_parser = ["memory-backend-ram", "memory-backend-file", "memory-backend-memfd"])]
    pub mem_type: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long, value_parser = parse_size)]
    pub size: u64,
    // Note:
    // `Clap` will incorrectly assume that we're trying to get multiple arguments since we got
    // a `Vec<u32>` from parser function `get_host_nodes`. Generally, we should use `Box` or a `new struct type`
    // to encapsulate this `Vec<u32>`. And fortunately, there's a trick (using full qualified path of Vec)
    // to avoid the new type wrapper. See: github.com/clap-rs/clap/issues/4626.
    #[arg(long, alias = "host-nodes", value_parser = get_host_nodes)]
    pub host_numa_nodes: Option<::std::vec::Vec<u32>>,
    #[arg(long, default_value = "default", value_parser=["default", "preferred", "bind", "interleave"])]
    pub policy: String,
    #[arg(long, value_parser = valid_path)]
    pub mem_path: Option<String>,
    #[arg(long, default_value = "true", value_parser = parse_bool, action = ArgAction::Append)]
    pub dump_guest_core: bool,
    #[arg(long, default_value = "off", value_parser = parse_bool, action = ArgAction::Append)]
    pub share: bool,
    #[arg(long, alias = "mem-prealloc", default_value = "false", value_parser = parse_bool, action = ArgAction::Append)]
    pub prealloc: bool,
}

impl MemZoneConfig {
    pub fn memfd(&self) -> bool {
        self.mem_type.eq("memory-backend-memfd")
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
    pub mem_zones: Option<Vec<MemZoneConfig>>,
}

impl Default for MachineMemConfig {
    fn default() -> Self {
        MachineMemConfig {
            mem_size: DEFAULT_MEMSIZE * M,
            mem_path: None,
            dump_guest_core: true,
            mem_share: false,
            mem_prealloc: false,
            mem_zones: None,
        }
    }
}

#[derive(Parser, Clone, Debug, Serialize, Deserialize, Default)]
#[command(no_binary_name(true))]
pub struct CpuConfig {
    #[arg(long, alias = "classtype", value_parser = ["host"])]
    pub family: String,
    #[arg(long, default_value = "off")]
    pub pmu: PmuConfig,
    #[arg(long, default_value = "off")]
    pub sve: SveConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PmuConfig {
    On,
    #[default]
    Off,
}

impl FromStr for PmuConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "on" => Ok(PmuConfig::On),
            "off" => Ok(PmuConfig::Off),
            _ => Err(anyhow!(
                "Invalid PMU option,must be one of \'on\" or \"off\"."
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum SveConfig {
    On,
    #[default]
    Off,
}

impl FromStr for SveConfig {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "on" => Ok(SveConfig::On),
            "off" => Ok(SveConfig::Off),
            _ => Err(anyhow!(
                "Invalid SVE option, must be one of \"on\" or \"off\"."
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum ShutdownAction {
    #[default]
    ShutdownActionPoweroff,
    ShutdownActionPause,
}

/// Config struct for machine-config.
/// Contains some basic Vm config about cpu, memory, name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineConfig {
    pub mach_type: MachineType,
    pub hypervisor: HypervisorType,
    pub nr_cpus: u8,
    pub nr_threads: u8,
    pub nr_cores: u8,
    pub nr_dies: u8,
    pub nr_clusters: u8,
    pub nr_sockets: u8,
    pub max_cpus: u8,
    pub mem_config: MachineMemConfig,
    pub cpu_config: CpuConfig,
    pub shutdown_action: ShutdownAction,
    pub battery: bool,
}

impl Default for MachineConfig {
    /// Set default config for `machine-config`.
    fn default() -> Self {
        MachineConfig {
            mach_type: MachineType::MicroVm,
            hypervisor: HypervisorType::Kvm,
            nr_cpus: DEFAULT_CPUS,
            nr_threads: DEFAULT_THREADS,
            nr_cores: DEFAULT_CORES,
            nr_dies: DEFAULT_DIES,
            nr_clusters: DEFAULT_CLUSTERS,
            nr_sockets: DEFAULT_SOCKETS,
            max_cpus: DEFAULT_MAX_CPUS,
            mem_config: MachineMemConfig::default(),
            cpu_config: CpuConfig::default(),
            shutdown_action: ShutdownAction::default(),
            battery: false,
        }
    }
}

impl ConfigCheck for MachineConfig {
    fn check(&self) -> Result<()> {
        if self.mem_config.mem_size < MIN_MEMSIZE || self.mem_config.mem_size > MAX_MEMSIZE {
            bail!("Memory size must >= 128MiB and <= 512GiB, default unit: MiB, current memory size: {:?} bytes",
            &self.mem_config.mem_size);
        }

        Ok(())
    }
}

#[derive(Parser)]
#[command(no_binary_name(true))]
struct AccelConfig {
    #[arg(long, alias = "classtype")]
    hypervisor: HypervisorType,
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
            // Libvirt checks the parameter types of 'kvm', 'kvm:tcg' and 'tcg'.
            if accel.ne("kvm:tcg") && accel.ne("tcg") && accel.ne("kvm") && accel.ne("test") {
                bail!("Only \'kvm\', \'kvm:tcg\', \'test\' and \'tcg\' are supported for \'accel\' of \'machine\'");
            }

            match accel.as_str() {
                "test" => self.machine_config.hypervisor = HypervisorType::Test,
                _ => self.machine_config.hypervisor = HypervisorType::Kvm,
            };
        }
        if let Some(usb) = cmd_parser.get_value::<ExBool>("usb")? {
            if usb.into() {
                bail!("Argument \'usb\' should be set to \'off\'");
            }
        }
        if let Some(mach_type) = cmd_parser
            .get_value::<MachineType>("")
            .with_context(|| "Unrecognized machine type")?
        {
            self.machine_config.mach_type = mach_type;
        }
        if let Some(mach_type) = cmd_parser
            .get_value::<MachineType>("type")
            .with_context(|| "Unrecognized machine type")?
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

    /// Add '-accel' accelerator config to `VmConfig`.
    pub fn add_accel(&mut self, accel_config: &str) -> Result<()> {
        let accel_cfg = AccelConfig::try_parse_from(str_slip_to_clap(accel_config, true, false))?;
        self.machine_config.hypervisor = accel_cfg.hypervisor;
        Ok(())
    }

    /// Add '-m' memory config to `VmConfig`.
    pub fn add_memory(&mut self, mem_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("m");
        cmd_parser.push("").push("size");

        cmd_parser.parse(mem_config)?;

        let mem = if let Some(mem_size) = cmd_parser.get_value::<String>("")? {
            memory_unit_conversion(&mem_size, M)?
        } else if let Some(mem_size) = cmd_parser.get_value::<String>("size")? {
            memory_unit_conversion(&mem_size, M)?
        } else {
            return Err(anyhow!(ConfigError::FieldIsMissing(
                "size".to_string(),
                "memory".to_string()
            )));
        };

        self.machine_config.mem_config.mem_size = mem;

        Ok(())
    }

    /// Add '-smp' cpu config to `VmConfig`.
    pub fn add_cpu(&mut self, cpu_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("smp");
        cmd_parser
            .push("")
            .push("maxcpus")
            .push("sockets")
            .push("dies")
            .push("clusters")
            .push("cores")
            .push("threads")
            .push("cpus");

        cmd_parser.parse(cpu_config)?;

        let cpu = if let Some(cpu) = cmd_parser.get_value::<u64>("")? {
            cpu
        } else if let Some(cpu) = cmd_parser.get_value::<u64>("cpus")? {
            if cpu == 0 {
                return Err(anyhow!(ConfigError::IllegalValue(
                    "cpu".to_string(),
                    1,
                    true,
                    MAX_NR_CPUS,
                    true
                )));
            }
            cpu
        } else {
            return Err(anyhow!(ConfigError::FieldIsMissing(
                "cpus".to_string(),
                "smp".to_string()
            )));
        };

        let sockets = smp_read_and_check(&cmd_parser, "sockets", 0)?;

        let dies = smp_read_and_check(&cmd_parser, "dies", 1)?;

        let clusters = smp_read_and_check(&cmd_parser, "clusters", 1)?;

        let cores = smp_read_and_check(&cmd_parser, "cores", 0)?;

        let threads = smp_read_and_check(&cmd_parser, "threads", 0)?;

        let max_cpus = cmd_parser.get_value::<u64>("maxcpus")?.unwrap_or_default();

        let (max_cpus, sockets, cores, threads) =
            adjust_topology(cpu, max_cpus, sockets, dies, clusters, cores, threads);

        // limit cpu count
        if !(MIN_NR_CPUS..=MAX_NR_CPUS).contains(&cpu) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "CPU number".to_string(),
                MIN_NR_CPUS,
                true,
                MAX_NR_CPUS,
                true,
            )));
        }

        if !(MIN_NR_CPUS..=MAX_NR_CPUS).contains(&max_cpus) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "MAX CPU number".to_string(),
                MIN_NR_CPUS,
                true,
                MAX_NR_CPUS,
                true,
            )));
        }

        if max_cpus < cpu {
            return Err(anyhow!(ConfigError::IllegalValue(
                "maxcpus".to_string(),
                cpu,
                true,
                MAX_NR_CPUS,
                true,
            )));
        }

        if sockets * dies * clusters * cores * threads != max_cpus {
            bail!("sockets * dies * clusters * cores * threads must be equal to max_cpus");
        }

        self.machine_config.nr_cpus = cpu as u8;
        self.machine_config.nr_threads = threads as u8;
        self.machine_config.nr_cores = cores as u8;
        self.machine_config.nr_dies = dies as u8;
        self.machine_config.nr_clusters = clusters as u8;
        self.machine_config.nr_sockets = sockets as u8;
        self.machine_config.max_cpus = max_cpus as u8;

        Ok(())
    }

    pub fn add_cpu_feature(&mut self, features: &str) -> Result<()> {
        let cpu_config = CpuConfig::try_parse_from(str_slip_to_clap(features, true, false))?;
        self.machine_config.cpu_config = cpu_config;

        Ok(())
    }

    pub fn add_mem_path(&mut self, mem_path: &str) -> Result<()> {
        self.machine_config.mem_config.mem_path = Some(mem_path.replace('\"', ""));
        Ok(())
    }

    pub fn enable_mem_prealloc(&mut self) {
        self.machine_config.mem_config.mem_prealloc = true;
    }

    pub fn add_no_shutdown(&mut self) -> bool {
        self.machine_config.shutdown_action = ShutdownAction::ShutdownActionPause;
        true
    }

    pub fn add_battery(&mut self) -> bool {
        self.machine_config.battery = true;
        true
    }
}

impl VmConfig {
    /// Convert memory zone cmdline to VM config
    ///
    /// # Arguments
    ///
    /// * `mem_zone` - The memory zone cmdline string.
    pub fn add_mem_zone(&mut self, mem_zone: &str) -> Result<MemZoneConfig> {
        let zone_config = MemZoneConfig::try_parse_from(str_slip_to_clap(mem_zone, true, false))?;

        if (zone_config.mem_path.is_none() && zone_config.mem_type.eq("memory-backend-file"))
            || (zone_config.mem_path.is_some() && zone_config.mem_type.ne("memory-backend-file"))
        {
            bail!("Object type: {} config path err", zone_config.mem_type);
        }

        if self.object.mem_object.get(&zone_config.id).is_some() {
            bail!("Object: {} has been added", zone_config.id);
        }
        self.object
            .mem_object
            .insert(zone_config.id.clone(), zone_config.clone());

        if zone_config.host_numa_nodes.is_none() {
            return Ok(zone_config);
        }

        if self.machine_config.mem_config.mem_zones.is_some() {
            self.machine_config
                .mem_config
                .mem_zones
                .as_mut()
                .unwrap()
                .push(zone_config.clone());
        } else {
            self.machine_config.mem_config.mem_zones = Some(vec![zone_config.clone()]);
        }

        Ok(zone_config)
    }
}

fn smp_read_and_check(cmd_parser: &CmdParser, name: &str, default_val: u64) -> Result<u64> {
    if let Some(values) = cmd_parser.get_value::<u64>(name)? {
        if values == 0 {
            return Err(anyhow!(ConfigError::IllegalValue(
                name.to_string(),
                1,
                true,
                u8::MAX as u64,
                false
            )));
        }
        Ok(values)
    } else {
        Ok(default_val)
    }
}

fn adjust_topology(
    cpu: u64,
    mut max_cpus: u64,
    mut sockets: u64,
    dies: u64,
    clusters: u64,
    mut cores: u64,
    mut threads: u64,
) -> (u64, u64, u64, u64) {
    if max_cpus == 0 {
        if sockets * dies * clusters * cores * threads > 0 {
            max_cpus = sockets * dies * clusters * cores * threads;
        } else {
            max_cpus = cpu;
        }
    }

    if cores == 0 {
        if sockets == 0 {
            sockets = 1;
        }
        if threads == 0 {
            threads = 1;
        }
        cores = max_cpus / (sockets * dies * clusters * threads);
    } else if sockets == 0 {
        if threads == 0 {
            threads = 1;
        }
        sockets = max_cpus / (dies * clusters * cores * threads);
    }

    if threads == 0 {
        threads = max_cpus / (sockets * dies * clusters * cores);
    }

    (max_cpus, sockets, cores, threads)
}

/// Convert memory units from GiB, Mib to Byte.
///
/// # Arguments
///
/// * `origin_value` - The origin memory value from user.
pub fn memory_unit_conversion(origin_value: &str, default_unit: u64) -> Result<u64> {
    if (origin_value.ends_with('K') | origin_value.ends_with('k'))
        && (origin_value.contains('K') ^ origin_value.contains('k'))
    {
        let value = origin_value.replacen('K', "", 1);
        let value = value.replacen('k', "", 1);
        get_inner(
            value
                .parse::<u64>()
                .with_context(|| {
                    ConfigError::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
                })?
                .checked_mul(K),
        )
    } else if (origin_value.ends_with('M') | origin_value.ends_with('m'))
        && (origin_value.contains('M') ^ origin_value.contains('m'))
    {
        let value = origin_value.replacen('M', "", 1);
        let value = value.replacen('m', "", 1);
        get_inner(
            value
                .parse::<u64>()
                .with_context(|| {
                    ConfigError::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
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
                .with_context(|| {
                    ConfigError::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
                })?
                .checked_mul(G),
        )
    } else {
        let size = origin_value.parse::<u64>().with_context(|| {
            ConfigError::ConvertValueFailed(origin_value.to_string(), String::from("u64"))
        })?;

        let memory_size = size.checked_mul(default_unit);

        get_inner(memory_size)
    }
}

fn get_inner<T>(outer: Option<T>) -> Result<T> {
    outer.with_context(|| ConfigError::IntegerOverflow("-m".to_string()))
}

fn get_host_nodes(nodes: &str) -> Result<Vec<u32>> {
    let mut host_nodes = IntegerList::from_str(nodes)
        .with_context(|| {
            ConfigError::ConvertValueFailed(String::from("u32"), "host-nodes".to_string())
        })?
        .0
        .iter()
        .map(|e| *e as u32)
        .collect::<Vec<u32>>();

    if host_nodes.is_empty() {
        bail!("Got empty host nodes list!");
    }

    host_nodes.sort_unstable();
    if host_nodes[host_nodes.len() - 1] >= MAX_NODES {
        return Err(anyhow!(ConfigError::IllegalValue(
            "host_nodes".to_string(),
            0,
            true,
            MAX_NODES as u64,
            false,
        )));
    }

    Ok(host_nodes)
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
            mem_zones: None,
        };
        let mut machine_config = MachineConfig {
            mach_type: MachineType::MicroVm,
            hypervisor: HypervisorType::Kvm,
            nr_cpus: 1,
            nr_cores: 1,
            nr_threads: 1,
            nr_dies: 1,
            nr_clusters: 1,
            nr_sockets: 1,
            max_cpus: MIN_NR_CPUS as u8,
            mem_config: memory_config,
            cpu_config: CpuConfig::default(),
            shutdown_action: ShutdownAction::default(),
            battery: false,
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
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024 * 1024);

        let test_string = "6g";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024 * 1024);

        let test_string = "6M";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        let test_string = "6m";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        // default unit is MiB
        let test_string = "6";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_ok());
        let ret = ret.unwrap();
        assert_eq!(ret, 6 * 1024 * 1024);

        let test_string = "G6";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "G6G";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "6Gg";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "6gG";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "g6G";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "G6g";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "M6";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "M6M";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "6Mm";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "6mM";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "m6M";
        let ret = memory_unit_conversion(test_string, M);
        assert!(ret.is_err());

        let test_string = "M6m";
        let ret = memory_unit_conversion(test_string, M);
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

    #[test]
    fn test_add_memory() {
        let mut vm_config = VmConfig::default();
        let memory_cfg = "size=8";
        let mem_cfg_ret = vm_config.add_memory(memory_cfg);
        assert!(mem_cfg_ret.is_ok());
        let mem_size = vm_config.machine_config.mem_config.mem_size;
        assert_eq!(mem_size, 8 * 1024 * 1024);

        let memory_cfg = "size=8m";
        let mem_cfg_ret = vm_config.add_memory(memory_cfg);
        assert!(mem_cfg_ret.is_ok());
        let mem_size = vm_config.machine_config.mem_config.mem_size;
        assert_eq!(mem_size, 8 * 1024 * 1024);

        let memory_cfg = "size=8G";
        let mem_cfg_ret = vm_config.add_memory(memory_cfg);
        assert!(mem_cfg_ret.is_ok());
        let mem_size = vm_config.machine_config.mem_config.mem_size;
        assert_eq!(mem_size, 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_add_machine() {
        let mut vm_config = VmConfig::default();
        let memory_cfg_str = "type=none,dump-guest-core=on,mem-share=on,accel=kvm,usb=off";
        let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
        assert!(machine_cfg_ret.is_ok());
        let machine_cfg = vm_config.machine_config;
        assert_eq!(machine_cfg.mach_type, MachineType::None);
        assert_eq!(machine_cfg.mem_config.dump_guest_core, true);
        assert_eq!(machine_cfg.mem_config.mem_share, true);

        let mut vm_config = VmConfig::default();
        let memory_cfg_str = "type=none,dump-guest-core=off,mem-share=off,accel=kvm,usb=off";
        let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
        assert!(machine_cfg_ret.is_ok());
        let machine_cfg = vm_config.machine_config;
        assert_eq!(machine_cfg.mach_type, MachineType::None);
        assert_eq!(machine_cfg.mem_config.dump_guest_core, false);
        assert_eq!(machine_cfg.mem_config.mem_share, false);

        let mut vm_config = VmConfig::default();
        let memory_cfg_str = "type=none,accel=kvm-tcg";
        let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
        assert!(machine_cfg_ret.is_err());

        let mut vm_config = VmConfig::default();
        let memory_cfg_str = "type=none,usb=on";
        let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
        assert!(machine_cfg_ret.is_err());

        #[cfg(target_arch = "aarch64")]
        {
            let mut vm_config = VmConfig::default();
            let memory_cfg_str =
                "type=none,dump-guest-core=off,mem-share=off,accel=kvm,usb=off,gic-version=3";
            let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
            assert!(machine_cfg_ret.is_ok());
            let machine_cfg = vm_config.machine_config;
            assert_eq!(machine_cfg.mach_type, MachineType::None);
            assert_eq!(machine_cfg.mem_config.dump_guest_core, false);
            assert_eq!(machine_cfg.mem_config.mem_share, false);

            let mut vm_config = VmConfig::default();
            let memory_cfg_str = "type=none,gic-version=-1";
            let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
            assert!(machine_cfg_ret.is_err());

            let mut vm_config = VmConfig::default();
            let memory_cfg_str = "type=none,gic-version=256";
            let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
            assert!(machine_cfg_ret.is_err());

            let mut vm_config = VmConfig::default();
            let memory_cfg_str = "type=none,gic-version=4";
            let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
            assert!(machine_cfg_ret.is_err());
        }
    }

    #[test]
    fn test_add_mem_path() {
        let mut vm_config = VmConfig::default();
        let memory_path_str = "/path/to/memory-backend";
        let mem_path = vm_config.machine_config.mem_config.mem_path.clone();
        // default value is none.
        assert!(mem_path.is_none());
        let mem_cfg_ret = vm_config.add_mem_path(memory_path_str);
        assert!(mem_cfg_ret.is_ok());
        let mem_path = vm_config.machine_config.mem_config.mem_path;
        assert!(mem_path.is_some());
        let mem_path = mem_path.unwrap();
        assert_eq!(mem_path, memory_path_str);
    }

    #[test]
    fn test_enable_memory_prealloc() {
        let mut vm_config = VmConfig::default();
        let mem_prealloc = vm_config.machine_config.mem_config.mem_prealloc;
        // default value is false.
        assert_eq!(mem_prealloc, false);
        vm_config.enable_mem_prealloc();
        let mem_prealloc = vm_config.machine_config.mem_config.mem_prealloc;
        assert_eq!(mem_prealloc, true);
    }

    #[test]
    fn test_add_cpu() {
        let mut vm_config = VmConfig::default();
        let cpu_cfg_str = "cpus=8,sockets=8,cores=1,threads=1";
        let cpu_cfg_ret = vm_config.add_cpu(cpu_cfg_str);
        assert!(cpu_cfg_ret.is_ok());
        let nr_cpu = vm_config.machine_config.nr_cpus;
        assert_eq!(nr_cpu, 8);

        let mut vm_config = VmConfig::default();
        let cpu_cfg_str = "cpus=9,sockets=8,cores=1,threads=1";
        let cpu_cfg_ret = vm_config.add_cpu(cpu_cfg_str);
        assert!(cpu_cfg_ret.is_err());

        let mut vm_config = VmConfig::default();
        let cpu_cfg_str = "cpus=0,sockets=0,cores=1,threads=1";
        let cpu_cfg_ret = vm_config.add_cpu(cpu_cfg_str);
        assert!(cpu_cfg_ret.is_err());

        let mut vm_config = VmConfig::default();
        let cpu_cfg_str = "cpus=254,sockets=254,cores=1,threads=1";
        let cpu_cfg_ret = vm_config.add_cpu(cpu_cfg_str);
        assert!(cpu_cfg_ret.is_ok());
        let nr_cpu = vm_config.machine_config.nr_cpus;
        assert_eq!(nr_cpu, 254);

        let mut vm_config = VmConfig::default();
        let cpu_cfg_str = "cpus=255,sockets=255,cores=1,threads=1";
        let cpu_cfg_ret = vm_config.add_cpu(cpu_cfg_str);
        assert!(cpu_cfg_ret.is_err());
    }

    #[test]
    fn test_add_mem_zone() {
        let mut vm_config = VmConfig::default();
        let zone_config_1 = vm_config
            .add_mem_zone("memory-backend-ram,size=2G,id=mem1,host-nodes=1,policy=bind")
            .unwrap();
        assert_eq!(zone_config_1.id, "mem1");
        assert_eq!(zone_config_1.size, 2147483648);
        assert_eq!(zone_config_1.host_numa_nodes, Some(vec![1]));
        assert_eq!(zone_config_1.policy, "bind");

        let zone_config_2 = vm_config
            .add_mem_zone("memory-backend-ram,size=2G,id=mem2,host-nodes=1-2,policy=default")
            .unwrap();
        assert_eq!(zone_config_2.host_numa_nodes, Some(vec![1, 2]));

        let zone_config_3 = vm_config
            .add_mem_zone("memory-backend-ram,size=2M,id=mem3,share=on")
            .unwrap();
        assert_eq!(zone_config_3.size, 2 * 1024 * 1024);
        assert_eq!(zone_config_3.share, true);

        let zone_config_4 = vm_config
            .add_mem_zone("memory-backend-ram,size=2M,id=mem4")
            .unwrap();
        assert_eq!(zone_config_4.share, false);
        assert_eq!(zone_config_4.memfd(), false);

        let zone_config_5 = vm_config
            .add_mem_zone("memory-backend-memfd,size=2M,id=mem5")
            .unwrap();
        assert_eq!(zone_config_5.memfd(), true);
    }

    #[test]
    fn test_host_mem_policy() {
        let policy = HostMemPolicy::from(String::from("default"));
        assert!(policy == HostMemPolicy::Default);

        let policy = HostMemPolicy::from(String::from("interleave"));
        assert!(policy == HostMemPolicy::Interleave);

        let policy = HostMemPolicy::from(String::from("error"));
        assert!(policy == HostMemPolicy::NotSupported);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_cpu_features() {
        // Test PMU flags
        let mut vm_config = VmConfig::default();
        vm_config.add_cpu_feature("host").unwrap();
        assert!(vm_config.machine_config.cpu_config.pmu == PmuConfig::Off);
        vm_config.add_cpu_feature("host,pmu=off").unwrap();
        assert!(vm_config.machine_config.cpu_config.pmu == PmuConfig::Off);
        vm_config.add_cpu_feature("host,pmu=on").unwrap();
        assert!(vm_config.machine_config.cpu_config.pmu == PmuConfig::On);
        vm_config.add_cpu_feature("host,sve=on").unwrap();
        assert!(vm_config.machine_config.cpu_config.sve == SveConfig::On);
        vm_config.add_cpu_feature("host,sve=off").unwrap();
        assert!(vm_config.machine_config.cpu_config.sve == SveConfig::Off);

        // Illegal cpu command lines: should set cpu family.
        let result = vm_config.add_cpu_feature("pmu=off");
        assert!(result.is_err());
        let result = vm_config.add_cpu_feature("sve=on");
        assert!(result.is_err());

        // Illegal parameters.
        let result = vm_config.add_cpu_feature("host,sve1=on");
        assert!(result.is_err());

        // Illegal values.
        let result = vm_config.add_cpu_feature("host,sve=false");
        assert!(result.is_err());
    }

    #[test]
    fn test_add_accel() {
        let mut vm_config = VmConfig::default();
        let accel_cfg = "kvm";
        assert!(vm_config.add_accel(accel_cfg).is_ok());
        let machine_cfg = vm_config.machine_config;
        assert_eq!(machine_cfg.hypervisor, HypervisorType::Kvm);

        let mut vm_config = VmConfig::default();
        let accel_cfg = "kvm:tcg";
        assert!(vm_config.add_accel(accel_cfg).is_ok());
        let machine_cfg = vm_config.machine_config;
        assert_eq!(machine_cfg.hypervisor, HypervisorType::Kvm);

        let mut vm_config = VmConfig::default();
        let accel_cfg = "kvm1";
        assert!(vm_config.add_accel(accel_cfg).is_err());
    }
}
