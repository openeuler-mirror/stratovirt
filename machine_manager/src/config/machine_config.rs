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
use super::{
    get_value_of_parameter, parse_bool, parse_size, str_slip_to_clap, valid_id, valid_path,
};
use crate::config::{ConfigCheck, IntegerList, VmConfig, MAX_NODES};
use crate::machine::HypervisorType;

const DEFAULT_CPUS: u8 = 1;
const DEFAULT_THREADS: u8 = 1;
const DEFAULT_CORES: u8 = 1;
const DEFAULT_DIES: u8 = 1;
const DEFAULT_CLUSTERS: u8 = 1;
const DEFAULT_SOCKETS: u8 = 1;
const DEFAULT_MAX_CPUS: u8 = 1;
const DEFAULT_MEMSIZE: u64 = 256;
const MAX_NR_CPUS: u8 = 254;
const MIN_NR_CPUS: u8 = 1;
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(MachineType::None),
            "microvm" => Ok(MachineType::MicroVm),
            #[cfg(target_arch = "x86_64")]
            "q35" => Ok(MachineType::StandardVm),
            #[cfg(target_arch = "aarch64")]
            "virt" => Ok(MachineType::StandardVm),
            _ => Err(anyhow!("Invalid machine type.")),
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

#[derive(Parser)]
#[command(no_binary_name(true))]
struct MemSizeConfig {
    #[arg(long, alias = "classtype", value_parser = parse_size)]
    size: u64,
}

#[derive(Parser)]
#[command(no_binary_name(true))]
struct MachineCmdConfig {
    #[arg(long, aliases = ["classtype", "type"])]
    mach_type: MachineType,
    #[arg(long, default_value = "on", action = ArgAction::Append, value_parser = parse_bool)]
    dump_guest_core: bool,
    #[arg(long, default_value = "off", action = ArgAction::Append, value_parser = parse_bool)]
    mem_share: bool,
    #[arg(long, default_value = "kvm")]
    accel: HypervisorType,
    // The "usb" member is added for compatibility with libvirt and is currently not in use.
    // It only supports configuration as "off". Currently, a `String` type is used to verify incoming values.
    // When it will be used, it needs to be changed to a `bool` type.
    #[arg(long, default_value = "off", value_parser = ["off"])]
    usb: String,
    #[cfg(target_arch = "aarch64")]
    #[arg(long, default_value = "3", value_parser = clap::value_parser!(u8).range(3..=3))]
    gic_version: u8,
}

#[derive(Parser)]
#[command(no_binary_name(true))]
struct SmpConfig {
    #[arg(long, alias = "classtype", value_parser = clap::value_parser!(u8).range(i64::from(MIN_NR_CPUS)..=i64::from(MAX_NR_CPUS)))]
    cpus: u8,
    #[arg(long, default_value = "0")]
    maxcpus: u8,
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(u8).range(..i64::from(u8::MAX)))]
    sockets: u8,
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(1..i64::from(u8::MAX)))]
    dies: u8,
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u8).range(1..i64::from(u8::MAX)))]
    clusters: u8,
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(u8).range(..i64::from(u8::MAX)))]
    cores: u8,
    #[arg(long, default_value = "0", value_parser = clap::value_parser!(u8).range(..i64::from(u8::MAX)))]
    threads: u8,
}

impl SmpConfig {
    fn auto_adjust_topology(&mut self) -> Result<()> {
        let mut max_cpus = self.maxcpus;
        let mut sockets = self.sockets;
        let mut cores = self.cores;
        let mut threads = self.threads;

        if max_cpus == 0 {
            let mut tmp_max = sockets
                .checked_mul(self.dies)
                .with_context(|| "Illegal smp config")?;
            tmp_max = tmp_max
                .checked_mul(self.clusters)
                .with_context(|| "Illegal smp config")?;
            tmp_max = tmp_max
                .checked_mul(cores)
                .with_context(|| "Illegal smp config")?;
            tmp_max = tmp_max
                .checked_mul(threads)
                .with_context(|| "Illegal smp config")?;

            if tmp_max > 0 {
                max_cpus = tmp_max;
            } else {
                max_cpus = self.cpus;
            }
        }

        if cores == 0 {
            if sockets == 0 {
                sockets = 1;
            }
            if threads == 0 {
                threads = 1;
            }
            cores = max_cpus / (sockets * self.dies * self.clusters * threads);
        } else if sockets == 0 {
            if threads == 0 {
                threads = 1;
            }
            sockets = max_cpus / (self.dies * self.clusters * cores * threads);
        }

        if threads == 0 {
            threads = max_cpus / (sockets * self.dies * self.clusters * cores);
        }

        let min_max_cpus = std::cmp::max(self.cpus, MIN_NR_CPUS);

        if !(min_max_cpus..=MAX_NR_CPUS).contains(&max_cpus) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "MAX CPU number".to_string(),
                u64::from(min_max_cpus),
                true,
                u64::from(MAX_NR_CPUS),
                true,
            )));
        }

        if sockets * self.dies * self.clusters * cores * threads != max_cpus {
            bail!("sockets * dies * clusters * cores * threads must be equal to max_cpus");
        }

        self.maxcpus = max_cpus;
        self.sockets = sockets;
        self.cores = cores;
        self.threads = threads;

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
        let mut has_type_label = false;
        if get_value_of_parameter("type", mach_config).is_ok() {
            has_type_label = true;
        }
        let mach_cfg = MachineCmdConfig::try_parse_from(str_slip_to_clap(
            mach_config,
            !has_type_label,
            false,
        ))?;
        // TODO: The current "accel" configuration in "-machine" command line and "-accel" command line are not foolproof.
        // Later parsing will overwrite first parsing. We will optimize this in the future.
        self.machine_config.hypervisor = mach_cfg.accel;
        self.machine_config.mach_type = mach_cfg.mach_type;
        self.machine_config.mem_config.dump_guest_core = mach_cfg.dump_guest_core;
        self.machine_config.mem_config.mem_share = mach_cfg.mem_share;

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
        // Is there a "size=" prefix tag in the command line.
        let mut has_size_label = false;
        if get_value_of_parameter("size", mem_config).is_ok() {
            has_size_label = true;
        }
        let mem_cfg =
            MemSizeConfig::try_parse_from(str_slip_to_clap(mem_config, !has_size_label, false))?;
        self.machine_config.mem_config.mem_size = mem_cfg.size;

        Ok(())
    }

    /// Add '-smp' cpu config to `VmConfig`.
    pub fn add_cpu(&mut self, cpu_config: &str) -> Result<()> {
        let mut has_cpus_label = false;
        if get_value_of_parameter("cpus", cpu_config).is_ok() {
            has_cpus_label = true;
        }
        let mut smp_cfg =
            SmpConfig::try_parse_from(str_slip_to_clap(cpu_config, !has_cpus_label, false))?;
        smp_cfg.auto_adjust_topology()?;

        self.machine_config.nr_cpus = smp_cfg.cpus as u8;
        self.machine_config.nr_threads = smp_cfg.threads as u8;
        self.machine_config.nr_cores = smp_cfg.cores as u8;
        self.machine_config.nr_dies = smp_cfg.dies as u8;
        self.machine_config.nr_clusters = smp_cfg.clusters as u8;
        self.machine_config.nr_sockets = smp_cfg.sockets as u8;
        self.machine_config.max_cpus = smp_cfg.maxcpus as u8;

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

    pub fn add_hw_signature(&mut self, config: &str) -> Result<()> {
        self.hardware_signature = Some(u32::from_str(config)?);
        Ok(())
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

        if self.object.mem_object.contains_key(&zone_config.id) {
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
            u64::from(MAX_NODES),
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
        assert!(machine_config.check().is_err());
        machine_config.mem_config.mem_size = MAX_MEMSIZE + 1;
        assert!(machine_config.check().is_err());
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
        assert!(machine_cfg.mem_config.dump_guest_core);
        assert!(machine_cfg.mem_config.mem_share);

        let mut vm_config = VmConfig::default();
        let memory_cfg_str = "none,dump-guest-core=off,mem-share=off,accel=kvm,usb=off";
        let machine_cfg_ret = vm_config.add_machine(memory_cfg_str);
        assert!(machine_cfg_ret.is_ok());
        let machine_cfg = vm_config.machine_config;
        assert_eq!(machine_cfg.mach_type, MachineType::None);
        assert_eq!(machine_cfg.hypervisor, HypervisorType::Kvm);
        assert!(!machine_cfg.mem_config.dump_guest_core);
        assert!(!machine_cfg.mem_config.mem_share);

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
        assert!(!mem_prealloc);
        vm_config.enable_mem_prealloc();
        let mem_prealloc = vm_config.machine_config.mem_config.mem_prealloc;
        assert!(mem_prealloc);
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
        assert!(zone_config_3.share);

        let zone_config_4 = vm_config
            .add_mem_zone("memory-backend-ram,size=2M,id=mem4")
            .unwrap();
        assert!(!zone_config_4.share);
        assert!(!zone_config_4.memfd());

        let zone_config_5 = vm_config
            .add_mem_zone("memory-backend-memfd,size=2M,id=mem5")
            .unwrap();
        assert!(zone_config_5.memfd());
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
