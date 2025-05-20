// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp::max;
use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use clap::Parser;

use super::error::ConfigError;
use super::{get_class_type, str_slip_to_clap};
use crate::config::{IntegerList, VmConfig, MAX_NODES};

const MIN_NUMA_DISTANCE: u8 = 10;

#[derive(Default)]
pub struct NumaNode {
    pub cpus: Vec<u8>,
    pub distances: BTreeMap<u32, u8>,
    pub size: u64,
    pub mem_dev: String,
}

pub type NumaNodes = BTreeMap<u32, NumaNode>;

/// Complete the NUMA node parameters from user.
///
/// # Arguments
///
/// * `numa_nodes` - The NUMA node information parsing from user.
/// * `nr_cpus` - The VM cpus number.
/// * `mem_size` - The VM memory size.
pub fn complete_numa_node(numa_nodes: &mut NumaNodes, nr_cpus: u8, mem_size: u64) -> Result<()> {
    if numa_nodes.len() > 8 {
        bail!(
            "NUMA nodes should be less than or equal to 8, now is {}",
            numa_nodes.len()
        );
    }

    let mut total_ram_size = 0_u64;
    let mut max_cpu_id = 0_u8;
    let mut cpus_id = HashSet::<u8>::new();
    for (_, node) in numa_nodes.iter() {
        total_ram_size += node.size;
        for id in node.cpus.iter() {
            if cpus_id.contains(id) {
                bail!("CPU id {} is repeat, please check it again", *id);
            }
            cpus_id.insert(*id);
            max_cpu_id = max(max_cpu_id, *id);
        }
    }

    if cpus_id.len() < nr_cpus as usize {
        if let Some(node_0) = numa_nodes.get_mut(&0) {
            for id in 0..nr_cpus {
                if !cpus_id.contains(&id) {
                    node_0.cpus.push(id);
                }
            }
        }
    }

    if total_ram_size != mem_size {
        bail!(
            "Total memory {} of NUMA nodes is not equals to memory size {}",
            total_ram_size,
            mem_size,
        );
    }
    if max_cpu_id >= nr_cpus {
        bail!(
            "CPU index {} should be smaller than max cpu {}",
            max_cpu_id,
            nr_cpus
        );
    }
    if cpus_id.len() > nr_cpus as usize {
        bail!(
            "Total cpu numbers {} of NUMA nodes should be less than or equals to smp {}",
            cpus_id.len(),
            nr_cpus
        );
    }

    Ok(())
}

#[derive(Parser)]
#[command(no_binary_name(true))]
pub struct NumaNodeConfig {
    #[arg(long, value_parser = ["node"])]
    pub classtype: String,
    #[arg(long, alias = "nodeid", value_parser = clap::value_parser!(u32).range(..MAX_NODES as i64))]
    pub numa_id: u32,
    #[arg(long, value_parser = get_cpus)]
    pub cpus: ::std::vec::Vec<u8>,
    #[arg(long, alias = "memdev")]
    pub mem_dev: String,
}

fn get_cpus(cpus_str: &str) -> Result<Vec<u8>> {
    let mut cpus = IntegerList::from_str(cpus_str)
        .with_context(|| ConfigError::ConvertValueFailed(String::from("u8"), "cpus".to_string()))?
        .0
        .iter()
        .map(|e| *e as u8)
        .collect::<Vec<u8>>();

    if cpus.is_empty() {
        bail!("Got empty cpus list!");
    }

    cpus.sort_unstable();

    Ok(cpus)
}

/// Parse the NUMA node memory parameters.
///
/// # Arguments
///
/// * `numa_config` - The NUMA node configuration.
pub fn parse_numa_mem(numa_config: &str) -> Result<NumaNodeConfig> {
    let config = NumaNodeConfig::try_parse_from(str_slip_to_clap(numa_config, true, false))?;
    Ok(config)
}

#[derive(Parser)]
#[command(no_binary_name(true))]
pub struct NumaDistConfig {
    #[arg(long, value_parser = ["dist"])]
    pub classtype: String,
    #[arg(long, alias = "src", value_parser = clap::value_parser!(u32).range(..MAX_NODES as i64))]
    pub numa_id: u32,
    #[arg(long, alias = "dst", value_parser = clap::value_parser!(u32).range(..MAX_NODES as i64))]
    pub destination: u32,
    #[arg(long, alias = "val", value_parser = clap::value_parser!(u8).range(MIN_NUMA_DISTANCE as i64..))]
    pub distance: u8,
}

impl NumaDistConfig {
    fn check(&self) -> Result<()> {
        if self.numa_id == self.destination && self.distance != MIN_NUMA_DISTANCE {
            bail!("Local distance of node {} should be 10.", self.numa_id);
        }
        if self.numa_id != self.destination && self.distance == MIN_NUMA_DISTANCE {
            bail!(
                "Remote distance of node {} should be more than 10.",
                self.numa_id
            );
        }
        Ok(())
    }
}

/// Parse the NUMA node distance parameters.
///
/// # Arguments
///
/// * `numa_dist` - The NUMA node distance configuration.
pub fn parse_numa_distance(numa_dist: &str) -> Result<NumaDistConfig> {
    let dist_cfg = NumaDistConfig::try_parse_from(str_slip_to_clap(numa_dist, true, false))?;
    dist_cfg.check()?;
    Ok(dist_cfg)
}

impl VmConfig {
    /// Add the NUMA node config to vm config.
    ///
    /// # Arguments
    ///
    /// * `numa_config` - The NUMA node configuration.
    pub fn add_numa(&mut self, numa_config: &str) -> Result<()> {
        let numa_type = get_class_type(numa_config).with_context(|| "Numa type not specified")?;
        self.numa_nodes.push((numa_type, numa_config.to_string()));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_numa_mem() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_numa("node,nodeid=0,cpus=0-1,memdev=mem0")
            .is_ok());
        assert!(vm_config
            .add_numa("node,nodeid=1,cpus=2-1,memdev=mem1")
            .is_ok());
        assert!(vm_config.add_numa("node,nodeid=2,memdev=mem2").is_ok());
        assert!(vm_config.add_numa("node,nodeid=3,cpus=3-4").is_ok());
        assert!(vm_config
            .add_numa("node,nodeid=0,cpus=[0-1:3-5],memdev=mem0")
            .is_ok());

        let numa = vm_config.numa_nodes.first().unwrap();
        let numa_config = parse_numa_mem(numa.1.as_str()).unwrap();
        assert_eq!(numa_config.cpus, vec![0, 1]);
        assert_eq!(numa_config.mem_dev, "mem0");

        let numa = vm_config.numa_nodes.get(1).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(2).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(3).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());

        let numa = vm_config.numa_nodes.get(4).unwrap();
        let numa_config = parse_numa_mem(numa.1.as_str()).unwrap();
        assert_eq!(numa_config.cpus, vec![0, 1, 3, 4, 5]);
    }

    #[test]
    fn test_parse_numa_distance() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_numa("dist,src=0,dst=1,val=15").is_ok());
        assert!(vm_config.add_numa("dist,dst=1,val=10").is_ok());
        assert!(vm_config.add_numa("dist,src=0,val=10").is_ok());
        assert!(vm_config.add_numa("dist,src=0,dst=1").is_ok());
        assert!(vm_config.add_numa("dist,src=0,dst=1,val=10").is_ok());

        let numa = vm_config.numa_nodes.first().unwrap();
        let dist_cfg = parse_numa_distance(numa.1.as_str()).unwrap();
        assert_eq!(dist_cfg.numa_id, 0);
        assert_eq!(dist_cfg.destination, 1);
        assert_eq!(dist_cfg.distance, 15);

        let numa = vm_config.numa_nodes.get(1).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(2).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(3).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(4).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
    }

    #[test]
    fn test_check_numa_nodes() {
        let nr_cpus = 4;
        let mem_size = 2147483648;

        let numa_node1 = NumaNode {
            cpus: vec![0, 1],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node1"),
        };
        let numa_node2 = NumaNode {
            cpus: vec![2, 3],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node2"),
        };

        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, numa_node1);
        numa_nodes.insert(1, numa_node2);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_ok());

        let numa_node3 = NumaNode {
            cpus: vec![2],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node3"),
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(2, numa_node3);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_ok());

        let numa_node4 = NumaNode {
            cpus: vec![2, 3, 4],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node4"),
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node4);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_err());

        let numa_node5 = NumaNode {
            cpus: vec![3, 4],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node5"),
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node5);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_err());

        let numa_node6 = NumaNode {
            cpus: vec![0, 1],
            distances: Default::default(),
            size: 1073741824,
            mem_dev: String::from("numa_node6"),
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node6);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_err());

        let numa_node7 = NumaNode {
            cpus: vec![2, 3],
            distances: Default::default(),
            size: 2147483648,
            mem_dev: String::from("numa_node7"),
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node7);
        assert!(complete_numa_node(&mut numa_nodes, nr_cpus, mem_size).is_err());
    }
}
