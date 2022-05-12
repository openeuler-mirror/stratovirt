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

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParser, IntegerList, VmConfig, MAX_NODES};
use std::collections::BTreeMap;

const MIN_NUMA_DISTANCE: u8 = 10;

#[derive(Default, Debug)]
pub struct NumaDistance {
    pub destination: u32,
    pub distance: u8,
}

#[derive(Default, Debug)]
pub struct NumaConfig {
    pub numa_id: u32,
    pub cpus: Vec<u8>,
    pub distances: Option<Vec<NumaDistance>>,
    pub size: u64,
    pub mem_dev: String,
}

#[derive(Default)]
pub struct NumaNode {
    pub cpus: Vec<u8>,
    pub distances: BTreeMap<u32, u8>,
    pub size: u64,
}

pub type NumaNodes = BTreeMap<u32, NumaNode>;

pub fn check_numa_node(numa_nodes: &NumaNodes, vm_config: &mut VmConfig) -> Result<()> {
    let mut total_ram_size = 0_u64;
    let mut total_cpu_num = 0_u8;
    let mut max_cpu_idx = 0_u8;
    for node in numa_nodes.iter() {
        total_ram_size += node.1.size;
        total_cpu_num += node.1.cpus.len() as u8;
        for idx in &node.1.cpus {
            if max_cpu_idx <= *idx {
                max_cpu_idx = *idx;
            }
        }
    }

    if total_ram_size != vm_config.machine_config.mem_config.mem_size {
        bail!(
            "Total memory {} of NUMA nodes is not equals to memory size {}",
            total_ram_size,
            vm_config.machine_config.mem_config.mem_size,
        );
    }
    if total_cpu_num != vm_config.machine_config.nr_cpus {
        bail!(
            "Total cpu numbers {} of NUMA nodes is not equals to smp {}",
            total_cpu_num,
            vm_config.machine_config.nr_cpus,
        );
    }
    if max_cpu_idx != vm_config.machine_config.nr_cpus - 1 {
        bail!("Error to configure CPU sets, please check you cmdline again");
    }

    Ok(())
}

pub fn parse_numa_mem(numa_config: &str) -> Result<NumaConfig> {
    let mut cmd_parser = CmdParser::new("numa");
    cmd_parser
        .push("")
        .push("nodeid")
        .push("cpus")
        .push("memdev");
    cmd_parser.parse(numa_config)?;

    let mut config: NumaConfig = NumaConfig::default();
    if let Some(node_id) = cmd_parser.get_value::<u32>("nodeid")? {
        if node_id >= MAX_NODES {
            return Err(ErrorKind::IllegalValue(
                "nodeid".to_string(),
                0,
                true,
                MAX_NODES as u64,
                false,
            )
            .into());
        }
        config.numa_id = node_id;
    } else {
        return Err(ErrorKind::FieldIsMissing("nodeid", "numa").into());
    }
    if let Some(cpus) = cmd_parser
        .get_value::<IntegerList>("cpus")
        .map_err(|_| ErrorKind::ConvertValueFailed(String::from("u64"), "cpus".to_string()))?
        .map(|v| v.0.iter().map(|e| *e as u8).collect())
    {
        config.cpus = cpus;
    } else {
        return Err(ErrorKind::FieldIsMissing("cpus", "numa").into());
    }
    if let Some(mem_dev) = cmd_parser.get_value::<String>("memdev")? {
        config.mem_dev = mem_dev;
    } else {
        return Err(ErrorKind::FieldIsMissing("memdev", "numa").into());
    }

    Ok(config)
}

pub fn parse_numa_distance(numa_dist: &str) -> Result<(u32, NumaDistance)> {
    let mut cmd_parser = CmdParser::new("numa");
    cmd_parser.push("").push("src").push("dst").push("val");
    cmd_parser.parse(numa_dist)?;

    let mut dist: NumaDistance = NumaDistance::default();
    let numa_id = if let Some(src) = cmd_parser.get_value::<u32>("src")? {
        if src >= MAX_NODES {
            return Err(ErrorKind::IllegalValue(
                "src".to_string(),
                0,
                true,
                MAX_NODES as u64,
                false,
            )
            .into());
        }
        src
    } else {
        return Err(ErrorKind::FieldIsMissing("src", "numa").into());
    };
    if let Some(dst) = cmd_parser.get_value::<u32>("dst")? {
        if dst >= MAX_NODES {
            return Err(ErrorKind::IllegalValue(
                "dst".to_string(),
                0,
                true,
                MAX_NODES as u64,
                false,
            )
            .into());
        }
        dist.destination = dst;
    } else {
        return Err(ErrorKind::FieldIsMissing("dst", "numa").into());
    }
    if let Some(val) = cmd_parser.get_value::<u8>("val")? {
        if val < MIN_NUMA_DISTANCE {
            bail!("NUMA distance shouldn't be less than 10");
        }
        dist.distance = val;
    } else {
        return Err(ErrorKind::FieldIsMissing("val", "numa").into());
    }

    if numa_id == dist.destination && dist.distance != MIN_NUMA_DISTANCE {
        bail!("Local distance of node {} should be 10.", numa_id);
    }

    Ok((numa_id, dist))
}

impl VmConfig {
    pub fn add_numa(&mut self, numa_config: &str) -> Result<()> {
        let mut cmd_params = CmdParser::new("numa");
        cmd_params.push("");

        cmd_params.get_parameters(numa_config)?;
        if let Some(numa_type) = cmd_params.get_value::<String>("")? {
            self.numa_nodes.push((numa_type, numa_config.to_string()));
        }

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
            .add_numa("-numa node,nodeid=0,cpus=0-1,memdev=mem0")
            .is_ok());
        assert!(vm_config
            .add_numa("-numa node,nodeid=1,cpus=2-1,memdev=mem1")
            .is_ok());
        assert!(vm_config
            .add_numa("-numa node,nodeid=2,memdev=mem2")
            .is_ok());
        assert!(vm_config.add_numa("-numa node,nodeid=3,cpus=3-4").is_ok());

        let numa = vm_config.numa_nodes.get(0).unwrap();
        let numa_config = parse_numa_mem(numa.1.as_str()).unwrap();
        assert_eq!(numa_config.cpus, vec![0, 1]);
        assert_eq!(numa_config.mem_dev, "mem0");

        let numa = vm_config.numa_nodes.get(1).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(2).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(3).unwrap();
        assert!(parse_numa_mem(numa.1.as_str()).is_err());
    }

    #[test]
    fn test_parse_numa_distance() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_numa("-numa dist,src=0,dst=1,val=10").is_ok());
        assert!(vm_config.add_numa("-numa dist,dst=1,val=10").is_ok());
        assert!(vm_config.add_numa("-numa dist,src=0,val=10").is_ok());
        assert!(vm_config.add_numa("-numa dist,src=0,dst=1").is_ok());

        let numa = vm_config.numa_nodes.get(0).unwrap();
        let dist = parse_numa_distance(numa.1.as_str()).unwrap();
        assert_eq!(dist.0, 0);
        assert_eq!(dist.1.destination, 1);
        assert_eq!(dist.1.distance, 10);

        let numa = vm_config.numa_nodes.get(1).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(2).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
        let numa = vm_config.numa_nodes.get(3).unwrap();
        assert!(parse_numa_distance(numa.1.as_str()).is_err());
    }

    #[test]
    fn test_check_numa_nodes() {
        let mut vm_config = VmConfig::default();
        vm_config.machine_config.nr_cpus = 4;
        vm_config.machine_config.mem_config.mem_size = 2147483648;

        let numa_node1 = NumaNode {
            cpus: vec![0, 1],
            distances: Default::default(),
            size: 1073741824,
        };
        let numa_node2 = NumaNode {
            cpus: vec![2, 3],
            distances: Default::default(),
            size: 1073741824,
        };

        let mut numa_nodes = BTreeMap::new();
        numa_nodes.insert(0, numa_node1);
        numa_nodes.insert(1, numa_node2);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_ok());

        let numa_node3 = NumaNode {
            cpus: vec![2],
            distances: Default::default(),
            size: 1073741824,
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(2, numa_node3);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_err());

        let numa_node4 = NumaNode {
            cpus: vec![2, 3, 4],
            distances: Default::default(),
            size: 1073741824,
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node4);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_err());

        let numa_node5 = NumaNode {
            cpus: vec![3, 4],
            distances: Default::default(),
            size: 1073741824,
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node5);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_err());

        let numa_node6 = NumaNode {
            cpus: vec![0, 1],
            distances: Default::default(),
            size: 1073741824,
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node6);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_err());

        let numa_node7 = NumaNode {
            cpus: vec![2, 3],
            distances: Default::default(),
            size: 2147483648,
        };
        numa_nodes.remove(&1);
        numa_nodes.insert(1, numa_node7);
        assert!(check_numa_node(&numa_nodes, &mut vm_config).is_err());
    }
}
