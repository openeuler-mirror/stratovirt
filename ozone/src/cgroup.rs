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

use std::collections::HashMap;

use crate::Result;

const CGROUP_ALLOW_LIST: [&str; 2] = ["cpuset.cpus", "memory.limit_in_bytes"];
pub type CgroupCfg = HashMap<String, Option<String>>;

pub fn init_cgroup() -> CgroupCfg {
    let mut cgroup: CgroupCfg = HashMap::new();
    for item in CGROUP_ALLOW_LIST.iter() {
        cgroup.insert(item.to_string(), None);
    }
    cgroup
}

pub fn parse_cgroup(cgroup: &mut CgroupCfg, config: &str) -> Result<()> {
    let split: Vec<&str> = config.split('=').collect();
    if split.len() != 2 {
        bail!("Invalid parameter: {:?}", &config);
    }
    if cgroup.contains_key(split[0]) {
        if cgroup.get(split[0]).unwrap().is_some() {
            bail!("{} has been set more than once", &split[0]);
        }
        cgroup.insert(split[0].to_string(), Some(split[1].to_string()));
    } else {
        bail!("Unknown argument: {:?}", &split[0]);
    }
    Ok(())
}
