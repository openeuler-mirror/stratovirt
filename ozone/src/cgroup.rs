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

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process,
};

use crate::OzoneError;
use anyhow::{bail, Context, Result};

const MOUNT_DIR: &str = "/proc/mounts";
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

pub fn realize_cgroup(cmd_parser: &CgroupCfg, exec_file: String, name: String) -> Result<()> {
    for (file, value) in cmd_parser.iter() {
        if let Some(value_to_write) = value {
            let split: Vec<&str> = file.split('.').collect();
            let base_path = get_base_location(split[0], &exec_file, &name)?;
            write_cgroup_value(&base_path, file, value_to_write)?;
            let pid = process::id();
            write_cgroup_value(&base_path, "tasks", &pid.to_string())?;
        }
    }

    Ok(())
}

pub fn clean_cgroup(cmd_parser: &CgroupCfg, exec_file: String, name: String) -> Result<()> {
    for (file, value) in cmd_parser.iter() {
        if value.is_some() {
            let split: Vec<&str> = file.split('.').collect();
            let base_path = get_base_location(split[0], &exec_file, &name)?;
            if base_path.exists() {
                std::fs::remove_dir(&base_path).with_context(|| {
                    format!("Failed to remove cgroup directory {:?}", &base_path)
                })?;
            }
        }
    }

    Ok(())
}

pub fn clean_node(exec_file: String, name: String) -> Result<()> {
    let base_path = get_base_location("cpuset", &exec_file, &name)?;
    if base_path.exists() {
        std::fs::remove_dir(&base_path)
            .with_context(|| format!("Failed to remove cgroup directory {:?}", &base_path))?;
    }

    Ok(())
}

fn get_base_location(controller: &str, exec_file: &str, name: &str) -> Result<PathBuf> {
    let mut target_path = PathBuf::new();
    let dir = OpenOptions::new()
        .read(true)
        .write(true)
        .open(MOUNT_DIR)
        .with_context(|| "Failed to open '/proc/mounts' ")?;
    let dir_bufs = BufReader::new(dir);
    for dir in dir_bufs.lines() {
        let dir = dir.with_context(|| "Failed to read directory in directory buf")?;
        if dir.starts_with("cgroup") && dir.contains(controller) {
            let split: Vec<&str> = dir.split(' ').collect();
            target_path = PathBuf::from(split[1]);
            break;
        }
    }
    if target_path.eq(&PathBuf::new()) {
        bail!("Failed to get base location");
    }
    target_path.push(exec_file);
    target_path.push(name);
    Ok(target_path)
}

pub fn set_numa_node(node: &str, exec_file: &str, name: &str) -> Result<()> {
    let write_path = get_base_location("cpuset", exec_file, name)?;
    write_cgroup_value(&write_path, "cpuset.mems", node)
        .with_context(|| OzoneError::WriteError("cpuset.mems".to_string(), node.to_string()))?;

    let mut upper_path = write_path.clone();
    upper_path.pop();
    upper_path.push("cpuset.cpus");
    inherit_config(&write_path, "cpuset.cpus").with_context(|| {
        format!(
            "Failed to inherit configuration for path: {:?}",
            &write_path
        )
    })?;
    let value = read_file_value(upper_path.clone());
    if let Ok(val) = value {
        write_cgroup_value(&write_path, "cpuset.cpus", &val)
            .with_context(|| OzoneError::WriteError("cpuset.cpus".to_string(), val.to_string()))?;
    } else {
        bail!("Can not read value from: {:?}", &upper_path);
    }
    let pid = process::id();
    write_cgroup_value(&write_path, "tasks", &pid.to_string())
        .with_context(|| "Failed to attach pid")?;
    Ok(())
}

fn write_cgroup_value(path: &Path, file: &str, value: &str) -> Result<()> {
    if file != "tasks" {
        if !path.exists() {
            fs::create_dir_all(path)
                .with_context(|| format!("Failed to create directory: {:?}", path))?;
        }
        inherit_config(path, file)
            .with_context(|| format!("Failed to inherit configuration for path: {:?}", &path))?;
    }

    let mut path_to_write = path.to_path_buf();
    path_to_write.push(file);
    fs::write(&path_to_write, format!("{}\n", value)).with_context(|| {
        OzoneError::WriteError(
            path_to_write.to_string_lossy().to_string(),
            value.to_string(),
        )
    })?;

    Ok(())
}

fn read_file_value(path: PathBuf) -> Result<String> {
    let mut value =
        fs::read_to_string(&path).with_context(|| format!("Failed to read path: {:?}", &path))?;
    value.pop();
    Ok(value)
}

// Reason for inherit configuration:
// Ozone creates a new hierarchy: /sys/fs/cgroup/<controller>/<exec_file>/<name> in cgroup. As the value in
// current hierarchy should be a sub-aggregate of its parent hierarchy, in other words: value in "..//<controller>
// /<exec_file>/<name>/file" should be a sub-aggregate of that in "../<controller>/<exec_file>/file". However, When
// creating the hierarchy "../<controller>/<exec_file>/<name>" values in "../<controller>/<exec_file>/file" always
// be empty, which means that the attempts to set values in "../<controller>/<exec_file>/<name>/file" will fail.
// In order to address this problem, Ozone inherit configuration from "../<controller>/file" to ""../<controller>
// /<exec_file>/file".
// IF many Ozones are launched with the same "exec_file", the first launched one will inherit configuration, other ones
// will not do that.
fn inherit_config(path: &Path, file: &str) -> Result<()> {
    let upper_file = path.with_file_name(file);
    let value = read_file_value(upper_file.clone())?;
    if value.is_empty() {
        if let Some(grand_parent_dir) = upper_file.parent() {
            let grand_parent_file = grand_parent_dir.with_file_name(file);
            let upper_value = read_file_value(grand_parent_file.clone())?;
            if upper_value.is_empty() {
                bail!("File: {:?} is empty", &grand_parent_file);
            }
            fs::write(upper_file.clone(), format!("{}\n", upper_value)).with_context(|| {
                OzoneError::WriteError(
                    upper_file.to_string_lossy().to_string(),
                    upper_value.to_string(),
                )
            })?;
        } else {
            bail!("Failed to get parent directory of: {:?}", &upper_file);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    pub use super::*;

    #[test]
    fn test_parse_cgroup() {
        let mut cgroup = init_cgroup();
        assert!(parse_cgroup(&mut cgroup, "cpuset.cpus=3-4,8-9").is_ok());
        assert!(parse_cgroup(&mut cgroup, "memory.limit_in_bytes=1000000").is_ok());
        if let Some(cpuset) = cgroup.get("cpuset.cpus") {
            assert!(cpuset.is_some());
            let cpuset = cpuset.as_ref().unwrap();
            assert_eq!(cpuset, "3-4,8-9");
        } else {
            assert!(false);
        }
        if let Some(cpuset) = cgroup.get("memory.limit_in_bytes") {
            assert!(cpuset.is_some());
            let cpuset = cpuset.as_ref().unwrap();
            assert_eq!(cpuset, "1000000");
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_parse_cgroup_01() {
        let mut cgroup = init_cgroup();
        assert!(parse_cgroup(&mut cgroup, "cpuset.cus=3-4,8-9").is_err());
        assert!(parse_cgroup(&mut cgroup, "cpuset.cpus=3-4").is_ok());
        assert!(parse_cgroup(&mut cgroup, "memory.limit_bytes=1000000").is_err());
        if let Some(cpuset) = cgroup.get("cpuset.cpus") {
            assert!(cpuset.is_some());
            let cpuset = cpuset.as_ref().unwrap();
            assert_eq!(cpuset, "3-4");
        } else {
            assert!(false);
        }
        assert!(cgroup.get("memory.limit_in_bytes").unwrap().is_none());
    }
}
