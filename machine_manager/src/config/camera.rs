// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use crate::{
    config::{check_arg_nonexist, check_id, CmdParser, ConfigCheck, VmConfig},
    qmp::qmp_schema,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CameraDevConfig {
    pub id: Option<String>,
    pub path: Option<String>,
    pub backend: CamBackendType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CamBackendType {
    V4l2,
    Demo,
}

impl FromStr for CamBackendType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "v4l2" => Ok(CamBackendType::V4l2),
            "demo" => Ok(CamBackendType::Demo),
            _ => Err(anyhow!("Unknown camera backend type")),
        }
    }
}

impl CameraDevConfig {
    pub fn new() -> CameraDevConfig {
        CameraDevConfig {
            id: None,
            path: None,
            backend: CamBackendType::V4l2,
        }
    }
}

impl Default for CameraDevConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl VmConfig {
    pub fn add_camera_backend(&mut self, camera_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("cameradev");
        cmd_parser.push("").push("id").push("path");
        cmd_parser.get_parameters(camera_config)?;

        let mut camera_backend = CameraDevConfig::new();
        camera_backend.backend = cmd_parser.get_value::<CamBackendType>("")?.unwrap();
        camera_backend.id = cmd_parser.get_value::<String>("id")?;
        camera_backend.path = cmd_parser.get_value::<String>("path")?;

        camera_backend.check()?;

        self.add_cameradev_with_config(camera_backend)
    }

    fn camera_backend_repeated(&self, id: &str, path: &str, backend: CamBackendType) -> bool {
        for (key, cam) in self.camera_backend.iter() {
            if key != id && cam.backend == backend && cam.path == Some(path.to_string()) {
                return true;
            }
        }

        false
    }

    pub fn add_cameradev_with_config(&mut self, conf: CameraDevConfig) -> Result<()> {
        let cameradev_id = conf
            .id
            .clone()
            .with_context(|| "no id configured for cameradev")?;
        let cameradev_path = conf
            .path
            .clone()
            .with_context(|| "no path configured for cameradev")?;
        let cameradev_backend = conf.backend;

        let cam = self.camera_backend.get(&cameradev_id);

        if cam.is_some() {
            bail!("cameradev with id {:?} has already existed", cameradev_id);
        }

        if self.camera_backend_repeated(&cameradev_id, &cameradev_path, cameradev_backend) {
            bail!("another cameradev has the same backend device");
        }

        self.camera_backend.insert(cameradev_id, conf);

        Ok(())
    }

    pub fn del_cameradev_by_id(&mut self, id: &str) -> Result<()> {
        if self.camera_backend.get(&id.to_string()).is_none() {
            bail!("no cameradev with id {}", id);
        }
        self.camera_backend.remove(&id.to_string());

        Ok(())
    }
}

impl ConfigCheck for CameraDevConfig {
    fn check(&self) -> Result<()> {
        // Note: backend has already been checked during args parsing.
        check_id(self.id.clone(), "cameradev")?;
        check_camera_path(self.path.clone())
    }
}

fn check_camera_path(path: Option<String>) -> Result<()> {
    check_arg_nonexist(path.clone(), "path", "cameradev")?;

    let path = path.unwrap();
    if !Path::new(&path).exists() {
        bail!(ConfigError::FileNotExist(path));
    }

    Ok(())
}

pub fn get_cameradev_config(args: qmp_schema::CameraDevAddArgument) -> Result<CameraDevConfig> {
    let config = CameraDevConfig {
        id: Some(args.id),
        path: args.path,
        backend: CamBackendType::from_str(&args.driver)?,
    };

    Ok(config)
}

pub fn get_cameradev_by_id(vm_config: &mut VmConfig, id: String) -> Option<CameraDevConfig> {
    vm_config.camera_backend.get(&id).cloned()
}
