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

use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::{
    config::{str_slip_to_clap, valid_id, VmConfig},
    qmp::qmp_schema,
};

#[derive(Parser, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[command(name = "camera device")]
pub struct CameraDevConfig {
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub backend: CamBackendType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CamBackendType {
    #[cfg(feature = "usb_camera_v4l2")]
    V4l2,
    #[cfg(all(target_env = "ohos", feature = "usb_camera_oh"))]
    OhCamera,
    #[cfg(not(target_env = "ohos"))]
    Demo,
}

impl FromStr for CamBackendType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            #[cfg(feature = "usb_camera_v4l2")]
            "v4l2" => Ok(CamBackendType::V4l2),
            #[cfg(all(target_env = "ohos", feature = "usb_camera_oh"))]
            "ohcamera" => Ok(CamBackendType::OhCamera),
            #[cfg(not(target_env = "ohos"))]
            "demo" => Ok(CamBackendType::Demo),
            _ => Err(anyhow!("Unknown camera backend type")),
        }
    }
}

impl VmConfig {
    pub fn add_camera_backend(&mut self, camera_config: &str) -> Result<()> {
        let cfg = format!("cameradev,backend={}", camera_config);
        let config = CameraDevConfig::try_parse_from(str_slip_to_clap(&cfg))?;

        self.add_cameradev_with_config(config)
    }

    fn camera_backend_repeated(&self, id: &str, path: &str, backend: CamBackendType) -> bool {
        for (key, cam) in self.camera_backend.iter() {
            if key != id && cam.backend == backend && cam.path == *path {
                return true;
            }
        }

        false
    }

    pub fn add_cameradev_with_config(&mut self, conf: CameraDevConfig) -> Result<()> {
        let cam = self.camera_backend.get(&conf.id);

        if cam.is_some() {
            bail!("cameradev with id {:?} has already existed", conf.id);
        }

        if self.camera_backend_repeated(&conf.id, &conf.path, conf.backend) {
            bail!("another cameradev has the same backend device");
        }

        self.camera_backend.insert(conf.id.clone(), conf);

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

pub fn get_cameradev_config(args: qmp_schema::CameraDevAddArgument) -> Result<CameraDevConfig> {
    let path = args.path.with_context(|| "cameradev config path is null")?;
    let config = CameraDevConfig {
        id: args.id,
        path,
        backend: CamBackendType::from_str(&args.driver)?,
    };

    Ok(config)
}

pub fn get_cameradev_by_id(vm_config: &mut VmConfig, id: String) -> Option<CameraDevConfig> {
    vm_config.camera_backend.get(&id).cloned()
}
