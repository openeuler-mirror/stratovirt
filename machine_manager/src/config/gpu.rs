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

use super::{error::ConfigError, M};
use crate::config::{CmdParser, ConfigCheck, MAX_STRING_LENGTH};
use anyhow::{anyhow, Result};
use log::warn;

/// The maximum number of scanouts.
pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

pub const VIRTIO_GPU_MAX_HOSTMEM: u64 = 256 * M;

#[derive(Clone, Debug)]
pub struct GpuConfig {
    pub id: String,
    pub max_outputs: u32,
    pub edid: bool,
    pub xres: u32,
    pub yres: u32,
    pub max_hostmem: u64,
}

impl Default for GpuConfig {
    fn default() -> Self {
        GpuConfig {
            id: "".to_string(),
            max_outputs: 1,
            edid: true,
            xres: 1024,
            yres: 768,
            max_hostmem: VIRTIO_GPU_MAX_HOSTMEM,
        }
    }
}

impl ConfigCheck for GpuConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "id".to_string(),
                MAX_STRING_LENGTH
            )));
        }

        if self.max_outputs > VIRTIO_GPU_MAX_SCANOUTS as u32 {
            return Err(anyhow!(ConfigError::UnitIdError(
                "max_outputs".to_string(),
                self.max_outputs as usize,
                VIRTIO_GPU_MAX_SCANOUTS,
            )));
        }

        if self.max_hostmem < VIRTIO_GPU_MAX_HOSTMEM {
            warn!(
                "max_hostmem must >= {}, allocating less than it may cause \
                the GPU to fail to start or refresh.",
                VIRTIO_GPU_MAX_HOSTMEM
            );
        }

        Ok(())
    }
}

pub fn parse_gpu(gpu_config: &str) -> Result<GpuConfig> {
    let mut cmd_parser = CmdParser::new("virtio-gpu-pci");
    cmd_parser
        .push("")
        .push("id")
        .push("max_outputs")
        .push("edid")
        .push("xres")
        .push("yres")
        .push("max_hostmem")
        .push("bus")
        .push("addr");
    cmd_parser.parse(gpu_config)?;

    let mut gpu_cfg: GpuConfig = GpuConfig::default();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        gpu_cfg.id = id;
    }
    if let Some(max_outputs) = cmd_parser.get_value::<u32>("max_outputs")? {
        gpu_cfg.max_outputs = max_outputs;
    }
    if let Some(edid) = cmd_parser.get_value::<bool>("edid")? {
        gpu_cfg.edid = edid;
    }
    if let Some(xres) = cmd_parser.get_value::<u32>("xres")? {
        gpu_cfg.xres = xres;
    }
    if let Some(yres) = cmd_parser.get_value::<u32>("yres")? {
        gpu_cfg.yres = yres;
    }
    if let Some(max_hostmem) = cmd_parser.get_value::<u64>("max_hostmem")? {
        gpu_cfg.max_hostmem = max_hostmem;
    }
    gpu_cfg.check()?;

    Ok(gpu_cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gpu_max_hostmem_greater_than_limit() {
        let max_hostmem = VIRTIO_GPU_MAX_HOSTMEM + 1;
        let gpu_cfg_cmdline = format!(
            "{}{}",
            "virtio-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,\
            max_outputs=1,edid=true,xres=1024,yres=768,max_hostmem=",
            max_hostmem.to_string()
        );

        let gpu_cfg_ = parse_gpu(&gpu_cfg_cmdline);

        assert!(gpu_cfg_.is_ok());

        let gpu_cfg = gpu_cfg_.unwrap();
        assert_eq!(gpu_cfg.max_hostmem, max_hostmem);
    }

    #[test]
    fn test_parse_gpu_max_hostmem_less_than_limit() {
        let max_hostmem = VIRTIO_GPU_MAX_HOSTMEM - 1;
        let gpu_cfg_cmdline = format!(
            "{}{}",
            "virtio-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,\
            max_outputs=1,edid=true,xres=1024,yres=768,max_hostmem=",
            max_hostmem.to_string()
        );

        let gpu_cfg_ = parse_gpu(&gpu_cfg_cmdline);

        assert!(gpu_cfg_.is_ok());

        let gpu_cfg = gpu_cfg_.unwrap();
        assert_eq!(gpu_cfg.max_hostmem, max_hostmem);
    }
}
