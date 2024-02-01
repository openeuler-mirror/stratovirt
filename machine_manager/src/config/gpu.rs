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

use anyhow::{anyhow, Result};
use log::warn;

use super::{error::ConfigError, M};
use crate::config::{check_arg_too_long, CmdParser, ConfigCheck};

/// The maximum number of outputs.
pub const VIRTIO_GPU_MAX_OUTPUTS: usize = 16;

pub const VIRTIO_GPU_MAX_HOSTMEM: u64 = 256 * M;

/// The bar0 size of enable_bar0 features
pub const VIRTIO_GPU_ENABLE_BAR0_SIZE: u64 = 64 * M;

#[derive(Clone, Debug)]
pub struct GpuDevConfig {
    pub id: String,
    pub max_outputs: u32,
    pub edid: bool,
    pub xres: u32,
    pub yres: u32,
    pub max_hostmem: u64,
    pub enable_bar0: bool,
}

impl Default for GpuDevConfig {
    fn default() -> Self {
        GpuDevConfig {
            id: "".to_string(),
            max_outputs: 1,
            edid: true,
            xres: 1024,
            yres: 768,
            max_hostmem: VIRTIO_GPU_MAX_HOSTMEM,
            enable_bar0: false,
        }
    }
}

impl ConfigCheck for GpuDevConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "id")?;
        if self.max_outputs > VIRTIO_GPU_MAX_OUTPUTS as u32 || self.max_outputs == 0 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "max_outputs".to_string(),
                0,
                false,
                VIRTIO_GPU_MAX_OUTPUTS as u64,
                true
            )));
        }

        if self.max_hostmem == 0 {
            return Err(anyhow!(ConfigError::IllegalValueUnilateral(
                "max_hostmem".to_string(),
                true,
                false,
                0
            )));
        }

        if self.max_hostmem < VIRTIO_GPU_MAX_HOSTMEM {
            warn!(
                "max_hostmem should >= {}, allocating less than it may cause \
                the GPU to fail to start or refresh.",
                VIRTIO_GPU_MAX_HOSTMEM
            );
        }

        Ok(())
    }
}

pub fn parse_gpu(gpu_config: &str) -> Result<GpuDevConfig> {
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
        .push("addr")
        .push("enable_bar0");
    cmd_parser.parse(gpu_config)?;

    let mut gpu_cfg: GpuDevConfig = GpuDevConfig::default();
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
    if let Some(enable_bar0) = cmd_parser.get_value::<bool>("enable_bar0")? {
        gpu_cfg.enable_bar0 = enable_bar0;
    }
    gpu_cfg.check()?;

    Ok(gpu_cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pci_gpu_config_cmdline_parser() {
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
        assert_eq!(gpu_cfg.id, "gpu_1");
        assert_eq!(gpu_cfg.max_outputs, 1);
        assert_eq!(gpu_cfg.edid, true);
        assert_eq!(gpu_cfg.xres, 1024);
        assert_eq!(gpu_cfg.yres, 768);
        assert_eq!(gpu_cfg.max_hostmem, max_hostmem);

        // max_outputs is illegal
        let gpu_cfg_cmdline = format!(
            "{}{}",
            "virtio-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,\
            max_outputs=17,edid=true,xres=1024,yres=768,max_hostmem=",
            max_hostmem.to_string()
        );
        let gpu_cfg_ = parse_gpu(&gpu_cfg_cmdline);
        assert!(gpu_cfg_.is_err());

        let gpu_cfg_cmdline = format!(
            "{}{}",
            "virtio-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,\
            max_outputs=0,edid=true,xres=1024,yres=768,max_hostmem=",
            max_hostmem.to_string()
        );
        let gpu_cfg_ = parse_gpu(&gpu_cfg_cmdline);
        assert!(gpu_cfg_.is_err());

        // max_hostmem is illegal
        let gpu_cfg_cmdline = "virtio-gpu-pci,id=gpu_1,bus=pcie.0,addr=0x4.0x0,\
            max_outputs=1,edid=true,xres=1024,yres=768,max_hostmem=0";
        let gpu_cfg_ = parse_gpu(&gpu_cfg_cmdline);
        assert!(gpu_cfg_.is_err());
    }
}
