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

use anyhow::{bail, Context, Result};
use machine_manager::config::{CpuConfig, CpuFeatureState};

#[derive(Copy, Clone, Debug)]
pub struct ArmCPUFeatures {
    pub pmu: CpuFeatureState,
    pub sve: CpuFeatureState,
    pub bti: CpuFeatureState,
    pub steal_time: CpuFeatureState,
}

impl Default for ArmCPUFeatures {
    fn default() -> Self {
        Self::from(&CpuConfig::default())
    }
}

impl From<&CpuConfig> for ArmCPUFeatures {
    fn from(conf: &CpuConfig) -> Self {
        Self {
            pmu: conf.pmu,
            sve: conf.sve,
            bti: conf.bti,
            steal_time: conf.steal_time,
        }
    }
}

/// Entry to cpreg list.
#[derive(Default, Clone, Copy, Debug)]
pub struct CpregListEntry {
    pub reg_id: u64,
    pub value: u128,
}

pub struct IdFeatureField {
    pub name: &'static str,
    pub reg_id: u64,
    pub mask: u64,
    pub policy: CpuFeatureState,
}

impl IdFeatureField {
    pub fn apply<R, W>(&self, read_reg: R, write_reg: W) -> Result<()>
    where
        R: FnOnce(u64) -> Result<u128>,
        W: FnOnce(u64, u128) -> Result<()>,
    {
        match self.policy {
            CpuFeatureState::Auto => Ok(()),
            CpuFeatureState::On => {
                let mask = u128::from(self.mask);
                let value = read_reg(self.reg_id)
                    .with_context(|| format!("Failed to read ID register for {}", self.name))?;
                if value & mask == 0 {
                    bail!("{} is not supported by the host", self.name);
                }
                Ok(())
            }
            CpuFeatureState::Off => {
                let mask = u128::from(self.mask);
                let mut value = read_reg(self.reg_id)
                    .with_context(|| format!("Failed to read ID register for {}", self.name))?;
                if value & mask == 0 {
                    return Ok(());
                }
                value &= !mask;
                write_reg(self.reg_id, value).with_context(|| {
                    format!(
                        "Failed to disable {} via writable ID register field",
                        self.name
                    )
                })
            }
        }
    }
}
