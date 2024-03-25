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

use machine_manager::config::{CpuConfig, PmuConfig, SveConfig};

#[derive(Copy, Clone, Debug, Default)]
pub struct ArmCPUFeatures {
    pub pmu: bool,
    pub sve: bool,
}

impl From<&CpuConfig> for ArmCPUFeatures {
    fn from(conf: &CpuConfig) -> Self {
        Self {
            pmu: match &conf.pmu {
                PmuConfig::On => true,
                PmuConfig::Off => false,
            },
            sve: match &conf.sve {
                SveConfig::On => true,
                SveConfig::Off => false,
            },
        }
    }
}

/// Entry to cpreg list.
#[derive(Default, Clone, Copy)]
pub struct CpregListEntry {
    pub reg_id: u64,
    pub value: u128,
}
