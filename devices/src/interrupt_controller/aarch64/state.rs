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

use anyhow::Result;

use super::gicv3::{GICv3, GICv3Its};
use migration::{MigrationHook, StateTransfer};

impl GICv3 {
    pub(crate) fn reset_gic_state(&self) -> Result<()> {
        self.hypervisor_gic.reset_gic_state()
    }
}

impl StateTransfer for GICv3 {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.hypervisor_gic.get_state_vec()
    }

    fn set_state(&self, state: &[u8], _version: u32) -> Result<()> {
        self.hypervisor_gic.set_state(state)
    }

    fn get_device_alias(&self) -> u64 {
        self.hypervisor_gic.get_device_alias()
    }
}

impl MigrationHook for GICv3 {}

impl StateTransfer for GICv3Its {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.its_handler.get_state_vec()
    }

    fn set_state(&self, state: &[u8], _version: u32) -> Result<()> {
        self.its_handler.set_state(state)
    }

    fn get_device_alias(&self) -> u64 {
        self.its_handler.get_device_alias()
    }
}

impl MigrationHook for GICv3Its {}
