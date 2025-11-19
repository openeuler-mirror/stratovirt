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

use std::sync::{atomic::AtomicBool, Arc, Mutex, Weak};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use devices::pci::config::{
    PciConfig, CLASS_CODE_HOST_BRIDGE, DEVICE_ID, PCI_CONFIG_SPACE_SIZE, PCI_VENDOR_ID_REDHAT,
    REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use devices::pci::{le_write_u16, PciDevBase, PciDevOps, PciState};
use devices::{Bus, Device, DeviceBase};
use migration::{DeviceStateDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::DescSerde;
use util::gen_base_func;

const DEVICE_ID_PCIE_HOST: u16 = 0x0008;

/// PciHost root (Device 0:Function 0).
pub struct PciHostRoot {
    base: PciDevBase,
}

impl PciHostRoot {
    pub fn new(parent_bus: Weak<Mutex<dyn Bus>>) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new("PCI Host Root".to_string(), false, Some(parent_bus)),
                config: PciConfig::new(0, PCI_CONFIG_SPACE_SIZE, 0),
                devfn: 0,
                bme: Arc::new(AtomicBool::new(false)),
            },
        }
    }
}

impl Device for PciHostRoot {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        self.init_write_mask(false)?;
        self.init_write_clear_mask(false)?;

        le_write_u16(
            &mut self.base.config.config,
            VENDOR_ID as usize,
            PCI_VENDOR_ID_REDHAT,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            DEVICE_ID as usize,
            DEVICE_ID_PCIE_HOST,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            CLASS_CODE_HOST_BRIDGE,
        )?;
        le_write_u16(&mut self.base.config.config, REVISION_ID, 0)?;

        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        let mut locked_bus = parent_bus.lock().unwrap();
        let name = self.name();
        let dev = Arc::new(Mutex::new(self));
        locked_bus.attach_child(0, dev.clone())?;

        MigrationManager::register_device_instance(
            PciHostRootState::descriptor(),
            dev.clone(),
            &name,
        );

        Ok(dev)
    }
}

impl PciDevOps for PciHostRoot {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        self.base.config.write(offset, data, 0, None);
    }
}

#[derive(Clone, DescSerde, Serialize, Deserialize)]
#[desc_version(current_version = "0.1.0")]
struct PciHostRootState {
    pci_state: PciState,
}

impl StateTransfer for PciHostRoot {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let state = PciHostRootState {
            pci_state: self.base.get_pci_state(),
        };

        Ok(serde_json::to_vec(&state)?)
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let pci_host_root: PciHostRootState = serde_json::from_slice(state)
            .with_context(|| MigrationError::FromBytesError("PciHostRootState"))?;

        self.base.set_pci_state(&pci_host_root.pci_state);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&PciHostRootState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for PciHostRoot {}
