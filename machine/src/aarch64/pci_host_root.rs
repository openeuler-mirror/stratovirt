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

use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;

use devices::pci::{
    config::{
        PciConfig, CLASS_CODE_HOST_BRIDGE, DEVICE_ID, PCI_CONFIG_SPACE_SIZE, PCI_VENDOR_ID_REDHAT,
        REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
    },
    le_write_u16, PciBus, PciDevBase, PciDevOps,
};
use devices::{Device, DeviceBase};

const DEVICE_ID_PCIE_HOST: u16 = 0x0008;

/// PciHost root (Device 0:Function 0).
pub struct PciHostRoot {
    base: PciDevBase,
}

impl PciHostRoot {
    pub fn new(parent_bus: Weak<Mutex<PciBus>>) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new("PCI Host Root".to_string(), false),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
                parent_bus,
                devfn: 0,
            },
        }
    }
}

impl Device for PciHostRoot {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl PciDevOps for PciHostRoot {
    fn pci_base(&self) -> &PciDevBase {
        &self.base
    }

    fn pci_base_mut(&mut self) -> &mut PciDevBase {
        &mut self.base
    }

    fn realize(mut self) -> Result<()> {
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

        let parent_bus = self.base.parent_bus.upgrade().unwrap();
        parent_bus
            .lock()
            .unwrap()
            .devices
            .insert(0, Arc::new(Mutex::new(self)));
        Ok(())
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        self.base.config.write(offset, data, 0, None);
    }
}
