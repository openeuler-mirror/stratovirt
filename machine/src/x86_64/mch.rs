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

use anyhow::{bail, Result};
use log::error;

use crate::x86_64::standard::VENDOR_ID_INTEL;
use address_space::{Region, RegionOps};
use devices::pci::{
    config::{
        PciConfig, CLASS_CODE_HOST_BRIDGE, DEVICE_ID, PCI_CONFIG_SPACE_SIZE, SUB_CLASS_CODE,
        VENDOR_ID,
    },
    le_read_u64, le_write_u16, PciBus, PciDevBase, PciDevOps,
};
use devices::{convert_bus_mut, convert_bus_ref, Device, DeviceBase, MUT_PCI_BUS, PCI_BUS};
use util::gen_base_func;
use util::num_ops::ranges_overlap;

const DEVICE_ID_INTEL_Q35_MCH: u16 = 0x29c0;

const PCIEXBAR: u8 = 0x60;
const PCIEXBAR_ENABLE_MASK: u64 = 0x1;
const PCIEXBAR_ADDR_MASK: u64 = 0xf_f000_0000;
const PCIEXBAR_LENGTH_MASK: u64 = 0x6;
const PCIEXBAR_LENGTH_256MB: u64 = 0x0;
const PCIEXBAR_LENGTH_128MB: u64 = 0x2;
const PCIEXBAR_LENGTH_64MB: u64 = 0x4;
const PCIEXBAR_128MB_ADDR_MASK: u64 = 1 << 26;
const PCIEXBAR_64MB_ADDR_MASK: u64 = 1 << 25;
// Bit 25:3 of PCIEXBAR is reserved.
const PCIEXBAR_RESERVED_MASK: u64 = 0x3ff_fff8;

/// Memory controller hub (Device 0:Function 0)
pub struct Mch {
    base: PciDevBase,
    mmconfig_region: Option<Region>,
    mmconfig_ops: RegionOps,
}

impl Mch {
    pub fn new(
        parent_bus: Weak<Mutex<PciBus>>,
        mmconfig_region: Region,
        mmconfig_ops: RegionOps,
    ) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new("Memory Controller Hub".to_string(), false, Some(parent_bus)),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
                devfn: 0,
            },
            mmconfig_region: Some(mmconfig_region),
            mmconfig_ops,
        }
    }

    fn update_pciexbar_mapping(&mut self) -> Result<()> {
        let pciexbar: u64 = le_read_u64(&self.base.config.config, PCIEXBAR as usize)?;
        let enable = pciexbar & PCIEXBAR_ENABLE_MASK;
        let length: u64;
        let mut addr_mask: u64 = PCIEXBAR_ADDR_MASK;
        match pciexbar & PCIEXBAR_LENGTH_MASK {
            PCIEXBAR_LENGTH_256MB => length = 256 << 20,
            PCIEXBAR_LENGTH_128MB => {
                length = 128 << 20;
                addr_mask |= PCIEXBAR_128MB_ADDR_MASK;
            }
            PCIEXBAR_LENGTH_64MB => {
                length = 64 << 20;
                addr_mask |= PCIEXBAR_128MB_ADDR_MASK | PCIEXBAR_64MB_ADDR_MASK;
            }
            _ => bail!("Invalid PCIEXBAR length."),
        }

        if let Some(region) = self.mmconfig_region.as_ref() {
            let bus = self.parent_bus().unwrap().upgrade().unwrap();
            PCI_BUS!(bus, locked_bus, pci_bus);
            pci_bus.mem_region.delete_subregion(region)?;
            self.mmconfig_region = None;
        }
        if enable == 0x1 {
            let region = Region::init_io_region(length, self.mmconfig_ops.clone(), "PcieXBar");
            let base_addr: u64 = pciexbar & addr_mask;
            let bus = self.parent_bus().unwrap().upgrade().unwrap();
            PCI_BUS!(bus, locked_bus, pci_bus);
            pci_bus.mem_region.add_subregion(region, base_addr)?;
        }
        Ok(())
    }

    fn check_pciexbar_update(&self, old_pciexbar: u64) -> bool {
        let cur_pciexbar: u64 = le_read_u64(&self.base.config.config, PCIEXBAR as usize).unwrap();

        if (cur_pciexbar & !PCIEXBAR_RESERVED_MASK) == (old_pciexbar & !PCIEXBAR_RESERVED_MASK) {
            return false;
        }
        true
    }
}

impl Device for Mch {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);
}

impl PciDevOps for Mch {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    fn realize(mut self) -> Result<()> {
        self.init_write_mask(false)?;
        self.init_write_clear_mask(false)?;

        le_write_u16(
            &mut self.base.config.config,
            VENDOR_ID as usize,
            VENDOR_ID_INTEL,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            DEVICE_ID as usize,
            DEVICE_ID_INTEL_Q35_MCH,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            CLASS_CODE_HOST_BRIDGE,
        )?;

        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        MUT_PCI_BUS!(parent_bus, locked_bus, pci_bus);
        pci_bus.devices.insert(0, Arc::new(Mutex::new(self)));
        Ok(())
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let old_pciexbar: u64 = le_read_u64(&self.base.config.config, PCIEXBAR as usize).unwrap();
        self.base.config.write(offset, data, 0, None, None);
        // SAFETY: offset is no more than 0xfff.
        if ranges_overlap(offset, data.len(), PCIEXBAR as usize, 8).unwrap()
            && self.check_pciexbar_update(old_pciexbar)
        {
            if let Err(e) = self.update_pciexbar_mapping() {
                error!("{:?}", e);
            }
        }
    }
}
