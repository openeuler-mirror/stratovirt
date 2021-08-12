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

use acpi::AcpiPMTimer;
use address_space::{AddressSpace, GuestAddress, Region, RegionOps};
use error_chain::ChainedError;
use pci::config::{PciConfig, DEVICE_ID, PCI_CONFIG_SPACE_SIZE, SUB_CLASS_CODE, VENDOR_ID};
use pci::errors::Result as PciResult;
use pci::{le_write_u16, le_write_u32, ranges_overlap, PciBus, PciDevOps};
use util::byte_code::ByteCode;

use super::VENDOR_ID_INTEL;
use crate::standard_vm::errors::Result;
use pci::config::CLASS_CODE_ISA_BRIDGE;

const DEVICE_ID_INTEL_ICH9: u16 = 0x2918;

const PM_BASE_OFFSET: u8 = 0x40;
const PM_TIMER_OFFSET: u8 = 8;

/// LPC bridge of ICH9 (IO controller hub 9), Device 1F : Function 0
#[allow(clippy::upper_case_acronyms)]
pub struct LPCBridge {
    config: PciConfig,
    parent_bus: Weak<Mutex<PciBus>>,
    sys_io: Arc<AddressSpace>,
    pm_timer: Arc<Mutex<AcpiPMTimer>>,
}

impl LPCBridge {
    pub fn new(parent_bus: Weak<Mutex<PciBus>>, sys_io: Arc<AddressSpace>) -> Self {
        Self {
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus,
            sys_io,
            pm_timer: Arc::new(Mutex::new(AcpiPMTimer::new())),
        }
    }

    fn update_pm_base(&self) -> Result<()> {
        let cloned_pmtmr = self.pm_timer.clone();
        let read_ops = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_pmtmr.lock().unwrap().read(data, addr, offset)
        };
        let write_ops = move |_data: &[u8], _addr: GuestAddress, _offset: u64| -> bool { false };
        let ops = RegionOps {
            read: Arc::new(read_ops),
            write: Arc::new(write_ops),
        };
        let pmtmr_region = Region::init_io_region(0x8, ops);

        let mut pm_base_addr = 0_u32;
        self.config
            .read(PM_BASE_OFFSET as usize, pm_base_addr.as_mut_bytes());
        self.sys_io
            .root()
            .add_subregion(pmtmr_region, pm_base_addr as u64 + PM_TIMER_OFFSET as u64)?;

        Ok(())
    }
}

impl PciDevOps for LPCBridge {
    fn init_write_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> PciResult<()> {
        self.config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> PciResult<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        le_write_u16(&mut self.config.config, VENDOR_ID as usize, VENDOR_ID_INTEL)?;
        le_write_u16(
            &mut self.config.config,
            DEVICE_ID as usize,
            DEVICE_ID_INTEL_ICH9,
        )?;
        le_write_u16(
            &mut self.config.config,
            SUB_CLASS_CODE as usize,
            CLASS_CODE_ISA_BRIDGE,
        )?;
        le_write_u32(&mut self.config.write_mask, PM_BASE_OFFSET as usize, 0xff80)?;

        let parent_bus = self.parent_bus.clone();
        parent_bus
            .upgrade()
            .unwrap()
            .lock()
            .unwrap()
            .devices
            .insert(0x1F << 3, Arc::new(Mutex::new(self)));
        Ok(())
    }

    fn read_config(&self, offset: usize, data: &mut [u8]) {
        let size = data.len();
        if offset + size > PCI_CONFIG_SPACE_SIZE || size > 4 {
            debug!(
                "Failed to read LPC bridge's pci config space: offset {}, data size {}",
                offset, size
            );
            return;
        }
        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let size = data.len();
        let end = offset + size;
        if end > PCI_CONFIG_SPACE_SIZE || size > 4 {
            debug!(
                "Failed to write LPC bridge's pci config space: offset {}, data size {}",
                offset, size
            );
            return;
        }

        self.config.write(offset, data, 0);
        if ranges_overlap(
            offset,
            end,
            PM_BASE_OFFSET as usize,
            PM_BASE_OFFSET as usize + 4,
        ) {
            if let Err(e) = self.update_pm_base() {
                error!("Failed to update PM base addr: {}", e.display_chain());
                return;
            }
        }
    }

    fn name(&self) -> String {
        "ICH9 LPC bridge".to_string()
    }
}
