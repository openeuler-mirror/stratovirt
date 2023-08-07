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

use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc, Mutex, Weak,
};

use anyhow::{bail, Result};

use crate::pci::{
    config::{
        PciConfig, RegionType, DEVICE_ID, PCI_CLASS_MEMORY_RAM, PCI_CONFIG_SPACE_SIZE,
        PCI_VENDOR_ID_REDHAT_QUMRANET, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
    },
    le_write_u16, PciBus, PciDevBase, PciDevOps,
};
use crate::{Device, DeviceBase};
use address_space::{GuestAddress, Region, RegionOps};

const PCI_VENDOR_ID_IVSHMEM: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;
const PCI_DEVICE_ID_IVSHMEM: u16 = 0x1110;
const PCI_REVIRSION_ID_IVSHMEM: u8 = 1;

const PCI_BAR_MAX_IVSHMEM: u8 = 3;

const IVSHMEM_REG_BAR_SIZE: u64 = 0x100;

/// Intel-VM shared memory device structure.
pub struct Ivshmem {
    base: PciDevBase,
    dev_id: Arc<AtomicU16>,
    ram_mem_region: Region,
}

impl Ivshmem {
    pub fn new(
        name: String,
        devfn: u8,
        parent_bus: Weak<Mutex<PciBus>>,
        ram_mem_region: Region,
    ) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(name, false),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, PCI_BAR_MAX_IVSHMEM),
                devfn,
                parent_bus,
            },
            dev_id: Arc::new(AtomicU16::new(0)),
            ram_mem_region,
        }
    }

    fn register_bars(&mut self) -> Result<()> {
        // Currently, ivshmem uses only the shared memory and does not use interrupt.
        // Therefore, bar0 read and write callback is not implemented.
        let reg_read = move |_: &mut [u8], _: GuestAddress, _: u64| -> bool { true };
        let reg_write = move |_: &[u8], _: GuestAddress, _: u64| -> bool { true };
        let reg_region_ops = RegionOps {
            read: Arc::new(reg_read),
            write: Arc::new(reg_write),
        };

        // bar0: mmio register
        self.base.config.register_bar(
            0,
            Region::init_io_region(IVSHMEM_REG_BAR_SIZE, reg_region_ops, "IvshmemIo"),
            RegionType::Mem64Bit,
            false,
            IVSHMEM_REG_BAR_SIZE,
        )?;

        // bar2: ram
        self.base.config.register_bar(
            2,
            self.ram_mem_region.clone(),
            RegionType::Mem64Bit,
            true,
            self.ram_mem_region.size(),
        )
    }
}

impl Device for Ivshmem {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl PciDevOps for Ivshmem {
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
            PCI_VENDOR_ID_IVSHMEM,
        )?;
        le_write_u16(
            &mut self.base.config.config,
            DEVICE_ID as usize,
            PCI_DEVICE_ID_IVSHMEM,
        )?;
        self.base.config.config[REVISION_ID] = PCI_REVIRSION_ID_IVSHMEM;

        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_MEMORY_RAM,
        )?;

        self.register_bars()?;

        // Attach to the PCI bus.
        let pci_bus = self.base.parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let pci_device = locked_pci_bus.devices.get(&self.base.devfn);
        match pci_device {
            Some(device) => bail!(
                "Devfn {:?} has been used by {:?}",
                &self.base.devfn,
                device.lock().unwrap().name()
            ),
            None => locked_pci_bus
                .devices
                .insert(self.base.devfn, Arc::new(Mutex::new(self))),
        };
        Ok(())
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.base.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();

        self.base.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&locked_parent_bus.io_region),
            Some(&locked_parent_bus.mem_region),
        );
    }
}
