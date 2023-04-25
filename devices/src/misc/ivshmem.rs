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

use anyhow::bail;

use address_space::{GuestAddress, Region, RegionOps};
use pci::{
    config::{
        PciConfig, RegionType, DEVICE_ID, PCI_CLASS_MEMORY_RAM, PCI_CONFIG_SPACE_SIZE,
        PCI_VENDOR_ID_REDHAT_QUMRANET, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
    },
    le_write_u16, PciBus, PciDevOps,
};

const PCI_VENDOR_ID_IVSHMEM: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;
const PCI_DEVICE_ID_IVSHMEM: u16 = 0x1110;
const PCI_REVIRSION_ID_IVSHMEM: u8 = 1;

const PCI_BAR_MAX_IVSHMEM: u8 = 3;

const IVSHMEM_REG_BAR_SIZE: u64 = 0x100;

/// Intel-VM shared memory device structure.
pub struct Ivshmem {
    config: PciConfig,
    devfn: u8,
    dev_id: Arc<AtomicU16>,
    name: String,
    parent_bus: Weak<Mutex<PciBus>>,
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
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, PCI_BAR_MAX_IVSHMEM),
            devfn,
            dev_id: Arc::new(AtomicU16::new(0)),
            name,
            parent_bus,
            ram_mem_region,
        }
    }

    fn register_bars(&mut self) -> pci::Result<()> {
        // Currently, ivshmem uses only the shared memory and does not use interrupt.
        // Therefore, bar0 read and write callback is not implemented.
        let reg_read = move |_: &mut [u8], _: GuestAddress, _: u64| -> bool { true };
        let reg_write = move |_: &[u8], _: GuestAddress, _: u64| -> bool { true };
        let reg_region_ops = RegionOps {
            read: Arc::new(reg_read),
            write: Arc::new(reg_write),
        };

        // bar0: mmio register
        self.config.register_bar(
            0,
            Region::init_io_region(IVSHMEM_REG_BAR_SIZE, reg_region_ops),
            RegionType::Mem64Bit,
            false,
            IVSHMEM_REG_BAR_SIZE,
        )?;

        // bar2: ram
        self.config.register_bar(
            2,
            self.ram_mem_region.clone(),
            RegionType::Mem64Bit,
            true,
            self.ram_mem_region.size(),
        )
    }
}

impl PciDevOps for Ivshmem {
    fn realize(mut self) -> pci::Result<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;
        le_write_u16(
            &mut self.config.config,
            VENDOR_ID as usize,
            PCI_VENDOR_ID_IVSHMEM,
        )?;
        le_write_u16(
            &mut self.config.config,
            DEVICE_ID as usize,
            PCI_DEVICE_ID_IVSHMEM,
        )?;
        self.config.config[REVISION_ID] = PCI_REVIRSION_ID_IVSHMEM;

        le_write_u16(
            &mut self.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_MEMORY_RAM,
        )?;

        self.register_bars()?;

        // Attach to the PCI bus.
        let pci_bus = self.parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let pci_device = locked_pci_bus.devices.get(&self.devfn);
        match pci_device {
            Some(device) => bail!(
                "Devfn {:?} has been used by {:?}",
                &self.devfn,
                device.lock().unwrap().name()
            ),
            None => locked_pci_bus
                .devices
                .insert(self.devfn, Arc::new(Mutex::new(self))),
        };
        Ok(())
    }

    fn init_write_mask(&mut self) -> pci::Result<()> {
        self.config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> pci::Result<()> {
        self.config.init_common_write_clear_mask()
    }

    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();

        self.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&locked_parent_bus.io_region),
            Some(&locked_parent_bus.mem_region),
        );
    }

    fn name(&self) -> String {
        self.name.clone()
    }
}
