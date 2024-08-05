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
    Arc, Mutex, RwLock, Weak,
};

use anyhow::Result;
use log::error;

use crate::pci::config::{
    PciConfig, RegionType, DEVICE_ID, PCI_CLASS_MEMORY_RAM, PCI_CONFIG_SPACE_SIZE,
    PCI_VENDOR_ID_REDHAT_QUMRANET, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use crate::pci::msix::init_msix;
use crate::pci::{le_write_u16, PciBus, PciDevBase, PciDevOps};
use crate::{convert_bus_ref, Bus, Device, DeviceBase, PCI_BUS};
use address_space::{GuestAddress, Region, RegionOps};
use util::gen_base_func;

const PCI_VENDOR_ID_IVSHMEM: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;
const PCI_DEVICE_ID_IVSHMEM: u16 = 0x1110;
const PCI_REVIRSION_ID_IVSHMEM: u8 = 1;

const PCI_BAR_MAX_IVSHMEM: u8 = 3;

const IVSHMEM_REG_BAR_SIZE: u64 = 0x100;

const IVSHMEM_BAR0_IRQ_MASK: u64 = 0;
const IVSHMEM_BAR0_IRQ_STATUS: u64 = 4;
const IVSHMEM_BAR0_IVPOSITION: u64 = 8;
const IVSHMEM_BAR0_DOORBELL: u64 = 12;

type Bar0Write = dyn Fn(&[u8], u64) -> bool + Send + Sync;
type Bar0Read = dyn Fn(&mut [u8], u64) -> bool + Send + Sync;

#[derive(Default)]
struct Bar0Ops {
    write: Option<Arc<Bar0Write>>,
    read: Option<Arc<Bar0Read>>,
}

/// Intel-VM shared memory device structure.
pub struct Ivshmem {
    base: PciDevBase,
    dev_id: Arc<AtomicU16>,
    ram_mem_region: Region,
    vector_nr: u32,
    bar0_ops: Arc<RwLock<Bar0Ops>>,
}

impl Ivshmem {
    pub fn new(
        name: String,
        devfn: u8,
        parent_bus: Weak<Mutex<dyn Bus>>,
        ram_mem_region: Region,
        vector_nr: u32,
    ) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(name, false, Some(parent_bus)),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, PCI_BAR_MAX_IVSHMEM),
                devfn,
            },
            dev_id: Arc::new(AtomicU16::new(0)),
            ram_mem_region,
            vector_nr,
            bar0_ops: Arc::new(RwLock::new(Bar0Ops::default())),
        }
    }

    fn register_bars(&mut self) -> Result<()> {
        // Currently, ivshmem does not support intx interrupt, ivposition and doorbell.
        let bar0_ops = self.bar0_ops.clone();
        let reg_read = move |data: &mut [u8], _: GuestAddress, offset: u64| -> bool {
            if offset >= IVSHMEM_REG_BAR_SIZE {
                error!("ivshmem: read offset {} exceeds bar0 size", offset);
                return true;
            }
            match offset {
                IVSHMEM_BAR0_IRQ_MASK | IVSHMEM_BAR0_IRQ_STATUS | IVSHMEM_BAR0_IVPOSITION => {}
                _ => {
                    if let Some(rcb) = bar0_ops.read().unwrap().read.as_ref() {
                        return rcb(data, offset);
                    }
                }
            }
            true
        };
        let bar0_ops = self.bar0_ops.clone();
        let reg_write = move |data: &[u8], _: GuestAddress, offset: u64| -> bool {
            if offset >= IVSHMEM_REG_BAR_SIZE {
                error!("ivshmem: write offset {} exceeds bar0 size", offset);
                return true;
            }
            match offset {
                IVSHMEM_BAR0_IRQ_MASK | IVSHMEM_BAR0_IRQ_STATUS | IVSHMEM_BAR0_DOORBELL => {}
                _ => {
                    if let Some(wcb) = bar0_ops.read().unwrap().write.as_ref() {
                        return wcb(data, offset);
                    }
                }
            }
            true
        };
        let reg_region_ops = RegionOps {
            read: Arc::new(reg_read),
            write: Arc::new(reg_write),
        };

        // bar0: mmio register
        self.base.config.register_bar(
            0,
            Region::init_io_region(IVSHMEM_REG_BAR_SIZE, reg_region_ops, "IvshmemIo"),
            RegionType::Mem32Bit,
            false,
            IVSHMEM_REG_BAR_SIZE,
        )?;

        // bar1: msix
        if self.vector_nr > 0 {
            init_msix(
                &mut self.base,
                1,
                self.vector_nr,
                self.dev_id.clone(),
                None,
                None,
            )?;
        }

        // bar2: ram
        self.base.config.register_bar(
            2,
            self.ram_mem_region.clone(),
            RegionType::Mem64Bit,
            true,
            self.ram_mem_region.size(),
        )
    }

    pub fn trigger_msix(&self, vector: u16) {
        if self.vector_nr == 0 {
            return;
        }
        if let Some(msix) = self.base.config.msix.as_ref() {
            msix.lock()
                .unwrap()
                .notify(vector, self.dev_id.load(Ordering::Acquire));
        }
    }

    pub fn set_bar0_ops(&mut self, bar0_ops: (Arc<Bar0Write>, Arc<Bar0Read>)) {
        self.bar0_ops.write().unwrap().write = Some(bar0_ops.0);
        self.bar0_ops.write().unwrap().read = Some(bar0_ops.1);
    }
}

impl Device for Ivshmem {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
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
        let bus = self.parent_bus().unwrap().upgrade().unwrap();
        PCI_BUS!(bus, locked_bus, pci_bus);
        self.dev_id
            .store(pci_bus.generate_dev_id(self.base.devfn), Ordering::Release);
        let dev = Arc::new(Mutex::new(self));
        locked_bus.attach_child(dev.lock().unwrap().base.devfn as u64, dev.clone())?;
        Ok(dev)
    }
}

impl PciDevOps for Ivshmem {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        PCI_BUS!(parent_bus, locked_bus, pci_bus);

        self.base.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&pci_bus.io_region),
            Some(&pci_bus.mem_region),
        );
    }
}
