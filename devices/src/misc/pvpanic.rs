// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Context, Result};
use log::{debug, error, info};

use crate::pci::{
    config::{
        PciConfig, RegionType, DEVICE_ID, HEADER_TYPE, PCI_CONFIG_SPACE_SIZE,
        PCI_DEVICE_ID_REDHAT_PVPANIC, PCI_VENDOR_ID_REDHAT, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
    },
    le_write_u16, PciBus, PciDevBase, PciDevOps,
};
use crate::{Device, DeviceBase};
use address_space::{GuestAddress, Region, RegionOps};
use machine_manager::config::{PvpanicDevConfig, PVPANIC_CRASHLOADED, PVPANIC_PANICKED};

const PCI_CLASS_SYSTEM_OTHER: u16 = 0x0880;
const PCI_CLASS_PI: u16 = 0x09;
const PCI_REVISION_ID_PVPANIC: u8 = 1;

#[cfg(target_arch = "aarch64")]
// param size in Region::init_io_region must greater than 4
const PVPANIC_REG_BAR_SIZE: u64 = 0x4;
#[cfg(target_arch = "x86_64")]
const PVPANIC_REG_BAR_SIZE: u64 = 0x1;

#[derive(Copy, Clone)]
pub struct PvPanicState {
    supported_features: u32,
}

impl PvPanicState {
    fn new(supported_features: u32) -> Self {
        Self { supported_features }
    }

    fn handle_event(&self, event: u32) -> Result<()> {
        if (event & !(PVPANIC_PANICKED | PVPANIC_CRASHLOADED)) != 0 {
            error!("pvpanic: unknown event 0x{:X}", event);
        }

        if (event & PVPANIC_PANICKED) == PVPANIC_PANICKED
            && (self.supported_features & PVPANIC_PANICKED) == PVPANIC_PANICKED
        {
            info!("pvpanic: panicked event");
        }

        if (event & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
            && (self.supported_features & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
        {
            info!("pvpanic: crashloaded event");
        }

        Ok(())
    }
}

pub struct PvPanicPci {
    base: PciDevBase,
    dev_id: AtomicU16,
    pvpanic: Arc<PvPanicState>,
}

impl PvPanicPci {
    pub fn new(config: &PvpanicDevConfig, devfn: u8, parent_bus: Weak<Mutex<PciBus>>) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(config.id.clone(), false),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 1),
                devfn,
                parent_bus,
            },
            dev_id: AtomicU16::new(0),
            pvpanic: Arc::new(PvPanicState::new(config.supported_features)),
        }
    }

    fn register_bar(&mut self) -> Result<()> {
        let cloned_pvpanic_read = self.pvpanic.clone();
        let bar0_read = Arc::new(move |data: &mut [u8], _: GuestAddress, _: u64| -> bool {
            debug!(
                "pvpanic: read bar0 called event {}",
                cloned_pvpanic_read.supported_features
            );

            data[0] = cloned_pvpanic_read.supported_features as u8;
            true
        });

        let cloned_pvpanic_write = self.pvpanic.clone();
        let bar0_write = Arc::new(move |data: &[u8], _: GuestAddress, _: u64| -> bool {
            debug!("pvpanic: write bar0 called event {:?}", data);
            let val = u8::from_le_bytes(match data.try_into() {
                Ok(value) => value,
                Err(_) => {
                    return false;
                }
            });

            matches!(cloned_pvpanic_write.handle_event(val as u32), Ok(()))
        });

        let bar0_region_ops = RegionOps {
            read: bar0_read,
            write: bar0_write,
        };

        let mut bar_region =
            Region::init_io_region(PVPANIC_REG_BAR_SIZE, bar0_region_ops, "PvPanic");
        bar_region.set_access_size(1);

        self.base.config.register_bar(
            0,
            bar_region,
            RegionType::Mem64Bit,
            false,
            PVPANIC_REG_BAR_SIZE,
        )
    }
}

impl Device for PvPanicPci {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }

    fn hotpluggable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "PvPanic".to_string()
    }
}

impl PciDevOps for PvPanicPci {
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
            PCI_DEVICE_ID_REDHAT_PVPANIC,
        )?;

        self.base.config.config[REVISION_ID] = PCI_REVISION_ID_PVPANIC;

        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_SYSTEM_OTHER,
        )?;

        self.base.config.config[PCI_CLASS_PI as usize] = 0x00;

        self.base.config.config[HEADER_TYPE as usize] = 0x00;

        self.register_bar()
            .with_context(|| "pvpanic: device register bar failed")?;

        // Attach to the PCI bus.
        let devfn = self.base.devfn;
        let dev = Arc::new(Mutex::new(self));
        let pci_bus = dev.lock().unwrap().base.parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let device_id = locked_pci_bus.generate_dev_id(devfn);
        dev.lock()
            .unwrap()
            .dev_id
            .store(device_id, Ordering::Release);
        let pci_device = locked_pci_bus.devices.get(&devfn);
        if pci_device.is_none() {
            locked_pci_bus.devices.insert(devfn, dev);
        } else {
            bail!(
                "pvpanic: Devfn {:?} has been used by {:?}",
                &devfn,
                pci_device.unwrap().lock().unwrap().name()
            );
        }

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
