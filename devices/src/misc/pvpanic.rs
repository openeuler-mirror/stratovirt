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
    atomic::{AtomicBool, AtomicU16, Ordering},
    Arc, Mutex, Weak,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::pci::config::{
    PciConfig, RegionType, CLASS_PI, DEVICE_ID, HEADER_TYPE, PCI_CLASS_SYSTEM_OTHER,
    PCI_CONFIG_SPACE_SIZE, PCI_DEVICE_ID_REDHAT_PVPANIC, PCI_SUBDEVICE_ID_QEMU,
    PCI_VENDOR_ID_REDHAT, PCI_VENDOR_ID_REDHAT_QUMRANET, REVISION_ID, SUBSYSTEM_ID,
    SUBSYSTEM_VENDOR_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use crate::pci::{le_write_u16, PciBus, PciDevBase, PciDevOps};
use crate::{convert_bus_mut, convert_bus_ref, Bus, Device, DeviceBase, MUT_PCI_BUS, PCI_BUS};
use address_space::{GuestAddress, Region, RegionOps};
use machine_manager::config::{get_pci_df, valid_id};
use util::gen_base_func;

const PVPANIC_PCI_REVISION_ID: u8 = 1;
const PVPANIC_PCI_VENDOR_ID: u16 = PCI_VENDOR_ID_REDHAT_QUMRANET;

#[cfg(target_arch = "aarch64")]
// param size in Region::init_io_region must greater than 4
const PVPANIC_REG_BAR_SIZE: u64 = 0x4;
#[cfg(target_arch = "x86_64")]
const PVPANIC_REG_BAR_SIZE: u64 = 0x1;

pub const PVPANIC_PANICKED: u32 = 1 << 0;
pub const PVPANIC_CRASHLOADED: u32 = 1 << 1;

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct PvpanicDevConfig {
    #[arg(long, value_parser = ["pvpanic"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    #[arg(long, alias = "supported-features", default_value = "3", value_parser = valid_supported_features)]
    pub supported_features: u32,
}

fn valid_supported_features(f: &str) -> Result<u32> {
    let features = f.parse::<u32>()?;
    let supported_features = match features & !(PVPANIC_PANICKED | PVPANIC_CRASHLOADED) {
        0 => features,
        _ => bail!("Unsupported pvpanic device features {}", features),
    };
    Ok(supported_features)
}

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
            bail!("pvpanic: unknown event 0x{:X}", event);
        }

        if (event & PVPANIC_PANICKED) == PVPANIC_PANICKED
            && (self.supported_features & PVPANIC_PANICKED) == PVPANIC_PANICKED
        {
            hisysevent::STRATOVIRT_PVPANIC("PANICKED".to_string());
            info!("pvpanic: panicked event");
        }

        if (event & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
            && (self.supported_features & PVPANIC_CRASHLOADED) == PVPANIC_CRASHLOADED
        {
            hisysevent::STRATOVIRT_PVPANIC("CRASHLOADED".to_string());
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
    pub fn new(config: &PvpanicDevConfig, devfn: u8, parent_bus: Weak<Mutex<dyn Bus>>) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(config.id.clone(), false, Some(parent_bus)),
                config: PciConfig::new(devfn, PCI_CONFIG_SPACE_SIZE, 1),
                devfn,
                bme: Arc::new(AtomicBool::new(false)),
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

            matches!(cloned_pvpanic_write.handle_event(u32::from(val)), Ok(()))
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
            PCI_DEVICE_ID_REDHAT_PVPANIC,
        )?;

        self.base.config.config[REVISION_ID] = PVPANIC_PCI_REVISION_ID;

        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_SYSTEM_OTHER,
        )?;

        le_write_u16(
            &mut self.base.config.config,
            SUBSYSTEM_VENDOR_ID,
            PVPANIC_PCI_VENDOR_ID,
        )?;

        le_write_u16(
            &mut self.base.config.config,
            SUBSYSTEM_ID,
            PCI_SUBDEVICE_ID_QEMU,
        )?;

        self.base.config.config[CLASS_PI as usize] = 0x00;

        self.base.config.config[HEADER_TYPE as usize] = 0x00;

        self.register_bar()
            .with_context(|| "pvpanic: device register bar failed")?;

        // Attach to the PCI bus.
        let devfn = self.base.devfn;
        let dev = Arc::new(Mutex::new(self));
        let bus = dev.lock().unwrap().parent_bus().unwrap().upgrade().unwrap();
        MUT_PCI_BUS!(bus, locked_bus, pci_bus);
        let device_id = pci_bus.generate_dev_id(devfn);
        dev.lock()
            .unwrap()
            .dev_id
            .store(device_id, Ordering::Release);
        locked_bus.attach_child(u64::from(devfn), dev.clone())?;

        Ok(dev)
    }

    fn unrealize(&mut self) -> Result<()> {
        Ok(())
    }
}

impl PciDevOps for PvPanicPci {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::{host::tests::create_pci_host, le_read_u16, PciHost};
    use crate::{convert_bus_ref, convert_device_mut, PCI_BUS};
    use machine_manager::config::str_slip_to_clap;

    /// Convert from Arc<Mutex<dyn Device>> to &mut PvPanicPci.
    #[macro_export]
    macro_rules! MUT_PVPANIC_PCI {
        ($trait_device:expr, $lock_device: ident, $struct_device: ident) => {
            convert_device_mut!($trait_device, $lock_device, $struct_device, PvPanicPci);
        };
    }

    fn init_pvpanic_dev(devfn: u8, supported_features: u32, dev_id: &str) -> Arc<Mutex<PciHost>> {
        let pci_host = create_pci_host();
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = Arc::downgrade(&locked_pci_host.child_bus().unwrap());

        let config = PvpanicDevConfig {
            id: dev_id.to_string(),
            supported_features,
            classtype: "".to_string(),
            bus: "pcie.0".to_string(),
            addr: (3, 0),
        };
        let pvpanic_dev = PvPanicPci::new(&config, devfn, root_bus);
        assert_eq!(pvpanic_dev.base.base.id, "pvpanic_test".to_string());

        pvpanic_dev.realize().unwrap();
        drop(locked_pci_host);

        pci_host
    }

    #[test]
    fn test_pvpanic_cmdline_parser() {
        // Test1: Right.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7,supported-features=0";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert_eq!(result.unwrap().supported_features, 0);

        // Test2: Default value.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert_eq!(result.unwrap().supported_features, 3);

        // Test3: Illegal value.
        let cmdline = "pvpanic,id=pvpanic0,bus=pcie.0,addr=0x7,supported-features=4";
        let result = PvpanicDevConfig::try_parse_from(str_slip_to_clap(cmdline, true, false));
        assert!(result.is_err());
    }

    #[test]
    fn test_pvpanic_attached() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7);
        drop(locked_bus);
        assert!(pvpanic_dev.is_some());
        assert_eq!(
            pvpanic_dev.unwrap().lock().unwrap().name(),
            "pvpanic_test".to_string()
        );

        let info = PciBus::find_attached_bus(&root_bus, "pvpanic_test");
        assert!(info.is_some());
        let (bus, dev) = info.unwrap();
        assert_eq!(bus.lock().unwrap().name(), "pcie.0");
        assert_eq!(dev.lock().unwrap().name(), "pvpanic_test");
    }

    #[test]
    fn test_pvpanic_config() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7).unwrap();
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);
        let info = le_read_u16(&pvpanic.pci_base_mut().config.config, VENDOR_ID as usize)
            .unwrap_or_else(|_| 0);
        assert_eq!(info, PCI_VENDOR_ID_REDHAT);

        let info = le_read_u16(&pvpanic.pci_base_mut().config.config, DEVICE_ID as usize)
            .unwrap_or_else(|_| 0);
        assert_eq!(info, PCI_DEVICE_ID_REDHAT_PVPANIC);

        let info = le_read_u16(
            &pvpanic.pci_base_mut().config.config,
            SUB_CLASS_CODE as usize,
        )
        .unwrap_or_else(|_| 0);
        assert_eq!(info, PCI_CLASS_SYSTEM_OTHER);

        let info = le_read_u16(&pvpanic.pci_base_mut().config.config, SUBSYSTEM_VENDOR_ID)
            .unwrap_or_else(|_| 0);
        assert_eq!(info, PVPANIC_PCI_VENDOR_ID);

        let info =
            le_read_u16(&pvpanic.pci_base_mut().config.config, SUBSYSTEM_ID).unwrap_or_else(|_| 0);
        assert_eq!(info, PCI_SUBDEVICE_ID_QEMU);
    }

    #[test]
    fn test_pvpanic_read_features() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7).unwrap();
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test read supported_features
        let mut data_read = [0xffu8; 1];
        let result = &pvpanic.pci_base_mut().config.bars[0]
            .region
            .as_ref()
            .unwrap()
            .read(&mut data_read.as_mut(), GuestAddress(0), 0, 1);
        assert!(result.is_ok());
        assert_eq!(
            data_read.to_vec(),
            vec![PVPANIC_PANICKED as u8 | PVPANIC_CRASHLOADED as u8]
        );
    }

    #[test]
    fn test_pvpanic_write_panicked() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7).unwrap();
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test write panicked event
        let data_write = [PVPANIC_PANICKED as u8; 1];
        let count = data_write.len() as u64;
        let result = &pvpanic.pci_base_mut().config.bars[0]
            .region
            .as_ref()
            .unwrap()
            .write(&mut data_write.as_ref(), GuestAddress(0), 0, count);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pvpanic_write_crashload() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let root_bus = pci_host.lock().unwrap().child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7).unwrap();
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test write crashload event
        let data_write = [PVPANIC_CRASHLOADED as u8; 1];
        let count = data_write.len() as u64;
        let result = &pvpanic.pci_base_mut().config.bars[0]
            .region
            .as_ref()
            .unwrap()
            .write(&mut data_write.as_ref(), GuestAddress(0), 0, count);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pvpanic_write_unknown() {
        let pci_host = init_pvpanic_dev(7, PVPANIC_PANICKED | PVPANIC_CRASHLOADED, "pvpanic_test");
        let locked_pci_host = pci_host.lock().unwrap();
        let root_bus = locked_pci_host.child_bus().unwrap();
        PCI_BUS!(root_bus, locked_bus, pci_bus);
        let pvpanic_dev = pci_bus.get_device(0, 7).unwrap();
        MUT_PVPANIC_PCI!(pvpanic_dev, locked_dev, pvpanic);

        // test write unknown event
        let data_write = [100u8; 1];
        let count = data_write.len() as u64;
        let result = &pvpanic.pci_base_mut().config.bars[0]
            .region
            .as_ref()
            .unwrap()
            .write(&mut data_write.as_ref(), GuestAddress(0), 0, count);
        assert!(result.is_err());
    }
}
