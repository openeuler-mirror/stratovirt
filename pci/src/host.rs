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

use std::sync::{Arc, Mutex};

use acpi::{
    AmlAddressSpaceDecode, AmlBuilder, AmlByte, AmlCacheable, AmlDWord, AmlDWordDesc, AmlDevice,
    AmlEisaId, AmlNameDecl, AmlPackage, AmlReadAndWrite, AmlResTemplate, AmlScopeBuilder,
    AmlWordDesc, AmlZero,
};
#[cfg(target_arch = "x86_64")]
use acpi::{
    AmlAnd, AmlArg, AmlCreateDWordField, AmlElse, AmlEqual, AmlISARanges, AmlIf, AmlInteger,
    AmlIoDecode, AmlIoResource, AmlLNot, AmlLocal, AmlMethod, AmlName, AmlOr, AmlReturn, AmlStore,
    AmlToUuid,
};
use address_space::{AddressSpace, GuestAddress, RegionOps};
use sysbus::SysBusDevOps;

use crate::{bus::PciBus, PciDevOps};
#[cfg(target_arch = "x86_64")]
use crate::{le_read_u32, le_write_u32};

#[cfg(target_arch = "x86_64")]
const CONFIG_ADDRESS_ENABLE_MASK: u32 = 0x8000_0000;
#[cfg(target_arch = "x86_64")]
const PIO_BUS_SHIFT: u32 = 16;
#[cfg(target_arch = "x86_64")]
const PIO_DEVFN_SHIFT: u32 = 8;
#[cfg(target_arch = "x86_64")]
const PIO_OFFSET_MASK: u32 = 0xff;

const CONFIG_BUS_MASK: u32 = 0xff;
const CONFIG_DEVFN_MASK: u32 = 0xff;
#[allow(dead_code)]
const ECAM_BUS_SHIFT: u32 = 20;
#[allow(dead_code)]
const ECAM_DEVFN_SHIFT: u32 = 12;
#[allow(dead_code)]
const ECAM_OFFSET_MASK: u64 = 0xfff;

#[derive(Clone)]
pub struct PciHost {
    pub root_bus: Arc<Mutex<PciBus>>,
    device: Option<Arc<Mutex<dyn PciDevOps>>>,
    #[cfg(target_arch = "x86_64")]
    config_addr: u32,
    pcie_ecam_range: (u64, u64),
    pcie_mmio_range: (u64, u64),
}

impl PciHost {
    /// Construct PCI/PCIe host.
    ///
    /// # Arguments
    ///
    /// * `sys_io` - IO space which the host bridge maps (only on x86_64).
    /// * `sys_mem`- Memory space which the host bridge maps.
    pub fn new(
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
        pcie_ecam_range: (u64, u64),
        pcie_mmio_range: (u64, u64),
    ) -> Self {
        #[cfg(target_arch = "x86_64")]
        let io_region = sys_io.root().clone();
        let mem_region = sys_mem.root().clone();
        let root_bus = PciBus::new(
            "pcie.0".to_string(),
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
        );
        PciHost {
            root_bus: Arc::new(Mutex::new(root_bus)),
            device: None,
            #[cfg(target_arch = "x86_64")]
            config_addr: 0,
            pcie_ecam_range,
            pcie_mmio_range,
        }
    }

    fn find_device(&self, bus_num: u8, devfn: u8) -> Option<Arc<Mutex<dyn PciDevOps>>> {
        let locked_root_bus = self.root_bus.lock().unwrap();
        if bus_num == 0 {
            return locked_root_bus.get_device(0, devfn);
        }
        for bus in &locked_root_bus.child_buses {
            if let Some(b) = PciBus::find_bus_by_num(bus, bus_num) {
                return b.lock().unwrap().get_device(bus_num, devfn);
            }
        }
        None
    }

    /// Build RegionOps for configuration space access by mmconfig.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    pub fn build_mmconfig_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], addr: GuestAddress, offset: u64| -> bool {
            cloned_hb.lock().unwrap().read(data, addr, offset)
        };
        let write = move |data: &[u8], addr: GuestAddress, offset: u64| {
            host_bridge.lock().unwrap().write(data, addr, offset)
        };
        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }

    /// Build RegionOps for access at 0xCF8.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn build_pio_addr_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset != 0 || data.len() != 4 {
                return true;
            }
            le_write_u32(data, 0, cloned_hb.lock().unwrap().config_addr).unwrap();
            true
        };
        let write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            if offset != 0 || data.len() != 4 {
                return true;
            }
            host_bridge.lock().unwrap().config_addr = le_read_u32(data, 0).unwrap();
            true
        };

        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }

    /// Build RegionOps for access at 0xCFC.
    ///
    /// # Arguments
    ///
    /// * `host_bridge` - Host brdige device.
    #[allow(dead_code)]
    #[cfg(target_arch = "x86_64")]
    pub fn build_pio_data_ops(host_bridge: Arc<Mutex<Self>>) -> RegionOps {
        let cloned_hb = host_bridge.clone();
        let read = move |data: &mut [u8], _addr: GuestAddress, offset: u64| -> bool {
            let locked_hb = cloned_hb.lock().unwrap();
            let buf_size = data.len();
            if buf_size > 4 || locked_hb.config_addr & CONFIG_ADDRESS_ENABLE_MASK == 0 {
                for d in data.iter_mut() {
                    *d = 0xff;
                }
                return true;
            }

            let mut offset: u32 =
                (locked_hb.config_addr & !CONFIG_ADDRESS_ENABLE_MASK) + offset as u32;
            let bus_num = ((offset as u32 >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset as u32 >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
            match locked_hb.find_device(bus_num, devfn) {
                Some(dev) => {
                    offset &= PIO_OFFSET_MASK;
                    dev.lock().unwrap().read_config(offset as usize, data);
                }
                None => {
                    for d in data.iter_mut() {
                        *d = 0xff;
                    }
                }
            }
            true
        };
        let write = move |data: &[u8], _addr: GuestAddress, offset: u64| -> bool {
            let locked_hb = host_bridge.lock().unwrap();
            if data.len() > 4 || locked_hb.config_addr & CONFIG_ADDRESS_ENABLE_MASK == 0 {
                return true;
            }

            let mut offset: u32 =
                (locked_hb.config_addr & !CONFIG_ADDRESS_ENABLE_MASK) + offset as u32;
            let bus_num = ((offset as u32 >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset as u32 >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
            if let Some(dev) = locked_hb.find_device(bus_num, devfn) {
                offset &= PIO_OFFSET_MASK;
                dev.lock().unwrap().write_config(offset as usize, data);
            }
            true
        };

        RegionOps {
            read: Arc::new(read),
            write: Arc::new(write),
        }
    }
}

impl SysBusDevOps for PciHost {
    fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        let bus_num = ((offset as u32 >> ECAM_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
        let devfn = ((offset as u32 >> ECAM_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
        match self.find_device(bus_num, devfn) {
            Some(dev) => {
                let addr: usize = (offset & ECAM_OFFSET_MASK) as usize;
                dev.lock().unwrap().read_config(addr, data);
            }
            None => {
                for d in data.iter_mut() {
                    *d = 0xff;
                }
            }
        }
        true
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        let bus_num = ((offset as u32 >> ECAM_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
        let devfn = ((offset as u32 >> ECAM_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
        match self.find_device(bus_num, devfn) {
            Some(dev) => {
                let addr: usize = (offset & ECAM_OFFSET_MASK) as usize;
                dev.lock().unwrap().write_config(addr, data);
                true
            }
            None => true,
        }
    }
}

impl AmlBuilder for PciHost {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut pci_host_bridge = AmlDevice::new("PCI0");
        pci_host_bridge.append_child(AmlNameDecl::new("_HID", AmlEisaId::new("PNP0A08")));
        pci_host_bridge.append_child(AmlNameDecl::new("_CID", AmlEisaId::new("PNP0A03")));
        pci_host_bridge.append_child(AmlNameDecl::new("_ADR", AmlZero));
        pci_host_bridge.append_child(AmlNameDecl::new("_UID", AmlZero));

        #[cfg(target_arch = "x86_64")]
        {
            let mut method = AmlMethod::new("_OSC", 4, false);
            method.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(0), "CDW1"));
            let mut if_obj_0 = AmlIf::new(AmlEqual::new(
                AmlArg(0),
                AmlToUuid::new("33db4d5b-1ff7-401c-9657-7441c03dd766"),
            ));
            if_obj_0.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(4), "CDW2"));
            if_obj_0.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(8), "CDW3"));
            let cdw3 = AmlName("CDW3".to_string());
            if_obj_0.append_child(AmlStore::new(cdw3.clone(), AmlLocal(0)));
            if_obj_0.append_child(AmlAnd::new(AmlLocal(0), AmlInteger(0x1f), AmlLocal(0)));
            let mut if_obj_1 = AmlIf::new(AmlLNot::new(AmlEqual::new(AmlArg(1), AmlInteger(1))));
            let cdw1 = AmlName("CDW1".to_string());
            if_obj_1.append_child(AmlOr::new(cdw1.clone(), AmlInteger(0x08), cdw1.clone()));
            if_obj_0.append_child(if_obj_1);
            let mut if_obj_2 = AmlIf::new(AmlLNot::new(AmlEqual::new(cdw3.clone(), AmlLocal(0))));
            if_obj_2.append_child(AmlOr::new(cdw1.clone(), AmlInteger(0x10), cdw1.clone()));
            if_obj_0.append_child(if_obj_2);
            if_obj_0.append_child(AmlStore::new(AmlLocal(0), cdw3));
            method.append_child(if_obj_0);
            let mut else_obj_0 = AmlElse::new();
            else_obj_0.append_child(AmlOr::new(cdw1.clone(), AmlInteger(0x04), cdw1));
            method.append_child(else_obj_0);
            method.append_child(AmlReturn::with_value(AmlArg(3)));
            pci_host_bridge.append_child(method);
        }

        let pcie_ecam = self.pcie_ecam_range;
        let pcie_mmio = self.pcie_mmio_range;
        // Build and append "\_SB.PCI0._CRS" to PCI host bridge node.
        let max_nr_bus = (pcie_ecam.1 >> 20) as u16;
        let mut crs = AmlResTemplate::new();
        crs.append_child(AmlWordDesc::new_bus_number(
            AmlAddressSpaceDecode::Positive,
            0,
            0,
            max_nr_bus - 1,
            0,
            max_nr_bus,
        ));
        #[cfg(target_arch = "x86_64")]
        {
            crs.append_child(AmlIoResource::new(
                AmlIoDecode::Decode16,
                0xcf8,
                0xcf8,
                1,
                8,
            ));
            crs.append_child(AmlWordDesc::new_io(
                AmlAddressSpaceDecode::Positive,
                AmlISARanges::EntireRange,
                0,
                0,
                0x0cf7,
                0,
                0xcf8,
            ));
            crs.append_child(AmlWordDesc::new_io(
                AmlAddressSpaceDecode::Positive,
                AmlISARanges::EntireRange,
                0,
                0x0d00,
                0xffff,
                0,
                0xf300,
            ));
        }
        crs.append_child(AmlDWordDesc::new_memory(
            AmlAddressSpaceDecode::Positive,
            AmlCacheable::NonCacheable,
            AmlReadAndWrite::ReadWrite,
            0,
            pcie_mmio.0 as u32,
            (pcie_mmio.0 + pcie_mmio.1) as u32 - 1,
            0,
            pcie_mmio.1 as u32,
        ));
        pci_host_bridge.append_child(AmlNameDecl::new("_CRS", crs));

        // Build and append pci-routing-table to PCI host bridge node.
        let slot_num = 32_u8;
        let mut prt_pkg = AmlPackage::new(slot_num);
        let pci_irq_base = 16_u32;
        (0..slot_num).for_each(|slot| {
            let mut pkg = AmlPackage::new(4);
            pkg.append_child(AmlDWord(((slot as u32) << 16) as u32 | 0xFFFF));
            pkg.append_child(AmlByte(0));
            pkg.append_child(AmlByte(0));
            pkg.append_child(AmlDWord(pci_irq_base + (slot as u32 % 8)));
            prt_pkg.append_child(pkg);
        });
        pci_host_bridge.append_child(AmlNameDecl::new("_PRT", prt_pkg));

        pci_host_bridge.aml_bytes()
    }
}
