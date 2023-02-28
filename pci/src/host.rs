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
    AmlAddressSpaceDecode, AmlAnd, AmlArg, AmlBuilder, AmlCacheable, AmlCreateDWordField,
    AmlDWordDesc, AmlDevice, AmlEisaId, AmlElse, AmlEqual, AmlISARanges, AmlIf, AmlInteger,
    AmlLNot, AmlLocal, AmlMethod, AmlName, AmlNameDecl, AmlOr, AmlReadAndWrite, AmlResTemplate,
    AmlReturn, AmlScopeBuilder, AmlStore, AmlToUuid, AmlWordDesc, AmlZero,
};
#[cfg(target_arch = "x86_64")]
use acpi::{AmlIoDecode, AmlIoResource};
#[cfg(target_arch = "aarch64")]
use acpi::{AmlOne, AmlQWordDesc};
use address_space::{AddressSpace, GuestAddress, RegionOps};
use anyhow::Context;
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
const ECAM_BUS_SHIFT: u32 = 20;
const ECAM_DEVFN_SHIFT: u32 = 12;
const ECAM_OFFSET_MASK: u64 = 0xfff;

#[derive(Clone)]
pub struct PciHost {
    pub root_bus: Arc<Mutex<PciBus>>,
    #[cfg(target_arch = "x86_64")]
    config_addr: u32,
    pcie_ecam_range: (u64, u64),
    pcie_mmio_range: (u64, u64),
    #[cfg(target_arch = "aarch64")]
    pcie_pio_range: (u64, u64),
    #[cfg(target_arch = "aarch64")]
    high_pcie_mmio_range: (u64, u64),
}

impl PciHost {
    /// Construct PCI/PCIe host.
    ///
    /// # Arguments
    ///
    /// * `sys_io` - IO space which the host bridge maps (only on x86_64).
    /// * `sys_mem`- Memory space which the host bridge maps.
    /// * `pcie_ecam_range` - PCIe ECAM base address and length.
    /// * `pcie_mmio_range` - PCIe MMIO base address and length.
    /// * `pcie_pio_range` - PCIe PIO base addreass and length (only on aarch64).
    /// * `high_pcie_mmio_range` - PCIe high MMIO base address and length (only on aarch64).
    pub fn new(
        #[cfg(target_arch = "x86_64")] sys_io: &Arc<AddressSpace>,
        sys_mem: &Arc<AddressSpace>,
        pcie_ecam_range: (u64, u64),
        pcie_mmio_range: (u64, u64),
        #[cfg(target_arch = "aarch64")] pcie_pio_range: (u64, u64),
        #[cfg(target_arch = "aarch64")] high_pcie_mmio_range: (u64, u64),
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
            #[cfg(target_arch = "x86_64")]
            config_addr: 0,
            pcie_ecam_range,
            pcie_mmio_range,
            #[cfg(target_arch = "aarch64")]
            pcie_pio_range,
            #[cfg(target_arch = "aarch64")]
            high_pcie_mmio_range,
        }
    }

    pub fn find_device(&self, bus_num: u8, devfn: u8) -> Option<Arc<Mutex<dyn PciDevOps>>> {
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
            let bus_num = ((offset >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
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
            let bus_num = ((offset >> PIO_BUS_SHIFT) & CONFIG_BUS_MASK) as u8;
            let devfn = ((offset >> PIO_DEVFN_SHIFT) & CONFIG_DEVFN_MASK) as u8;
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

    fn reset(&mut self) -> sysbus::Result<()> {
        for (_id, pci_dev) in self.root_bus.lock().unwrap().devices.iter_mut() {
            sysbus::Result::with_context(pci_dev.lock().unwrap().reset(true), || {
                "Fail to reset pci device under pci host"
            })?;
        }

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
fn build_osc_for_aml(pci_host_bridge: &mut AmlDevice) {
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
    /*
     * Hotplug: We now support PCIe native hotplug(bit 0) with PCI Express Capability Structure(bit 4)
     * other bits: bit1: SHPC; bit2: PME; bit3: AER;
     */
    if_obj_0.append_child(AmlAnd::new(AmlLocal(0), AmlInteger(0x11), AmlLocal(0)));
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

#[cfg(target_arch = "aarch64")]
fn build_osc_for_aml(pci_host_bridge: &mut AmlDevice) {
    // _OSC means Operating System Capabilities.
    pci_host_bridge.append_child(AmlNameDecl::new("SUPP", AmlInteger(0)));
    pci_host_bridge.append_child(AmlNameDecl::new("CTRL", AmlInteger(0)));
    let mut method = AmlMethod::new("_OSC", 4, false);
    method.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(0), "CDW1"));
    // The id is for PCI Host Bridge Device.
    let mut if_obj_0 = AmlIf::new(AmlEqual::new(
        AmlArg(0),
        AmlToUuid::new("33db4d5b-1ff7-401c-9657-7441c03dd766"),
    ));
    // Get value from argument for SUPP and CTRL.
    if_obj_0.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(4), "CDW2"));
    if_obj_0.append_child(AmlCreateDWordField::new(AmlArg(3), AmlInteger(8), "CDW3"));
    if_obj_0.append_child(AmlStore::new(
        AmlName("CDW2".to_string()),
        AmlName("SUPP".to_string()),
    ));
    if_obj_0.append_child(AmlStore::new(
        AmlName("CDW3".to_string()),
        AmlName("CTRL".to_string()),
    ));
    /*
     * Hotplug: We now support PCIe native hotplug(bit 0) with PCI Express Capability Structure(bit 4)
     * other bits: bit1: SHPC; bit2: PME; bit3: AER;
     */
    if_obj_0.append_child(AmlStore::new(
        AmlAnd::new(AmlName("CTRL".to_string()), AmlInteger(0x11), AmlLocal(0)),
        AmlName("CTRL".to_string()),
    ));
    let mut if_obj_1 = AmlIf::new(AmlLNot::new(AmlEqual::new(AmlArg(1), AmlInteger(1))));
    if_obj_1.append_child(AmlAnd::new(
        AmlName("CDW1".to_string()),
        AmlInteger(0x08),
        AmlName("CDW1".to_string()),
    ));
    if_obj_0.append_child(if_obj_1);
    let mut if_obj_2 = AmlIf::new(AmlLNot::new(AmlEqual::new(
        AmlName("CDW3".to_string()),
        AmlName("CTRL".to_string()),
    )));
    if_obj_2.append_child(AmlOr::new(
        AmlName("CDW1".to_string()),
        AmlInteger(0x10),
        AmlName("CDW1".to_string()),
    ));
    if_obj_0.append_child(if_obj_2);
    if_obj_0.append_child(AmlStore::new(
        AmlName("CTRL".to_string()),
        AmlName("CDW3".to_string()),
    ));
    // For pci host, kernel will use _OSC return value to determine
    // whether native_pcie_hotplug is enabled or not.
    if_obj_0.append_child(AmlReturn::with_value(AmlArg(3)));
    method.append_child(if_obj_0);
    let mut else_obj_0 = AmlElse::new();
    else_obj_0.append_child(AmlOr::new(
        AmlName("CDW1".to_string()),
        AmlInteger(0x04),
        AmlName("CDW1".to_string()),
    ));
    else_obj_0.append_child(AmlReturn::with_value(AmlArg(3)));
    method.append_child(else_obj_0);
    pci_host_bridge.append_child(method);
}

impl AmlBuilder for PciHost {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut pci_host_bridge = AmlDevice::new("PCI0");
        pci_host_bridge.append_child(AmlNameDecl::new("_HID", AmlEisaId::new("PNP0A08")));
        pci_host_bridge.append_child(AmlNameDecl::new("_CID", AmlEisaId::new("PNP0A03")));
        pci_host_bridge.append_child(AmlNameDecl::new("_ADR", AmlZero));
        pci_host_bridge.append_child(AmlNameDecl::new("_UID", AmlZero));
        #[cfg(target_arch = "aarch64")]
        {
            // CCA: Cache Coherency Attribute, which determines whether
            // guest supports DMA features in pci host on aarch64 platform.
            pci_host_bridge.append_child(AmlNameDecl::new("_CCA", AmlOne));
        }

        build_osc_for_aml(&mut pci_host_bridge);

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
        #[cfg(target_arch = "aarch64")]
        {
            let pcie_pio = self.pcie_pio_range;
            crs.append_child(AmlDWordDesc::new_io(
                AmlAddressSpaceDecode::Positive,
                AmlISARanges::EntireRange,
                0,
                pcie_pio.0 as u32,
                (pcie_pio.0 + pcie_pio.1) as u32 - 1,
                0,
                pcie_pio.1 as u32,
            ));
            let high_pcie_mmio = self.high_pcie_mmio_range;
            crs.append_child(AmlQWordDesc::new_memory(
                AmlAddressSpaceDecode::Positive,
                AmlCacheable::NonCacheable,
                AmlReadAndWrite::ReadWrite,
                0,
                high_pcie_mmio.0 as u64,
                (high_pcie_mmio.0 + high_pcie_mmio.1) as u64 - 1,
                0,
                high_pcie_mmio.1 as u64,
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

        pci_host_bridge.aml_bytes()
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Weak;

    use address_space::Region;
    use byteorder::{ByteOrder, LittleEndian};

    use super::*;
    use crate::bus::PciBus;
    use crate::config::{PciConfig, PCI_CONFIG_SPACE_SIZE, SECONDARY_BUS_NUM};
    use crate::root_port::RootPort;
    use crate::Result;

    struct PciDevice {
        devfn: u8,
        config: PciConfig,
        parent_bus: Weak<Mutex<PciBus>>,
    }

    impl PciDevOps for PciDevice {
        fn init_write_mask(&mut self) -> Result<()> {
            let mut offset = 0_usize;
            while offset < self.config.config.len() {
                LittleEndian::write_u32(
                    &mut self.config.write_mask[offset..offset + 4],
                    0xffff_ffff,
                );
                offset += 4;
            }
            Ok(())
        }

        fn init_write_clear_mask(&mut self) -> Result<()> {
            Ok(())
        }

        fn read_config(&mut self, offset: usize, data: &mut [u8]) {
            self.config.read(offset, data);
        }

        fn write_config(&mut self, offset: usize, data: &[u8]) {
            #[allow(unused_variables)]
            self.config.write(
                offset,
                data,
                0,
                #[cfg(target_arch = "x86_64")]
                None,
                None,
            );
        }

        fn name(&self) -> String {
            "PCI device".to_string()
        }

        fn realize(mut self) -> Result<()> {
            let devfn = self.devfn;
            self.init_write_mask()?;
            self.init_write_clear_mask()?;

            let dev = Arc::new(Mutex::new(self));
            dev.lock()
                .unwrap()
                .parent_bus
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .devices
                .insert(devfn, dev.clone());
            Ok(())
        }
    }

    pub fn create_pci_host() -> Arc<Mutex<PciHost>> {
        #[cfg(target_arch = "x86_64")]
        let sys_io = AddressSpace::new(Region::init_container_region(1 << 16)).unwrap();
        let sys_mem = AddressSpace::new(Region::init_container_region(u64::max_value())).unwrap();
        Arc::new(Mutex::new(PciHost::new(
            #[cfg(target_arch = "x86_64")]
            &sys_io,
            &sys_mem,
            (0xB000_0000, 0x1000_0000),
            (0xC000_0000, 0x3000_0000),
            #[cfg(target_arch = "aarch64")]
            (0xF000_0000, 0x1000_0000),
            #[cfg(target_arch = "aarch64")]
            (512 << 30, 512 << 30),
        )))
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_pio_ops() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().root_bus);
        let pio_addr_ops = PciHost::build_pio_addr_ops(pci_host.clone());
        let pio_data_ops = PciHost::build_pio_data_ops(pci_host.clone());
        let root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus, false);
        root_port.realize().unwrap();

        let mut data = [0_u8; 4];
        let addr: u32 = CONFIG_ADDRESS_ENABLE_MASK | 8 << PIO_DEVFN_SHIFT | 0x28;
        LittleEndian::write_u32(&mut data, addr);
        (pio_addr_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, data);
        let data = [1_u8; 4];
        (pio_data_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_data_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, data);

        // Non-DWORD access on CONFIG_ADDR

        let mut config = [0_u8; 4];
        (pio_addr_ops.read)(&mut config, GuestAddress(0), 0);
        let data = [0x12, 0x34];
        (pio_addr_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, config);

        let data = [0x12, 0x34, 0x56, 0x78];
        (pio_addr_ops.write)(&data, GuestAddress(0), 1);
        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, config);

        let mut buf = [0_u8; 2];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, [0_u8; 2]);

        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 1);
        assert_eq!(buf, [0_u8; 4]);

        let mut buf = [0_u8; 5];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, [0_u8; 5]);

        // Enable bit of CONFIG_ADDR is not set.
        let mut data = [0_u8; 4];
        let addr: u32 = 8 << PIO_DEVFN_SHIFT | 16 << 2;
        LittleEndian::write_u32(&mut data, addr);
        (pio_addr_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, data);
        let data = [1_u8; 4];
        (pio_data_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_data_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, [0xff_u8; 4]);

        // Access non-exist device.
        let mut data = [0_u8; 4];
        let addr: u32 = 1 << PIO_DEVFN_SHIFT | 16 << 2;
        LittleEndian::write_u32(&mut data, addr);
        (pio_addr_ops.write)(&data, GuestAddress(0), 0);
        let mut buf = [0_u8; 4];
        (pio_addr_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, data);
        let mut buf = [0_u8; 4];
        (pio_data_ops.read)(&mut buf, GuestAddress(0), 0);
        assert_eq!(buf, [0xff_u8; 4]);
    }

    #[test]
    fn test_mmio_ops() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().root_bus);
        let mmconfig_region_ops = PciHost::build_mmconfig_ops(pci_host.clone());

        let mut root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus.clone(), false);
        root_port.write_config(SECONDARY_BUS_NUM as usize, &[1]);
        root_port.realize().unwrap();
        let mut root_port = RootPort::new("pcie.2".to_string(), 16, 0, root_bus, false);
        root_port.write_config(SECONDARY_BUS_NUM as usize, &[2]);
        root_port.realize().unwrap();

        let bus = PciBus::find_bus_by_name(&pci_host.lock().unwrap().root_bus, "pcie.2").unwrap();
        let pci_dev = PciDevice {
            devfn: 8,
            config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 0),
            parent_bus: Arc::downgrade(&bus),
        };
        pci_dev.realize().unwrap();

        let addr: u64 = 8_u64 << ECAM_DEVFN_SHIFT | SECONDARY_BUS_NUM as u64;
        let data = [1_u8];
        (mmconfig_region_ops.write)(&data, GuestAddress(0), addr);
        let mut buf = [0_u8];
        (mmconfig_region_ops.read)(&mut buf, GuestAddress(0), addr);
        assert_eq!(buf, data);
        let addr: u64 = 16_u64 << ECAM_DEVFN_SHIFT | SECONDARY_BUS_NUM as u64;
        let data = [2_u8];
        (mmconfig_region_ops.write)(&data, GuestAddress(0), addr);
        let mut buf = [0_u8];
        (mmconfig_region_ops.read)(&mut buf, GuestAddress(0), addr);
        assert_eq!(buf, data);

        // Access non-exist device.
        let addr: u64 = 1 << ECAM_BUS_SHIFT | 16 << ECAM_DEVFN_SHIFT | 2;
        let mut buf = [0_u8; 2];
        (mmconfig_region_ops.read)(&mut buf, GuestAddress(0), addr);
        assert_eq!(buf, [0xff_u8; 2]);

        let addr: u64 = 2 << ECAM_BUS_SHIFT | 8 << ECAM_DEVFN_SHIFT | 2;
        let data = [1_u8; 2];
        (mmconfig_region_ops.write)(&data, GuestAddress(0), addr);
        let mut buf = [0_u8; 2];
        (mmconfig_region_ops.read)(&mut buf, GuestAddress(0), addr);
        assert_eq!(buf, data);
    }
}
