// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::cmp::max;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use address_space::{AddressSpace, Region};
use log::debug;
use machine_manager::config::XhciConfig;
use pci::config::{
    PciConfig, RegionType, DEVICE_ID, MINMUM_BAR_SIZE_FOR_MMIO, PCI_CONFIG_SPACE_SIZE,
    PCI_DEVICE_ID_REDHAT_XHCI, PCI_VENDOR_ID_REDHAT, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use pci::msix::update_dev_id;
use pci::{init_msix, le_write_u16, PciBus, PciDevOps};

use crate::usb::UsbDeviceOps;
use crate::xhci::xhci_controller::{XhciDevice, MAX_INTRS, MAX_SLOTS};
use crate::xhci::xhci_regs::{
    build_cap_ops, build_doorbell_ops, build_oper_ops, build_port_ops, build_runtime_ops,
    XHCI_CAP_LENGTH, XHCI_OFF_DOORBELL, XHCI_OFF_RUNTIME,
};
use anyhow::{bail, Context, Result};

/// 5.2 PCI Configuration Registers(USB)
const PCI_CLASS_PI: u16 = 0x09;
const PCI_INTERRUPT_PIN: u16 = 0x3d;
const PCI_CACHE_LINE_SIZE: u16 = 0x0c;
const PCI_SERIAL_BUS_RELEASE_NUMBER: u8 = 0x60;
const PCI_FRAME_LENGTH_ADJUSTMENT: u8 = 0x61;
const PCI_SERIAL_BUS_RELEASE_VERSION_3_0: u8 = 0x30;
const PCI_CLASS_SERIAL_USB: u16 = 0x0c03;
const PCI_NO_FRAME_LENGTH_TIMING_CAP: u8 = 0x40;
/// PCI capability offset or size.
const XHCI_PCI_CONFIG_LENGTH: u32 = 0x4000;
const XHCI_PCI_CAP_OFFSET: u32 = 0x0;
const XHCI_PCI_CAP_LENGTH: u32 = XHCI_CAP_LENGTH;
const XHCI_PCI_OPER_OFFSET: u32 = XHCI_PCI_CAP_LENGTH;
const XHCI_PCI_OPER_LENGTH: u32 = 0x400;
const XHCI_PCI_RUNTIME_OFFSET: u32 = XHCI_OFF_RUNTIME;
const XHCI_PCI_RUNTIME_LENGTH: u32 = (MAX_INTRS as u32 + 1) * 0x20;
const XHCI_PCI_DOORBELL_OFFSET: u32 = XHCI_OFF_DOORBELL;
const XHCI_PCI_DOORBELL_LENGTH: u32 = (MAX_SLOTS + 1) * 0x20;
const XHCI_PCI_PORT_OFFSET: u32 = XHCI_PCI_OPER_OFFSET + XHCI_PCI_OPER_LENGTH;
const XHCI_PCI_PORT_LENGTH: u32 = 0x10;
const XHCI_MSIX_TABLE_OFFSET: u32 = 0x3000;
const XHCI_MSIX_PBA_OFFSET: u32 = 0x3800;

/// Registers offset.
/// 0x0    0x40    0x440    0x1000    0x2000      0x3000   0x4000
/// | cap  | oper  | port   | runtime | doorbell  | MSIX   |      

/// XHCI pci device which can be attached to PCI bus.
pub struct XhciPciDevice {
    pci_config: PciConfig,
    devfn: u8,
    xhci: Arc<Mutex<XhciDevice>>,
    dev_id: Arc<AtomicU16>,
    name: String,
    parent_bus: Weak<Mutex<PciBus>>,
    mem_region: Region,
}

impl XhciPciDevice {
    pub fn new(
        config: &XhciConfig,
        devfn: u8,
        parent_bus: Weak<Mutex<PciBus>>,
        mem_space: &Arc<AddressSpace>,
    ) -> Self {
        Self {
            pci_config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 1),
            devfn,
            xhci: XhciDevice::new(mem_space, config),
            dev_id: Arc::new(AtomicU16::new(0)),
            name: config.id.to_string(),
            parent_bus,
            mem_region: Region::init_container_region(XHCI_PCI_CONFIG_LENGTH as u64),
        }
    }

    fn mem_region_init(&mut self) -> pci::Result<()> {
        let cap_region =
            Region::init_io_region(XHCI_PCI_CAP_LENGTH as u64, build_cap_ops(&self.xhci));
        pci::Result::with_context(
            self.mem_region
                .add_subregion(cap_region, XHCI_PCI_CAP_OFFSET as u64),
            || "Failed to register cap region.",
        )?;

        let mut oper_region =
            Region::init_io_region(XHCI_PCI_OPER_LENGTH as u64, build_oper_ops(&self.xhci));
        oper_region.set_access_size(4);
        pci::Result::with_context(
            self.mem_region
                .add_subregion(oper_region, XHCI_PCI_OPER_OFFSET as u64),
            || "Failed to register oper region.",
        )?;

        let port_num = self.xhci.lock().unwrap().usb_ports.len();
        for i in 0..port_num {
            let port = &self.xhci.lock().unwrap().usb_ports[i];
            let port_region =
                Region::init_io_region(XHCI_PCI_PORT_LENGTH as u64, build_port_ops(port));
            let offset = (XHCI_PCI_PORT_OFFSET + XHCI_PCI_PORT_LENGTH * i as u32) as u64;
            pci::Result::with_context(self.mem_region.add_subregion(port_region, offset), || {
                "Failed to register port region."
            })?;
        }

        let mut runtime_region = Region::init_io_region(
            XHCI_PCI_RUNTIME_LENGTH as u64,
            build_runtime_ops(&self.xhci),
        );
        runtime_region.set_access_size(4);
        pci::Result::with_context(
            self.mem_region
                .add_subregion(runtime_region, XHCI_PCI_RUNTIME_OFFSET as u64),
            || "Failed to register runtime region.",
        )?;

        let doorbell_region = Region::init_io_region(
            XHCI_PCI_DOORBELL_LENGTH as u64,
            build_doorbell_ops(&self.xhci),
        );
        pci::Result::with_context(
            self.mem_region
                .add_subregion(doorbell_region, XHCI_PCI_DOORBELL_OFFSET as u64),
            || "Failed to register doorbell region.",
        )?;
        Ok(())
    }

    pub fn attach_device(&self, dev: &Arc<Mutex<dyn UsbDeviceOps>>) -> Result<()> {
        let mut locked_xhci = self.xhci.lock().unwrap();
        let usb_port = if let Some(usb_port) = locked_xhci.assign_usb_port(dev) {
            usb_port
        } else {
            bail!("No available USB port.");
        };
        locked_xhci.port_update(&usb_port)?;
        let mut locked_dev = dev.lock().unwrap();
        debug!(
            "Attach usb device: xhci port id {} device id {}",
            usb_port.lock().unwrap().port_id,
            locked_dev.device_id()
        );
        locked_dev.handle_attach()?;
        locked_dev.set_controller(Arc::downgrade(&self.xhci));
        Ok(())
    }
}

impl PciDevOps for XhciPciDevice {
    fn init_write_mask(&mut self) -> pci::Result<()> {
        self.pci_config.init_common_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> pci::Result<()> {
        self.pci_config.init_common_write_clear_mask()
    }

    fn realize(mut self) -> pci::Result<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;
        le_write_u16(
            &mut self.pci_config.config,
            VENDOR_ID as usize,
            PCI_VENDOR_ID_REDHAT,
        )?;
        le_write_u16(
            &mut self.pci_config.config,
            DEVICE_ID as usize,
            PCI_DEVICE_ID_REDHAT_XHCI,
        )?;
        le_write_u16(&mut self.pci_config.config, REVISION_ID, 0x3_u16)?;
        le_write_u16(
            &mut self.pci_config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_SERIAL_USB,
        )?;
        self.pci_config.config[PCI_CLASS_PI as usize] = 0x30;
        self.pci_config.config[PCI_INTERRUPT_PIN as usize] = 0x01;
        self.pci_config.config[PCI_CACHE_LINE_SIZE as usize] = 0x10;
        self.pci_config.config[PCI_SERIAL_BUS_RELEASE_NUMBER as usize] =
            PCI_SERIAL_BUS_RELEASE_VERSION_3_0;
        self.pci_config.config[PCI_FRAME_LENGTH_ADJUSTMENT as usize] =
            PCI_NO_FRAME_LENGTH_TIMING_CAP;
        self.dev_id.store(self.devfn as u16, Ordering::SeqCst);
        self.mem_region_init()?;

        let intrs_num = self.xhci.lock().unwrap().intrs.len() as u32;
        init_msix(
            0_usize,
            intrs_num,
            &mut self.pci_config,
            self.dev_id.clone(),
            &self.name,
            Some(&self.mem_region),
            Some((XHCI_MSIX_TABLE_OFFSET, XHCI_MSIX_PBA_OFFSET)),
        )?;

        let mut mem_region_size = (XHCI_PCI_CONFIG_LENGTH as u64).next_power_of_two();
        mem_region_size = max(mem_region_size, MINMUM_BAR_SIZE_FOR_MMIO as u64);
        self.pci_config.register_bar(
            0_usize,
            self.mem_region.clone(),
            RegionType::Mem64Bit,
            false,
            mem_region_size,
        )?;

        let devfn = self.devfn;
        // It is safe to unwrap, because it is initialized in init_msix.
        let cloned_msix = self.pci_config.msix.as_ref().unwrap().clone();
        let cloned_dev_id = self.dev_id.clone();
        // Registers the msix to the xhci device for interrupt notification.
        self.xhci.lock().unwrap().send_interrupt_ops = Some(Box::new(move |n: u32| {
            cloned_msix
                .lock()
                .unwrap()
                .notify(n as u16, cloned_dev_id.load(Ordering::Acquire));
        }));
        let dev = Arc::new(Mutex::new(self));
        // Attach to the PCI bus.
        let pci_bus = dev.lock().unwrap().parent_bus.upgrade().unwrap();
        let mut locked_pci_bus = pci_bus.lock().unwrap();
        let pci_device = locked_pci_bus.devices.get(&devfn);
        if pci_device.is_none() {
            locked_pci_bus.devices.insert(devfn, dev);
        } else {
            bail!(
                "Devfn {:?} has been used by {:?}",
                &devfn,
                pci_device.unwrap().lock().unwrap().name()
            );
        }
        Ok(())
    }

    fn unrealize(&mut self) -> pci::Result<()> {
        Ok(())
    }

    fn devfn(&self) -> Option<u8> {
        Some(self.devfn)
    }

    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.pci_config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        update_dev_id(&self.parent_bus, self.devfn, &self.dev_id);
        let parent_bus = self.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();

        self.pci_config.write(
            offset,
            data,
            self.dev_id.clone().load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&locked_parent_bus.io_region),
            Some(&locked_parent_bus.mem_region),
        );
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn reset(&mut self, _reset_child_device: bool) -> pci::Result<()> {
        self.xhci.lock().unwrap().reset();

        self.pci_config.reset()?;

        Ok(())
    }
}
