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
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{bail, Context, Result};
use clap::Parser;
use log::error;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::xhci_controller::{XhciDevice, MAX_INTRS, MAX_SLOTS};
use super::xhci_regs::{
    build_cap_ops, build_doorbell_ops, build_oper_ops, build_port_ops, build_runtime_ops,
    XHCI_CAP_LENGTH, XHCI_OFF_DOORBELL, XHCI_OFF_RUNTIME,
};
use crate::pci::config::{
    PciConfig, RegionType, DEVICE_ID, MINIMUM_BAR_SIZE_FOR_MMIO, PCI_CONFIG_SPACE_SIZE,
    PCI_DEVICE_ID_REDHAT_XHCI, PCI_VENDOR_ID_REDHAT, REVISION_ID, SUB_CLASS_CODE, VENDOR_ID,
};
use crate::pci::{init_intx, init_msix, le_write_u16, PciBus, PciDevBase, PciDevOps};
use crate::usb::UsbDevice;
use crate::{Device, DeviceBase};
use address_space::{AddressRange, AddressSpace, Region, RegionIoEventFd};
use machine_manager::config::{get_pci_df, valid_id};
use machine_manager::event_loop::register_event_helper;
use util::loop_context::{
    read_fd, EventNotifier, EventNotifierHelper, NotifierCallback, NotifierOperation,
};

/// 5.2 PCI Configuration Registers(USB)
const PCI_CLASS_PI: u16 = 0x09;
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
const XHCI_PCI_RUNTIME_LENGTH: u32 = (MAX_INTRS + 1) * 0x20;
const XHCI_PCI_DOORBELL_OFFSET: u32 = XHCI_OFF_DOORBELL;
const XHCI_PCI_DOORBELL_LENGTH: u32 = (MAX_SLOTS + 1) * 0x20;
const XHCI_PCI_PORT_OFFSET: u32 = XHCI_PCI_OPER_OFFSET + XHCI_PCI_OPER_LENGTH;
const XHCI_PCI_PORT_LENGTH: u32 = 0x10;
const XHCI_MSIX_TABLE_OFFSET: u32 = 0x3000;
const XHCI_MSIX_PBA_OFFSET: u32 = 0x3800;

/// XHCI controller configuration.
#[derive(Parser, Clone, Debug, Default)]
#[command(name = "nec-usb-xhci")]
pub struct XhciConfig {
    #[arg(long, value_parser = valid_id)]
    id: Option<String>,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    // number of usb2.0 ports.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..u8::MAX as i64))]
    pub p2: Option<u8>,
    // number of usb3.0 ports.
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..u8::MAX as i64))]
    pub p3: Option<u8>,
    #[arg(long)]
    pub iothread: Option<String>,
}

/// Registers offset.
/// 0x0    0x40    0x440    0x1000    0x2000      0x3000   0x4000
/// | cap  | oper  | port   | runtime | doorbell  | MSIX   |

/// XHCI pci device which can be attached to PCI bus.
pub struct XhciPciDevice {
    base: PciDevBase,
    pub xhci: Arc<Mutex<XhciDevice>>,
    dev_id: Arc<AtomicU16>,
    mem_region: Region,
    doorbell_fd: Arc<EventFd>,
    delete_evts: Vec<RawFd>,
    iothread: Option<String>,
}

impl XhciPciDevice {
    pub fn new(
        config: &XhciConfig,
        devfn: u8,
        parent_bus: Weak<Mutex<PciBus>>,
        mem_space: &Arc<AddressSpace>,
    ) -> Self {
        Self {
            base: PciDevBase {
                base: DeviceBase::new(config.id.clone().unwrap(), true),
                config: PciConfig::new(PCI_CONFIG_SPACE_SIZE, 1),
                devfn,
                parent_bus,
            },
            xhci: XhciDevice::new(mem_space, config),
            dev_id: Arc::new(AtomicU16::new(0)),
            mem_region: Region::init_container_region(
                XHCI_PCI_CONFIG_LENGTH as u64,
                "XhciPciContainer",
            ),
            doorbell_fd: Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()),
            delete_evts: Vec::new(),
            iothread: config.iothread.clone(),
        }
    }

    fn mem_region_init(&mut self) -> Result<()> {
        let cap_region = Region::init_io_region(
            XHCI_PCI_CAP_LENGTH as u64,
            build_cap_ops(&self.xhci),
            "XhciPciCapRegion",
        );
        self.mem_region
            .add_subregion(cap_region, XHCI_PCI_CAP_OFFSET as u64)
            .with_context(|| "Failed to register cap region.")?;

        let mut oper_region = Region::init_io_region(
            XHCI_PCI_OPER_LENGTH as u64,
            build_oper_ops(&self.xhci),
            "XhciPciOperRegion",
        );
        oper_region.set_access_size(4);
        self.mem_region
            .add_subregion(oper_region, XHCI_PCI_OPER_OFFSET as u64)
            .with_context(|| "Failed to register oper region.")?;

        let port_num = self.xhci.lock().unwrap().usb_ports.len();
        for i in 0..port_num {
            let port = &self.xhci.lock().unwrap().usb_ports[i];
            let port_region = Region::init_io_region(
                XHCI_PCI_PORT_LENGTH as u64,
                build_port_ops(port),
                "XhciPciPortRegion",
            );
            let offset = (XHCI_PCI_PORT_OFFSET + XHCI_PCI_PORT_LENGTH * i as u32) as u64;
            self.mem_region
                .add_subregion(port_region, offset)
                .with_context(|| "Failed to register port region.")?;
        }

        let mut runtime_region = Region::init_io_region(
            XHCI_PCI_RUNTIME_LENGTH as u64,
            build_runtime_ops(&self.xhci),
            "XhciPciRuntimeRegion",
        );
        runtime_region.set_access_size(4);
        self.mem_region
            .add_subregion(runtime_region, XHCI_PCI_RUNTIME_OFFSET as u64)
            .with_context(|| "Failed to register runtime region.")?;

        let doorbell_region = Region::init_io_region(
            XHCI_PCI_DOORBELL_LENGTH as u64,
            build_doorbell_ops(&self.xhci),
            "XhciPciDoorbellRegion",
        );
        doorbell_region.set_ioeventfds(&self.ioeventfds());

        self.mem_region
            .add_subregion(doorbell_region, XHCI_PCI_DOORBELL_OFFSET as u64)
            .with_context(|| "Failed to register doorbell region.")?;
        Ok(())
    }

    fn ioeventfds(&self) -> Vec<RegionIoEventFd> {
        vec![RegionIoEventFd {
            fd: self.doorbell_fd.clone(),
            addr_range: AddressRange::from((0, 4u64)),
            data_match: false,
            data: 0,
        }]
    }

    pub fn attach_device(&self, dev: &Arc<Mutex<dyn UsbDevice>>) -> Result<()> {
        let mut locked_xhci = self.xhci.lock().unwrap();
        let usb_port = locked_xhci
            .assign_usb_port(dev)
            .with_context(|| "No available USB port.")?;
        locked_xhci.port_update(&usb_port, false)?;
        trace::usb_xhci_attach_device(
            &usb_port.lock().unwrap().port_id,
            &dev.lock().unwrap().device_id(),
        );
        let mut locked_dev = dev.lock().unwrap();
        locked_dev.handle_attach()?;
        locked_dev.set_controller(Arc::downgrade(&self.xhci));
        Ok(())
    }

    pub fn detach_device(&self, id: String) -> Result<()> {
        let mut locked_xhci = self.xhci.lock().unwrap();
        let usb_port = locked_xhci.find_usb_port_by_id(&id);
        if usb_port.is_none() {
            bail!("Failed to detach device: id {} not found", id);
        }
        let usb_port = usb_port.unwrap();
        let slot_id = usb_port.lock().unwrap().slot_id;
        locked_xhci.detach_slot(slot_id)?;
        locked_xhci.port_update(&usb_port, true)?;

        // Unrealize device and discharge usb port.
        let mut locked_port = usb_port.lock().unwrap();
        let dev = locked_port.dev.as_ref().unwrap();
        let mut locked_dev = dev.lock().unwrap();
        trace::usb_xhci_detach_device(&locked_port.port_id, &locked_dev.device_id());
        locked_dev.usb_device_base_mut().unplugged = true;
        locked_dev.unrealize()?;
        drop(locked_dev);
        locked_xhci.discharge_usb_port(&mut locked_port);

        Ok(())
    }
}

impl Device for XhciPciDevice {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl PciDevOps for XhciPciDevice {
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
            PCI_DEVICE_ID_REDHAT_XHCI,
        )?;
        le_write_u16(&mut self.base.config.config, REVISION_ID, 0x3_u16)?;
        le_write_u16(
            &mut self.base.config.config,
            SUB_CLASS_CODE as usize,
            PCI_CLASS_SERIAL_USB,
        )?;
        self.base.config.config[PCI_CLASS_PI as usize] = 0x30;

        #[cfg(target_arch = "aarch64")]
        self.base.config.set_interrupt_pin();

        self.base.config.config[PCI_CACHE_LINE_SIZE as usize] = 0x10;
        self.base.config.config[PCI_SERIAL_BUS_RELEASE_NUMBER as usize] =
            PCI_SERIAL_BUS_RELEASE_VERSION_3_0;
        self.base.config.config[PCI_FRAME_LENGTH_ADJUSTMENT as usize] =
            PCI_NO_FRAME_LENGTH_TIMING_CAP;
        self.dev_id.store(self.base.devfn as u16, Ordering::SeqCst);
        self.mem_region_init()?;

        let handler = Arc::new(Mutex::new(DoorbellHandler::new(
            self.xhci.clone(),
            self.doorbell_fd.clone(),
        )));

        register_event_helper(
            EventNotifierHelper::internal_notifiers(handler),
            self.iothread.as_ref(),
            &mut self.delete_evts,
        )?;

        let intrs_num = self.xhci.lock().unwrap().intrs.len() as u32;
        init_msix(
            &mut self.base,
            0_usize,
            intrs_num,
            self.dev_id.clone(),
            Some(&self.mem_region),
            Some((XHCI_MSIX_TABLE_OFFSET, XHCI_MSIX_PBA_OFFSET)),
        )?;

        init_intx(
            self.name(),
            &mut self.base.config,
            self.base.parent_bus.clone(),
            self.base.devfn,
        )?;

        let mut mem_region_size = (XHCI_PCI_CONFIG_LENGTH as u64).next_power_of_two();
        mem_region_size = max(mem_region_size, MINIMUM_BAR_SIZE_FOR_MMIO as u64);
        self.base.config.register_bar(
            0_usize,
            self.mem_region.clone(),
            RegionType::Mem64Bit,
            false,
            mem_region_size,
        )?;

        let devfn = self.base.devfn;
        // It is safe to unwrap, because it is initialized in init_msix.
        let cloned_msix = self.base.config.msix.as_ref().unwrap().clone();
        let cloned_intx = self.base.config.intx.as_ref().unwrap().clone();
        let cloned_dev_id = self.dev_id.clone();
        // Registers the msix to the xhci device for interrupt notification.
        self.xhci
            .lock()
            .unwrap()
            .set_interrupt_ops(Arc::new(move |n: u32, level: u8| -> bool {
                let mut locked_msix = cloned_msix.lock().unwrap();
                if locked_msix.enabled && level != 0 {
                    locked_msix.notify(n as u16, cloned_dev_id.load(Ordering::Acquire));
                    return true;
                }
                if n == 0 && !locked_msix.enabled {
                    cloned_intx.lock().unwrap().notify(level);
                }

                false
            }));
        let dev = Arc::new(Mutex::new(self));
        // Attach to the PCI bus.
        let pci_bus = dev.lock().unwrap().base.parent_bus.upgrade().unwrap();
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

    fn unrealize(&mut self) -> Result<()> {
        trace::usb_xhci_exit();
        Ok(())
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let parent_bus = self.base.parent_bus.upgrade().unwrap();
        let locked_parent_bus = parent_bus.lock().unwrap();
        locked_parent_bus.update_dev_id(self.base.devfn, &self.dev_id);

        self.base.config.write(
            offset,
            data,
            self.dev_id.clone().load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&locked_parent_bus.io_region),
            Some(&locked_parent_bus.mem_region),
        );
    }

    fn reset(&mut self, _reset_child_device: bool) -> Result<()> {
        self.xhci.lock().unwrap().reset();

        self.base.config.reset()?;

        Ok(())
    }
}

struct DoorbellHandler {
    xhci: Arc<Mutex<XhciDevice>>,
    fd: Arc<EventFd>,
}

impl DoorbellHandler {
    fn new(xhci: Arc<Mutex<XhciDevice>>, fd: Arc<EventFd>) -> Self {
        DoorbellHandler { xhci, fd }
    }
}

impl EventNotifierHelper for DoorbellHandler {
    fn internal_notifiers(io_handler: Arc<Mutex<Self>>) -> Vec<EventNotifier> {
        let cloned_io_handler = io_handler.clone();
        let handler: Rc<NotifierCallback> = Rc::new(move |_event, fd: RawFd| {
            read_fd(fd);
            let locked_handler = cloned_io_handler.lock().unwrap();
            let mut locked_xhci = locked_handler.xhci.lock().unwrap();

            if !locked_xhci.running() {
                error!("Failed to write doorbell, XHCI is not running");
                return None;
            }
            if let Err(e) = locked_xhci.handle_command() {
                error!("Failed to handle command: {:?}", e);
                locked_xhci.host_controller_error();
            }

            None
        });
        vec![EventNotifier::new(
            NotifierOperation::AddShared,
            io_handler.lock().unwrap().fd.as_raw_fd(),
            None,
            EventSet::IN,
            vec![handler],
        )]
    }
}
