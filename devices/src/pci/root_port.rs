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

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use log::{error, info};
use once_cell::sync::OnceCell;

use super::config::{
    PciConfig, PcieDevType, CLASS_CODE_PCI_BRIDGE, COMMAND, COMMAND_IO_SPACE, COMMAND_MEMORY_SPACE,
    DEVICE_ID, HEADER_TYPE, HEADER_TYPE_BRIDGE, IO_BASE, MEMORY_BASE, PCIE_CONFIG_SPACE_SIZE,
    PCI_EXP_HP_EV_ABP, PCI_EXP_HP_EV_CCI, PCI_EXP_HP_EV_PDC, PCI_EXP_HP_EV_SPT, PCI_EXP_LNKSTA,
    PCI_EXP_LNKSTA_CLS_2_5GB, PCI_EXP_LNKSTA_DLLLA, PCI_EXP_LNKSTA_NLW_X1, PCI_EXP_SLOTSTA_EVENTS,
    PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_HPIE, PCI_EXP_SLTCTL_PCC, PCI_EXP_SLTCTL_PIC,
    PCI_EXP_SLTCTL_PWR_IND_BLINK, PCI_EXP_SLTCTL_PWR_IND_OFF, PCI_EXP_SLTCTL_PWR_IND_ON,
    PCI_EXP_SLTCTL_PWR_OFF, PCI_EXP_SLTSTA, PCI_EXP_SLTSTA_PDC, PCI_EXP_SLTSTA_PDS,
    PCI_VENDOR_ID_REDHAT, PREF_MEMORY_BASE, PREF_MEMORY_LIMIT, PREF_MEM_RANGE_64BIT,
    SUB_CLASS_CODE, VENDOR_ID,
};
use crate::pci::bus::PciBus;
use crate::pci::config::{BRIDGE_CONTROL, BRIDGE_CTL_SEC_BUS_RESET};
use crate::pci::hotplug::HotplugOps;
use crate::pci::intx::init_intx;
use crate::pci::msix::init_msix;
use crate::pci::{
    init_multifunction, le_read_u16, le_write_clear_value_u16, le_write_set_value_u16,
    le_write_u16, to_pcidevops, PciDevBase, PciDevOps, PciError, PciIntxState, INTERRUPT_PIN,
};
use crate::{
    convert_bus_mut, convert_bus_ref, Bus, Device, DeviceBase, MsiIrqManager, MUT_PCI_BUS, PCI_BUS,
    PCI_BUS_DEVICE,
};
use address_space::Region;
use machine_manager::config::{get_pci_df, parse_bool, valid_id};
use machine_manager::qmp::qmp_channel::send_device_deleted_msg;
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;
use util::gen_base_func;
use util::num_ops::{ranges_overlap, str_to_num};

const DEVICE_ID_RP: u16 = 0x000c;

static FAST_UNPLUG_FEATURE: OnceCell<bool> = OnceCell::new();

/// Basic information of RootPort like port number.
#[derive(Parser, Debug, Clone, Default)]
#[command(no_binary_name(true))]
pub struct RootPortConfig {
    #[arg(long, value_parser = ["pcie-root-port"])]
    pub classtype: String,
    #[arg(long, value_parser = str_to_num::<u8>)]
    pub port: u8,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: String,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: (u8, u8),
    #[arg(long, default_value = "off", value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: bool,
    #[arg(long, default_value = "0")]
    pub chassis: u8,
}

/// Device state root port.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
struct RootPortState {
    /// Max length of config_space is 4096.
    config_space: [u8; 4096],
    write_mask: [u8; 4096],
    write_clear_mask: [u8; 4096],
    last_cap_end: u16,
    last_ext_cap_offset: u16,
    last_ext_cap_end: u16,
}

pub struct RootPort {
    base: PciDevBase,
    port_num: u8,
    #[cfg(target_arch = "x86_64")]
    io_region: Region,
    mem_region: Region,
    dev_id: Arc<AtomicU16>,
    multifunction: bool,
    hpev_notified: bool,
}

impl RootPort {
    /// Construct a new pcie root port.
    ///
    /// # Arguments
    ///
    /// * `cfg` - Root port config.
    /// * `parent_bus` - Weak reference to the parent bus.
    pub fn new(cfg: RootPortConfig, parent_bus: Weak<Mutex<dyn Bus>>) -> Self {
        let devfn = cfg.addr.0 << 3 | cfg.addr.1;
        #[cfg(target_arch = "x86_64")]
        let io_region = Region::init_container_region(1 << 16, "RootPortIo");
        let mem_region = Region::init_container_region(u64::MAX, "RootPortMem");
        let child_bus = Arc::new(Mutex::new(PciBus::new(
            cfg.id.clone(),
            #[cfg(target_arch = "x86_64")]
            io_region.clone(),
            mem_region.clone(),
        )));
        let mut dev_base = DeviceBase::new(cfg.id, true, Some(parent_bus));
        dev_base.child = Some(child_bus);

        Self {
            base: PciDevBase {
                base: dev_base,
                config: PciConfig::new(devfn, PCIE_CONFIG_SPACE_SIZE, 2),
                devfn,
                bme: Arc::new(AtomicBool::new(false)),
            },
            port_num: cfg.port,
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
            dev_id: Arc::new(AtomicU16::new(0)),
            multifunction: cfg.multifunction,
            hpev_notified: false,
        }
    }

    fn hotplug_command_completed(&mut self) {
        if let Err(e) = le_write_set_value_u16(
            &mut self.base.config.config,
            (self.base.config.pci_express_cap_offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_HP_EV_CCI,
        ) {
            error!("{}", format!("{:?}", e));
            error!("Failed to write command completed");
        }
    }

    fn update_hp_event_status(&mut self) {
        let cap_offset = self.base.config.pci_express_cap_offset;
        let slot_status = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
        )
        .unwrap();
        let slot_control = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTCTL) as usize,
        )
        .unwrap();

        self.hpev_notified = (slot_control & PCI_EXP_SLTCTL_HPIE != 0)
            && (slot_status & slot_control & PCI_EXP_HP_EV_SPT != 0);
    }

    fn hotplug_event_notify(&mut self) {
        let last_event = self.hpev_notified;
        self.update_hp_event_status();
        if last_event == self.hpev_notified {
            return;
        }

        let msix = self.base.config.msix.as_ref().unwrap();
        let intx = self.base.config.intx.as_ref().unwrap();
        let mut locked_msix = msix.lock().unwrap();
        if locked_msix.enabled {
            locked_msix.notify(0, self.dev_id.load(Ordering::Acquire));
        } else if self.base.config.config[INTERRUPT_PIN as usize] != 0 {
            intx.lock().unwrap().notify(u8::from(self.hpev_notified));
        }
    }

    fn hotplug_event_clear(&mut self) {
        self.update_hp_event_status();

        let msix = self.base.config.msix.as_ref().unwrap();
        let intx = self.base.config.intx.as_ref().unwrap();
        let locked_msix = msix.lock().unwrap();
        let intr_pin = self.base.config.config[INTERRUPT_PIN as usize];
        if !locked_msix.enabled && intr_pin != 0 && !self.hpev_notified {
            intx.lock().unwrap().notify(0);
        }
    }

    /// Update register when the guest OS trigger the removal of the device.
    fn update_register_status(&mut self) -> Result<()> {
        let cap_offset = self.base.config.pci_express_cap_offset;
        le_write_clear_value_u16(
            &mut self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_SLTSTA_PDS,
        )?;
        le_write_clear_value_u16(
            &mut self.base.config.config,
            (cap_offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_DLLLA,
        )?;
        le_write_set_value_u16(
            &mut self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_SLTSTA_PDC,
        )?;
        Ok(())
    }

    /// Remove all devices attached on the secondary bus.
    fn remove_devices(&mut self) {
        // Store device in a temp vector and unlock the bus.
        // If the device unrealize called when the bus is locked, a deadlock occurs.
        // This is because the device unrealize also requires the bus lock.
        let bus = self.child_bus().unwrap();
        let devices = bus.lock().unwrap().child_devices();
        for dev in devices.values() {
            PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
            if let Err(e) = pci_dev.unrealize() {
                error!("{}", format!("{:?}", e));
                error!("Failed to unrealize device {}.", locked_dev.name());
            }
            info!("Device {} unplug from {}", locked_dev.name(), self.name());

            // Send QMP event for successful hot unplugging.
            send_device_deleted_msg(&locked_dev.name());
        }
        bus.lock().unwrap().bus_base_mut().children.clear();
    }

    fn register_region(&mut self) {
        let bus = self.parent_bus().unwrap().upgrade().unwrap();
        PCI_BUS!(bus, locked_bus, pci_bus);

        let command: u16 = le_read_u16(&self.base.config.config, COMMAND as usize).unwrap();
        if command & COMMAND_IO_SPACE != 0 {
            #[cfg(target_arch = "x86_64")]
            if let Err(e) = pci_bus
                .io_region
                .add_subregion(self.io_region.clone(), 0)
                .with_context(|| "Failed to add IO container region.")
            {
                error!("{}", format!("{:?}", e));
            }
        }
        if command & COMMAND_MEMORY_SPACE != 0 {
            if let Err(e) = pci_bus
                .mem_region
                .add_subregion(self.mem_region.clone(), 0)
                .with_context(|| "Failed to add memory container region.")
            {
                error!("{}", format!("{:?}", e));
            }
        }
    }

    fn correct_race_unplug(&mut self, offset: usize, data: &[u8], old_status: u16) {
        let size = data.len();
        let cap_offset = self.base.config.pci_express_cap_offset;
        // SAFETY: Checked in write_config.
        if !ranges_overlap(offset, size, (cap_offset + PCI_EXP_SLTSTA) as usize, 2).unwrap() {
            return;
        }

        let status = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
        )
        .unwrap();
        let val: u16 = u16::from(data[0]) + (u16::from(data[1]) << 8);
        if (val & !old_status & PCI_EXP_SLOTSTA_EVENTS) != 0 {
            let tmpstat =
                (status & !PCI_EXP_SLOTSTA_EVENTS) | (old_status & PCI_EXP_SLOTSTA_EVENTS);
            le_write_u16(
                &mut self.base.config.config,
                (cap_offset + PCI_EXP_SLTSTA) as usize,
                tmpstat,
            )
            .unwrap();
        }
    }

    fn do_unplug(&mut self, offset: usize, data: &[u8], old_ctl: u16, old_status: u16) {
        self.correct_race_unplug(offset, data, old_status);

        let size = data.len();
        let cap_offset = self.base.config.pci_express_cap_offset;
        // Only care the write config about slot control
        // SAFETY: Checked in write_config.
        if !ranges_overlap(offset, size, (cap_offset + PCI_EXP_SLTCTL) as usize, 2).unwrap() {
            return;
        }

        let status = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
        )
        .unwrap();
        let val = le_read_u16(&self.base.config.config, offset).unwrap();
        // Only unplug device when the slot is on
        // Don't unplug when slot is off for guest OS overwrite the off status before slot on.
        if (status & PCI_EXP_SLTSTA_PDS != 0)
            && (val & PCI_EXP_SLTCTL_PCC == PCI_EXP_SLTCTL_PCC)
            && (val & PCI_EXP_SLTCTL_PWR_IND_OFF == PCI_EXP_SLTCTL_PWR_IND_OFF)
            && (old_ctl & PCI_EXP_SLTCTL_PCC != PCI_EXP_SLTCTL_PCC
                || old_ctl & PCI_EXP_SLTCTL_PWR_IND_OFF != PCI_EXP_SLTCTL_PWR_IND_OFF)
        {
            self.remove_devices();

            if let Err(e) = self.update_register_status() {
                error!("{}", format!("{:?}", e));
                error!("Failed to update register status");
            }
        }

        // According to the PCIe specification 6.7.3, CCI events is different from others.
        // To avoid mixing them together, trigger a notify for each.
        self.hotplug_event_notify();
        self.hotplug_command_completed();
        self.hotplug_event_notify();
    }

    pub fn set_fast_unplug_feature(v: bool) {
        if let Err(v) = FAST_UNPLUG_FEATURE.set(v) {
            error!("Failed to set fast unplug feature: {}", v);
        }
    }
}

impl Device for RootPort {
    gen_base_func!(device_base, device_base_mut, DeviceBase, base.base);

    /// Only set slot status to on, and no other device reset actions are implemented.
    fn reset(&mut self, reset_child_device: bool) -> Result<()> {
        if reset_child_device {
            let child_bus = self.child_bus().unwrap();
            MUT_PCI_BUS!(child_bus, locked_child_bus, child_pci_bus);
            child_pci_bus
                .reset()
                .with_context(|| "Fail to reset child_bus in root port")?;
        } else {
            let cap_offset = self.base.config.pci_express_cap_offset;
            le_write_u16(
                &mut self.base.config.config,
                (cap_offset + PCI_EXP_SLTSTA) as usize,
                PCI_EXP_SLTSTA_PDS,
            )?;
            le_write_u16(
                &mut self.base.config.config,
                (cap_offset + PCI_EXP_SLTCTL) as usize,
                !PCI_EXP_SLTCTL_PCC | PCI_EXP_SLTCTL_PWR_IND_ON,
            )?;
            le_write_u16(
                &mut self.base.config.config,
                (cap_offset + PCI_EXP_LNKSTA) as usize,
                PCI_EXP_LNKSTA_DLLLA,
            )?;
        }

        self.base.config.reset_bridge_regs()?;
        self.base.config.reset()
    }

    fn realize(mut self) -> Result<Arc<Mutex<Self>>> {
        let parent_bus = self.parent_bus().unwrap();
        self.init_write_mask(true)?;
        self.init_write_clear_mask(true)?;

        let config_space = &mut self.base.config.config;
        le_write_u16(config_space, VENDOR_ID as usize, PCI_VENDOR_ID_REDHAT)?;
        le_write_u16(config_space, DEVICE_ID as usize, DEVICE_ID_RP)?;
        le_write_u16(config_space, SUB_CLASS_CODE as usize, CLASS_CODE_PCI_BRIDGE)?;
        config_space[HEADER_TYPE as usize] = HEADER_TYPE_BRIDGE;
        config_space[PREF_MEMORY_BASE as usize] = PREF_MEM_RANGE_64BIT;
        config_space[PREF_MEMORY_LIMIT as usize] = PREF_MEM_RANGE_64BIT;

        init_multifunction(
            self.multifunction,
            config_space,
            self.base.devfn,
            parent_bus.clone(),
        )?;

        #[cfg(target_arch = "aarch64")]
        self.base.config.set_interrupt_pin();

        self.base.config.add_pcie_cap(
            self.base.devfn,
            self.port_num,
            PcieDevType::RootPort as u8,
        )?;

        self.dev_id
            .store(u16::from(self.base.devfn), Ordering::SeqCst);
        init_msix(&mut self.base, 0, 1, self.dev_id.clone(), None, None)?;

        init_intx(
            self.name(),
            &mut self.base.config,
            parent_bus.clone(),
            self.base.devfn,
        )?;

        let arc_parent_bus = parent_bus.upgrade().unwrap();
        MUT_PCI_BUS!(arc_parent_bus, locked_parent_bus, parent_pci_bus);
        let child_bus = self.child_bus().unwrap();
        MUT_PCI_BUS!(child_bus, locked_child_bus, child_pci_bus);
        #[cfg(target_arch = "x86_64")]
        parent_pci_bus
            .io_region
            .add_subregion(child_pci_bus.io_region.clone(), 0)
            .with_context(|| "Failed to register subregion in I/O space.")?;
        parent_pci_bus
            .mem_region
            .add_subregion(child_pci_bus.mem_region.clone(), 0)
            .with_context(|| "Failed to register subregion in memory space.")?;
        drop(locked_child_bus);

        let name = self.name();
        let root_port = Arc::new(Mutex::new(self));
        let locked_root_port = root_port.lock().unwrap();
        let child_bus = locked_root_port.child_bus().unwrap();
        MUT_PCI_BUS!(child_bus, locked_child_bus, child_pci_bus);
        child_pci_bus.base.parent = Some(Arc::downgrade(&root_port) as Weak<Mutex<dyn Device>>);
        child_pci_bus.hotplug_controller =
            Some(Arc::downgrade(&root_port) as Weak<Mutex<dyn HotplugOps>>);
        parent_pci_bus.attach_child(u64::from(locked_root_port.base.devfn), root_port.clone())?;
        // Need to drop locked_root_port in order to register root_port instance.
        drop(locked_root_port);
        MigrationManager::register_device_instance(
            RootPortState::descriptor(),
            root_port.clone(),
            &name,
        );

        Ok(root_port)
    }
}

/// Convert from Arc<Mutex<dyn Device>> to &mut RootPort.
#[macro_export]
macro_rules! MUT_ROOT_PORT {
    ($trait_device:expr, $lock_device: ident, $struct_device: ident) => {
        convert_device_mut!($trait_device, $lock_device, $struct_device, RootPort);
    };
}

/// Convert from Arc<Mutex<dyn Device>> to &RootPort.
#[macro_export]
macro_rules! ROOT_PORT {
    ($trait_device:expr, $lock_device: ident, $struct_device: ident) => {
        convert_device_ref!($trait_device, $lock_device, $struct_device, RootPort);
    };
}

impl PciDevOps for RootPort {
    gen_base_func!(pci_base, pci_base_mut, PciDevBase, base);

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let size = data.len();
        // SAFETY: offset is no more than 0xfff.
        let end = offset + size;
        if end > PCIE_CONFIG_SPACE_SIZE || size > 4 {
            error!(
                "Failed to write pcie config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        let cap_offset = self.base.config.pci_express_cap_offset;
        let old_ctl = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTCTL) as usize,
        )
        .unwrap();
        let old_status = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
        )
        .unwrap();

        let old_br_ctl = le_read_u16(&self.base.config.config, BRIDGE_CONTROL.into()).unwrap();

        self.base.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&self.io_region),
            Some(&self.mem_region),
        );

        let new_br_ctl = le_read_u16(&self.base.config.config, BRIDGE_CONTROL.into()).unwrap();
        if (!old_br_ctl & new_br_ctl & BRIDGE_CTL_SEC_BUS_RESET) != 0 {
            if let Err(e) = self.reset(true) {
                error!(
                    "Failed to reset child devices under root port {}: {:?}",
                    self.name(),
                    e
                )
            }
        }

        if ranges_overlap(offset, size, COMMAND as usize, 1).unwrap()
            || ranges_overlap(offset, size, IO_BASE as usize, 2).unwrap()
            || ranges_overlap(offset, size, MEMORY_BASE as usize, 20).unwrap()
        {
            self.register_region();
        }

        let mut status = le_read_u16(
            &self.base.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
        )
        .unwrap();
        let exp_slot_status = (cap_offset + PCI_EXP_SLTSTA) as usize;
        if ranges_overlap(offset, size, exp_slot_status, 2).unwrap() {
            let new_status = le_read_u16(data, 0).unwrap();
            if new_status & !old_status & PCI_EXP_SLOTSTA_EVENTS != 0 {
                status = (status & !PCI_EXP_SLOTSTA_EVENTS) | (old_status & PCI_EXP_SLOTSTA_EVENTS);
                if let Err(e) = le_write_u16(
                    &mut self.base.config.config,
                    (cap_offset + PCI_EXP_SLTSTA) as usize,
                    status,
                ) {
                    error!("Failed to write config: {:?}", e);
                }
            }
            self.hotplug_event_clear();
        }
        self.do_unplug(offset, data, old_ctl, old_status);
    }

    fn get_dev_path(&self) -> Option<String> {
        let parent_bus = self.parent_bus().unwrap().upgrade().unwrap();
        let parent_dev_path = self.get_parent_dev_path(parent_bus);
        let dev_path = self.populate_dev_path(parent_dev_path, self.base.devfn, "/pci-bridge@");
        Some(dev_path)
    }

    fn get_intx_state(&self) -> Option<Arc<Mutex<PciIntxState>>> {
        let intx = self.base.config.intx.as_ref().unwrap();
        if intx.lock().unwrap().intx_state.is_some() {
            let intx_state = intx.lock().unwrap().intx_state.as_ref().unwrap().clone();
            return Some(intx_state);
        }

        None
    }

    fn get_msi_irq_manager(&self) -> Option<Arc<dyn MsiIrqManager>> {
        let msix = self.base.config.msix.as_ref().unwrap();
        msix.lock().unwrap().msi_irq_manager.clone()
    }
}

impl HotplugOps for RootPort {
    fn plug(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()> {
        if !dev.lock().unwrap().hotpluggable() {
            bail!("Don't support hot-plug!");
        }
        PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
        let devfn = pci_dev.pci_base().devfn;
        drop(locked_dev);
        // Only if devfn is equal to 0, hot plugging is supported.
        if devfn != 0 {
            return Err(anyhow!(PciError::HotplugUnsupported(devfn)));
        }

        let offset = self.base.config.pci_express_cap_offset;
        le_write_set_value_u16(
            &mut self.base.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_SLTSTA_PDS | PCI_EXP_HP_EV_PDC | PCI_EXP_HP_EV_ABP,
        )?;
        le_write_set_value_u16(
            &mut self.base.config.config,
            (offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_CLS_2_5GB | PCI_EXP_LNKSTA_NLW_X1 | PCI_EXP_LNKSTA_DLLLA,
        )?;
        self.hotplug_event_notify();

        Ok(())
    }

    fn unplug_request(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()> {
        let pcie_cap_offset = self.base.config.pci_express_cap_offset;
        let sltctl = le_read_u16(
            &self.base.config.config,
            (pcie_cap_offset + PCI_EXP_SLTCTL) as usize,
        )
        .unwrap();

        if (sltctl & PCI_EXP_SLTCTL_PIC) == PCI_EXP_SLTCTL_PWR_IND_BLINK {
            bail!("Guest is still on the fly of another (un)plugging");
        }

        if !dev.lock().unwrap().hotpluggable() {
            bail!("Don't support hot-unplug request!");
        }
        PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
        let devfn = pci_dev.pci_base().devfn;
        drop(locked_dev);
        if devfn != 0 {
            return self.unplug(dev);
        }

        let offset = self.base.config.pci_express_cap_offset;
        le_write_clear_value_u16(
            &mut self.base.config.config,
            (offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_DLLLA,
        )?;

        let mut slot_status = 0;
        if let Some(&true) = FAST_UNPLUG_FEATURE.get() {
            slot_status |= PCI_EXP_HP_EV_PDC;
        }
        le_write_set_value_u16(
            &mut self.base.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            slot_status,
        )?;

        if ((sltctl & PCI_EXP_SLTCTL_PIC) == PCI_EXP_SLTCTL_PWR_IND_OFF)
            && ((sltctl & PCI_EXP_SLTCTL_PCC) == PCI_EXP_SLTCTL_PWR_OFF)
        {
            // if the slot has already been unpluged, skip notifying the guest.
            return Ok(());
        }

        le_write_set_value_u16(
            &mut self.base.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            slot_status | PCI_EXP_HP_EV_ABP,
        )?;
        self.hotplug_event_notify();
        Ok(())
    }

    fn unplug(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()> {
        if !dev.lock().unwrap().hotpluggable() {
            bail!("Don't support hot-unplug!");
        }
        PCI_BUS_DEVICE!(dev, locked_dev, pci_dev);
        let devfn = u64::from(pci_dev.pci_base().devfn);
        pci_dev.unrealize()?;
        let child_bus = self.child_bus().unwrap();
        child_bus.lock().unwrap().detach_child(devfn)?;
        Ok(())
    }
}

impl StateTransfer for RootPort {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = RootPortState::default();

        for idx in 0..self.base.config.config.len() {
            state.config_space[idx] = self.base.config.config[idx];
            state.write_mask[idx] = self.base.config.write_mask[idx];
            state.write_clear_mask[idx] = self.base.config.write_clear_mask[idx];
        }
        state.last_cap_end = self.base.config.last_cap_end;
        state.last_ext_cap_end = self.base.config.last_ext_cap_end;
        state.last_ext_cap_offset = self.base.config.last_ext_cap_offset;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> Result<()> {
        let root_port_state = *RootPortState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("ROOT_PORT"))?;

        let length = self.base.config.config.len();
        self.base.config.config = root_port_state.config_space[..length].to_vec();
        self.base.config.write_mask = root_port_state.write_mask[..length].to_vec();
        self.base.config.write_clear_mask = root_port_state.write_clear_mask[..length].to_vec();
        self.base.config.last_cap_end = root_port_state.last_cap_end;
        self.base.config.last_ext_cap_end = root_port_state.last_ext_cap_end;
        self.base.config.last_ext_cap_offset = root_port_state.last_ext_cap_offset;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&RootPortState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for RootPort {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{convert_device_mut, pci::host::tests::create_pci_host, MUT_ROOT_PORT};

    #[test]
    fn test_read_config() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().child_bus().unwrap());
        let root_port_config = RootPortConfig {
            addr: (1, 0),
            id: "pcie.1".to_string(),
            ..Default::default()
        };
        let root_port = RootPort::new(root_port_config, root_bus.clone());
        root_port.realize().unwrap();

        let dev = pci_host.lock().unwrap().find_device(0, 8).unwrap();
        let mut buf = [1_u8; 4];
        MUT_ROOT_PORT!(dev, locked_dev, root_port);
        root_port.read_config(PCIE_CONFIG_SPACE_SIZE - 1, &mut buf);
        assert_eq!(buf, [1_u8; 4]);
    }

    #[test]
    fn test_write_config() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().child_bus().unwrap());
        let root_port_config = RootPortConfig {
            addr: (1, 0),
            id: "pcie.1".to_string(),
            ..Default::default()
        };
        let root_port = RootPort::new(root_port_config, root_bus.clone());
        root_port.realize().unwrap();
        let dev = pci_host.lock().unwrap().find_device(0, 8).unwrap();
        MUT_ROOT_PORT!(dev, locked_dev, root_port);

        // Invalid write.
        let data = [1_u8; 4];
        root_port.write_config(PCIE_CONFIG_SPACE_SIZE - 1, &data);
        let mut buf = [0_u8];
        root_port.read_config(PCIE_CONFIG_SPACE_SIZE - 1, &mut buf);
        assert_eq!(buf, [0_u8]);
    }
}
