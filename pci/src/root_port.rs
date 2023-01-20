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

use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};

use address_space::Region;
use anyhow::{anyhow, bail, Context, Result};
use log::{error, info};
use machine_manager::event;
use machine_manager::qmp::{qmp_schema as schema, QmpChannel};
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use once_cell::sync::OnceCell;
use util::byte_code::ByteCode;

use super::config::{
    PciConfig, PcieDevType, CLASS_CODE_PCI_BRIDGE, COMMAND, COMMAND_IO_SPACE, COMMAND_MEMORY_SPACE,
    DEVICE_ID, HEADER_TYPE, HEADER_TYPE_BRIDGE, IO_BASE, MEMORY_BASE, PCIE_CONFIG_SPACE_SIZE,
    PCI_EXP_HP_EV_ABP, PCI_EXP_HP_EV_CCI, PCI_EXP_HP_EV_PDC, PCI_EXP_LNKSTA,
    PCI_EXP_LNKSTA_CLS_2_5GB, PCI_EXP_LNKSTA_DLLLA, PCI_EXP_LNKSTA_NLW_X1, PCI_EXP_SLOTSTA_EVENTS,
    PCI_EXP_SLTCTL, PCI_EXP_SLTCTL_PCC, PCI_EXP_SLTCTL_PIC, PCI_EXP_SLTCTL_PWR_IND_BLINK,
    PCI_EXP_SLTCTL_PWR_IND_OFF, PCI_EXP_SLTCTL_PWR_IND_ON, PCI_EXP_SLTCTL_PWR_OFF, PCI_EXP_SLTSTA,
    PCI_EXP_SLTSTA_PDC, PCI_EXP_SLTSTA_PDS, PCI_VENDOR_ID_REDHAT, PREF_MEMORY_BASE,
    PREF_MEMORY_LIMIT, PREF_MEM_RANGE_64BIT, SUB_CLASS_CODE, VENDOR_ID,
};
use crate::bus::PciBus;
use crate::config::{BRIDGE_CONTROL, BRIDGE_CTL_SEC_BUS_RESET};
use crate::hotplug::HotplugOps;
use crate::msix::init_msix;
use crate::{init_multifunction, PciError};
use crate::{
    le_read_u16, le_write_clear_value_u16, le_write_set_value_u16, le_write_u16, ranges_overlap,
    PciDevOps,
};

const DEVICE_ID_RP: u16 = 0x000c;

static FAST_UNPLUG_FEATURE: OnceCell<bool> = OnceCell::new();

/// Device state root port.
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct RootPortState {
    /// Max length of config_space is 4096.
    config_space: [u8; 4096],
    write_mask: [u8; 4096],
    write_clear_mask: [u8; 4096],
    last_cap_end: u16,
    last_ext_cap_offset: u16,
    last_ext_cap_end: u16,
}

pub struct RootPort {
    name: String,
    devfn: u8,
    port_num: u8,
    config: PciConfig,
    parent_bus: Weak<Mutex<PciBus>>,
    sec_bus: Arc<Mutex<PciBus>>,
    #[cfg(target_arch = "x86_64")]
    io_region: Region,
    mem_region: Region,
    dev_id: Arc<AtomicU16>,
    multifunction: bool,
}

impl RootPort {
    /// Construct a new pcie root port.
    ///
    /// # Arguments
    ///
    /// * `name` - Root port name.
    /// * `devfn` - Device number << 3 | Function number.
    /// * `port_num` - Root port number.
    /// * `parent_bus` - Weak reference to the parent bus.
    pub fn new(
        name: String,
        devfn: u8,
        port_num: u8,
        parent_bus: Weak<Mutex<PciBus>>,
        multifunction: bool,
    ) -> Self {
        #[cfg(target_arch = "x86_64")]
        let io_region = Region::init_container_region(1 << 16);
        let mem_region = Region::init_container_region(u64::max_value());
        let sec_bus = Arc::new(Mutex::new(PciBus::new(
            name.clone(),
            #[cfg(target_arch = "x86_64")]
            io_region.clone(),
            mem_region.clone(),
        )));

        Self {
            name,
            devfn,
            port_num,
            config: PciConfig::new(PCIE_CONFIG_SPACE_SIZE, 2),
            parent_bus,
            sec_bus,
            #[cfg(target_arch = "x86_64")]
            io_region,
            mem_region,
            dev_id: Arc::new(AtomicU16::new(0)),
            multifunction,
        }
    }

    fn hotplug_command_completed(&mut self) {
        if let Err(e) = le_write_set_value_u16(
            &mut self.config.config,
            (self.config.pci_express_cap_offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_HP_EV_CCI,
        ) {
            error!("{}", format!("{:?}", e));
            error!("Failed to write command completed");
        }
    }

    fn hotplug_event_notify(&mut self) {
        if let Some(msix) = self.config.msix.as_mut() {
            msix.lock()
                .unwrap()
                .notify(0, self.dev_id.load(Ordering::Acquire));
        } else {
            error!("Failed to send interrupt: msix does not exist");
        }
    }

    /// Update register when the guest OS trigger the removal of the device.
    fn update_register_status(&mut self) -> Result<()> {
        let cap_offset = self.config.pci_express_cap_offset;
        le_write_clear_value_u16(
            &mut self.config.config,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_SLTSTA_PDS,
        )?;
        le_write_clear_value_u16(
            &mut self.config.config,
            (cap_offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_DLLLA,
        )?;
        le_write_set_value_u16(
            &mut self.config.config,
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
        let devices = self.sec_bus.lock().unwrap().devices.clone();
        for dev in devices.values() {
            let mut locked_dev = dev.lock().unwrap();
            if let Err(e) = locked_dev.unrealize() {
                error!("{}", format!("{:?}", e));
                error!("Failed to unrealize device {}.", locked_dev.name());
            }
            info!("Device {} unplug from {}", locked_dev.name(), self.name);

            // Send QMP event for successful hot unplugging.
            if QmpChannel::is_connected() {
                let device_del = schema::DeviceDeleted {
                    device: Some(locked_dev.name()),
                    path: format!("/machine/peripheral/{}", &locked_dev.name()),
                };
                event!(DeviceDeleted; device_del);
            }
        }
        self.sec_bus.lock().unwrap().devices.clear();
    }

    fn register_region(&mut self) {
        let command: u16 = le_read_u16(&self.config.config, COMMAND as usize).unwrap();
        if command & COMMAND_IO_SPACE != 0 {
            #[cfg(target_arch = "x86_64")]
            if let Err(e) = self
                .parent_bus
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .io_region
                .add_subregion(self.io_region.clone(), 0)
                .with_context(|| "Failed to add IO container region.")
            {
                error!("{}", format!("{:?}", e));
            }
        }
        if command & COMMAND_MEMORY_SPACE != 0 {
            if let Err(e) = self
                .parent_bus
                .upgrade()
                .unwrap()
                .lock()
                .unwrap()
                .mem_region
                .add_subregion(self.mem_region.clone(), 0)
                .with_context(|| "Failed to add memory container region.")
            {
                error!("{}", format!("{:?}", e));
            }
        }
    }

    fn correct_race_unplug(&mut self, offset: usize, data: &[u8], old_status: u16) {
        let end = offset + data.len();
        let cap_offset = self.config.pci_express_cap_offset;
        if !ranges_overlap(
            offset,
            end,
            (cap_offset + PCI_EXP_SLTSTA) as usize,
            (cap_offset + PCI_EXP_SLTSTA + 2) as usize,
        ) {
            return;
        }

        let status =
            le_read_u16(&self.config.config, (cap_offset + PCI_EXP_SLTSTA) as usize).unwrap();
        let val: u16 = data[0] as u16 + ((data[1] as u16) << 8);
        if (val & !old_status & PCI_EXP_SLOTSTA_EVENTS) != 0 {
            let tmpstat =
                (status & !PCI_EXP_SLOTSTA_EVENTS) | (old_status & PCI_EXP_SLOTSTA_EVENTS);
            le_write_u16(
                &mut self.config.config,
                (cap_offset + PCI_EXP_SLTSTA) as usize,
                tmpstat,
            )
            .unwrap();
        }
    }

    fn do_unplug(&mut self, offset: usize, data: &[u8], old_ctl: u16, old_status: u16) {
        self.correct_race_unplug(offset, data, old_status);

        let end = offset + data.len();
        let cap_offset = self.config.pci_express_cap_offset;
        // Only care the write config about slot control
        if !ranges_overlap(
            offset,
            end,
            (cap_offset + PCI_EXP_SLTCTL) as usize,
            (cap_offset + PCI_EXP_SLTCTL + 2) as usize,
        ) {
            return;
        }

        let status =
            le_read_u16(&self.config.config, (cap_offset + PCI_EXP_SLTSTA) as usize).unwrap();
        let val = le_read_u16(&self.config.config, offset).unwrap();
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

impl PciDevOps for RootPort {
    fn init_write_mask(&mut self) -> Result<()> {
        self.config.init_common_write_mask()?;
        self.config.init_bridge_write_mask()
    }

    fn init_write_clear_mask(&mut self) -> Result<()> {
        self.config.init_common_write_clear_mask()?;
        self.config.init_bridge_write_clear_mask()
    }

    fn realize(mut self) -> Result<()> {
        self.init_write_mask()?;
        self.init_write_clear_mask()?;

        let config_space = &mut self.config.config;
        le_write_u16(config_space, VENDOR_ID as usize, PCI_VENDOR_ID_REDHAT)?;
        le_write_u16(config_space, DEVICE_ID as usize, DEVICE_ID_RP)?;
        le_write_u16(config_space, SUB_CLASS_CODE as usize, CLASS_CODE_PCI_BRIDGE)?;
        config_space[HEADER_TYPE as usize] = HEADER_TYPE_BRIDGE;
        config_space[PREF_MEMORY_BASE as usize] = PREF_MEM_RANGE_64BIT;
        config_space[PREF_MEMORY_LIMIT as usize] = PREF_MEM_RANGE_64BIT;
        init_multifunction(
            self.multifunction,
            config_space,
            self.devfn,
            self.parent_bus.clone(),
        )?;
        self.config
            .add_pcie_cap(self.devfn, self.port_num, PcieDevType::RootPort as u8)?;

        self.dev_id.store(self.devfn as u16, Ordering::SeqCst);
        init_msix(
            0,
            1,
            &mut self.config,
            self.dev_id.clone(),
            &self.name,
            None,
            None,
        )?;

        let parent_bus = self.parent_bus.upgrade().unwrap();
        let mut locked_parent_bus = parent_bus.lock().unwrap();
        #[cfg(target_arch = "x86_64")]
        locked_parent_bus
            .io_region
            .add_subregion(self.sec_bus.lock().unwrap().io_region.clone(), 0)
            .with_context(|| "Failed to register subregion in I/O space.")?;
        locked_parent_bus
            .mem_region
            .add_subregion(self.sec_bus.lock().unwrap().mem_region.clone(), 0)
            .with_context(|| "Failed to register subregion in memory space.")?;

        let name = self.name.clone();
        let root_port = Arc::new(Mutex::new(self));
        #[allow(unused_mut)]
        let mut locked_root_port = root_port.lock().unwrap();
        locked_root_port.sec_bus.lock().unwrap().parent_bridge =
            Some(Arc::downgrade(&root_port) as Weak<Mutex<dyn PciDevOps>>);
        locked_root_port.sec_bus.lock().unwrap().hotplug_controller =
            Some(Arc::downgrade(&root_port) as Weak<Mutex<dyn HotplugOps>>);
        let pci_device = locked_parent_bus.devices.get(&locked_root_port.devfn);
        if pci_device.is_none() {
            locked_parent_bus
                .child_buses
                .push(locked_root_port.sec_bus.clone());
            locked_parent_bus
                .devices
                .insert(locked_root_port.devfn, root_port.clone());
        } else {
            bail!(
                "Devfn {:?} has been used by {:?}",
                locked_root_port.devfn,
                pci_device.unwrap().lock().unwrap().name()
            );
        }
        // Need to drop locked_root_port in order to register root_port instance.
        drop(locked_root_port);
        MigrationManager::register_device_instance(RootPortState::descriptor(), root_port, &name);

        Ok(())
    }

    fn read_config(&mut self, offset: usize, data: &mut [u8]) {
        self.config.read(offset, data);
    }

    fn write_config(&mut self, offset: usize, data: &[u8]) {
        let size = data.len();
        let end = offset + size;
        if end > PCIE_CONFIG_SPACE_SIZE || size > 4 {
            error!(
                "Failed to write pcie config space at offset {} with data size {}",
                offset, size
            );
            return;
        }

        let cap_offset = self.config.pci_express_cap_offset;
        let old_ctl =
            le_read_u16(&self.config.config, (cap_offset + PCI_EXP_SLTCTL) as usize).unwrap();
        let old_status =
            le_read_u16(&self.config.config, (cap_offset + PCI_EXP_SLTSTA) as usize).unwrap();

        let old_br_ctl = le_read_u16(&self.config.config, BRIDGE_CONTROL.into()).unwrap();

        self.config.write(
            offset,
            data,
            self.dev_id.load(Ordering::Acquire),
            #[cfg(target_arch = "x86_64")]
            Some(&self.io_region),
            Some(&self.mem_region),
        );

        let new_br_ctl = le_read_u16(&self.config.config, BRIDGE_CONTROL.into()).unwrap();
        if (!old_br_ctl & new_br_ctl & BRIDGE_CTL_SEC_BUS_RESET) != 0 {
            if let Err(e) = self.reset(true) {
                error!(
                    "Failed to reset child devices under root port {}: {}",
                    self.name, e
                )
            }
        }

        if ranges_overlap(offset, end, COMMAND as usize, (COMMAND + 1) as usize)
            || ranges_overlap(offset, end, IO_BASE as usize, (IO_BASE + 2) as usize)
            || ranges_overlap(
                offset,
                end,
                MEMORY_BASE as usize,
                (MEMORY_BASE + 20) as usize,
            )
        {
            self.register_region();
        }

        self.do_unplug(offset, data, old_ctl, old_status);
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    /// Only set slot status to on, and no other device reset actions are implemented.
    fn reset(&mut self, reset_child_device: bool) -> Result<()> {
        if reset_child_device {
            self.sec_bus
                .lock()
                .unwrap()
                .reset()
                .with_context(|| "Fail to reset sec_bus in root port")?;
        } else {
            let cap_offset = self.config.pci_express_cap_offset;
            le_write_u16(
                &mut self.config.config,
                (cap_offset + PCI_EXP_SLTSTA) as usize,
                PCI_EXP_SLTSTA_PDS,
            )?;
            le_write_u16(
                &mut self.config.config,
                (cap_offset + PCI_EXP_SLTCTL) as usize,
                !PCI_EXP_SLTCTL_PCC | PCI_EXP_SLTCTL_PWR_IND_ON,
            )?;
            le_write_u16(
                &mut self.config.config,
                (cap_offset + PCI_EXP_LNKSTA) as usize,
                PCI_EXP_LNKSTA_DLLLA,
            )?;
        }
        self.config.reset_bridge_regs()?;
        self.config.reset_common_regs()
    }

    fn get_dev_path(&self) -> Option<String> {
        let parent_bus = self.parent_bus.upgrade().unwrap();
        let parent_dev_path = self.get_parent_dev_path(parent_bus);
        let dev_path = self.populate_dev_path(parent_dev_path, self.devfn, "/pci-bridge@");
        Some(dev_path)
    }
}

impl HotplugOps for RootPort {
    fn plug(&mut self, dev: &Arc<Mutex<dyn PciDevOps>>) -> Result<()> {
        let devfn = dev
            .lock()
            .unwrap()
            .devfn()
            .with_context(|| "Failed to get devfn")?;
        // Only if devfn is equal to 0, hot plugging is supported.
        if devfn != 0 {
            return Err(anyhow!(PciError::HotplugUnsupported(devfn)));
        }

        let offset = self.config.pci_express_cap_offset;
        le_write_set_value_u16(
            &mut self.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            PCI_EXP_SLTSTA_PDS | PCI_EXP_HP_EV_PDC | PCI_EXP_HP_EV_ABP,
        )?;
        le_write_set_value_u16(
            &mut self.config.config,
            (offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_CLS_2_5GB | PCI_EXP_LNKSTA_NLW_X1 | PCI_EXP_LNKSTA_DLLLA,
        )?;
        self.hotplug_event_notify();

        Ok(())
    }

    fn unplug_request(&mut self, dev: &Arc<Mutex<dyn PciDevOps>>) -> Result<()> {
        let pcie_cap_offset = self.config.pci_express_cap_offset;
        let sltctl = le_read_u16(
            &self.config.config,
            (pcie_cap_offset + PCI_EXP_SLTCTL) as usize,
        )
        .unwrap();

        if (sltctl & PCI_EXP_SLTCTL_PIC) == PCI_EXP_SLTCTL_PWR_IND_BLINK {
            bail!("Guest is still on the fly of another (un)pluging");
        }

        let devfn = dev
            .lock()
            .unwrap()
            .devfn()
            .with_context(|| "Failed to get devfn")?;
        if devfn != 0 {
            return self.unplug(dev);
        }

        let offset = self.config.pci_express_cap_offset;
        le_write_clear_value_u16(
            &mut self.config.config,
            (offset + PCI_EXP_LNKSTA) as usize,
            PCI_EXP_LNKSTA_DLLLA,
        )?;

        let mut slot_status = 0;
        if let Some(&true) = FAST_UNPLUG_FEATURE.get() {
            slot_status |= PCI_EXP_HP_EV_PDC;
        }
        le_write_set_value_u16(
            &mut self.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            slot_status,
        )?;

        if ((sltctl & PCI_EXP_SLTCTL_PIC) == PCI_EXP_SLTCTL_PWR_IND_OFF)
            && ((sltctl & PCI_EXP_SLTCTL_PCC) == PCI_EXP_SLTCTL_PWR_OFF)
        {
            // if the slot has already been unpluged, skip notifing the guest.
            return Ok(());
        }

        le_write_set_value_u16(
            &mut self.config.config,
            (offset + PCI_EXP_SLTSTA) as usize,
            slot_status | PCI_EXP_HP_EV_ABP,
        )?;
        self.hotplug_event_notify();
        Ok(())
    }

    fn unplug(&mut self, dev: &Arc<Mutex<dyn PciDevOps>>) -> Result<()> {
        let devfn = dev
            .lock()
            .unwrap()
            .devfn()
            .with_context(|| "Failed to get devfn")?;
        let mut locked_dev = dev.lock().unwrap();
        locked_dev.unrealize()?;
        self.sec_bus.lock().unwrap().devices.remove(&devfn);
        Ok(())
    }
}

impl StateTransfer for RootPort {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let mut state = RootPortState::default();

        for idx in 0..self.config.config.len() {
            state.config_space[idx] = self.config.config[idx];
            state.write_mask[idx] = self.config.write_mask[idx];
            state.write_clear_mask[idx] = self.config.write_clear_mask[idx];
        }
        state.last_cap_end = self.config.last_cap_end;
        state.last_ext_cap_end = self.config.last_ext_cap_end;
        state.last_ext_cap_offset = self.config.last_ext_cap_offset;

        Ok(state.as_bytes().to_vec())
    }

    fn set_state_mut(&mut self, state: &[u8]) -> migration::Result<()> {
        let root_port_state = *RootPortState::from_bytes(state)
            .ok_or_else(|| anyhow!(MigrationError::FromBytesError("ROOT_PORT")))?;

        let length = self.config.config.len();
        self.config.config = root_port_state.config_space[..length].to_vec();
        self.config.write_mask = root_port_state.write_mask[..length].to_vec();
        self.config.write_clear_mask = root_port_state.write_clear_mask[..length].to_vec();
        self.config.last_cap_end = root_port_state.last_cap_end;
        self.config.last_ext_cap_end = root_port_state.last_ext_cap_end;
        self.config.last_ext_cap_offset = root_port_state.last_ext_cap_offset;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&RootPortState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for RootPort {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::tests::create_pci_host;

    #[test]
    fn test_read_config() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().root_bus);
        let root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus, false);
        root_port.realize().unwrap();

        let root_port = pci_host.lock().unwrap().find_device(0, 8).unwrap();
        let mut buf = [1_u8; 4];
        root_port
            .lock()
            .unwrap()
            .read_config(PCIE_CONFIG_SPACE_SIZE - 1, &mut buf);
        assert_eq!(buf, [1_u8; 4]);
    }

    #[test]
    fn test_write_config() {
        let pci_host = create_pci_host();
        let root_bus = Arc::downgrade(&pci_host.lock().unwrap().root_bus);
        let root_port = RootPort::new("pcie.1".to_string(), 8, 0, root_bus, false);
        root_port.realize().unwrap();
        let root_port = pci_host.lock().unwrap().find_device(0, 8).unwrap();

        // Invalid write.
        let data = [1_u8; 4];
        root_port
            .lock()
            .unwrap()
            .write_config(PCIE_CONFIG_SPACE_SIZE - 1, &data);
        let mut buf = [0_u8];
        root_port
            .lock()
            .unwrap()
            .read_config(PCIE_CONFIG_SPACE_SIZE - 1, &mut buf);
        assert_eq!(buf, [0_u8]);
    }
}
