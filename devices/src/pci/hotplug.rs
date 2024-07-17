// Copyright (c) 2021 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Context, Result};

use crate::pci::PciBus;
use crate::{convert_bus_ref, Bus, Device, PCI_BUS};

pub trait HotplugOps: Send {
    /// Plug device, usually called when hot plug device in device_add.
    fn plug(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()>;

    /// Unplug device request, usually called when hot unplug device in device_del.
    /// Only send unplug request to the guest OS, without actually removing the device.
    fn unplug_request(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()>;

    /// Remove the device.
    fn unplug(&mut self, dev: &Arc<Mutex<dyn Device>>) -> Result<()>;
}

/// Plug the device into the bus.
///
/// # Arguments
///
/// * `bus` - Bus which to be attached.
/// * `dev` - PCI device.
///
/// # Errors
///
/// Return Error if
/// * No hot plug controller found.
/// * Device plug failed.
pub fn handle_plug(bus: &Arc<Mutex<dyn Bus>>, dev: &Arc<Mutex<dyn Device>>) -> Result<()> {
    PCI_BUS!(bus, locked_bus, pci_bus);
    if let Some(hpc) = pci_bus.hotplug_controller.as_ref() {
        hpc.upgrade().unwrap().lock().unwrap().plug(dev)
    } else {
        bail!(
            "No hot plug controller found for bus {} when plug",
            pci_bus.name()
        );
    }
}

/// Unplug the device from the bus.
///
/// # Arguments
///
/// * `bus` - Bus which the device attached.
/// * `dev` - PCI device.
///
/// # Errors
///
/// Return Error if
/// * No hot plug controller found.
/// * Device unplug request failed.
pub fn handle_unplug_pci_request(
    bus: &Arc<Mutex<dyn Bus>>,
    dev: &Arc<Mutex<dyn Device>>,
) -> Result<()> {
    PCI_BUS!(bus, locked_bus, pci_bus);
    let hpc = pci_bus
        .hotplug_controller
        .as_ref()
        .cloned()
        .with_context(|| {
            format!(
                "No hot plug controller found for bus {} when unplug request",
                pci_bus.name()
            )
        })?;
    // No need to hold the lock.
    drop(locked_bus);
    hpc.upgrade().unwrap().lock().unwrap().unplug_request(dev)
}
