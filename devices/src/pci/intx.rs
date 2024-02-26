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

use std::sync::{Arc, Mutex, Weak};

use anyhow::Result;
use log::error;

use crate::interrupt_controller::LineIrqManager;
use crate::pci::{swizzle_map_irq, PciBus, PciConfig, INTERRUPT_PIN, PCI_INTR_BASE, PCI_PIN_NUM};
use util::test_helper::{is_test_enabled, trigger_intx};

pub type InterruptHandler = Box<dyn Fn(u32, bool) -> Result<()> + Send + Sync>;

/// PCI INTx information.
pub struct PciIntxState {
    /// Gsi of PCI bus INT#A.
    pub gsi_base: u32,
    /// INTx IRQ numbers to be asserted of every INTx virtual interrupt line.
    pub irq_count: [i8; PCI_PIN_NUM as usize],
    /// Handler of asserting the INTx IRQ.
    pub irq_handler: Arc<dyn LineIrqManager>,
}

impl PciIntxState {
    pub fn new(gsi_base: u32, irq_handler: Arc<dyn LineIrqManager>) -> Self {
        Self {
            gsi_base,
            irq_count: [0; PCI_PIN_NUM as usize],
            irq_handler,
        }
    }
}

/// INTx structure.
pub struct Intx {
    /// Device name.
    pub device_name: String,
    /// Physical interrupt pin.
    pub irq_pin: u32,
    /// Interrupt level.
    pub level: u8,
    /// Driver enable status.
    pub enabled: bool,
    /// Interrupt info related to INTx.
    pub intx_state: Option<Arc<Mutex<PciIntxState>>>,
}

impl Intx {
    pub fn new(name: String, irq_pin: u32, intx_state: Option<Arc<Mutex<PciIntxState>>>) -> Self {
        Self {
            device_name: name,
            irq_pin,
            level: 0,
            enabled: true,
            intx_state,
        }
    }

    pub fn notify(&mut self, level: u8) {
        assert!(level == 0 || level == 1);
        if self.level == level {
            return;
        };

        let change: i8 = level as i8 - self.level as i8;
        self.level = level;
        if !self.enabled {
            error!(
                "INTx is disabled, failed to set irq INTx interrupt for {}.",
                self.device_name
            );
            return;
        }

        self.change_irq_level(change);
    }

    pub fn change_irq_level(&self, change: i8) {
        if let Some(intx_state) = &self.intx_state {
            let mut locked_intx_state = intx_state.lock().unwrap();
            locked_intx_state.irq_count[self.irq_pin as usize] += change;
            if locked_intx_state.irq_count[self.irq_pin as usize] < 0 {
                locked_intx_state.irq_count[self.irq_pin as usize] = 0;
            }

            let irq = locked_intx_state.gsi_base + self.irq_pin;
            let level = locked_intx_state.irq_count[self.irq_pin as usize] != 0;

            if is_test_enabled() {
                trigger_intx(irq + PCI_INTR_BASE as u32, change);
                return;
            }

            let irq_handler = &locked_intx_state.irq_handler;
            if let Err(e) = irq_handler.set_level_irq(irq, level) {
                error!(
                    "Failed to set irq {} level {} of device {}: {}.",
                    irq, level, self.device_name, e
                );
            }
        } else {
            error!(
                "Can't set irq pin {} for {}, the INTx handler is not initialized",
                self.irq_pin, self.device_name
            );
        };
    }

    pub fn reset(&mut self) {
        self.notify(0);
        self.enabled = true;
    }
}

pub fn init_intx(
    name: String,
    config: &mut PciConfig,
    parent_bus: Weak<Mutex<PciBus>>,
    devfn: u8,
) -> Result<()> {
    if config.config[INTERRUPT_PIN as usize] == 0 {
        let (irq, intx_state) = (std::u32::MAX, None);
        let intx = Arc::new(Mutex::new(Intx::new(name, irq, intx_state)));
        config.intx = Some(intx);
        return Ok(());
    }

    let (irq, intx_state) = if let Some(pci_bus) = parent_bus.upgrade() {
        let locked_pci_bus = pci_bus.lock().unwrap();
        let pin = config.config[INTERRUPT_PIN as usize] - 1;

        let (irq, intx_state) = match &locked_pci_bus.parent_bridge {
            Some(parent_bridge) => {
                let parent_bridge = parent_bridge.upgrade().unwrap();
                let locked_parent_bridge = parent_bridge.lock().unwrap();
                (
                    swizzle_map_irq(locked_parent_bridge.pci_base().devfn, pin),
                    locked_parent_bridge.get_intx_state(),
                )
            }
            None => {
                if locked_pci_bus.intx_state.is_some() {
                    (
                        swizzle_map_irq(devfn, pin),
                        Some(locked_pci_bus.intx_state.as_ref().unwrap().clone()),
                    )
                } else {
                    (std::u32::MAX, None)
                }
            }
        };
        (irq, intx_state)
    } else {
        (std::u32::MAX, None)
    };

    let intx = Arc::new(Mutex::new(Intx::new(name, irq, intx_state)));

    config.intx = Some(intx);
    Ok(())
}
