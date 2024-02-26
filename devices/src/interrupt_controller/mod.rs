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

//! # Interrupt Controller
//!
//! This module is to create and manager interrupt controller.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Create hypervisor-based interrupt controller.
//! 2. Manager lifecycle for `GIC`.
//!
//! ## Platform Support
//!
//! - `aarch64`

#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "aarch64")]
mod aarch64;
mod error;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    GICConfig as ICGICConfig, GICDevice, GICVersion, GICv2, GICv2Access,
    GICv2Config as ICGICv2Config, GICv3, GICv3Access, GICv3Config as ICGICv3Config, GICv3ItsAccess,
    GICv3ItsState, GICv3State, GicRedistRegion, InterruptController, GIC_IRQ_INTERNAL, GIC_IRQ_MAX,
};
pub use error::InterruptError;

use std::sync::Arc;

use anyhow::Result;
use vmm_sys_util::eventfd::EventFd;

use super::pci::MsiVector;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub enum TriggerMode {
    Level,
    #[default]
    Edge,
}

pub trait LineIrqManager: Send + Sync {
    fn irqfd_enable(&self) -> bool;

    fn register_irqfd(
        &self,
        _irq_fd: Arc<EventFd>,
        _irq: u32,
        _trigger_mode: TriggerMode,
    ) -> Result<()> {
        Ok(())
    }

    fn unregister_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Ok(())
    }

    fn set_level_irq(&self, _irq: u32, _level: bool) -> Result<()> {
        Ok(())
    }

    fn set_edge_irq(&self, _irq: u32) -> Result<()> {
        Ok(())
    }

    fn write_irqfd(&self, _irq_fd: Arc<EventFd>) -> Result<()> {
        Ok(())
    }
}

pub trait MsiIrqManager: Send + Sync {
    fn allocate_irq(&self, _vector: MsiVector) -> Result<u32> {
        Ok(0)
    }

    fn release_irq(&self, _irq: u32) -> Result<()> {
        Ok(())
    }

    fn register_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Ok(())
    }

    fn unregister_irqfd(&self, _irq_fd: Arc<EventFd>, _irq: u32) -> Result<()> {
        Ok(())
    }

    fn trigger(
        &self,
        _irq_fd: Option<Arc<EventFd>>,
        _vector: MsiVector,
        _dev_id: u32,
    ) -> Result<()> {
        Ok(())
    }

    fn update_route_table(&self, _gsi: u32, _vector: MsiVector) -> Result<()> {
        Ok(())
    }
}

pub struct IrqManager {
    pub line_irq_manager: Option<Arc<dyn LineIrqManager>>,
    pub msi_irq_manager: Option<Arc<dyn MsiIrqManager>>,
}

#[derive(Default, Clone)]
pub struct IrqState {
    pub irq: u32,
    irq_fd: Option<Arc<EventFd>>,
    irq_handler: Option<Arc<dyn LineIrqManager>>,
    trigger_mode: TriggerMode,
}

impl IrqState {
    pub fn new(
        irq: u32,
        irq_fd: Option<Arc<EventFd>>,
        irq_handler: Option<Arc<dyn LineIrqManager>>,
        trigger_mode: TriggerMode,
    ) -> Self {
        IrqState {
            irq,
            irq_fd,
            irq_handler,
            trigger_mode,
        }
    }

    pub fn register_irq(&mut self) -> Result<()> {
        let irq_handler = self.irq_handler.as_ref().unwrap();
        if !irq_handler.irqfd_enable() {
            self.irq_fd = None;
            return Ok(());
        }

        if let Some(irqfd) = self.irq_fd.clone() {
            irq_handler.register_irqfd(irqfd, self.irq, self.trigger_mode.clone())?;
        }

        Ok(())
    }

    pub fn trigger_irq(&self) -> Result<()> {
        let irq_handler = self.irq_handler.as_ref().unwrap();
        if let Some(irq_fd) = &self.irq_fd {
            return irq_handler.write_irqfd(irq_fd.clone());
        }
        if self.trigger_mode == TriggerMode::Edge {
            irq_handler.set_edge_irq(self.irq)
        } else {
            irq_handler.set_level_irq(self.irq, true)
        }
    }
}
