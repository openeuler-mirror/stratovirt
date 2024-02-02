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

mod gicv2;
mod gicv3;
mod state;

pub use gicv2::GICv2;
pub use gicv2::GICv2Access;
pub use gicv2::GICv2Config;
pub use gicv3::GICv3;
pub use gicv3::GICv3Access;
pub use gicv3::GICv3Config;
pub use gicv3::GICv3ItsAccess;
pub use gicv3::GicRedistRegion;
pub use state::{GICv3ItsState, GICv3State};

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use crate::interrupt_controller::error::InterruptError;
use machine_manager::machine::{MachineLifecycle, VmState};
use util::device_tree::{self, FdtBuilder};

// First 32 are private to each CPU (SGIs and PPIs).
pub const GIC_IRQ_INTERNAL: u32 = 32;
// Last usable IRQ on aarch64.
pub const GIC_IRQ_MAX: u32 = 192;

/// GIC version type.
pub enum GICVersion {
    GICv2,
    GICv3,
}

pub struct GICConfig {
    /// Config GIC version
    pub version: Option<GICVersion>,
    /// Config number of CPUs handled by the device
    pub vcpu_count: u64,
    /// Config maximum number of irqs handled by the device
    pub max_irq: u32,
    /// v2 config.
    pub v2: Option<GICv2Config>,
    /// v3 config.
    pub v3: Option<GICv3Config>,
}

impl GICConfig {
    pub fn check_sanity(&self) -> Result<()> {
        if self.max_irq <= GIC_IRQ_INTERNAL {
            return Err(anyhow!(InterruptError::InvalidConfig(
                "GIC irq numbers need above 32".to_string()
            )));
        }
        Ok(())
    }
}

/// A wrapper for `GIC` must perform the function.
pub trait GICDevice: MachineLifecycle {
    /// Realize function for hypervisor_based `GIC` device.
    fn realize(&self) -> Result<()>;

    /// Reset 'GIC'
    fn reset(&self) -> Result<()> {
        Ok(())
    }

    /// Constructs `fdt` node for `GIC`.
    ///
    /// # Arguments
    ///
    /// * `fdt` - Device tree presented by bytes.
    fn generate_fdt(&self, fdt: &mut FdtBuilder) -> Result<()>;

    /// Get GIC redistributor number.
    fn get_redist_count(&self) -> u8 {
        0
    }
}

#[derive(Clone)]
/// A wrapper around creating and using a hypervisor-based interrupt controller.
pub struct InterruptController {
    gic: Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>,
}

impl InterruptController {
    /// Constructs a new hypervisor_based `InterruptController`.
    ///
    /// # Arguments
    ///
    /// * `gic_conf` - Configuration for `GIC`.
    pub fn new(
        gic: Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>,
    ) -> InterruptController {
        InterruptController { gic }
    }

    pub fn realize(&self) -> Result<()> {
        self.gic
            .realize()
            .with_context(|| "Failed to realize GIC")?;
        Ok(())
    }

    /// Reset the InterruptController
    pub fn reset(&self) -> Result<()> {
        self.gic.reset().with_context(|| "Failed to reset GIC")
    }

    /// Change `InterruptController` lifecycle state to `Stopped`.
    pub fn stop(&self) {
        self.gic.notify_lifecycle(VmState::Running, VmState::Paused);
    }

    pub fn get_redist_count(&self) -> u8 {
        self.gic.get_redist_count()
    }
}

impl device_tree::CompileFDT for InterruptController {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> Result<()> {
        self.gic.generate_fdt(fdt)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gic_config() {
        let mut gic_conf = GICConfig {
            version: Some(GICVersion::GICv3),
            vcpu_count: 4,
            max_irq: GIC_IRQ_MAX,
            v2: None,
            v3: None,
        };

        assert!(gic_conf.check_sanity().is_ok());
        gic_conf.max_irq = 32;
        assert!(gic_conf.check_sanity().is_err());
    }
}
