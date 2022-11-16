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
#[allow(dead_code)]
mod state;

use kvm_ioctls::DeviceFd;

pub use gicv2::{GICv2, GICv2Config};
pub use gicv3::{GICv3, GICv3Config};

use std::sync::Arc;

use crate::interrupt_controller::error::InterruptError;
use anyhow::{anyhow, Context, Result};
use machine_manager::machine::{KvmVmState, MachineLifecycle};
use util::{
    device_tree::{self, FdtBuilder},
    Result as UtilResult,
};

// First 32 are private to each CPU (SGIs and PPIs).
pub(crate) const GIC_IRQ_INTERNAL: u32 = 32;
// Last usable IRQ on aarch64.
pub const GIC_IRQ_MAX: u32 = 192;

/// GIC version type.
pub enum GICVersion {
    GICv2,
    GICv3,
}

/// A wrapper for kvm_based device check and access.
pub struct KvmDevice;

impl KvmDevice {
    fn kvm_device_check(fd: &DeviceFd, group: u32, attr: u64) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: 0,
            flags: 0,
        };
        fd.has_device_attr(&attr)
            .with_context(|| "Failed to check device attributes for GIC.")?;
        Ok(())
    }

    fn kvm_device_access(
        fd: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        write: bool,
    ) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr,
            flags: 0,
        };

        if write {
            fd.set_device_attr(&attr)
                .with_context(|| "Failed to set device attributes for GIC.")?;
        } else {
            let mut attr = attr;
            fd.get_device_attr(&mut attr)
                .with_context(|| "Failed to get device attributes for GIC.")?;
        };

        Ok(())
    }
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
    fn check_sanity(&self) -> Result<()> {
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
    /// Constructs a kvm_based `GIC` device.
    ///
    /// # Arguments
    ///
    /// * `vm` - File descriptor for vmfd.
    /// * `gic_conf` - Configuration for `GIC`.
    fn create_device(
        gic_conf: &GICConfig,
    ) -> Result<Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>>
    where
        Self: Sized;

    /// Realize function for kvm_based `GIC` device.
    fn realize(&self) -> Result<()>;

    /// Constructs `fdt` node for `GIC`.
    ///
    /// # Arguments
    ///
    /// * `fdt` - Device tree presented by bytes.
    fn generate_fdt(&self, fdt: &mut FdtBuilder) -> UtilResult<()>;

    /// Get GIC redistributor number.
    fn get_redist_count(&self) -> u8 {
        0
    }
}

/// A wrapper around creating and using a kvm-based interrupt controller.
pub struct InterruptController {
    gic: Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>,
}

impl InterruptController {
    /// Constructs a new kvm_based `InterruptController`.
    ///
    /// # Arguments
    ///
    /// * `gic_conf` - Configuration for `GIC`.
    pub fn new(gic_conf: &GICConfig) -> Result<InterruptController> {
        gic_conf.check_sanity()?;
        let gic = match &gic_conf.version {
            Some(GICVersion::GICv3) => GICv3::create_device(gic_conf),
            Some(GICVersion::GICv2) => GICv2::create_device(gic_conf),
            // Try v3 first if no version specified.
            None => GICv3::create_device(gic_conf).or_else(|_| GICv2::create_device(gic_conf)),
        };
        let intc = InterruptController {
            gic: gic.with_context(|| "Failed to realize GIC")?,
        };
        Ok(intc)
    }

    pub fn realize(&self) -> Result<()> {
        self.gic
            .realize()
            .with_context(|| "Failed to realize GIC")?;
        Ok(())
    }

    /// Change `InterruptController` lifecycle state to `Stopped`.
    pub fn stop(&self) {
        self.gic
            .notify_lifecycle(KvmVmState::Running, KvmVmState::Paused);
    }

    pub fn get_redist_count(&self) -> u8 {
        self.gic.get_redist_count()
    }
}

impl device_tree::CompileFDT for InterruptController {
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> UtilResult<()> {
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
