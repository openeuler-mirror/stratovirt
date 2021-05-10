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

mod gicv3;

pub use gicv3::GICv3;

use std::sync::Arc;

use kvm_ioctls::VmFd;
use machine_manager::machine::{KvmVmState, MachineLifecycle};
use util::{device_tree, errors::Result as UtilResult};

use super::errors::{ErrorKind, Result, ResultExt};

// First 32 are private to each CPU (SGIs and PPIs).
const GIC_IRQ_INTERNAL: u32 = 32;

/// Configure a Interrupt controller.
pub struct GICConfig {
    /// Config GIC version
    pub version: u32,
    /// Config number of CPUs handled by the device
    pub vcpu_count: u64,
    /// Config maximum number of irqs handled by the device
    pub max_irq: u32,
    /// Config msi support
    pub msi: bool,
    /// GIC distributor address range.
    pub dist_range: (u64, u64),
    /// GIC redistributor address range, support multiple redistributor regions.
    pub redist_region_ranges: Vec<(u64, u64)>,
    /// GIC ITS address ranges.
    pub its_range: Option<(u64, u64)>,
}

impl GICConfig {
    fn check_sanity(&self) -> Result<()> {
        if self.version != kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3 {
            return Err(ErrorKind::InvalidConfig("GIC only support GICv3".to_string()).into());
        };

        if self.vcpu_count > 256 || self.vcpu_count == 0 {
            return Err(
                ErrorKind::InvalidConfig("GIC only support maximum 256 vcpus".to_string()).into(),
            );
        }

        if self.max_irq <= GIC_IRQ_INTERNAL {
            return Err(
                ErrorKind::InvalidConfig("GIC irq numbers need above 32".to_string()).into(),
            );
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
        vm: &Arc<VmFd>,
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
    fn generate_fdt(&self, fdt: &mut Vec<u8>) -> UtilResult<()>;
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
    /// * `vm` - File descriptor for vmfd.
    /// * `gic_conf` - Configuration for `GIC`.
    pub fn new(vm: Arc<VmFd>, gic_conf: &GICConfig) -> Result<InterruptController> {
        Ok(InterruptController {
            gic: GICv3::create_device(&vm, gic_conf).chain_err(|| "Failed to realize GIC")?,
        })
    }

    pub fn realize(&self) -> Result<()> {
        self.gic.realize().chain_err(|| "Failed to realize GIC")?;
        Ok(())
    }

    /// Change `InterruptController` lifecycle state to `Stopped`.
    pub fn stop(&self) {
        self.gic
            .notify_lifecycle(KvmVmState::Running, KvmVmState::Paused);
    }
}

impl device_tree::CompileFDT for InterruptController {
    fn generate_fdt_node(&self, fdt: &mut Vec<u8>) -> UtilResult<()> {
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
            version: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3.into(),
            vcpu_count: 4,
            max_irq: 192,
            msi: false,
            dist_range: (0x0800_0000, 0x0001_0000),
            redist_region_ranges: vec![(0x080A_0000, 0x00F6_0000)],
            its_range: None,
        };

        assert!(gic_conf.check_sanity().is_ok());
        gic_conf.version = 3;
        assert!(gic_conf.check_sanity().is_err());
        gic_conf.version = kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3.into();
        assert!(gic_conf.check_sanity().is_ok());

        gic_conf.vcpu_count = 257;
        assert!(gic_conf.check_sanity().is_err());
        gic_conf.vcpu_count = 0;
        assert!(gic_conf.check_sanity().is_err());
        gic_conf.vcpu_count = 24;
        assert!(gic_conf.check_sanity().is_ok());

        assert!(gic_conf.check_sanity().is_ok());

        gic_conf.max_irq = 32;
        assert!(gic_conf.check_sanity().is_err());
    }
}
