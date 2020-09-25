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

use std::sync::Arc;

use kvm_ioctls::VmFd;

pub use gicv3::Error as GICError;
pub use gicv3::GICv3;
use machine_manager::machine::{KvmVmState, MachineLifecycle};
#[cfg(target_arch = "aarch64")]
use util::{device_tree, errors};

// First 32 are private to each CPU (SGIs and PPIs).
const GIC_IRQ_INTERNAL: u32 = 32;

#[derive(Debug)]
pub enum Error {
    /// Invalid argument
    EINVAL(std::string::String),
}

/// Configure a Interrupt controller.
pub struct GICConfig {
    /// Config GIC version
    pub version: u32,
    /// GIC region mappings base address, aligned 64K
    pub map_region: u64,
    /// Config number of CPUs handled by the device
    pub vcpu_count: u64,
    /// Config maximum number of irqs handled by the device
    pub max_irq: u32,
    /// Config msi support
    pub msi: bool,
}

impl GICConfig {
    fn check_sanity(&self) -> Result<(), Error> {
        if self.version != kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3 {
            return Err(Error::EINVAL("GIC only support GICv3".to_string()));
        };

        if self.vcpu_count > 256 || self.vcpu_count == 0 {
            return Err(Error::EINVAL(
                "GIC only support maximum 256 vcpus".to_string(),
            ));
        }

        if self.map_region < 0x1000_0000 {
            return Err(Error::EINVAL(
                "GIC mapping Guest Physical Address need above 0x1000_0000".to_string(),
            ));
        };

        if self.max_irq <= GIC_IRQ_INTERNAL {
            return Err(Error::EINVAL("GIC irq numbers need above 32".to_string()));
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
    ) -> Result<Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>, GICError>
    where
        Self: Sized;

    /// Constructs `fdt` node for `GIC`.
    ///
    /// # Arguments
    ///
    /// * `fdt` - Device tree presented by bytes.
    fn generate_fdt(&self, fdt: &mut Vec<u8>) -> errors::Result<()>;
}

/// A wrapper around creating and using a kvm-based interrupt controller.
pub struct InterruptController {
    #[cfg(target_arch = "aarch64")]
    gic: Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>,
}

impl InterruptController {
    /// Constructs a new kvm_based `InterruptController`.
    ///
    /// # Arguments
    ///
    /// * `vm` - File descriptor for vmfd.
    /// * `gic_conf` - Configuration for `GIC`.
    pub fn new(vm: Arc<VmFd>, gic_conf: &GICConfig) -> Result<InterruptController, std::io::Error> {
        Ok(InterruptController {
            gic: GICv3::create_device(&vm, gic_conf).unwrap(),
        })
    }

    /// Change `InterruptController` lifecycle state to `Stopped`.
    pub fn stop(&self) {
        self.gic
            .notify_lifecycle(KvmVmState::Running, KvmVmState::Paused);
        debug!("Device gic stopped!");
    }
}

#[cfg(target_arch = "aarch64")]
impl device_tree::CompileFDT for InterruptController {
    fn generate_fdt_node(&self, fdt: &mut Vec<u8>) -> errors::Result<()> {
        self.gic.generate_fdt(fdt)?;
        debug!("Interrupt Controller device tree generated!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_create_gicv3() {
        use super::*;
        use kvm_ioctls::Kvm;

        let vm = if let Ok(vm_fd) = Kvm::new().and_then(|kvm| kvm.create_vm()) {
            Arc::new(vm_fd)
        } else {
            return;
        };

        let gic_conf = GICConfig {
            version: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3.into(),
            map_region: 0x0002_0000_0000,
            vcpu_count: 4,
            max_irq: 192,
            msi: false,
        };

        assert!(gicv3::GICv3::new(&vm, &gic_conf).is_ok());
    }
}
