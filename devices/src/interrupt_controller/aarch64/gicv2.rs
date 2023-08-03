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

use std::marker::{Send, Sync};
use std::sync::{Arc, Mutex};

use super::{GICConfig, GICDevice, KvmDevice, UtilResult};
use crate::interrupt_controller::InterruptError;
use address_space::AddressSpace;
use anyhow::{anyhow, Context, Result};
use hypervisor::kvm::KVM_FDS;
use kvm_ioctls::DeviceFd;
use log::error;
use machine_manager::machine::{KvmVmState, MachineLifecycle};
use util::device_tree::{self, FdtBuilder};
// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;

/// Configure a v2 Interrupt controller.
pub struct GICv2Config {
    /// GIC distributor address range.
    pub dist_range: (u64, u64),
    /// GIC cpu interface address range.
    pub cpu_range: (u64, u64),
    /// GIC v2m range .
    pub v2m_range: Option<(u64, u64)>,
    /// GIC system memory.
    pub sys_mem: Option<Arc<AddressSpace>>,
}

/// Access wrapper for GICv2.
pub trait GICv2Access {
    /// Returns `gicr_attr` of `vCPU`.
    fn vcpu_gicr_attr(&self, offset: u64, cpu: usize) -> u64;

    fn access_gic_distributor(&self, offset: u64, gicd_value: &mut u32, write: bool) -> Result<()>;

    fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()>;
}

struct GicCpuInterfaceRegion {
    /// Base address.
    base: u64,
    /// Size of Cpu Interface region.
    size: u64,
}

struct GicDistGuestRegion {
    /// Base address.
    base: u64,
    /// Size of Cpu Interface region.
    size: u64,
}

/// A wrapper around creating and managing a `GICv2`.
pub struct GICv2 {
    /// The fd for the GICv2 device.
    fd: DeviceFd,
    /// Maximum irq number.
    nr_irqs: u32,
    /// GICv2 cpu interface region.
    cpu_interface_region: GicCpuInterfaceRegion,
    /// Guest physical address space of the GICv2 distributor register mappings.
    dist_guest_region: GicDistGuestRegion,
    /// Lifecycle state for GICv2.
    state: Arc<Mutex<KvmVmState>>,
}

impl GICv2 {
    fn new(config: &GICConfig) -> Result<Self> {
        let v2config = match config.v2.as_ref() {
            Some(v2) => v2,
            None => {
                return Err(anyhow!(InterruptError::InvalidConfig(
                    "no v2 config found".to_string()
                )))
            }
        };

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };

        let gic_fd = KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .create_device(&mut gic_device)
            .with_context(|| "Failed to create GICv2 device")?;

        let cpu_interface_region = GicCpuInterfaceRegion {
            base: v2config.dist_range.0 + KVM_VGIC_V2_DIST_SIZE,
            size: KVM_VGIC_V2_CPU_SIZE,
        };
        let dist_guest_region = GicDistGuestRegion {
            base: v2config.dist_range.0,
            size: v2config.dist_range.1,
        };

        let gicv2 = GICv2 {
            fd: gic_fd,
            nr_irqs: config.max_irq,
            cpu_interface_region,
            dist_guest_region,
            state: Arc::new(Mutex::new(KvmVmState::Created)),
        };

        Ok(gicv2)
    }

    fn realize(&self) -> Result<()> {
        KvmDevice::kvm_device_check(&self.fd, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0)?;

        // Init the interrupt number support by the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &self.nr_irqs as *const u32 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv2 attribute: irqs")?;

        // Finalize the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            true,
        )
        .with_context(|| "KVM failed to initialize GICv2")?;

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
            &self.dist_guest_region.base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv2 attribute: distributor address")?;

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            &self.cpu_interface_region.base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv2 attribute: cpu address")?;

        *self.state.lock().unwrap() = KvmVmState::Running;

        Ok(())
    }

    fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }
}

impl MachineLifecycle for GICv2 {
    fn pause(&self) -> bool {
        // VM change state will flush REDIST pending tables into guest RAM.
        if KvmDevice::kvm_device_access(
            self.device_fd(),
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES as u64,
            0,
            true,
        )
        .is_ok()
        {
            *self.state.lock().unwrap() = KvmVmState::Running;
            true
        } else {
            false
        }
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        let state = self.state.lock().unwrap();
        if *state != old {
            error!("GICv2 lifecycle error: state check failed.");
            return false;
        }
        drop(state);

        match (old, new) {
            (KvmVmState::Running, KvmVmState::Paused) => self.pause(),
            _ => true,
        }
    }
}

impl GICv2Access for GICv2 {
    fn vcpu_gicr_attr(&self, offset: u64, cpu: usize) -> u64 {
        (((cpu as u64) << kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_SHIFT as u64)
            & kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_MASK as u64)
            | ((offset << kvm_bindings::KVM_DEV_ARM_VGIC_OFFSET_SHIFT as u64)
                & kvm_bindings::KVM_DEV_ARM_VGIC_OFFSET_MASK as u64)
    }

    fn access_gic_distributor(&self, offset: u64, gicd_value: &mut u32, write: bool) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            offset,
            gicd_value as *mut u32 as u64,
            write,
        )
        .with_context(|| format!("Failed to access gic distributor for offset 0x{:x}", offset))
    }

    fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
            self.vcpu_gicr_attr(offset, cpu),
            gicc_value as *mut u64 as u64,
            write,
        )
        .with_context(|| format!("Failed to access gic cpu for offset 0x{:x}", offset))
    }
}

impl GICDevice for GICv2 {
    fn create_device(gic_conf: &GICConfig) -> Result<Arc<dyn GICDevice + Send + Sync>> {
        let gicv2 = Arc::new(GICv2::new(gic_conf)?);

        Ok(gicv2)
    }

    fn realize(&self) -> Result<()> {
        self.realize().with_context(|| "Failed to realize GICv2")?;

        Ok(())
    }

    fn generate_fdt(&self, fdt: &mut FdtBuilder) -> UtilResult<()> {
        let gic_reg = vec![
            self.dist_guest_region.base,
            self.dist_guest_region.size,
            self.cpu_interface_region.base,
            self.cpu_interface_region.size,
        ];

        let intc_node_dep = fdt.begin_node("intc")?;
        fdt.set_property_string("compatible", "arm,cortex-a15-gic")?;
        fdt.set_property("interrupt-controller", &Vec::new())?;
        fdt.set_property_u32("#interrupt-cells", 0x3)?;
        fdt.set_property_u32("phandle", device_tree::GIC_PHANDLE)?;
        fdt.set_property_u32("#address-cells", 0x2)?;
        fdt.set_property_u32("#size-cells", 0x2)?;
        fdt.set_property_array_u64("reg", &gic_reg)?;

        let gic_intr = [
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            0x9,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ];

        fdt.set_property_array_u32("interrupts", &gic_intr)?;

        fdt.end_node(intc_node_dep)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hypervisor::kvm::KVMFds;

    use super::super::GICVersion;
    use super::super::GICv2Config;
    use super::*;

    use crate::GIC_IRQ_MAX;

    #[test]
    fn test_create_gicv2() {
        let kvm_fds = KVMFds::new();
        if kvm_fds.vm_fd.is_none() {
            return;
        }
        KVM_FDS.store(Arc::new(kvm_fds));

        let gic_conf = GICConfig {
            version: Some(GICVersion::GICv2),
            vcpu_count: 4,
            max_irq: GIC_IRQ_MAX,
            v2: Some(GICv2Config {
                dist_range: (0x0800_0000, 0x0001_0000),
                cpu_range: (0x080A_0000, 0x00F6_0000),
                v2m_range: None,
                sys_mem: None,
            }),
            v3: None,
        };
        assert!(GICv2::new(&gic_conf).is_ok());
    }
}
