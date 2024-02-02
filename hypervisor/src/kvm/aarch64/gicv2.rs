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

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use kvm_ioctls::{DeviceFd, VmFd};

use super::KvmDevice;
use crate::error::HypervisorError;
use devices::GICv2Access;

pub struct KvmGICv2 {
    fd: DeviceFd,
}

impl KvmGICv2 {
    pub fn new(vm_fd: Arc<VmFd>) -> Result<Self> {
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };

        let gic_fd = match vm_fd.create_device(&mut gic_device) {
            Ok(fd) => fd,
            Err(e) => return Err(anyhow!(HypervisorError::CreateKvmDevice(e))),
        };

        Ok(Self { fd: gic_fd })
    }
}

impl GICv2Access for KvmGICv2 {
    fn init_gic(&self, nr_irqs: u32, dist_base: u64, cpu_if_base: u64) -> Result<()> {
        KvmDevice::kvm_device_check(&self.fd, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0)?;

        // Init the interrupt number support by the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &nr_irqs as *const u32 as u64,
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
            &dist_base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv2 attribute: distributor address")?;

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            &cpu_if_base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv2 attribute: cpu address")
    }

    fn vcpu_gicr_attr(&self, offset: u64, cpu: usize) -> u64 {
        (((cpu as u64) << kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_SHIFT as u64)
            & kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_MASK)
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

    fn pause(&self) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES as u64,
            0,
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use devices::{GICDevice, GICVersion, GICv2, ICGICConfig, ICGICv2Config, GIC_IRQ_MAX};

    use crate::kvm::aarch64::gicv2::KvmGICv2;
    use crate::kvm::KvmHypervisor;

    #[test]
    fn test_create_kvm_gicv2() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let gic_conf = ICGICConfig {
            version: Some(GICVersion::GICv2),
            vcpu_count: 4,
            max_irq: GIC_IRQ_MAX,
            v2: Some(ICGICv2Config {
                dist_range: (0x0800_0000, 0x0001_0000),
                cpu_range: (0x080A_0000, 0x00F6_0000),
                v2m_range: None,
                sys_mem: None,
            }),
            v3: None,
        };
        let hypervisor_gic = KvmGICv2::new(kvm_hyp.vm_fd.clone().unwrap()).unwrap();
        let gic = GICv2::new(Arc::new(hypervisor_gic), &gic_conf).unwrap();
        assert!(gic.realize().is_ok());
    }
}
