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
use log::info;

use super::KvmDevice;
use crate::error::HypervisorError;
use devices::{GICv3Access, GICv3ItsAccess, GicRedistRegion};

pub struct KvmGICv3 {
    fd: DeviceFd,
    vcpu_count: u64,
}

impl KvmGICv3 {
    pub fn new(vm_fd: Arc<VmFd>, vcpu_count: u64) -> Result<Self> {
        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };

        let gic_fd = match vm_fd.create_device(&mut gic_device) {
            Ok(fd) => fd,
            Err(e) => return Err(anyhow!(HypervisorError::CreateKvmDevice(e))),
        };

        Ok(Self {
            fd: gic_fd,
            vcpu_count,
        })
    }
}

impl GICv3Access for KvmGICv3 {
    fn init_gic(
        &self,
        nr_irqs: u32,
        redist_regions: Vec<GicRedistRegion>,
        dist_base: u64,
    ) -> Result<()> {
        if redist_regions.len() > 1 {
            KvmDevice::kvm_device_check(
                &self.fd,
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION as u64,
            )
            .with_context(|| {
                "Multiple redistributors are acquired while KVM does not provide support."
            })?;
        }

        if redist_regions.len() == 1 {
            KvmDevice::kvm_device_access(
                &self.fd,
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
                &redist_regions.get(0).unwrap().base as *const u64 as u64,
                true,
            )
            .with_context(|| "Failed to set GICv3 attribute: redistributor address")?;
        } else {
            for redist in &redist_regions {
                KvmDevice::kvm_device_access(
                    &self.fd,
                    kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                    u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION),
                    &redist.base_attr as *const u64 as u64,
                    true,
                )
                .with_context(|| "Failed to set GICv3 attribute: redistributor region address")?;
            }
        }

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &dist_base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv3 attribute: distributor address")?;

        KvmDevice::kvm_device_check(&self.fd, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0)?;

        // Init the interrupt number support by the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &nr_irqs as *const u32 as u64,
            true,
        )
        .with_context(|| "Failed to set GICv3 attribute: irqs")?;

        // Finalize the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            true,
        )
        .with_context(|| "KVM failed to initialize GICv3")
    }

    fn vcpu_gicr_attr(&self, cpu: usize) -> u64 {
        let clustersz = 16;

        let aff1 = (cpu / clustersz) as u64;
        let aff0 = (cpu % clustersz) as u64;

        let affid = (aff1 << 8) | aff0;
        let cpu_affid: u64 = ((affid & 0xFF_0000_0000) >> 8) | (affid & 0xFF_FFFF);

        let last = u64::from((self.vcpu_count - 1) == cpu as u64);

        ((cpu_affid << 32) | (1 << 24) | (1 << 8) | (last << 4))
            & kvm_bindings::KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64
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

    fn access_gic_redistributor(
        &self,
        offset: u64,
        cpu: usize,
        gicr_value: &mut u32,
        write: bool,
    ) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
            self.vcpu_gicr_attr(cpu) | offset,
            gicr_value as *mut u32 as u64,
            write,
        )
        .with_context(|| {
            format!(
                "Failed to access gic redistributor for offset 0x{:x}",
                offset
            )
        })
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
            self.vcpu_gicr_attr(cpu) | offset,
            gicc_value as *mut u64 as u64,
            write,
        )
        .with_context(|| format!("Failed to access gic cpu for offset 0x{:x}", offset))
    }

    fn access_gic_line_level(&self, offset: u64, gicll_value: &mut u32, write: bool) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO,
            self.vcpu_gicr_attr(0) | offset,
            gicll_value as *mut u32 as u64,
            write,
        )
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

pub struct KvmGICv3Its {
    fd: DeviceFd,
}

impl KvmGICv3Its {
    pub fn new(vm_fd: Arc<VmFd>) -> Result<Self> {
        let mut its_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
            fd: 0,
            flags: 0,
        };

        let its_fd = match vm_fd.create_device(&mut its_device) {
            Ok(fd) => fd,
            Err(e) => return Err(anyhow!(HypervisorError::CreateKvmDevice(e))),
        };

        Ok(Self { fd: its_fd })
    }
}

impl GICv3ItsAccess for KvmGICv3Its {
    fn init_gic_its(&self, msi_base: u64) -> Result<()> {
        KvmDevice::kvm_device_check(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
        )
        .with_context(|| "ITS address attribute is not supported for KVM")?;

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            &msi_base as *const u64 as u64,
            true,
        )
        .with_context(|| "Failed to set ITS attribute: ITS address")?;

        // Finalize the GIC Its.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            &msi_base as *const u64 as u64,
            true,
        )
        .with_context(|| "KVM failed to initialize ITS")?;

        Ok(())
    }

    fn access_gic_its(&self, attr: u32, its_value: &mut u64, write: bool) -> Result<()> {
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
            attr as u64,
            its_value as *const u64 as u64,
            write,
        )
    }

    fn access_gic_its_tables(&self, save: bool) -> Result<()> {
        let attr = if save {
            kvm_bindings::KVM_DEV_ARM_ITS_SAVE_TABLES as u64
        } else {
            kvm_bindings::KVM_DEV_ARM_ITS_RESTORE_TABLES as u64
        };
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr,
            std::ptr::null::<u64>() as u64,
            true,
        )
    }

    fn reset(&self) -> Result<()> {
        info!("Reset gicv3 its");
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_ITS_CTRL_RESET),
            std::ptr::null::<u64>() as u64,
            true,
        )
        .with_context(|| "Failed to reset ITS")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::kvm::aarch64::gicv3::{KvmGICv3, KvmGICv3Its};
    use crate::kvm::KvmHypervisor;
    use devices::{GICDevice, GICVersion, GICv3, ICGICConfig, ICGICv3Config, GIC_IRQ_MAX};

    #[test]
    fn test_create_kvm_gicv3() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        assert!(KvmGICv3::new(kvm_hyp.vm_fd.clone().unwrap(), 4).is_ok());
    }

    #[test]
    fn test_create_kvm_gicv3its() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        assert!(KvmGICv3Its::new(kvm_hyp.vm_fd.clone().unwrap()).is_ok());
    }

    #[test]
    fn test_realize_gic_device_without_its() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let gic_config = ICGICConfig {
            version: Some(GICVersion::GICv3),
            vcpu_count: 4_u64,
            max_irq: GIC_IRQ_MAX,
            v2: None,
            v3: Some(ICGICv3Config {
                msi: false,
                dist_range: (0x0800_0000, 0x0001_0000),
                redist_region_ranges: vec![(0x080A_0000, 0x00F6_0000)],
                its_range: None,
            }),
        };

        let hypervisor_gic =
            KvmGICv3::new(kvm_hyp.vm_fd.clone().unwrap(), gic_config.vcpu_count).unwrap();
        let its_handler = KvmGICv3Its::new(kvm_hyp.vm_fd.clone().unwrap()).unwrap();
        let gic = GICv3::new(Arc::new(hypervisor_gic), Arc::new(its_handler), &gic_config).unwrap();
        assert!(gic.realize().is_ok());
        assert!(gic.its_dev.is_none());
    }

    #[test]
    fn test_gic_redist_regions() {
        let kvm_hyp = KvmHypervisor::new().unwrap_or(KvmHypervisor::default());
        if kvm_hyp.vm_fd.is_none() {
            return;
        }

        let gic_config = ICGICConfig {
            version: Some(GICVersion::GICv3),
            vcpu_count: 210_u64,
            max_irq: GIC_IRQ_MAX,
            v2: None,
            v3: Some(ICGICv3Config {
                msi: true,
                dist_range: (0x0800_0000, 0x0001_0000),
                redist_region_ranges: vec![(0x080A_0000, 0x00F6_0000), (256 << 30, 0x200_0000)],
                its_range: Some((0x0808_0000, 0x0002_0000)),
            }),
        };

        let hypervisor_gic =
            KvmGICv3::new(kvm_hyp.vm_fd.clone().unwrap(), gic_config.vcpu_count).unwrap();
        let its_handler = KvmGICv3Its::new(kvm_hyp.vm_fd.clone().unwrap()).unwrap();
        let gic = GICv3::new(Arc::new(hypervisor_gic), Arc::new(its_handler), &gic_config).unwrap();
        assert!(gic.realize().is_ok());
        assert!(gic.its_dev.is_some());
        assert_eq!(gic.redist_regions.len(), 2);
    }
}
