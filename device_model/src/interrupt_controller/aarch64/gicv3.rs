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

use std::sync::{Arc, Mutex};

use kvm_ioctls::{DeviceFd, VmFd};

use machine_manager::machine::{KvmVmState, MachineLifecycle};
use util::kvm_ioctls_ext::{check_device_attr, get_device_attr};
use util::{device_tree, errors};

use super::GICConfig;
use super::GICDevice;

use crate::{LayoutEntryType, MEM_LAYOUT};

// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const SZ_64K: u64 = 0x0001_0000;
const KVM_VGIC_V3_REDIST_SIZE: u64 = 2 * SZ_64K;

#[derive(Debug)]
pub enum Error {
    /// Error while calling KVM ioctl for setting up the global interrupt controller.
    CreateGIC(kvm_ioctls::Error),
    /// Error while setting device attributes for the GIC.
    SetDeviceAttribute(kvm_ioctls::Error),
    /// Error while getting device attributes for the GIC.
    GetDeviceAttribute(kvm_ioctls::Error),
    /// Error while check device attributes for the GIC.
    CheckDeviceAttribute(kvm_ioctls::Error),
    /// Error while multiple redistributor is acquired but KVM does not support it.
    MultiRedistributor,
}
type Result<T> = std::result::Result<T, Error>;

/// A wrapper for kvm_based device check and access.
pub struct KvmDevice;

impl KvmDevice {
    fn kvm_device_check(fd: &DeviceFd, group: u32, attr: u64) -> Result<bool> {
        let attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: 0,
            flags: 0,
        };

        let support = check_device_attr(fd, &attr).map_err(Error::CheckDeviceAttribute)?;

        if support == 0 {
            Ok(true)
        } else {
            Ok(false)
        }
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
                .map_err(Error::SetDeviceAttribute)?;
        } else {
            let mut attr = attr;
            get_device_attr(fd, &mut attr).map_err(Error::GetDeviceAttribute)?;
        };

        Ok(())
    }
}

trait GICv3Access {
    /// Returns `gicr_attr` of `vCPU`.
    fn vcpu_gicr_attr(&self, cpu: usize) -> u64;

    fn access_gic_distributor(&self, offset: u64, gicd_value: &mut u32, write: bool) -> Result<()>;

    fn access_gic_redistributor(
        &self,
        offset: u64,
        cpu: usize,
        gicr_value: &mut u32,
        write: bool,
    ) -> Result<()>;

    fn access_gic_cpu(
        &self,
        offset: u64,
        cpu: usize,
        gicc_value: &mut u64,
        write: bool,
    ) -> Result<()>;

    fn access_gic_line_level(&self, offset: u64, gicll_value: &mut u32, write: bool) -> Result<()>;
}

struct GicRedistRegion {
    /// Base address.
    pub base: u64,
    /// Size of redistributor region.
    pub size: u64,
    /// Attribute of redistributor region.
    pub base_attr: u64,
}

/// A wrapper around creating and managing a `GICv3`.
pub struct GICv3 {
    /// The fd for the GICv3 device.
    fd: DeviceFd,
    /// Number of vCPUs, determines the number of redistributor and CPU interface.
    vcpu_count: u64,
    /// GICv3 ITS, support MSI.
    its: bool,
    /// GICv3 ITS device.
    its_dev: Option<GICv3Its>,
    /// Maximum irq number.
    nr_irqs: u32,
    /// GICv3 redistributor info, support multiple redistributor regions.
    redist_regions: Vec<GicRedistRegion>,
    /// Base address in the guest physical address space of the GICv3 distributor
    /// register mappings.
    dist_base: u64,
    /// GICv3 distributor region size.
    dist_size: u64,
    /// Lifecycle state for GICv3.
    state: Arc<Mutex<KvmVmState>>,
}

impl GICv3 {
    pub fn new(vm: &Arc<VmFd>, config: &GICConfig) -> Result<Self> {
        config.check_sanity().unwrap();

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };

        let gic_fd = match vm.create_device(&mut gic_device) {
            Ok(fd) => fd,
            Err(e) => return Err(Error::CreateGIC(e)),
        };

        // Calculate GIC redistributor regions' address range according to vcpu count.
        let base = MEM_LAYOUT[LayoutEntryType::GicRedist as usize].0;
        let size = MEM_LAYOUT[LayoutEntryType::GicRedist as usize].1;
        let redist_capability = size / KVM_VGIC_V3_REDIST_SIZE;
        let redist_region_count = std::cmp::min(config.vcpu_count, redist_capability);
        let mut redist_regions = vec![GicRedistRegion {
            base,
            size,
            base_attr: (redist_region_count << 52) | base,
        }];

        if config.vcpu_count > redist_capability {
            let high_redist_base = MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize].0;
            let high_redist_region_count = config.vcpu_count - redist_capability;
            let high_redist_attr = (high_redist_region_count << 52) | high_redist_base | 0x1;

            redist_regions.push(GicRedistRegion {
                base: high_redist_base,
                size: high_redist_region_count * KVM_VGIC_V3_REDIST_SIZE,
                base_attr: high_redist_attr,
            })
        }

        let mut gicv3 = GICv3 {
            fd: gic_fd,
            vcpu_count: config.vcpu_count,
            nr_irqs: config.max_irq,
            its: config.msi,
            its_dev: None,
            redist_regions,
            dist_base: MEM_LAYOUT[LayoutEntryType::GicDist as usize].0,
            dist_size: MEM_LAYOUT[LayoutEntryType::GicDist as usize].1,
            state: Arc::new(Mutex::new(KvmVmState::Created)),
        };

        if gicv3.its {
            gicv3.its_dev = Some(GICv3Its::new(&vm).unwrap());
        }

        Ok(gicv3)
    }

    fn realize(&self) -> Result<()> {
        let multi_redist_supported = KvmDevice::kvm_device_check(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION as u64,
        )?;
        if !multi_redist_supported && self.redist_regions.len() > 1 {
            error!("Multi redistributor region not supported by KVM, max cpus count is 123");
            return Err(Error::MultiRedistributor);
        }

        if self.redist_regions.len() == 1 {
            KvmDevice::kvm_device_access(
                &self.fd,
                kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
                &self.redist_regions.get(0).unwrap().base as *const u64 as u64,
                true,
            )?;
        } else {
            for redist in &self.redist_regions {
                KvmDevice::kvm_device_access(
                    &self.fd,
                    kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
                    u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION),
                    &redist.base_attr as *const u64 as u64,
                    true,
                )?;
            }
        }

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &self.dist_base as *const u64 as u64,
            true,
        )?;

        KvmDevice::kvm_device_check(&self.fd, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0)?;

        // Init the interrupt number support by the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &self.nr_irqs as *const u32 as u64,
            true,
        )?;

        // Finalize the GIC.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            true,
        )?;

        let mut state = self.state.lock().unwrap();
        *state = KvmVmState::Running;

        Ok(())
    }

    fn device_fd(&self) -> &DeviceFd {
        &self.fd
    }
}

impl MachineLifecycle for GICv3 {
    fn pause(&self) -> bool {
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
            addr: 0,
            flags: 0,
        };

        if self.device_fd().set_device_attr(&attr).is_ok() {
            let mut state = self.state.lock().unwrap();
            *state = KvmVmState::Running;

            true
        } else {
            false
        }
    }

    fn notify_lifecycle(&self, old: KvmVmState, new: KvmVmState) -> bool {
        let state = self.state.lock().unwrap();
        if *state != old {
            error!("GICv3 lifecycle error: state check failed.");
            return false;
        }
        drop(state);

        match (old, new) {
            (KvmVmState::Running, KvmVmState::Paused) => self.pause(),
            _ => true,
        }
    }
}

impl GICv3Access for GICv3 {
    fn vcpu_gicr_attr(&self, cpu: usize) -> u64 {
        let clustersz = 16;

        let aff1 = (cpu / clustersz) as u64;
        let aff0 = (cpu % clustersz) as u64;

        let affid = (aff1 << 8) | aff0;
        let cpu_affid: u64 = ((affid & 0xFF_0000_0000) >> 8) | (affid & 0xFF_FFFF);

        let last = if (self.vcpu_count - 1) == cpu as u64 {
            1
        } else {
            0
        };

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
}

impl GICDevice for GICv3 {
    fn create_device(
        vm: &Arc<VmFd>,
        gic_conf: &GICConfig,
    ) -> Result<Arc<dyn GICDevice + std::marker::Send + std::marker::Sync>> {
        let gic = GICv3::new(vm, gic_conf)?;

        gic.realize()?;

        if let Some(its) = &gic.its_dev {
            its.realize()?;
        }

        Ok(Arc::new(gic))
    }

    fn generate_fdt(&self, fdt: &mut Vec<u8>) -> errors::Result<()> {
        let redist_count = self.redist_regions.len() as u32;
        let mut gic_reg = vec![self.dist_base, self.dist_size];

        for redist in &self.redist_regions {
            gic_reg.push(redist.base);
            gic_reg.push(redist.size);
        }

        let node = "/intc";
        device_tree::add_sub_node(fdt, node)?;
        device_tree::set_property_string(fdt, node, "compatible", "arm,gic-v3")?;
        device_tree::set_property(fdt, node, "interrupt-controller", None)?;
        device_tree::set_property_u32(fdt, node, "#interrupt-cells", 0x3)?;
        device_tree::set_property_u32(fdt, node, "phandle", device_tree::GIC_PHANDLE)?;
        device_tree::set_property_u32(fdt, node, "#address-cells", 0x2)?;
        device_tree::set_property_u32(fdt, node, "#size-cells", 0x2)?;
        device_tree::set_property_u32(fdt, node, "#redistributor-regions", redist_count)?;
        device_tree::set_property_array_u64(fdt, node, "reg", &gic_reg)?;

        let gic_intr = [
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            0x9,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ];
        device_tree::set_property_array_u32(fdt, node, "interrupts", &gic_intr)?;

        if let Some(its) = &self.its_dev {
            device_tree::set_property(fdt, node, "ranges", None)?;
            let its_reg = [its.msi_base, its.msi_size];
            let node = "/intc/its";
            device_tree::add_sub_node(fdt, node)?;
            device_tree::set_property_string(fdt, node, "compatible", "arm,gic-v3-its")?;
            device_tree::set_property(fdt, node, "msi-controller", None)?;
            device_tree::set_property_u32(fdt, node, "phandle", device_tree::GIC_ITS_PHANDLE)?;
            device_tree::set_property_array_u64(fdt, node, "reg", &its_reg)?;
        }

        Ok(())
    }
}

pub struct GICv3Its {
    /// The fd for the GICv3Its device
    fd: DeviceFd,

    /// Base address in the guest physical address space of the GICv3 ITS
    /// control register frame.
    msi_base: u64,

    /// GICv3 ITS needs to be 64K aligned and the region covers 128K.
    msi_size: u64,
}

impl GICv3Its {
    fn new(vm: &Arc<VmFd>) -> Result<Self> {
        let mut its_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_ITS,
            fd: 0,
            flags: 0,
        };

        let its_fd = match vm.create_device(&mut its_device) {
            Ok(fd) => fd,
            Err(e) => return Err(Error::CreateGIC(e)),
        };

        Ok(GICv3Its {
            fd: its_fd,
            msi_base: MEM_LAYOUT[LayoutEntryType::GicIts as usize].0,
            msi_size: MEM_LAYOUT[LayoutEntryType::GicIts as usize].1,
        })
    }

    fn realize(&self) -> Result<()> {
        KvmDevice::kvm_device_check(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
        )?;

        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            &self.msi_base as *const u64 as u64,
            true,
        )?;

        // Finalize the GIC Its.
        KvmDevice::kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            &self.msi_base as *const u64 as u64,
            true,
        )?;

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

        gic_conf.max_irq = 32;
        assert!(gic_conf.check_sanity().is_err());

        gic_conf.max_irq = 32;
        assert!(gic_conf.check_sanity().is_err());
    }
}
