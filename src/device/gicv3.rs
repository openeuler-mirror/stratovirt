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

use std::sync::Arc;

use kvm_ioctls::{DeviceFd, VmFd};

#[cfg(target_arch = "aarch64")]
use crate::helper::device_tree;
use crate::memory::{LayoutEntryType, MEM_LAYOUT};

// See arch/arm64/include/uapi/asm/kvm.h file from the linux kernel.
const SZ_64K: u64 = 0x0001_0000;
const KVM_VGIC_V3_REDIST_SIZE: u64 = 2 * SZ_64K;
// First 32 are private to each CPU (SGIs and PPIs).
const GIC_IRQ_INTERNAL: u32 = 32;

#[derive(Debug)]
pub enum Error {
    InvalidConfig(String),
    CreateKvmDevice(kvm_ioctls::Error),
    CheckDeviceAttribute(kvm_ioctls::Error),
    GetDeviceAttribute(kvm_ioctls::Error),
    SetDeviceAttribute(kvm_ioctls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidConfig(info) => write!(f, "Invalid GIC config: {}", info),
            Error::CreateKvmDevice(ref e) => {
                write!(f, "Failed to create kvm device: {:#?}.", e)
            }
            Error::CheckDeviceAttribute(ref e) => {
                write!(f, "Failed to check device attributes for GIC: {:#?}.", e)
            }
            Error::GetDeviceAttribute(ref e) => {
                write!(f, "Failed to get device attributes for GIC: {:#?}.", e)
            }
            Error::SetDeviceAttribute(ref e) => {
                write!(f, "Failed to set device attributes for GIC: {:#?}.", e)
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn kvm_device_check(fd: &DeviceFd, group: u32, attr: u64) -> Result<()> {
    let attr = kvm_bindings::kvm_device_attr {
        group,
        attr,
        addr: 0,
        flags: 0,
    };

    Ok(fd
        .has_device_attr(&attr)
        .map_err(Error::CheckDeviceAttribute)?)
}

fn kvm_device_access(fd: &DeviceFd, group: u32, attr: u64, addr: u64, write: bool) -> Result<()> {
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
        fd.get_device_attr(&mut attr)
            .map_err(Error::GetDeviceAttribute)?;
    };

    Ok(())
}

/// A wrapper around creating and managing a `GICv3`.
pub struct GICv3 {
    /// The fd for the GICv3 device.
    fd: DeviceFd,
    /// GICv3 ITS device.
    its_dev: GICv3Its,
    /// Maximum irq number.
    nr_irqs: u32,
    /// Base address of GICv3 redistributor.
    redist_base: u64,
    /// Size of agicv3 redistributor.
    redist_size: u64,
    /// Base address in the guest physical address space of the GICv3 distributor
    /// register mappings.
    dist_base: u64,
    /// GICv3 distributor region size.
    dist_size: u64,
}

impl GICv3 {
    pub fn new(vm: &Arc<VmFd>, vcpu_count: u64, max_irq: u32) -> Result<Self> {
        let capability = std::cmp::min(
            MEM_LAYOUT[LayoutEntryType::GicRedist as usize].1 / KVM_VGIC_V3_REDIST_SIZE,
            254,
        );
        if vcpu_count > capability || vcpu_count == 0 {
            return Err(Error::InvalidConfig(format!(
                "GIC only support maximum {} vcpus",
                capability
            ))
            .into());
        }
        if max_irq <= GIC_IRQ_INTERNAL {
            return Err(Error::InvalidConfig("GIC irq numbers need above 32".to_string()).into());
        }

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
            fd: 0,
            flags: 0,
        };

        let gic_fd = vm
            .create_device(&mut gic_device)
            .map_err(Error::CreateKvmDevice)?;

        Ok(GICv3 {
            fd: gic_fd,
            nr_irqs: max_irq,
            its_dev: GICv3Its::new(&vm)?,
            redist_base: MEM_LAYOUT[LayoutEntryType::GicRedist as usize].0,
            redist_size: vcpu_count * KVM_VGIC_V3_REDIST_SIZE,
            dist_base: MEM_LAYOUT[LayoutEntryType::GicDist as usize].0,
            dist_size: MEM_LAYOUT[LayoutEntryType::GicDist as usize].1,
        })
    }

    pub fn realize(&self) -> Result<()> {
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_REDIST),
            &self.redist_base as *const u64 as u64,
            true,
        )?;
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_V3_ADDR_TYPE_DIST),
            &self.dist_base as *const u64 as u64,
            true,
        )?;
        kvm_device_check(&self.fd, kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0)?;
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            0,
            &self.nr_irqs as *const u32 as u64,
            true,
        )?;
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            0,
            true,
        )?;

        self.its_dev.realize()?;
        Ok(())
    }

    pub fn generate_fdt_node(&self, fdt: &mut Vec<u8>) {
        let gic_reg = vec![
            self.dist_base,
            self.dist_size,
            self.redist_base,
            self.redist_size,
        ];
        let node = "/intc";
        device_tree::add_sub_node(fdt, node);
        device_tree::set_property_string(fdt, node, "compatible", "arm,gic-v3");
        device_tree::set_property(fdt, node, "interrupt-controller", None);
        device_tree::set_property_u32(fdt, node, "#interrupt-cells", 0x3);
        device_tree::set_property_u32(fdt, node, "phandle", device_tree::GIC_PHANDLE);
        device_tree::set_property_u32(fdt, node, "#address-cells", 0x2);
        device_tree::set_property_u32(fdt, node, "#size-cells", 0x2);
        device_tree::set_property_u32(fdt, node, "#redistributor-regions", 0x1);
        device_tree::set_property_array_u64(fdt, node, "reg", &gic_reg);

        let gic_intr = [
            device_tree::GIC_FDT_IRQ_TYPE_PPI,
            0x9,
            device_tree::IRQ_TYPE_LEVEL_HIGH,
        ];
        device_tree::set_property_array_u32(fdt, node, "interrupts", &gic_intr);

        device_tree::set_property(fdt, node, "ranges", None);
        let its_reg = [self.its_dev.msi_base, self.its_dev.msi_size];
        let node = "/intc/its";
        device_tree::add_sub_node(fdt, node);
        device_tree::set_property_string(fdt, node, "compatible", "arm,gic-v3-its");
        device_tree::set_property(fdt, node, "msi-controller", None);
        device_tree::set_property_u32(fdt, node, "phandle", device_tree::GIC_ITS_PHANDLE);
        device_tree::set_property_array_u64(fdt, node, "reg", &its_reg);
    }
}

struct GICv3Its {
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

        let its_fd = vm
            .create_device(&mut its_device)
            .map_err(Error::CreateKvmDevice)?;

        Ok(GICv3Its {
            fd: its_fd,
            msi_base: MEM_LAYOUT[LayoutEntryType::GicIts as usize].0,
            msi_size: MEM_LAYOUT[LayoutEntryType::GicIts as usize].1,
        })
    }

    fn realize(&self) -> Result<()> {
        kvm_device_check(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
        )?;
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            u64::from(kvm_bindings::KVM_VGIC_ITS_ADDR_TYPE),
            &self.msi_base as *const u64 as u64,
            true,
        )?;
        kvm_device_access(
            &self.fd,
            kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            &self.msi_base as *const u64 as u64,
            true,
        )?;

        Ok(())
    }
}
