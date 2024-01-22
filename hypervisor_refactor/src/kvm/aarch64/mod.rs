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

pub mod gicv2;
pub mod gicv3;

use anyhow::{Context, Result};
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

use crate::kvm::{KvmCpu, KvmHypervisor};

ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);
ioctl_iow_nr!(KVM_ARM_VCPU_INIT, KVMIO, 0xae, kvm_vcpu_init);

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
            .with_context(|| "Failed to check device attributes.")?;
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
                .with_context(|| "Failed to set device attributes.")?;
        } else {
            let mut attr = attr;
            fd.get_device_attr(&mut attr)
                .with_context(|| "Failed to get device attributes.")?;
        };

        Ok(())
    }
}

impl KvmHypervisor {
    pub fn arch_init(&self) -> Result<()> {
        Ok(())
    }
}

impl KvmCpu {
    pub fn arch_get_msr_index_list(&self) -> Vec<u32> {
        Vec::new()
    }
}
