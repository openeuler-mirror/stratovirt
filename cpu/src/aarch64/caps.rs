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

use std::{convert::TryInto, mem::size_of};

use kvm_bindings::{
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_SIZE_MASK, KVM_REG_SIZE_U32,
    KVM_REG_SIZE_U64,
};
use kvm_ioctls::{Cap, Kvm, VcpuFd};
use machine_manager::config::{CpuConfig, PmuConfig};

use super::core_regs::{get_one_reg_vec, set_one_reg_vec, Result};

// Capabilities for ARM cpu.
#[derive(Debug, Clone)]
pub struct ArmCPUCaps {
    pub irq_chip: bool,
    pub ioevent_fd: bool,
    pub irq_fd: bool,
    pub user_mem: bool,
    pub psci02: bool,
    pub mp_state: bool,
}

impl ArmCPUCaps {
    /// Initialize ArmCPUCaps instance.
    pub fn init_capabilities() -> Self {
        let kvm = Kvm::new().unwrap();

        ArmCPUCaps {
            irq_chip: kvm.check_extension(Cap::Irqchip),
            ioevent_fd: kvm.check_extension(Cap::Ioeventfd),
            irq_fd: kvm.check_extension(Cap::Irqfd),
            user_mem: kvm.check_extension(Cap::UserMemory),
            psci02: kvm.check_extension(Cap::ArmPsci02),
            mp_state: kvm.check_extension(Cap::MpState),
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct ArmCPUFeatures {
    pub pmu: bool,
}

impl From<&CpuConfig> for ArmCPUFeatures {
    fn from(conf: &CpuConfig) -> Self {
        Self {
            pmu: match &conf.pmu {
                PmuConfig::On => true,
                PmuConfig::Off => false,
            },
        }
    }
}

/// Entry to cpreg list.
#[derive(Default, Clone, Copy)]
pub struct CpregListEntry {
    pub reg_id: u64,
    pub value: u64,
}

impl CpregListEntry {
    fn cpreg_tuples_entry(&self) -> bool {
        self.reg_id & KVM_REG_ARM_COPROC_MASK as u64 == KVM_REG_ARM_CORE as u64
    }

    fn normal_cpreg_entry(&self) -> bool {
        if self.cpreg_tuples_entry() {
            return false;
        }

        ((self.reg_id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32)
            || ((self.reg_id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64)
    }

    /// Validate cpreg_list's tuples entry and normal entry.
    pub fn validate(&self) -> bool {
        if self.cpreg_tuples_entry() {
            return true;
        }

        self.normal_cpreg_entry()
    }

    /// Get Cpreg value from Kvm.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn get_cpreg(&mut self, vcpu_fd: &VcpuFd) -> Result<()> {
        if self.normal_cpreg_entry() {
            let val = get_one_reg_vec(vcpu_fd, self.reg_id)?;
            if (self.reg_id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32 {
                self.value = u32::from_be_bytes(
                    val.as_slice()
                        .split_at(size_of::<u32>())
                        .0
                        .try_into()
                        .unwrap(),
                ) as u64;
            } else if (self.reg_id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U64 {
                self.value = u64::from_be_bytes(
                    val.as_slice()
                        .split_at(size_of::<u64>())
                        .0
                        .try_into()
                        .unwrap(),
                )
            }
        }

        Ok(())
    }

    /// Set Cpreg value to Kvm.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn set_cpreg(&self, vcpu_fd: &VcpuFd) -> Result<()> {
        if self.normal_cpreg_entry() {
            let mut value: Vec<u8> = self.value.to_be_bytes().to_vec();
            let data = if (self.reg_id & KVM_REG_SIZE_MASK) == KVM_REG_SIZE_U32 {
                value.split_off(size_of::<u32>() / size_of::<u8>())
            } else {
                value
            };

            set_one_reg_vec(vcpu_fd, self.reg_id, &data)?;
        }

        Ok(())
    }
}
