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

use kvm_bindings::{
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_SIZE_MASK, KVM_REG_SIZE_U32,
    KVM_REG_SIZE_U64,
};
use kvm_ioctls::{Cap, Kvm, VcpuFd};

use super::core_regs::Result;
use machine_manager::config::{CpuConfig, PmuConfig};

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
    pub value: u128,
}

impl CpregListEntry {
    fn cpreg_tuples_entry(&self) -> bool {
        (self.reg_id & KVM_REG_ARM_COPROC_MASK as u64) == (KVM_REG_ARM_CORE as u64)
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
            self.value = vcpu_fd.get_one_reg(self.reg_id)?;
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
            vcpu_fd.set_one_reg(self.reg_id, self.value)?;
        }

        Ok(())
    }
}
