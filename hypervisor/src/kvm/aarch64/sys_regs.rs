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

use kvm_bindings::*;

// Arm Architecture Reference Manual defines the encoding of AArch64 system registers:
// (Ref: ARMv8 ARM, Section: "System instruction class encoding overview")
// While KVM defines another ID for each AArch64 system register, which is used in calling
// `KVM_G/SET_ONE_REG` to access a system register of a guest. A mapping exists between the
// Arm standard encoding and the KVM ID.
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/kvm.h#L216
#[macro_export]
macro_rules! arm64_sys_reg {
    ($op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        KVM_REG_SIZE_U64
            | KVM_REG_ARM64
            | KVM_REG_ARM64_SYSREG as u64
            | (((($op0 as u32) << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
                as u64)
            | (((($op1 as u32) << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
                as u64)
            | (((($crn as u32) << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
                as u64)
            | (((($crm as u32) << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
                as u64)
            | (((($op2 as u32) << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK)
                as u64)
    };
}

// The following system register codes can be found at this website:
// https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/asm/sysreg.h

// MPIDR - Multiprocessor Affinity Register(SYS_MPIDR_EL1).
pub const KVM_REG_ARM_MPIDR_EL1: u64 = arm64_sys_reg!(3, 0, 0, 0, 5);

// Counter-timer Virtual Count register: Due to the API interface problem, the encode of
// this register is SYS_CNTV_CVAL_EL0.
pub const KVM_REG_ARM_TIMER_CNT: u64 = arm64_sys_reg!(3, 3, 14, 3, 2);
