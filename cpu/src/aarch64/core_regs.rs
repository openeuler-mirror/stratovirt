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

use std::mem::size_of;

use kvm_bindings::{
    kvm_regs, user_fpsimd_state, user_pt_regs, KVM_NR_SPSR, KVM_REG_ARM64, KVM_REG_ARM_CORE,
    KVM_REG_SIZE_U128, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64,
};

/// AArch64 cpu core register.
/// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/kvm.h#L50
/// User structures for general purpose, floating point and debug registers.
/// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/ptrace.h#L75
#[allow(dead_code)]
pub enum Arm64CoreRegs {
    KvmSpEl1,
    KvmElrEl1,
    KvmSpsr(usize),
    UserPTRegRegs(usize),
    UserPTRegSp,
    UserPTRegPc,
    UserPTRegPState,
    UserFPSIMDStateVregs(usize),
    UserFPSIMDStateFpsr,
    UserFPSIMDStateFpcr,
}

impl From<Arm64CoreRegs> for u64 {
    fn from(elem: Arm64CoreRegs) -> Self {
        let register_size;
        let regid;
        match elem {
            Arm64CoreRegs::KvmSpEl1 => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, sp_el1)
            }
            Arm64CoreRegs::KvmElrEl1 => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, elr_el1)
            }
            Arm64CoreRegs::KvmSpsr(idx) if idx < KVM_NR_SPSR as usize => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, spsr) + idx * 8
            }
            Arm64CoreRegs::UserPTRegRegs(idx) if idx < 31 => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, regs, user_pt_regs, regs) + idx * 8
            }
            Arm64CoreRegs::UserPTRegSp => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, regs, user_pt_regs, sp)
            }
            Arm64CoreRegs::UserPTRegPc => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, regs, user_pt_regs, pc)
            }
            Arm64CoreRegs::UserPTRegPState => {
                register_size = KVM_REG_SIZE_U64;
                regid = offset_of!(kvm_regs, regs, user_pt_regs, pstate)
            }
            Arm64CoreRegs::UserFPSIMDStateVregs(idx) if idx < 32 => {
                register_size = KVM_REG_SIZE_U128;
                regid = offset_of!(kvm_regs, fp_regs, user_fpsimd_state, vregs) + idx * 16
            }
            Arm64CoreRegs::UserFPSIMDStateFpsr => {
                register_size = KVM_REG_SIZE_U32;
                regid = offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpsr)
            }
            Arm64CoreRegs::UserFPSIMDStateFpcr => {
                register_size = KVM_REG_SIZE_U32;
                regid = offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpcr)
            }
            _ => panic!("No such Register"),
        };

        KVM_REG_ARM64 as u64
            | register_size as u64
            | u64::from(KVM_REG_ARM_CORE)
            | (regid / size_of::<u32>()) as u64
    }
}
