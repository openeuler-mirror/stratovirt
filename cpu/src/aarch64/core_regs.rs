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

use util::offset_of;

/// AArch64 cpu core register.
/// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/kvm.h#L50
/// User structures for general purpose, floating point and debug registers.
/// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/ptrace.h#L75
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
        let (register_size, reg_offset) = match elem {
            Arm64CoreRegs::KvmSpEl1 => (KVM_REG_SIZE_U64, offset_of!(kvm_regs, sp_el1)),
            Arm64CoreRegs::KvmElrEl1 => (KVM_REG_SIZE_U64, offset_of!(kvm_regs, elr_el1)),
            Arm64CoreRegs::KvmSpsr(idx) if idx < KVM_NR_SPSR as usize => {
                (KVM_REG_SIZE_U64, offset_of!(kvm_regs, spsr) + idx * 8)
            }
            Arm64CoreRegs::UserPTRegRegs(idx) if idx < 31 => (
                KVM_REG_SIZE_U64,
                offset_of!(kvm_regs, regs, user_pt_regs, regs) + idx * 8,
            ),
            Arm64CoreRegs::UserPTRegSp => (
                KVM_REG_SIZE_U64,
                offset_of!(kvm_regs, regs, user_pt_regs, sp),
            ),
            Arm64CoreRegs::UserPTRegPc => (
                KVM_REG_SIZE_U64,
                offset_of!(kvm_regs, regs, user_pt_regs, pc),
            ),
            Arm64CoreRegs::UserPTRegPState => (
                KVM_REG_SIZE_U64,
                offset_of!(kvm_regs, regs, user_pt_regs, pstate),
            ),
            Arm64CoreRegs::UserFPSIMDStateVregs(idx) if idx < 32 => (
                KVM_REG_SIZE_U128,
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, vregs) + idx * 16,
            ),
            Arm64CoreRegs::UserFPSIMDStateFpsr => (
                KVM_REG_SIZE_U32,
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpsr),
            ),
            Arm64CoreRegs::UserFPSIMDStateFpcr => (
                KVM_REG_SIZE_U32,
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpcr),
            ),
            _ => panic!("No such Register"),
        };

        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields, we index it as if it
        // was a 32bit array.
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //     __u64                    spsr[KVM_NR_SPSR];
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };

        // struct user_fpsimd_state {
        //     __uint128_t	vregs[32];
        //     __u32		fpsr;
        //     __u32		fpcr;
        //     __u32		__reserved[2];
        // };

        // #define KVM_REG_ARM64	0x6000000000000000ULL
        // #define KVM_REG_SIZE_U32	0x0020000000000000ULL
        // #define KVM_REG_SIZE_U64	0x0030000000000000ULL
        // #define KVM_REG_SIZE_U128	0x0040000000000000ULL
        // #define KVM_REG_ARM_CORE	0x00100000ULL

        // The id of the register is encoded as specified for `KVM_GET_ONE_REG` in the kernel
        // documentation.
        // reg_id = KVM_REG_ARM64 | KVM_REG_SIZE_* | KVM_REG_ARM_CORE | reg_offset_index
        // reg_offset_index = reg_offset / sizeof(u32)
        // KVM_REG_SIZE_* => KVM_REG_SIZE_U32/KVM_REG_SIZE_U64/KVM_REG_SIZE_U128

        // calculate reg_id
        KVM_REG_ARM64
            | register_size
            | u64::from(KVM_REG_ARM_CORE)
            | (reg_offset / size_of::<u32>()) as u64
    }
}
