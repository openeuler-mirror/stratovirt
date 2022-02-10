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

use hypervisor::kvm::{KVM_GET_ONE_REG, KVM_SET_ONE_REG};
use kvm_bindings::{
    kvm_one_reg, kvm_regs, user_fpsimd_state, user_pt_regs, KVM_NR_SPSR, KVM_REG_ARM64,
    KVM_REG_ARM_CORE, KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT, KVM_REG_SIZE_U128, KVM_REG_SIZE_U32,
    KVM_REG_SIZE_U64,
};
use kvm_ioctls::VcpuFd;
use util::byte_code::ByteCode;
use vmm_sys_util::{
    errno,
    ioctl::{ioctl_with_mut_ref, ioctl_with_ref},
};

pub type Result<T> = std::result::Result<T, errno::Error>;

const KVM_REG_MAX_SIZE: u64 = 256;
const KVM_NR_REGS: u64 = 31;
const KVM_NR_FP_REGS: u64 = 32;

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

/// Returns the 128 bits value of the specified vCPU register.
///
/// The id of the register is encoded as specified in the kernel documentation
/// for `KVM_GET_ONE_REG`.
///
/// Max register size is 256 Bytes.
///
/// # Arguments
///
/// * `vcpu_fd` - The file descriptor of kvm_based vcpu.
/// * `reg_id` - ID of register.
pub fn get_one_reg_vec(vcpu_fd: &VcpuFd, reg_id: u64) -> Result<Vec<u8>> {
    let reg_size = 1_u64 << ((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT);
    if reg_size > KVM_REG_MAX_SIZE {
        return Err(errno::Error::new(libc::EINVAL));
    }
    let mut reg_value: Vec<u8> = vec![0; reg_size as usize];
    reg_value.resize(reg_size as usize, 0);
    let mut onereg = kvm_one_reg {
        id: reg_id,
        addr: reg_value.as_mut_ptr() as *mut u8 as u64,
    };

    // This is safe because we allocated the struct and we know the kernel will read
    // exactly the size of the struct.
    let ret = unsafe { ioctl_with_mut_ref(vcpu_fd, KVM_GET_ONE_REG(), &mut onereg) };
    if ret < 0 {
        return Err(errno::Error::last());
    }

    Ok(reg_value)
}

/// Sets the value of one register for this vCPU.
///
/// The id of the register is encoded as specified in the kernel documentation
/// for `KVM_SET_ONE_REG`.
///
/// Max register size is 256 Bytes.
///
/// # Arguments
///
/// * `reg_id` - ID of the register for which we are setting the value.
/// * `data` - value for the specified register.
pub fn set_one_reg_vec(vcpu_fd: &VcpuFd, reg_id: u64, data: &[u8]) -> Result<()> {
    let reg_size = 1u64 << ((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT);
    if reg_size > KVM_REG_MAX_SIZE || reg_size as usize > data.len() {
        return Err(errno::Error::new(libc::EINVAL));
    };
    let data_ref = data.as_ptr() as *const u8;
    let onereg = kvm_one_reg {
        id: reg_id,
        addr: data_ref as u64,
    };

    // This is safe because we allocated the struct and we know the kernel will read
    // exactly the size of the struct.
    let ret = unsafe { ioctl_with_ref(vcpu_fd, KVM_SET_ONE_REG(), &onereg) };
    if ret < 0 {
        return Err(errno::Error::last());
    }

    Ok(())
}

/// Returns the vcpu's current `core_register`.
///
/// The register state is gotten from `KVM_GET_ONE_REG` api in KVM.
///
/// # Arguments
///
/// * `vcpu_fd` - the VcpuFd in KVM mod.
pub fn get_core_regs(vcpu_fd: &VcpuFd) -> Result<kvm_regs> {
    let mut core_regs = kvm_regs::default();

    core_regs.regs.sp = vcpu_fd.get_one_reg(Arm64CoreRegs::UserPTRegSp.into())?;
    core_regs.sp_el1 = vcpu_fd.get_one_reg(Arm64CoreRegs::KvmSpEl1.into())?;
    core_regs.regs.pstate = vcpu_fd.get_one_reg(Arm64CoreRegs::UserPTRegPState.into())?;
    core_regs.regs.pc = vcpu_fd.get_one_reg(Arm64CoreRegs::UserPTRegPc.into())?;
    core_regs.elr_el1 = vcpu_fd.get_one_reg(Arm64CoreRegs::KvmElrEl1.into())?;

    for i in 0..KVM_NR_REGS as usize {
        core_regs.regs.regs[i] = vcpu_fd.get_one_reg(Arm64CoreRegs::UserPTRegRegs(i).into())?;
    }

    for i in 0..KVM_NR_SPSR as usize {
        core_regs.spsr[i] = vcpu_fd.get_one_reg(Arm64CoreRegs::KvmSpsr(i).into())?;
    }

    for i in 0..KVM_NR_FP_REGS as usize {
        let register_value_vec =
            get_one_reg_vec(&vcpu_fd, Arm64CoreRegs::UserFPSIMDStateVregs(i).into())?;
        core_regs.fp_regs.vregs[i][0] = *u64::from_bytes(&register_value_vec[0..8]).unwrap();
        core_regs.fp_regs.vregs[i][1] = *u64::from_bytes(&register_value_vec[8..16]).unwrap();
    }

    let register_value_vec = get_one_reg_vec(&vcpu_fd, Arm64CoreRegs::UserFPSIMDStateFpsr.into())?;
    core_regs.fp_regs.fpsr = *u32::from_bytes(&register_value_vec[0..4]).unwrap();

    let register_value_vec = get_one_reg_vec(&vcpu_fd, Arm64CoreRegs::UserFPSIMDStateFpcr.into())?;
    core_regs.fp_regs.fpcr = *u32::from_bytes(&register_value_vec[0..4]).unwrap();

    Ok(core_regs)
}

/// Sets the vcpu's current "core_register"
///
/// The register state is gotten from `KVM_SET_ONE_REG` api in KVM.
///
/// # Arguments
///
/// * `vcpu_fd` - the VcpuFd in KVM mod.
/// * `core_regs` - kvm_regs state to be written.
pub fn set_core_regs(vcpu_fd: &VcpuFd, core_regs: kvm_regs) -> Result<()> {
    vcpu_fd.set_one_reg(Arm64CoreRegs::UserPTRegSp.into(), core_regs.regs.sp)?;
    vcpu_fd.set_one_reg(Arm64CoreRegs::KvmSpEl1.into(), core_regs.sp_el1)?;
    vcpu_fd.set_one_reg(Arm64CoreRegs::UserPTRegPState.into(), core_regs.regs.pstate)?;
    vcpu_fd.set_one_reg(Arm64CoreRegs::UserPTRegPc.into(), core_regs.regs.pc)?;
    vcpu_fd.set_one_reg(Arm64CoreRegs::KvmElrEl1.into(), core_regs.elr_el1)?;

    for i in 0..KVM_NR_REGS as usize {
        vcpu_fd.set_one_reg(
            Arm64CoreRegs::UserPTRegRegs(i).into(),
            core_regs.regs.regs[i] as u64,
        )?;
    }

    for i in 0..KVM_NR_SPSR as usize {
        vcpu_fd.set_one_reg(Arm64CoreRegs::KvmSpsr(i).into(), core_regs.spsr[i])?;
    }

    for i in 0..KVM_NR_FP_REGS as usize {
        let mut data: Vec<u8> = Vec::new();
        data.append(&mut core_regs.fp_regs.vregs[i][0].as_bytes().to_vec());
        data.append(&mut core_regs.fp_regs.vregs[i][1].as_bytes().to_vec());
        set_one_reg_vec(
            &vcpu_fd,
            Arm64CoreRegs::UserFPSIMDStateVregs(i).into(),
            &data,
        )?;
    }

    set_one_reg_vec(
        &vcpu_fd,
        Arm64CoreRegs::UserFPSIMDStateFpsr.into(),
        &core_regs.fp_regs.fpsr.as_bytes().to_vec(),
    )?;

    set_one_reg_vec(
        &vcpu_fd,
        Arm64CoreRegs::UserFPSIMDStateFpcr.into(),
        &core_regs.fp_regs.fpcr.as_bytes().to_vec(),
    )?;

    Ok(())
}
