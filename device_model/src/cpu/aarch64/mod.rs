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

use std::convert::Into;
use std::mem;
use std::sync::Arc;

use kvm_bindings::{
    kvm_regs, kvm_vcpu_init, user_fpsimd_state, user_pt_regs, KVM_NR_SPSR, KVM_REG_ARM64,
    KVM_REG_ARM_CORE, KVM_REG_SIZE_U128, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64,
};
use kvm_ioctls::{VcpuFd, VmFd};

use self::errors::{ErrorKind, Result};

pub mod errors {
    error_chain! {
        errors {
            GetSysRegister(err_info: String) {
                description("Get sys Register error")
                display("Failed to get system register: {}!", err_info)
            }
            SetSysRegister(err_info: String) {
                description("Set sys Register error")
                display("Failed to Set system register: {}!", err_info)
            }
        }
    }
}

// PSR (Processor State Register) bits.
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/ptrace.h#L34
#[allow(non_upper_case_globals)]
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;

// MPIDR - Multiprocessor Affinity Register.
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/asm/sysreg.h#L130
pub const SYS_MPIDR_EL1: u64 = 0x6030_0000_0013_c005;

// MPIDR is Multiprocessor Affinity Register
// [40:63] bit reserved on AArch64 Architecture,
const UNINIT_MPIDR: u64 = 0xFFFF_FF00_0000_0000;

// AArch64 cpu core register
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/kvm.h#L50

// User structures for general purpose, floating point and debug registers.
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/ptrace.h#L75
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum Arm64CoreRegs {
    KVM_USER_PT_REGS,
    KVM_SP_EL1,
    KVM_ELR_EL1,
    KVM_SPSR(usize),
    KVM_USER_FPSIMD_STATE,
    USER_PT_REG_REGS(usize),
    USER_PT_REG_SP,
    USER_PT_REG_PC,
    USER_PT_REG_PSTATE,
    USER_FPSIMD_STATE_VREGS(usize),
    USER_FPSIMD_STATE_FPSR,
    USER_FPSIMD_STATE_FPCR,
    USER_FPSIMD_STATE_RES(usize),
}

#[allow(clippy::zero_ptr)]
impl Into<u64> for Arm64CoreRegs {
    fn into(self) -> u64 {
        let register_size;
        let regid = match self {
            Arm64CoreRegs::KVM_USER_PT_REGS => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, regs)
            }
            Arm64CoreRegs::KVM_SP_EL1 => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, sp_el1)
            }
            Arm64CoreRegs::KVM_ELR_EL1 => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, elr_el1)
            }
            Arm64CoreRegs::KVM_SPSR(idx) if idx < KVM_NR_SPSR as usize => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, spsr) + idx * 8
            }
            Arm64CoreRegs::KVM_USER_FPSIMD_STATE => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, fp_regs)
            }
            Arm64CoreRegs::USER_PT_REG_REGS(idx) if idx < 31 => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, regs, user_pt_regs, regs) + idx * 8
            }
            Arm64CoreRegs::USER_PT_REG_SP => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, regs, user_pt_regs, sp)
            }
            Arm64CoreRegs::USER_PT_REG_PC => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, regs, user_pt_regs, pc)
            }
            Arm64CoreRegs::USER_PT_REG_PSTATE => {
                register_size = KVM_REG_SIZE_U64;
                offset_of!(kvm_regs, regs, user_pt_regs, pstate)
            }
            Arm64CoreRegs::USER_FPSIMD_STATE_VREGS(idx) if idx < 32 => {
                register_size = KVM_REG_SIZE_U128;
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, vregs) + idx * 16
            }
            Arm64CoreRegs::USER_FPSIMD_STATE_FPSR => {
                register_size = KVM_REG_SIZE_U32;
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpsr)
            }
            Arm64CoreRegs::USER_FPSIMD_STATE_FPCR => {
                register_size = KVM_REG_SIZE_U32;
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, fpcr)
            }
            Arm64CoreRegs::USER_FPSIMD_STATE_RES(idx) if idx < 2 => {
                register_size = 128;
                offset_of!(kvm_regs, fp_regs, user_fpsimd_state, __reserved) + idx * 8
            }
            _ => panic!("No such Register"),
        };

        KVM_REG_ARM64 as u64
            | register_size as u64
            | u64::from(KVM_REG_ARM_CORE)
            | (regid / mem::size_of::<u32>()) as u64
    }
}

pub fn set_one_core_reg(vcpu: &Arc<VcpuFd>, reg: Arm64CoreRegs, data: u64) -> Result<()> {
    match vcpu.set_one_reg(reg.into(), data) {
        Ok(_) => Ok(()),
        Err(e) => Err(ErrorKind::SetSysRegister(format!("{:?}", e)).into()),
    }
}

/// AArch64 CPU booting configure information
///
/// Before jumping into the kernel, primary CPU general-purpose
/// register `x0` need to setting to physical address of device
/// tree blob (dtb) in system RAM.
///
/// See: https://elixir.bootlin.com/linux/v5.6/source/Documentation/arm64/booting.rst
#[derive(Default, Copy, Clone)]
pub struct AArch64CPUBootConfig {
    pub fdt_addr: u64,
    pub kernel_addr: u64,
}

/// AArch64 CPU architect information
#[derive(Default, Copy, Clone)]
pub struct CPUAArch64 {
    /// The vcpu id, `0` means primary CPU.
    vcpu_id: u32,
    /// MPIDR register value of this vcpu,
    /// The MPIDR provides an additional processor identification mechanism
    /// for scheduling purposes.
    mpidr: u64,
    /// The guest physical address of kernel start point.
    boot_ip: u64,
    /// The guest physical address of device tree blob (dtb).
    fdt_addr: u64,
    /// Used to pass vcpu target and supported features to kvm.
    kvi: kvm_vcpu_init,
}

impl CPUAArch64 {
    pub fn new(vm_fd: &Arc<VmFd>, vcpu_id: u32) -> Self {
        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        vm_fd.get_preferred_target(&mut kvi).unwrap();

        CPUAArch64 {
            vcpu_id,
            mpidr: UNINIT_MPIDR,
            boot_ip: 0,
            fdt_addr: 0,
            kvi,
        }
    }

    pub fn realize(
        &mut self,
        vcpu_fd: &Arc<VcpuFd>,
        boot_config: &AArch64CPUBootConfig,
    ) -> Result<()> {
        self.boot_ip = boot_config.kernel_addr;
        self.fdt_addr = boot_config.fdt_addr;

        // support PSCI 0.2
        // We already checked that the capability is supported.
        self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;

        // Non-boot cpus are powered off initially.
        if self.vcpu_id != 0 {
            self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        vcpu_fd.vcpu_init(&self.kvi).unwrap();

        self.get_mpidr(vcpu_fd);

        Ok(())
    }

    pub fn get_mpidr(&mut self, vcpu_fd: &Arc<VcpuFd>) -> u64 {
        if self.mpidr == UNINIT_MPIDR {
            self.mpidr = match vcpu_fd.get_one_reg(SYS_MPIDR_EL1) {
                Ok(mpidr) => mpidr as u64,
                Err(e) => panic!("update vcpu mpidr failed {:?}", e),
            };
        }
        debug!("self.mpidr is {}", self.mpidr);
        self.mpidr
    }

    pub fn reset_vcpu(&self, vcpu: &Arc<VcpuFd>) -> Result<()> {
        // Configure PSTATE(Processor State), mask all interrupts.
        let data: u64 = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
        set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_PSTATE, data)
            .expect("Failed to set core reg pstate register");

        // Reset x1, x2, x3 register to zero.
        set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_REGS(1), 0)
            .expect("Failed to init x1 to zero");

        set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_REGS(2), 0)
            .expect("Failed to init x2 to zero");

        set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_REGS(3), 0)
            .expect("Failed to init x3 to zero");

        // Configure boot ip and device tree address, prepare for kernel setup
        if self.vcpu_id == 0 {
            set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_REGS(0), self.fdt_addr)
                .expect("Failed to set device tree address");

            set_one_core_reg(&vcpu, Arm64CoreRegs::USER_PT_REG_PC, self.boot_ip)
                .expect("Failed to set boot ip");
        }

        Ok(())
    }
}
