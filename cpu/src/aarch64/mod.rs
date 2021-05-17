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

#[allow(dead_code)]
mod caps;
#[allow(dead_code)]
mod core_regs;

use std::sync::Arc;

use hypervisor::KVM_FDS;
use kvm_bindings::{kvm_regs, kvm_vcpu_init};
use kvm_ioctls::VcpuFd;

use crate::errors::{Result, ResultExt};
pub use caps::ArmCPUCaps;
use core_regs::Arm64CoreRegs;

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

/// AArch64 CPU booting configure information
///
/// Before jumping into the kernel, primary CPU general-purpose
/// register `x0` need to setting to physical address of device
/// tree blob (dtb) in system RAM.
///
/// See: https://elixir.bootlin.com/linux/v5.6/source/Documentation/arm64/booting.rst
#[derive(Default, Copy, Clone)]
pub struct ArmCPUBootConfig {
    pub fdt_addr: u64,
    pub kernel_addr: u64,
}

/// AArch64 CPU architect information
#[derive(Default, Copy, Clone)]
pub struct ArmCPUState {
    /// The vcpu id, `0` means primary CPU.
    apic_id: u32,
    /// MPIDR register value of this vcpu,
    /// The MPIDR provides an additional processor identification mechanism
    /// for scheduling purposes.
    mpidr: u64,
    /// Used to pass vcpu target and supported features to kvm.
    kvi: kvm_vcpu_init,
    /// Vcpu core registers.
    core_regs: kvm_regs,
}

impl ArmCPUState {
    /// Allocates a new `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    pub fn new(vcpu_id: u32) -> Self {
        ArmCPUState {
            apic_id: vcpu_id,
            mpidr: UNINIT_MPIDR,
            ..Default::default()
        }
    }

    /// Set register value in `ArmCPUState` according to `boot_config`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    /// * `boot_config` - Boot message from boot_loader.
    pub fn set_boot_config(
        &mut self,
        vcpu_fd: &Arc<VcpuFd>,
        boot_config: &ArmCPUBootConfig,
    ) -> Result<()> {
        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .get_preferred_target(&mut self.kvi)
            .chain_err(|| "Failed to get kvm vcpu preferred target")?;

        // support PSCI 0.2
        // We already checked that the capability is supported.
        self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.apic_id != 0 {
            self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        // Set core regs.
        self.core_regs.regs.pstate = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
        self.core_regs.regs.regs[1] = 0;
        self.core_regs.regs.regs[2] = 0;
        self.core_regs.regs.regs[3] = 0;

        // Configure boot ip and device tree address, prepare for kernel setup
        if self.apic_id == 0 {
            self.core_regs.regs.regs[0] = boot_config.fdt_addr;
            self.core_regs.regs.pc = boot_config.kernel_addr;
        }

        vcpu_fd
            .vcpu_init(&self.kvi)
            .chain_err(|| "Failed to init kvm vcpu")?;
        self.mpidr = vcpu_fd
            .get_one_reg(SYS_MPIDR_EL1)
            .chain_err(|| "Failed to get mpidr")?;

        Ok(())
    }

    /// Get mpidr value.
    pub fn mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Reset register value with `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        vcpu_fd
            .set_one_reg(
                Arm64CoreRegs::UserPTRegPState.into(),
                self.core_regs.regs.pstate,
            )
            .chain_err(|| {
                format!(
                    "Failed to set core reg pstate register for CPU {}/KVM",
                    self.apic_id
                )
            })?;

        vcpu_fd
            .set_one_reg(
                Arm64CoreRegs::UserPTRegRegs(1).into(),
                self.core_regs.regs.regs[1],
            )
            .chain_err(|| format!("Failed to init x1 to zero for CPU {}/KVM", self.apic_id))?;

        vcpu_fd
            .set_one_reg(
                Arm64CoreRegs::UserPTRegRegs(2).into(),
                self.core_regs.regs.regs[2],
            )
            .chain_err(|| format!("Failed to init x2 to zero for CPU {}/KVM", self.apic_id))?;

        vcpu_fd
            .set_one_reg(
                Arm64CoreRegs::UserPTRegRegs(3).into(),
                self.core_regs.regs.regs[3],
            )
            .chain_err(|| format!("Failed to init x3 to zero for CPU {}/KVM", self.apic_id))?;

        if self.apic_id == 0 {
            vcpu_fd
                .set_one_reg(
                    Arm64CoreRegs::UserPTRegRegs(0).into(),
                    self.core_regs.regs.regs[0],
                )
                .chain_err(|| {
                    format!(
                        "Failed to set device tree address for CPU {}/KVM",
                        self.apic_id
                    )
                })?;

            vcpu_fd
                .set_one_reg(Arm64CoreRegs::UserPTRegPc.into(), self.core_regs.regs.pc)
                .chain_err(|| format!("Failed to set boot ip for CPU {}/KVM", self.apic_id))?;
        }

        Ok(())
    }
}
