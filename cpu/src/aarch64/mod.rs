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

mod core_regs;

use std::sync::Arc;

use hypervisor::KVM_FDS;
use kvm_ioctls::VcpuFd;
use kvm_ioctls::{VcpuFd, VmFd};

use crate::errors::{Result, ResultExt};
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
}

impl CPUAArch64 {
    pub fn new(vcpu_id: u32) -> Self {
        CPUAArch64 {
            vcpu_id,
            mpidr: UNINIT_MPIDR,
            boot_ip: 0,
            fdt_addr: 0,
        }
    }

    pub fn realize(
        &mut self,
        vcpu_fd: &Arc<VcpuFd>,
        boot_config: &AArch64CPUBootConfig,
    ) -> Result<()> {
        self.boot_ip = boot_config.kernel_addr;
        self.fdt_addr = boot_config.fdt_addr;

        let mut kvi = kvm_bindings::kvm_vcpu_init::default();
        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .get_preferred_target(&mut kvi)
            .chain_err(|| "Failed to get kvm vcpu preferred target")?;

        // support PSCI 0.2
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.vcpu_id != 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        vcpu_fd
            .vcpu_init(&kvi)
            .chain_err(|| "Failed to init kvm vcpu")?;
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

    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        // Configure PSTATE(Processor State), mask all interrupts.
        let data: u64 = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
        vcpu_fd
            .set_one_reg(Arm64CoreRegs::UserPTRegPState.into(), data)
            .chain_err(|| {
                format!(
                    "Failed to set core reg pstate register for CPU {}/KVM",
                    self.vcpu_id
                )
            })?;

        // Reset x1, x2, x3 register to zero.
        vcpu_fd
            .set_one_reg(Arm64CoreRegs::UserPTRegRegs(1).into(), 0)
            .chain_err(|| format!("Failed to init x1 to zero for CPU {}/KVM", self.vcpu_id))?;

        vcpu_fd
            .set_one_reg(Arm64CoreRegs::UserPTRegRegs(2).into(), 0)
            .chain_err(|| format!("Failed to init x2 to zero for CPU {}/KVM", self.vcpu_id))?;

        vcpu_fd
            .set_one_reg(Arm64CoreRegs::UserPTRegRegs(3).into(), 0)
            .chain_err(|| format!("Failed to init x3 to zero for CPU {}/KVM", self.vcpu_id))?;

        // Configure boot ip and device tree address, prepare for kernel setup
        if self.vcpu_id == 0 {
            vcpu_fd
                .set_one_reg(Arm64CoreRegs::UserPTRegRegs(0).into(), self.fdt_addr)
                .chain_err(|| {
                    format!(
                        "Failed to set device tree address for CPU {}/KVM",
                        self.vcpu_id
                    )
                })?;

            vcpu_fd
                .set_one_reg(Arm64CoreRegs::UserPTRegPc.into(), self.boot_ip)
                .chain_err(|| format!("Failed to set boot ip for CPU {}/KVM", self.vcpu_id))?;
        }

        Ok(())
    }
}
