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

pub mod caps;

pub use self::caps::ArmCPUFeatures;
pub use self::caps::CpregListEntry;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::{
    kvm_mp_state as MpState, kvm_regs as Regs, kvm_vcpu_events as VcpuEvents,
    KVM_MP_STATE_RUNNABLE as MP_STATE_RUNNABLE, KVM_MP_STATE_STOPPED as MP_STATE_STOPPED,
};

use crate::CPU;
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

// PSR (Processor State Register) bits.
// See: https://elixir.bootlin.com/linux/v5.6/source/arch/arm64/include/uapi/asm/ptrace.h#L34
#[allow(non_upper_case_globals)]
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
// MPIDR is Multiprocessor Affinity Register
// [40:63] bit reserved on AArch64 Architecture,
const UNINIT_MPIDR: u64 = 0xFFFF_FF00_0000_0000;

/// Interrupt ID for pmu.
/// See: https://developer.arm.com/documentation/den0094/b/
/// And: https://developer.arm.com/documentation/dai0492/b/
pub const PPI_BASE: u32 = 16;
pub const PMU_INTR: u32 = 7;

/// AArch64 CPU booting configure information
///
/// Before jumping into the kernel, primary CPU general-purpose
/// register `x0` need to setting to physical address of device
/// tree blob (dtb) in system RAM.
///
/// See: https://elixir.bootlin.com/linux/v5.6/source/Documentation/arm64/booting.rst
#[derive(Default, Copy, Clone, Debug)]
pub struct ArmCPUBootConfig {
    pub fdt_addr: u64,
    pub boot_pc: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArmRegsIndex {
    CoreRegs,
    MpState,
    VcpuEvents,
    CpregList,
    VtimerCount,
}

#[derive(Default, Copy, Clone, Debug)]
pub struct ArmCPUTopology {}

impl ArmCPUTopology {
    pub fn new() -> Self {
        ArmCPUTopology::default()
    }

    pub fn set_topology(self, _topology: (u8, u8, u8)) -> Self {
        self
    }
}

/// AArch64 CPU architect information
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct ArmCPUState {
    /// The vcpu id, `0` means primary CPU.
    pub apic_id: u32,
    /// MPIDR register value of this vcpu,
    /// The MPIDR provides an additional processor identification mechanism
    /// for scheduling purposes.
    pub mpidr: u64,
    /// Vcpu core registers.
    pub core_regs: Regs,
    /// Vcpu cpu events register.
    pub cpu_events: VcpuEvents,
    /// Vcpu mpstate register.
    pub mp_state: MpState,
    /// The length of Cpreg.
    pub cpreg_len: usize,
    /// The list of Cpreg.
    pub cpreg_list: [CpregListEntry; 512],
    /// Vcpu features
    pub features: ArmCPUFeatures,
    /// Virtual timer count.
    pub vtimer_cnt: u64,
}

impl ArmCPUState {
    /// Allocates a new `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    pub fn new(vcpu_id: u32) -> Self {
        let mp_state = MpState {
            mp_state: if vcpu_id == 0 {
                MP_STATE_RUNNABLE
            } else {
                MP_STATE_STOPPED
            },
        };

        ArmCPUState {
            apic_id: vcpu_id,
            mpidr: UNINIT_MPIDR,
            mp_state,
            ..Default::default()
        }
    }

    pub fn set(&mut self, cpu_state: &Arc<Mutex<ArmCPUState>>) {
        let locked_cpu_state = cpu_state.lock().unwrap();
        self.apic_id = locked_cpu_state.apic_id;
        self.mpidr = locked_cpu_state.mpidr;
        self.core_regs = locked_cpu_state.core_regs;
        self.cpu_events = locked_cpu_state.cpu_events;
        self.mp_state = locked_cpu_state.mp_state;
        self.cpreg_len = locked_cpu_state.cpreg_len;
        self.cpreg_list = locked_cpu_state.cpreg_list;
        self.features = locked_cpu_state.features;
    }

    /// Set cpu topology
    ///
    /// # Arguments
    ///
    /// * `topology` - ARM CPU Topology
    pub fn set_cpu_topology(&mut self, _topology: &ArmCPUTopology) -> Result<()> {
        Ok(())
    }

    /// Get mpidr value.
    pub fn mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Get core_regs value.
    pub fn core_regs(&self) -> Regs {
        self.core_regs
    }

    pub fn set_core_reg(&mut self, boot_config: &ArmCPUBootConfig) {
        // Set core regs.
        self.core_regs.regs.pstate = PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
        self.core_regs.regs.regs[1] = 0;
        self.core_regs.regs.regs[2] = 0;
        self.core_regs.regs.regs[3] = 0;

        // Configure boot ip and device tree address, prepare for kernel setup
        if self.apic_id == 0 {
            self.core_regs.regs.regs[0] = boot_config.fdt_addr;
            self.core_regs.regs.pc = boot_config.boot_pc;
        }
    }

    /// Get cpu features.
    pub fn get_features(&self) -> &ArmCPUFeatures {
        &self.features
    }
}

impl StateTransfer for CPU {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        self.hypervisor_cpu
            .get_regs(self.arch_cpu.clone(), ArmRegsIndex::CoreRegs)?;
        self.hypervisor_cpu
            .get_regs(self.arch_cpu.clone(), ArmRegsIndex::MpState)?;
        self.hypervisor_cpu
            .get_regs(self.arch_cpu.clone(), ArmRegsIndex::CpregList)?;
        self.hypervisor_cpu
            .get_regs(self.arch_cpu.clone(), ArmRegsIndex::VcpuEvents)?;

        Ok(self.arch_cpu.lock().unwrap().as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> Result<()> {
        let cpu_state = *ArmCPUState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("CPU"))?;

        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();
        *cpu_state_locked = cpu_state;
        drop(cpu_state_locked);

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&ArmCPUState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for CPU {}
