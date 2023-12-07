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
mod core_regs;
mod regs;

pub use self::caps::{ArmCPUCaps, ArmCPUFeatures};

use std::{
    mem::forget,
    os::unix::prelude::{AsRawFd, FromRawFd},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use kvm_bindings::{
    kvm_device_attr, kvm_mp_state, kvm_regs, kvm_vcpu_events, kvm_vcpu_init, RegList,
    KVM_ARM_VCPU_PMU_V3_CTRL, KVM_ARM_VCPU_PMU_V3_INIT, KVM_ARM_VCPU_PMU_V3_IRQ,
    KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_STOPPED,
};
use kvm_ioctls::{DeviceFd, VcpuFd};

use self::caps::CpregListEntry;
use self::core_regs::{get_core_regs, set_core_regs};
use self::regs::{KVM_REG_ARM_MPIDR_EL1, KVM_REG_ARM_TIMER_CNT};
use crate::CPU;
use hypervisor::kvm::KVM_FDS;
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

const KVM_MAX_CPREG_ENTRIES: usize = 500;

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
    apic_id: u32,
    /// MPIDR register value of this vcpu,
    /// The MPIDR provides an additional processor identification mechanism
    /// for scheduling purposes.
    mpidr: u64,
    /// Used to pass vcpu target and supported features to kvm.
    kvi: kvm_vcpu_init,
    /// Vcpu core registers.
    core_regs: kvm_regs,
    /// Vcpu cpu events register.
    cpu_events: kvm_vcpu_events,
    /// Vcpu mpstate register.
    mp_state: kvm_mp_state,
    /// The length of Cpreg.
    cpreg_len: usize,
    /// The list of Cpreg.
    cpreg_list: [CpregListEntry; 512],
    /// Vcpu features
    features: ArmCPUFeatures,
    /// Virtual timer count.
    vtimer_cnt: u64,
}

impl ArmCPUState {
    /// Allocates a new `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    pub fn new(vcpu_id: u32) -> Self {
        let mp_state = kvm_mp_state {
            mp_state: if vcpu_id == 0 {
                KVM_MP_STATE_RUNNABLE
            } else {
                KVM_MP_STATE_STOPPED
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
        self.kvi = locked_cpu_state.kvi;
        self.core_regs = locked_cpu_state.core_regs;
        self.cpu_events = locked_cpu_state.cpu_events;
        self.mp_state = locked_cpu_state.mp_state;
        self.cpreg_len = locked_cpu_state.cpreg_len;
        self.cpreg_list = locked_cpu_state.cpreg_list;
        self.features = locked_cpu_state.features;
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
        vcpu_config: &ArmCPUFeatures,
    ) -> Result<()> {
        KVM_FDS
            .load()
            .vm_fd
            .as_ref()
            .unwrap()
            .get_preferred_target(&mut self.kvi)
            .with_context(|| "Failed to get kvm vcpu preferred target")?;

        // support PSCI 0.2
        // We already checked that the capability is supported.
        self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.apic_id != 0 {
            self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        // Enable PMU from config.
        if vcpu_config.pmu {
            self.kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PMU_V3;
        }

        self.set_core_reg(boot_config);

        vcpu_fd
            .vcpu_init(&self.kvi)
            .with_context(|| "Failed to init kvm vcpu")?;
        self.mpidr = vcpu_fd
            .get_one_reg(KVM_REG_ARM_MPIDR_EL1)
            .with_context(|| "Failed to get mpidr")? as u64;

        self.features = *vcpu_config;

        Ok(())
    }

    /// Set cpu topology
    ///
    /// # Arguments
    ///
    /// * `topology` - ARM CPU Topology
    pub fn set_cpu_topology(&mut self, _topology: &ArmCPUTopology) -> Result<()> {
        Ok(())
    }

    /// Reset register value in `Kvm` with `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        set_core_regs(vcpu_fd, self.core_regs)
            .with_context(|| format!("Failed to set core register for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_mp_state(self.mp_state)
            .with_context(|| format!("Failed to set mpstate for CPU {}", self.apic_id))?;
        for cpreg in self.cpreg_list[0..self.cpreg_len].iter() {
            cpreg
                .set_cpreg(&vcpu_fd.clone())
                .with_context(|| format!("Failed to set cpreg for CPU {}", self.apic_id))?;
        }
        vcpu_fd
            .set_vcpu_events(&self.cpu_events)
            .with_context(|| format!("Failed to set vcpu event for CPU {}", self.apic_id))?;

        Ok(())
    }

    /// Get mpidr value.
    pub fn mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Get core_regs value.
    pub fn core_regs(&self) -> kvm_regs {
        self.core_regs
    }

    /// Get kvm_vcpu_init.
    pub fn kvi(&self) -> kvm_vcpu_init {
        self.kvi
    }

    fn set_core_reg(&mut self, boot_config: &ArmCPUBootConfig) {
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

    /// Set virtual timer Count register value to `Kvm` with `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn set_virtual_timer_cnt(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        vcpu_fd
            .set_one_reg(KVM_REG_ARM_TIMER_CNT, self.vtimer_cnt as u128)
            .with_context(|| "Failed to set virtual timer count")
    }

    /// Get virtual timer Count register value from `Kvm` with `ArmCPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    pub fn get_virtual_timer_cnt(&mut self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        self.vtimer_cnt = vcpu_fd
            .get_one_reg(KVM_REG_ARM_TIMER_CNT)
            .with_context(|| "Failed to get virtual timer count")? as u64;
        Ok(())
    }
}

impl CPU {
    /// Init PMU for ARM CPU
    pub fn init_pmu(&self) -> Result<()> {
        let pmu_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: KVM_ARM_VCPU_PMU_V3_INIT as u64,
            addr: 0,
            flags: 0,
        };
        // SAFETY: the fd can be guaranteed to be legal during creation.
        let vcpu_device = unsafe { DeviceFd::from_raw_fd(self.fd.as_raw_fd()) };
        vcpu_device
            .has_device_attr(&pmu_attr)
            .with_context(|| "Kernel does not support PMU for vCPU")?;
        // Set IRQ 23, PPI 7 for PMU.
        let irq = PMU_INTR + PPI_BASE;
        let pmu_irq_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: KVM_ARM_VCPU_PMU_V3_IRQ as u64,
            addr: &irq as *const u32 as u64,
            flags: 0,
        };

        vcpu_device
            .set_device_attr(&pmu_irq_attr)
            .with_context(|| "Failed to set IRQ for PMU")?;
        // Init PMU after setting IRQ.
        vcpu_device
            .set_device_attr(&pmu_attr)
            .with_context(|| "Failed to enable PMU for vCPU")?;
        // forget `vcpu_device` to avoid fd close on exit, as DeviceFd is backed by File.
        forget(vcpu_device);

        Ok(())
    }
}

impl StateTransfer for CPU {
    fn get_state_vec(&self) -> migration::Result<Vec<u8>> {
        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();

        cpu_state_locked.core_regs = get_core_regs(&self.fd)?;
        if self.caps.mp_state {
            let mut mp_state = self.fd.get_mp_state()?;
            if mp_state.mp_state != KVM_MP_STATE_STOPPED {
                mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
            }
            cpu_state_locked.mp_state = mp_state;
        }

        let mut cpreg_list = RegList::new(KVM_MAX_CPREG_ENTRIES)?;
        self.fd.get_reg_list(&mut cpreg_list)?;
        cpu_state_locked.cpreg_len = 0;
        for (index, cpreg) in cpreg_list.as_slice().iter().enumerate() {
            let mut cpreg_entry = CpregListEntry {
                reg_id: *cpreg,
                value: 0,
            };
            if cpreg_entry.validate() {
                cpreg_entry.get_cpreg(&self.fd.clone())?;
                cpu_state_locked.cpreg_list[index] = cpreg_entry;
                cpu_state_locked.cpreg_len += 1;
            }
        }
        cpu_state_locked.cpu_events = self.fd.get_vcpu_events()?;

        Ok(cpu_state_locked.as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> migration::Result<()> {
        let cpu_state = *ArmCPUState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("CPU"))?;

        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();
        *cpu_state_locked = cpu_state;

        self.fd.vcpu_init(&cpu_state.kvi)?;

        if cpu_state.features.pmu {
            self.init_pmu()
                .with_context(|| MigrationError::FromBytesError("Failed to init pmu."))?;
        }
        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&ArmCPUState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for CPU {}
