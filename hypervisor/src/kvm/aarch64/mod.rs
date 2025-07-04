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

pub mod cpu_caps;
pub mod gicv2;
pub mod gicv3;

mod core_regs;
mod sys_regs;

use std::mem::forget;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use kvm_bindings::*;
use kvm_ioctls::DeviceFd;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr, ioctl_iowr_nr};

use self::core_regs::Arm64CoreRegs;
use self::sys_regs::{KVM_REG_ARM_MPIDR_EL1, KVM_REG_ARM_TIMER_CNT};
use crate::kvm::{KvmCpu, KvmHypervisor};
use cpu::{
    ArchCPU, CPUBootConfig, CPUFeatures, CpregListEntry, RegsIndex, CPU, PMU_INTR, PPI_BASE,
};

pub const KVM_MAX_CPREG_ENTRIES: usize = 500;
const KVM_NR_REGS: u64 = 31;
const KVM_NR_FP_REGS: u64 = 32;

ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);
ioctl_iow_nr!(KVM_ARM_VCPU_INIT, KVMIO, 0xae, kvm_vcpu_init);

/// A wrapper for kvm_based device check and access.
pub struct KvmDevice;
impl KvmDevice {
    fn kvm_device_check(fd: &DeviceFd, group: u32, attr: u64) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: 0,
            flags: 0,
        };
        fd.has_device_attr(&attr)
            .with_context(|| "Failed to check device attributes.")?;
        Ok(())
    }

    fn kvm_device_access(
        fd: &DeviceFd,
        group: u32,
        attr: u64,
        addr: u64,
        write: bool,
    ) -> Result<()> {
        let attr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr,
            flags: 0,
        };

        if write {
            fd.set_device_attr(&attr)
                .with_context(|| "Failed to set device attributes.")?;
        } else {
            let mut attr = attr;
            fd.get_device_attr(&mut attr)
                .with_context(|| "Failed to get device attributes.")?;
        };

        Ok(())
    }
}

impl KvmHypervisor {
    pub fn arch_init(&self) -> Result<()> {
        Ok(())
    }
}

impl KvmCpu {
    pub fn arch_init_pmu(&self) -> Result<()> {
        let pmu_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(KVM_ARM_VCPU_PMU_V3_INIT),
            addr: 0,
            flags: 0,
        };
        // SAFETY: The fd can be guaranteed to be legal during creation.
        let vcpu_device = unsafe { DeviceFd::from_raw_fd(self.fd.as_raw_fd()) };
        vcpu_device
            .has_device_attr(&pmu_attr)
            .with_context(|| "Kernel does not support PMU for vCPU")?;
        // Set IRQ 23, PPI 7 for PMU.
        let irq = PMU_INTR + PPI_BASE;
        let pmu_irq_attr = kvm_device_attr {
            group: KVM_ARM_VCPU_PMU_V3_CTRL,
            attr: u64::from(KVM_ARM_VCPU_PMU_V3_IRQ),
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

    pub fn arch_vcpu_init(&self) -> Result<()> {
        self.fd
            .vcpu_init(&self.kvi.lock().unwrap())
            .with_context(|| "Failed to init kvm vcpu")
    }

    pub fn arch_set_boot_config(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        boot_config: &CPUBootConfig,
        vcpu_config: &CPUFeatures,
    ) -> Result<()> {
        let mut kvi = self.kvi.lock().unwrap();
        self.vm_fd
            .as_ref()
            .unwrap()
            .get_preferred_target(&mut kvi)
            .with_context(|| "Failed to get kvm vcpu preferred target")?;

        // support PSCI 0.2
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if arch_cpu.lock().unwrap().apic_id != 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        // Enable PMU from config.
        if vcpu_config.pmu {
            if !self.caps.pmuv3 {
                bail!("PMUv3 is not supported by KVM");
            }
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PMU_V3;
        }
        // Enable SVE from config.
        if vcpu_config.sve {
            if !self.caps.sve {
                bail!("SVE is not supported by KVM");
            }
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_SVE;
        }
        drop(kvi);

        arch_cpu.lock().unwrap().set_core_reg(boot_config);

        self.arch_vcpu_init()?;

        if vcpu_config.sve {
            self.fd
                .vcpu_finalize(&(i32::try_from(kvm_bindings::KVM_ARM_VCPU_SVE)?))?;
        }

        arch_cpu.lock().unwrap().mpidr = u64::try_from(
            self.get_one_reg(KVM_REG_ARM_MPIDR_EL1)
                .with_context(|| "Failed to get mpidr")?,
        )?;

        arch_cpu.lock().unwrap().features = *vcpu_config;

        Ok(())
    }

    fn get_one_reg(&self, reg_id: u64) -> Result<u128> {
        let mut val = [0_u8; 16];
        self.fd.get_one_reg(reg_id, &mut val)?;
        let data = u128::from_le_bytes(val);
        trace::kvm_get_one_reg(self.id, reg_id, data);
        Ok(data)
    }

    fn set_one_reg(&self, reg_id: u64, val: u128) -> Result<()> {
        trace::kvm_set_one_reg(self.id, reg_id, val);
        self.fd.set_one_reg(reg_id, &val.to_le_bytes())?;
        Ok(())
    }

    pub fn arch_get_one_reg(&self, reg_id: u64) -> Result<u128> {
        self.get_one_reg(reg_id)
    }

    pub fn arch_get_regs(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        regs_index: RegsIndex,
    ) -> Result<()> {
        let mut locked_arch_cpu = arch_cpu.lock().unwrap();

        match regs_index {
            RegsIndex::CoreRegs => {
                locked_arch_cpu.core_regs = self.get_core_regs()?;
            }
            RegsIndex::MpState => {
                if self.caps.mp_state {
                    let mut mp_state = self.fd.get_mp_state()?;
                    if mp_state.mp_state != KVM_MP_STATE_STOPPED {
                        mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
                    }
                    trace::kvm_get_mp_state(self.id, &mp_state);
                    locked_arch_cpu.mp_state = mp_state;
                }
            }
            RegsIndex::VcpuEvents => {
                if self.caps.vcpu_events {
                    locked_arch_cpu.cpu_events = self.fd.get_vcpu_events()?;
                    trace::kvm_get_vcpu_events(self.id, &locked_arch_cpu.cpu_events);
                }
            }
            RegsIndex::CpregList => {
                let mut cpreg_list = RegList::new(KVM_MAX_CPREG_ENTRIES)?;
                self.fd.get_reg_list(&mut cpreg_list)?;
                locked_arch_cpu.cpreg_len = 0;
                for cpreg in cpreg_list.as_slice() {
                    let mut cpreg_entry = CpregListEntry {
                        reg_id: *cpreg,
                        value: 0,
                    };
                    if !self.get_cpreg(&mut cpreg_entry)? {
                        // We sync these cpreg by hand, such as core regs.
                        continue;
                    }
                    let index = locked_arch_cpu.cpreg_len;
                    locked_arch_cpu.cpreg_list[index] = cpreg_entry;
                    locked_arch_cpu.cpreg_len += 1;
                }
                trace::kvm_get_reg_list(
                    self.id,
                    &&locked_arch_cpu.cpreg_list[0..locked_arch_cpu.cpreg_len],
                );
            }
            RegsIndex::VtimerCount => {
                locked_arch_cpu.vtimer_cnt = u64::try_from(
                    self.get_one_reg(KVM_REG_ARM_TIMER_CNT)
                        .with_context(|| "Failed to get virtual timer count")?,
                )?;
                locked_arch_cpu.vtimer_cnt_valid = true;
            }
        }

        Ok(())
    }

    pub fn arch_set_regs(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        regs_index: RegsIndex,
    ) -> Result<()> {
        let mut locked_arch_cpu = arch_cpu.lock().unwrap();
        let apic_id = locked_arch_cpu.apic_id;
        match regs_index {
            RegsIndex::CoreRegs => {
                self.set_core_regs(locked_arch_cpu.core_regs)
                    .with_context(|| format!("Failed to set core register for CPU {}", apic_id))?;
            }
            RegsIndex::MpState => {
                if self.caps.mp_state {
                    trace::kvm_set_mp_state(self.id, &locked_arch_cpu.mp_state);
                    self.fd
                        .set_mp_state(locked_arch_cpu.mp_state)
                        .with_context(|| format!("Failed to set mpstate for CPU {}", apic_id))?;
                }
            }
            RegsIndex::VcpuEvents => {
                if self.caps.vcpu_events {
                    trace::kvm_set_vcpu_events(self.id, &locked_arch_cpu.cpu_events);
                    self.fd
                        .set_vcpu_events(&locked_arch_cpu.cpu_events)
                        .with_context(|| format!("Failed to set vcpu event for CPU {}", apic_id))?;
                }
            }
            RegsIndex::CpregList => {
                for cpreg in locked_arch_cpu.cpreg_list[0..locked_arch_cpu.cpreg_len].iter() {
                    self.set_cpreg(cpreg)
                        .with_context(|| format!("Failed to set cpreg for CPU {}", apic_id))?;
                }
            }
            RegsIndex::VtimerCount => {
                if locked_arch_cpu.vtimer_cnt_valid {
                    self.set_one_reg(
                        KVM_REG_ARM_TIMER_CNT,
                        u128::from(locked_arch_cpu.vtimer_cnt),
                    )
                    .with_context(|| "Failed to set virtual timer count")?;
                    locked_arch_cpu.vtimer_cnt_valid = false;
                }
            }
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
    fn get_core_regs(&self) -> Result<kvm_regs> {
        let mut core_regs = kvm_regs::default();

        core_regs.regs.sp = u64::try_from(self.get_one_reg(Arm64CoreRegs::UserPTRegSp.into())?)?;
        core_regs.sp_el1 = u64::try_from(self.get_one_reg(Arm64CoreRegs::KvmSpEl1.into())?)?;
        core_regs.regs.pstate =
            u64::try_from(self.get_one_reg(Arm64CoreRegs::UserPTRegPState.into())?)?;
        core_regs.regs.pc = u64::try_from(self.get_one_reg(Arm64CoreRegs::UserPTRegPc.into())?)?;
        core_regs.elr_el1 = u64::try_from(self.get_one_reg(Arm64CoreRegs::KvmElrEl1.into())?)?;

        for i in 0..usize::try_from(KVM_NR_REGS)? {
            core_regs.regs.regs[i] =
                u64::try_from(self.get_one_reg(Arm64CoreRegs::UserPTRegRegs(i).into())?)?;
        }

        for i in 0..usize::try_from(KVM_NR_SPSR)? {
            core_regs.spsr[i] = u64::try_from(self.get_one_reg(Arm64CoreRegs::KvmSpsr(i).into())?)?;
        }

        // State save and restore is not supported for SVE for now, so we just skip it.
        if self.kvi.lock().unwrap().features[0] & (1 << kvm_bindings::KVM_ARM_VCPU_SVE) == 0 {
            for i in 0..usize::try_from(KVM_NR_FP_REGS)? {
                core_regs.fp_regs.vregs[i] =
                    self.get_one_reg(Arm64CoreRegs::UserFPSIMDStateVregs(i).into())?;
            }
        }

        core_regs.fp_regs.fpsr =
            u32::try_from(self.get_one_reg(Arm64CoreRegs::UserFPSIMDStateFpsr.into())?)?;
        core_regs.fp_regs.fpcr =
            u32::try_from(self.get_one_reg(Arm64CoreRegs::UserFPSIMDStateFpcr.into())?)?;

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
    fn set_core_regs(&self, core_regs: kvm_regs) -> Result<()> {
        self.set_one_reg(
            Arm64CoreRegs::UserPTRegSp.into(),
            u128::from(core_regs.regs.sp),
        )?;
        self.set_one_reg(Arm64CoreRegs::KvmSpEl1.into(), u128::from(core_regs.sp_el1))?;
        self.set_one_reg(
            Arm64CoreRegs::UserPTRegPState.into(),
            u128::from(core_regs.regs.pstate),
        )?;
        self.set_one_reg(
            Arm64CoreRegs::UserPTRegPc.into(),
            u128::from(core_regs.regs.pc),
        )?;
        self.set_one_reg(
            Arm64CoreRegs::KvmElrEl1.into(),
            u128::from(core_regs.elr_el1),
        )?;

        for i in 0..usize::try_from(KVM_NR_REGS)? {
            self.set_one_reg(
                Arm64CoreRegs::UserPTRegRegs(i).into(),
                u128::from(core_regs.regs.regs[i]),
            )?;
        }

        for i in 0..usize::try_from(KVM_NR_SPSR)? {
            self.set_one_reg(
                Arm64CoreRegs::KvmSpsr(i).into(),
                u128::from(core_regs.spsr[i]),
            )?;
        }

        // State save and restore is not supported for SVE for now, so we just skip it.
        if self.kvi.lock().unwrap().features[0] & (1 << kvm_bindings::KVM_ARM_VCPU_SVE) == 0 {
            for i in 0..usize::try_from(KVM_NR_FP_REGS)? {
                self.set_one_reg(
                    Arm64CoreRegs::UserFPSIMDStateVregs(i).into(),
                    core_regs.fp_regs.vregs[i],
                )?;
            }
        }

        self.set_one_reg(
            Arm64CoreRegs::UserFPSIMDStateFpsr.into(),
            u128::from(core_regs.fp_regs.fpsr),
        )?;
        self.set_one_reg(
            Arm64CoreRegs::UserFPSIMDStateFpcr.into(),
            u128::from(core_regs.fp_regs.fpcr),
        )?;

        Ok(())
    }

    fn reg_sync_by_cpreg_list(reg_id: u64) -> Result<bool> {
        let coproc = reg_id as u32 & KVM_REG_ARM_COPROC_MASK;
        if coproc == KVM_REG_ARM_CORE {
            return Ok(false);
        }

        let size = reg_id & KVM_REG_SIZE_MASK;
        if size == KVM_REG_SIZE_U32 || size == KVM_REG_SIZE_U64 {
            Ok(true)
        } else {
            bail!("Can't handle size of register in cpreg list");
        }
    }

    fn get_cpreg(&self, cpreg: &mut CpregListEntry) -> Result<bool> {
        if !Self::reg_sync_by_cpreg_list(cpreg.reg_id)? {
            return Ok(false);
        }
        cpreg.value = self.get_one_reg(cpreg.reg_id)?;
        Ok(true)
    }

    fn set_cpreg(&self, cpreg: &CpregListEntry) -> Result<bool> {
        if !Self::reg_sync_by_cpreg_list(cpreg.reg_id)? {
            return Ok(false);
        }
        self.set_one_reg(cpreg.reg_id, cpreg.value)?;
        Ok(true)
    }

    pub fn arch_put_register(&self, cpu: Arc<CPU>) -> Result<()> {
        let arch_cpu = &cpu.arch_cpu;
        self.arch_set_regs(arch_cpu.clone(), RegsIndex::CoreRegs)?;
        self.arch_set_regs(arch_cpu.clone(), RegsIndex::MpState)?;
        self.arch_set_regs(arch_cpu.clone(), RegsIndex::CpregList)?;
        self.arch_set_regs(arch_cpu.clone(), RegsIndex::VcpuEvents)
    }

    pub fn arch_reset_vcpu(&self, cpu: Arc<CPU>) -> Result<()> {
        cpu.arch_cpu.lock().unwrap().set(&cpu.boot_state());
        self.arch_vcpu_init()
    }
}
