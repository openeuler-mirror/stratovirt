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

mod cpuid;

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::{
    kvm_cpuid_entry2 as CpuidEntry2, kvm_debugregs as DebugRegs, kvm_fpu as Fpu,
    kvm_lapic_state as LapicState, kvm_mp_state as MpState, kvm_msr_entry as MsrEntry,
    kvm_regs as Regs, kvm_segment as Segment, kvm_sregs as Sregs, kvm_vcpu_events as VcpuEvents,
    kvm_xcrs as Xcrs, kvm_xsave as Xsave, CpuId,
    KVM_CPUID_FLAG_SIGNIFCANT_INDEX as CPUID_FLAG_SIGNIFICANT_INDEX,
    KVM_MP_STATE_RUNNABLE as MP_STATE_RUNNABLE,
    KVM_MP_STATE_UNINITIALIZED as MP_STATE_UNINITIALIZED,
};

use self::cpuid::host_cpuid;
use crate::CPU;
use migration::{
    DeviceStateDesc, FieldDesc, MigrationError, MigrationHook, MigrationManager, StateTransfer,
};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

const ECX_EPB_SHIFT: u32 = 3;
const X86_FEATURE_HYPERVISOR: u32 = 31;
const X86_FEATURE_TSC_DEADLINE_TIMER: u32 = 24;

const MSR_LIST: &[u32] = &[
    0x0174,      // MSR_IA32_SYSENTER_CS
    0x0175,      // MSR_IA32_SYSENTER_ESP
    0x0176,      // MSR_IA32_SYSENTER_EIP
    0xc000_0081, // MSR_STAR, legacy mode SYSCALL target
    0xc000_0082, // MSR_LSTAR, long mode SYSCALL target
    0xc000_0083, // MSR_CSTAR, compat mode SYSCALL target
    0xc000_0084, // MSR_SYSCALL_MASK, EFLAGS mask for syscall
    0xc000_0102, // MSR_KERNEL_GS_BASE, SwapGS GS shadow
    0x0010,      // MSR_IA32_TSC,
    0x01a0,      // MSR_IA32_MISC_ENABLE,
    0x2ff,       // MSR_MTRRdefType
];

const MSR_IA32_MISC_ENABLE: u32 = 0x01a0;
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 0x1;

const ECX_INVALID: u32 = 0u32 << 8;
const ECX_THREAD: u32 = 1u32 << 8;
const ECX_CORE: u32 = 2u32 << 8;
const ECX_DIE: u32 = 5u32 << 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum X86RegsIndex {
    Regs,
    Sregs,
    Fpu,
    MpState,
    LapicState,
    MsrEntry,
    VcpuEvents,
    Xsave,
    Xcrs,
    DebugRegs,
}

/// X86 CPU booting configure information
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Clone, Debug)]
pub struct X86CPUBootConfig {
    pub prot64_mode: bool,
    /// Register %rip value
    pub boot_ip: u64,
    /// Register %rsp value
    pub boot_sp: u64,
    /// Boot selector
    pub boot_selector: u16,
    /// zero page address, as the second parameter of __startup_64
    /// arch/x86/kernel/head_64.S:86
    pub zero_page: u64,
    pub code_segment: Segment,
    pub data_segment: Segment,
    pub gdt_base: u64,
    pub gdt_size: u16,
    pub idt_base: u64,
    pub idt_size: u16,
    pub pml4_start: u64,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Copy, Clone, Debug)]
pub struct X86CPUTopology {
    threads: u8,
    cores: u8,
    dies: u8,
}

impl X86CPUTopology {
    pub fn new() -> Self {
        X86CPUTopology::default()
    }

    pub fn set_topology(mut self, toplogy: (u8, u8, u8)) -> Self {
        self.threads = toplogy.0;
        self.cores = toplogy.1;
        self.dies = toplogy.2;
        self
    }
}

/// The state of vCPU's register.
#[allow(clippy::upper_case_acronyms)]
#[repr(C)]
#[derive(Copy, Clone, Desc, ByteCode)]
#[desc_version(compat_version = "0.1.0")]
pub struct X86CPUState {
    max_vcpus: u32,
    nr_threads: u32,
    nr_cores: u32,
    nr_dies: u32,
    nr_sockets: u32,
    pub apic_id: u32,
    pub regs: Regs,
    pub sregs: Sregs,
    pub fpu: Fpu,
    pub mp_state: MpState,
    pub lapic: LapicState,
    pub msr_len: usize,
    pub msr_list: [MsrEntry; 256],
    pub cpu_events: VcpuEvents,
    pub xsave: Xsave,
    pub xcrs: Xcrs,
    pub debugregs: DebugRegs,
}

impl X86CPUState {
    /// Allocates a new `X86CPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    /// * `max_vcpus` - Number of vcpus.
    pub fn new(vcpu_id: u32, max_vcpus: u32) -> Self {
        let mp_state = MpState {
            mp_state: if vcpu_id == 0 {
                MP_STATE_RUNNABLE
            } else {
                MP_STATE_UNINITIALIZED
            },
        };
        X86CPUState {
            apic_id: vcpu_id,
            max_vcpus,
            mp_state,
            nr_threads: 1,
            nr_cores: 1,
            nr_dies: 1,
            nr_sockets: 1,
            ..Default::default()
        }
    }

    pub fn set(&mut self, cpu_state: &Arc<Mutex<X86CPUState>>) {
        let locked_cpu_state = cpu_state.lock().unwrap();
        self.max_vcpus = locked_cpu_state.max_vcpus;
        self.apic_id = locked_cpu_state.apic_id;
        self.regs = locked_cpu_state.regs;
        self.sregs = locked_cpu_state.sregs;
        self.fpu = locked_cpu_state.fpu;
        self.mp_state = locked_cpu_state.mp_state;
        self.lapic = locked_cpu_state.lapic;
        self.msr_len = locked_cpu_state.msr_len;
        self.msr_list = locked_cpu_state.msr_list;
        self.cpu_events = locked_cpu_state.cpu_events;
        self.xsave = locked_cpu_state.xsave;
        self.xcrs = locked_cpu_state.xcrs;
        self.debugregs = locked_cpu_state.debugregs;
    }

    /// Set cpu topology
    ///
    /// # Arguments
    ///
    /// * `topology` - X86 CPU Topology
    pub fn set_cpu_topology(&mut self, topology: &X86CPUTopology) -> Result<()> {
        self.nr_threads = topology.threads as u32;
        self.nr_cores = topology.cores as u32;
        self.nr_dies = topology.dies as u32;
        Ok(())
    }

    pub fn setup_lapic(&mut self, lapic: LapicState) -> Result<()> {
        // Disable nmi and external interrupt before enter protected mode
        // See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/apicdef.h
        const APIC_LVT0: usize = 0x350;
        const APIC_LVT1: usize = 0x360;
        const APIC_MODE_NMI: u32 = 0x4;
        const APIC_MODE_EXTINT: u32 = 0x7;
        const APIC_ID: usize = 0x20;

        self.lapic = lapic;

        // SAFETY: The member regs in struct LapicState is a u8 array with 1024 entries,
        // so it's saft to cast u8 pointer to u32 at position APIC_LVT0 and APIC_LVT1.
        // Safe because all value in this unsafe block is certain.
        unsafe {
            let apic_lvt_lint0 = &mut self.lapic.regs[APIC_LVT0..] as *mut [i8] as *mut u32;
            *apic_lvt_lint0 &= !0x700;
            *apic_lvt_lint0 |= APIC_MODE_EXTINT << 8;

            let apic_lvt_lint1 = &mut self.lapic.regs[APIC_LVT1..] as *mut [i8] as *mut u32;
            *apic_lvt_lint1 &= !0x700;
            *apic_lvt_lint1 |= APIC_MODE_NMI << 8;

            let apic_id = &mut self.lapic.regs[APIC_ID..] as *mut [i8] as *mut u32;
            *apic_id = self.apic_id << 24;
        }

        Ok(())
    }

    pub fn setup_regs(&mut self, boot_config: &X86CPUBootConfig) {
        self.regs = Regs {
            rflags: 0x0002, // Means processor has been initialized
            rip: boot_config.boot_ip,
            rsp: boot_config.boot_sp,
            rbp: boot_config.boot_sp,
            rsi: boot_config.zero_page,
            ..Default::default()
        };
    }

    pub fn setup_sregs(&mut self, sregs: Sregs, boot_config: &X86CPUBootConfig) -> Result<()> {
        self.sregs = sregs;

        self.sregs.cs.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.cs.selector = boot_config.boot_selector;
        self.sregs.ds.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.ds.selector = boot_config.boot_selector;
        self.sregs.es.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.es.selector = boot_config.boot_selector;
        self.sregs.fs.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.fs.selector = boot_config.boot_selector;
        self.sregs.gs.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.gs.selector = boot_config.boot_selector;
        self.sregs.ss.base = (boot_config.boot_selector as u64) << 4;
        self.sregs.ss.selector = boot_config.boot_selector;

        if boot_config.prot64_mode {
            self.set_prot64_sregs(boot_config);
        }

        Ok(())
    }

    pub fn set_prot64_sregs(&mut self, boot_config: &X86CPUBootConfig) {
        // X86_CR0_PE: Protection Enable
        // EFER_LME: Long mode enable
        // EFER_LMA: Long mode active
        // arch/x86/include/uapi/asm/processor-flags.h
        const X86_CR0_PE: u64 = 0x1;
        const EFER_LME: u64 = 0x100;
        const EFER_LMA: u64 = 0x400;

        // X86_CR0_PG: enable Paging
        // X86_CR4_PAE: enable physical address extensions
        // arch/x86/include/uapi/asm/processor-flags.h
        const X86_CR0_PG: u64 = 0x8000_0000;
        const X86_CR4_PAE: u64 = 0x20;

        // Init gdt table, gdt table has loaded to Guest Memory Space
        self.sregs.cs = boot_config.code_segment;
        self.sregs.ds = boot_config.data_segment;
        self.sregs.es = boot_config.data_segment;
        self.sregs.fs = boot_config.data_segment;
        self.sregs.gs = boot_config.data_segment;
        self.sregs.ss = boot_config.data_segment;

        // Init gdt table, gdt table has loaded to Guest Memory Space
        self.sregs.gdt.base = boot_config.gdt_base;
        self.sregs.gdt.limit = boot_config.gdt_size;

        // Init idt table, idt table has loaded to Guest Memory Space
        self.sregs.idt.base = boot_config.idt_base;
        self.sregs.idt.limit = boot_config.idt_size;

        // Open 64-bit protected mode, include
        // Protection enable, Long mode enable, Long mode active
        self.sregs.cr0 |= X86_CR0_PE;
        self.sregs.efer |= EFER_LME | EFER_LMA;

        // Setup page table
        self.sregs.cr3 = boot_config.pml4_start;
        self.sregs.cr4 |= X86_CR4_PAE;
        self.sregs.cr0 |= X86_CR0_PG;
    }

    pub fn setup_fpu(&mut self) {
        // Default value for fxregs_state.mxcsr
        // arch/x86/include/asm/fpu/types.h
        const MXCSR_DEFAULT: u32 = 0x1f80;

        self.fpu = Fpu {
            fcw: 0x37f,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default()
        };
    }

    pub fn setup_msrs(&mut self) {
        // Enable fasting-string operation to improve string
        // store operations.
        for (index, msr) in MSR_LIST.iter().enumerate() {
            let data = match *msr {
                MSR_IA32_MISC_ENABLE => MSR_IA32_MISC_ENABLE_FAST_STRING,
                _ => 0u64,
            };

            self.msr_list[index] = MsrEntry {
                index: *msr,
                data,
                ..Default::default()
            };
            self.msr_len += 1;
        }
    }

    pub fn adjust_cpuid(&self, cpuid: &mut CpuId) -> Result<()> {
        if self.nr_dies < 2 {
            return Ok(());
        }

        // Intel CPU topology with multi-dies support requires CPUID[0x1f].
        let entries = cpuid.as_mut_slice();
        for entry in entries.iter_mut() {
            if entry.function == 0 {
                if entry.eax >= 0x1f {
                    return Ok(());
                } else {
                    entry.eax = 0x1f;
                }
                break;
            }
        }
        for index in 0..4 {
            let entry = CpuidEntry2 {
                function: 0x1f,
                index,
                ..Default::default()
            };
            cpuid.push(entry)?;
        }
        Ok(())
    }

    pub fn setup_cpuid(&self, cpuid: &mut CpuId) -> Result<()> {
        let core_offset = 32u32 - (self.nr_threads - 1).leading_zeros();
        let die_offset = (32u32 - (self.nr_cores - 1).leading_zeros()) + core_offset;
        let pkg_offset = (32u32 - (self.nr_dies - 1).leading_zeros()) + die_offset;
        self.adjust_cpuid(cpuid)?;
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            match entry.function {
                1 => {
                    if entry.index == 0 {
                        entry.ecx |= 1u32 << X86_FEATURE_HYPERVISOR;
                        entry.ecx |= 1u32 << X86_FEATURE_TSC_DEADLINE_TIMER;
                        entry.ebx = self.apic_id << 24 | 8 << 8;
                    }
                }
                2 => {
                    host_cpuid(
                        2,
                        0,
                        &mut entry.eax,
                        &mut entry.ebx,
                        &mut entry.ecx,
                        &mut entry.edx,
                    );
                }
                4 => {
                    // cache info: needed for Pentium Pro compatibility
                    // Passthrough host cache info directly to guest
                    host_cpuid(
                        4,
                        entry.index,
                        &mut entry.eax,
                        &mut entry.ebx,
                        &mut entry.ecx,
                        &mut entry.edx,
                    );
                    entry.eax &= !0xfc00_0000;
                    if entry.eax & 0x0001_ffff != 0 && self.max_vcpus > 1 {
                        entry.eax |= (self.max_vcpus - 1) << 26;
                    }
                }
                6 => {
                    entry.ecx &= !(1u32 << ECX_EPB_SHIFT);
                }
                10 => {
                    if entry.eax != 0 {
                        let version_id = entry.eax & 0xff;
                        let num_counters = entry.eax & 0xff00;
                        if version_id != 2 || num_counters == 0 {
                            entry.eax = 0;
                        }
                    }
                }
                0xb => {
                    // Extended Topology Enumeration Leaf
                    entry.edx = self.apic_id;
                    entry.ecx = entry.index & 0xff;
                    match entry.index {
                        0 => {
                            entry.eax = core_offset;
                            entry.ebx = self.nr_threads;
                            entry.ecx |= ECX_THREAD;
                        }
                        1 => {
                            entry.eax = pkg_offset;
                            entry.ebx = self.nr_threads * self.nr_cores;
                            entry.ecx |= ECX_CORE;
                        }
                        _ => {
                            entry.eax = 0;
                            entry.ebx = 0;
                            entry.ecx |= ECX_INVALID;
                        }
                    }
                }
                0x1f => {
                    if self.nr_dies < 2 {
                        entry.eax = 0;
                        entry.ebx = 0;
                        entry.ecx = 0;
                        entry.edx = 0;
                        continue;
                    }

                    entry.edx = self.apic_id;
                    entry.ecx = entry.index & 0xff;
                    entry.flags = CPUID_FLAG_SIGNIFICANT_INDEX;

                    match entry.index {
                        0 => {
                            entry.eax = core_offset;
                            entry.ebx = self.nr_threads;
                            entry.ecx |= ECX_THREAD;
                        }
                        1 => {
                            entry.eax = die_offset;
                            entry.ebx = self.nr_cores * self.nr_threads;
                            entry.ecx |= ECX_CORE;
                        }
                        2 => {
                            entry.eax = pkg_offset;
                            entry.ebx = self.nr_dies * self.nr_cores * self.nr_threads;
                            entry.ecx |= ECX_DIE;
                        }
                        _ => {
                            entry.eax = 0;
                            entry.ebx = 0;
                            entry.ecx |= ECX_INVALID;
                        }
                    }
                }
                0x8000_0002..=0x8000_0004 => {
                    // Passthrough host cpu model name directly to guest
                    host_cpuid(
                        entry.function,
                        entry.index,
                        &mut entry.eax,
                        &mut entry.ebx,
                        &mut entry.ecx,
                        &mut entry.edx,
                    );
                }
                _ => (),
            }
        }

        Ok(())
    }
}

impl StateTransfer for CPU {
    fn get_state_vec(&self) -> Result<Vec<u8>> {
        let hypervisor_cpu = self.hypervisor_cpu();

        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::MpState)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::Regs)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::Sregs)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::Xsave)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::Fpu)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::Xcrs)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::DebugRegs)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::LapicState)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::MsrEntry)?;
        hypervisor_cpu.get_regs(self.arch_cpu.clone(), X86RegsIndex::VcpuEvents)?;

        Ok(self.arch_cpu.lock().unwrap().as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> Result<()> {
        let cpu_state = *X86CPUState::from_bytes(state)
            .with_context(|| MigrationError::FromBytesError("CPU"))?;

        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();
        *cpu_state_locked = cpu_state;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        MigrationManager::get_desc_alias(&X86CPUState::descriptor().name).unwrap_or(!0)
    }
}

impl MigrationHook for CPU {}
