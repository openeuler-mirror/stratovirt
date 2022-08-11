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
mod cpuid;

use std::sync::{Arc, Mutex};

use error_chain::bail;
use kvm_bindings::{
    kvm_debugregs, kvm_fpu, kvm_lapic_state, kvm_mp_state, kvm_msr_entry, kvm_regs, kvm_segment,
    kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave, Msrs, KVM_MAX_CPUID_ENTRIES,
    KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_UNINITIALIZED,
};
use kvm_ioctls::{Kvm, VcpuFd};
use migration::{DeviceStateDesc, FieldDesc, MigrationHook, MigrationManager, StateTransfer};
use migration_derive::{ByteCode, Desc};
use util::byte_code::ByteCode;

use self::cpuid::host_cpuid;
use crate::errors::{Result, ResultExt};
use crate::CPU;

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

/// X86 CPU booting configure information
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Clone)]
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
    pub code_segment: kvm_segment,
    pub data_segment: kvm_segment,
    pub gdt_base: u64,
    pub gdt_size: u16,
    pub idt_base: u64,
    pub idt_size: u16,
    pub pml4_start: u64,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Copy, Clone)]
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
    nr_vcpus: u32,
    nr_threads: u32,
    nr_cores: u32,
    nr_dies: u32,
    nr_sockets: u32,
    apic_id: u32,
    regs: kvm_regs,
    sregs: kvm_sregs,
    fpu: kvm_fpu,
    mp_state: kvm_mp_state,
    lapic: kvm_lapic_state,
    msr_len: usize,
    msr_list: [kvm_msr_entry; 256],
    cpu_events: kvm_vcpu_events,
    xsave: kvm_xsave,
    xcrs: kvm_xcrs,
    debugregs: kvm_debugregs,
}

impl X86CPUState {
    /// Allocates a new `X86CPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_id` - ID of this `CPU`.
    /// * `nr_vcpus` - Number of vcpus.
    pub fn new(vcpu_id: u32, nr_vcpus: u32) -> Self {
        let mp_state = kvm_mp_state {
            mp_state: if vcpu_id == 0 {
                KVM_MP_STATE_RUNNABLE
            } else {
                KVM_MP_STATE_UNINITIALIZED
            },
        };
        X86CPUState {
            apic_id: vcpu_id,
            nr_vcpus,
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
        self.nr_vcpus = locked_cpu_state.nr_vcpus;
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

    /// Set register value in `X86CPUState` according to `boot_config`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    /// * `boot_config` - Boot message from boot_loader.
    pub fn set_boot_config(
        &mut self,
        vcpu_fd: &Arc<VcpuFd>,
        boot_config: &X86CPUBootConfig,
    ) -> Result<()> {
        self.setup_lapic(vcpu_fd)?;
        self.setup_regs(boot_config);
        self.setup_sregs(vcpu_fd, boot_config)?;
        self.setup_fpu();
        self.setup_msrs();

        Ok(())
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

    /// Reset register value with `X86CPUState`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    /// * `caps` - Vcpu capabilities in kvm.
    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>, caps: &caps::X86CPUCaps) -> Result<()> {
        self.setup_cpuid(vcpu_fd)
            .chain_err(|| format!("Failed to set cpuid for CPU {}", self.apic_id))?;

        vcpu_fd
            .set_mp_state(self.mp_state)
            .chain_err(|| format!("Failed to set mpstate for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_sregs(&self.sregs)
            .chain_err(|| format!("Failed to set sregs for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_regs(&self.regs)
            .chain_err(|| format!("Failed to set regs for CPU {}", self.apic_id))?;
        if caps.has_xsave {
            vcpu_fd
                .set_xsave(&self.xsave)
                .chain_err(|| format!("Failed to set xsave for CPU {}", self.apic_id))?;
        } else {
            vcpu_fd
                .set_fpu(&self.fpu)
                .chain_err(|| format!("Failed to set fpu for CPU {}", self.apic_id))?;
        }
        if caps.has_xcrs {
            vcpu_fd
                .set_xcrs(&self.xcrs)
                .chain_err(|| format!("Failed to set xcrs for CPU {}", self.apic_id))?;
        }
        vcpu_fd
            .set_debug_regs(&self.debugregs)
            .chain_err(|| format!("Failed to set debug register for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_lapic(&self.lapic)
            .chain_err(|| format!("Failed to set lapic for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_msrs(&Msrs::from_entries(&self.msr_list[0..self.msr_len]).unwrap())
            .chain_err(|| format!("Failed to set msrs for CPU {}", self.apic_id))?;
        vcpu_fd
            .set_vcpu_events(&self.cpu_events)
            .chain_err(|| format!("Failed to set vcpu events for CPU {}", self.apic_id))?;

        Ok(())
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn setup_lapic(&mut self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        // Disable nmi and external interrupt before enter protected mode
        // See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/apicdef.h
        const APIC_LVT0: usize = 0x350;
        const APIC_LVT1: usize = 0x360;
        const APIC_MODE_NMI: u32 = 0x4;
        const APIC_MODE_EXTINT: u32 = 0x7;
        const APIC_ID: usize = 0x20;

        self.lapic = vcpu_fd
            .get_lapic()
            .chain_err(|| format!("Failed to get lapic for CPU {}/KVM", self.apic_id))?;

        // The member regs in struct kvm_lapic_state is a u8 array with 1024 entries,
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

    fn setup_regs(&mut self, boot_config: &X86CPUBootConfig) {
        self.regs = kvm_regs {
            rflags: 0x0002, // Means processor has been initialized
            rip: boot_config.boot_ip,
            rsp: boot_config.boot_sp,
            rbp: boot_config.boot_sp,
            rsi: boot_config.zero_page,
            ..Default::default()
        };
    }

    fn setup_sregs(&mut self, vcpu_fd: &Arc<VcpuFd>, boot_config: &X86CPUBootConfig) -> Result<()> {
        self.sregs = vcpu_fd
            .get_sregs()
            .chain_err(|| format!("Failed to get sregs for CPU {}/KVM", self.apic_id))?;

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

    fn set_prot64_sregs(&mut self, boot_config: &X86CPUBootConfig) {
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

    fn setup_fpu(&mut self) {
        // Default value for fxregs_state.mxcsr
        // arch/x86/include/asm/fpu/types.h
        const MXCSR_DEFAULT: u32 = 0x1f80;

        self.fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default()
        };
    }

    fn setup_msrs(&mut self) {
        // Enable fasting-string operation to improve string
        // store operations.
        for (index, msr) in MSR_LIST.iter().enumerate() {
            let data = match *msr {
                MSR_IA32_MISC_ENABLE => MSR_IA32_MISC_ENABLE_FAST_STRING,
                _ => 0u64,
            };

            self.msr_list[index] = kvm_msr_entry {
                index: *msr,
                data,
                ..Default::default()
            };
            self.msr_len += 1;
        }
    }

    fn setup_cpuid(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        let core_offset = 32u32 - (self.nr_threads - 1).leading_zeros();
        let die_offset = (32u32 - (self.nr_cores - 1).leading_zeros()) + core_offset;
        let pkg_offset = (32u32 - (self.nr_dies - 1).leading_zeros()) + die_offset;
        let sys_fd = match Kvm::new() {
            Ok(fd) => fd,
            _ => bail!("setup_cpuid: Open /dev/kvm failed"),
        };
        let mut cpuid = sys_fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .chain_err(|| format!("Failed to get supported cpuid for CPU {}/KVM", self.apic_id))?;
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
                    if entry.eax & 0x0001_ffff != 0 && self.nr_vcpus > 1 {
                        entry.eax |= (self.nr_vcpus - 1) << 26;
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
                    entry.edx = self.apic_id as u32;
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

                    entry.edx = self.apic_id as u32;
                    entry.ecx = entry.index & 0xff;

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

        vcpu_fd
            .set_cpuid2(&cpuid)
            .chain_err(|| format!("Failed to set cpuid for CPU {}/KVM", self.apic_id))?;
        Ok(())
    }
}

impl StateTransfer for CPU {
    fn get_state_vec(&self) -> migration::errors::Result<Vec<u8>> {
        let mut msr_entries = self.caps.create_msr_entries();
        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();

        cpu_state_locked.mp_state = self.fd.get_mp_state()?;
        cpu_state_locked.regs = self.fd.get_regs()?;
        cpu_state_locked.sregs = self.fd.get_sregs()?;
        if self.caps.has_xsave {
            cpu_state_locked.xsave = self.fd.get_xsave()?;
        } else {
            cpu_state_locked.fpu = self.fd.get_fpu()?;
        }
        if self.caps.has_xcrs {
            cpu_state_locked.xcrs = self.fd.get_xcrs()?;
        }
        cpu_state_locked.debugregs = self.fd.get_debug_regs()?;
        cpu_state_locked.lapic = self.fd.get_lapic()?;
        cpu_state_locked.msr_len = self.fd.get_msrs(&mut msr_entries)?;
        for (i, entry) in msr_entries.as_slice().iter().enumerate() {
            cpu_state_locked.msr_list[i] = *entry;
        }
        cpu_state_locked.cpu_events = self.fd.get_vcpu_events()?;

        Ok(cpu_state_locked.as_bytes().to_vec())
    }

    fn set_state(&self, state: &[u8]) -> migration::errors::Result<()> {
        let cpu_state = *X86CPUState::from_bytes(state)
            .ok_or(migration::errors::ErrorKind::FromBytesError("CPU"))?;

        let mut cpu_state_locked = self.arch_cpu.lock().unwrap();
        *cpu_state_locked = cpu_state;

        Ok(())
    }

    fn get_device_alias(&self) -> u64 {
        if let Some(alias) = MigrationManager::get_desc_alias(&X86CPUState::descriptor().name) {
            alias
        } else {
            !0
        }
    }
}

impl MigrationHook for CPU {}

#[cfg(test)]
mod test {
    use super::*;
    use hypervisor::kvm::{KVMFds, KVM_FDS};
    use kvm_bindings::kvm_segment;
    use serial_test::serial;
    use std::sync::Arc;

    #[test]
    #[serial]
    fn test_x86_64_cpu() {
        let kvm_fds = KVMFds::new();
        if kvm_fds.vm_fd.is_none() {
            return;
        }
        KVM_FDS.store(Arc::new(kvm_fds));

        let code_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 16,
            type_: 11,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let data_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 24,
            type_: 3,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let cpu_config = X86CPUBootConfig {
            prot64_mode: true,
            boot_ip: 0,
            boot_sp: 0,
            boot_selector: 0,
            zero_page: 0x0000_7000,
            code_segment: code_seg,
            data_segment: data_seg,
            gdt_base: 0x500u64,
            gdt_size: 16,
            idt_base: 0x520u64,
            idt_size: 8,
            pml4_start: 0x0000_9000,
        };

        // For `get_lapic` in realize function to work,
        // you need to create a irq_chip for VM before creating the VCPU.
        let kvm_fds = KVM_FDS.load();
        let vm_fd = kvm_fds.vm_fd.as_ref().unwrap();
        vm_fd.create_irq_chip().unwrap();
        let vcpu = Arc::new(vm_fd.create_vcpu(0).unwrap());
        let mut x86_cpu = X86CPUState::new(0, 1);
        //test `set_boot_config` function
        assert!(x86_cpu.set_boot_config(&vcpu, &cpu_config).is_ok());

        // test setup special registers
        let cpu_caps = caps::X86CPUCaps::init_capabilities();
        assert!(x86_cpu.reset_vcpu(&vcpu, &cpu_caps).is_ok());
        let x86_sregs = vcpu.get_sregs().unwrap();
        assert_eq!(x86_sregs.cs, code_seg);
        assert_eq!(x86_sregs.ds, data_seg);
        assert_eq!(x86_sregs.es, data_seg);
        assert_eq!(x86_sregs.fs, data_seg);
        assert_eq!(x86_sregs.gs, data_seg);
        assert_eq!(x86_sregs.ss, data_seg);
        assert_eq!(x86_sregs.gdt.base, cpu_config.gdt_base);
        assert_eq!(x86_sregs.gdt.limit, cpu_config.gdt_size);
        assert_eq!(x86_sregs.idt.base, cpu_config.idt_base);
        assert_eq!(x86_sregs.idt.limit, cpu_config.idt_size);
        assert_eq!(x86_sregs.cr0 & 0x1, 1);
        assert_eq!((x86_sregs.cr0 & 0x8000_0000) >> 31, 1);
        assert_eq!(x86_sregs.cr3, cpu_config.pml4_start);
        assert_eq!((x86_sregs.cr4 & 0x20) >> 5, 1);
        assert_eq!((x86_sregs.efer & 0x700) >> 8, 5);

        // test setup_regs function
        let x86_regs = vcpu.get_regs().unwrap();
        assert_eq!(x86_regs.rflags, 0x0002);
        assert_eq!(x86_regs.rip, 0);
        assert_eq!(x86_regs.rsp, 0);
        assert_eq!(x86_regs.rbp, 0);
        assert_eq!(x86_regs.rsi, 0x0000_7000);

        // test setup_fpu function
        if !cpu_caps.has_xsave {
            let x86_fpu = vcpu.get_fpu().unwrap();
            assert_eq!(x86_fpu.fcw, 0x37f);
        }
    }
}
