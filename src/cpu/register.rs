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

use kvm_bindings::{
    kvm_fpu, kvm_lapic_state, kvm_mp_state, kvm_msr_entry, kvm_regs, kvm_segment, kvm_sregs, Msrs,
    KVM_MAX_CPUID_ENTRIES, KVM_MP_STATE_RUNNABLE, KVM_MP_STATE_UNINITIALIZED,
};
use kvm_ioctls::{Kvm, VcpuFd};

use crate::helper::cpuid::host_cpuid;

const ECX_EPB_SHIFT: u32 = 3;
const X86_FEATURE_HYPERVISOR: u32 = 31;
const X86_FEATURE_TSC_DEADLINE_TIMER: u32 = 24;

const MSR_IA32_MISC_ENABLE: u32 = 0x01a0;
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 0x1;

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
];

#[derive(Default)]
/// CPU booting configure information
pub struct CPUBootConfig {
    /// Register %rip value
    pub boot_ip: u64,
    /// Register %rsp value
    pub boot_sp: u64,
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

#[derive(Copy, Clone)]
pub struct CPUState {
    nr_vcpus: u32,
    apic_id: u32,
    regs: kvm_regs,
    sregs: kvm_sregs,
    fpu: kvm_fpu,
    mp_state: kvm_mp_state,
    lapic: kvm_lapic_state,
    msr_len: usize,
    msr_list: [kvm_msr_entry; 256],
}

impl CPUState {
    /// Allocates a new `CPUX86State`.
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
        CPUState {
            apic_id: vcpu_id,
            nr_vcpus,
            regs: kvm_regs::default(),
            sregs: kvm_sregs::default(),
            fpu: kvm_fpu::default(),
            mp_state,
            lapic: kvm_lapic_state::default(),
            msr_len: 0,
            msr_list: [kvm_msr_entry::default(); 256],
        }
    }

    /// Set register value in `CPUX86State` according to `boot_config`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.
    /// * `boot_config` - Boot message from boot_loader.
    pub fn set_boot_config(&mut self, vcpu_fd: &VcpuFd, boot_config: &CPUBootConfig) {
        self.setup_lapic(vcpu_fd);
        self.setup_regs(&boot_config);
        self.setup_sregs(vcpu_fd, &boot_config);
        self.setup_fpu();
        self.setup_msrs();
    }

    /// Reset register value in `Kvm` with `CPUX86State`.
    ///
    /// # Arguments
    ///
    /// * `vcpu_fd` - Vcpu file descriptor in kvm.   
    pub fn reset_vcpu(&self, vcpu_fd: &VcpuFd) {
        self.setup_cpuid(vcpu_fd);

        vcpu_fd
            .set_lapic(&self.lapic)
            .expect("Failed to set lapic register");
        vcpu_fd
            .set_mp_state(self.mp_state)
            .expect("Failed to set mpstate register");
        vcpu_fd
            .set_sregs(&self.sregs)
            .expect("Failed to set special register register");
        vcpu_fd
            .set_regs(&self.regs)
            .expect("Failed to set common register register");
        vcpu_fd
            .set_fpu(&self.fpu)
            .expect("Failed to set fpu register");
        vcpu_fd
            .set_msrs(&Msrs::from_entries(&self.msr_list[0..self.msr_len]))
            .expect("Failed to set msrs register");
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn setup_lapic(&mut self, vcpu_fd: &VcpuFd) {
        // Disable nmi and external interrupt before enter protected mode
        // See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/apicdef.h
        const APIC_LVT0: usize = 0x350;
        const APIC_LVT1: usize = 0x360;
        const APIC_MODE_NMI: u32 = 0x4;
        const APIC_MODE_EXTINT: u32 = 0x7;

        self.lapic = vcpu_fd.get_lapic().expect("Failed to get lapic register");

        // The member regs in struct kvm_lapic_state is a u8 array with 1024 entries,
        // so it's saft to cast u8 pointer to u32 at position APIC_LVT0 and APIC_LVT1.
        unsafe {
            let apic_lvt_lint0 = &mut self.lapic.regs[APIC_LVT0..] as *mut [i8] as *mut u32;
            *apic_lvt_lint0 &= !0x700;
            *apic_lvt_lint0 |= APIC_MODE_EXTINT << 8;

            let apic_lvt_lint1 = &mut self.lapic.regs[APIC_LVT1..] as *mut [i8] as *mut u32;
            *apic_lvt_lint1 &= !0x700;
            *apic_lvt_lint1 |= APIC_MODE_NMI << 8;
        }
    }

    fn setup_regs(&mut self, boot_config: &CPUBootConfig) {
        self.regs = kvm_regs {
            rflags: 0x0002, /* Means processor has been initialized */
            rip: boot_config.boot_ip,
            rsp: boot_config.boot_sp,
            rbp: boot_config.boot_sp,
            rsi: boot_config.zero_page,
            ..Default::default()
        };
    }

    fn setup_sregs(&mut self, vcpu_fd: &VcpuFd, boot_config: &CPUBootConfig) {
        self.sregs = vcpu_fd
            .get_sregs()
            .expect("Failed to get spectial register.");

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

    fn setup_cpuid(&self, vcpu_fd: &VcpuFd) {
        let sys_fd = match Kvm::new() {
            Ok(fd) => fd,
            _ => panic!("setup_cpuid: Open /dev/kvm failed"),
        };
        let mut cpuid = sys_fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .expect("Failed to get supported cpuid");
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            match entry.function {
                1 => {
                    if entry.index == 0 {
                        entry.ecx |= 1u32 << X86_FEATURE_HYPERVISOR;
                        entry.ecx |= 1u32 << X86_FEATURE_TSC_DEADLINE_TIMER
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
                            entry.eax = 0u32;
                            entry.ebx = 1u32;
                            entry.ecx |= 1u32 << 8;
                        }
                        1 => {
                            entry.eax = 32u32 - self.nr_vcpus.leading_zeros();
                            entry.ebx = self.nr_vcpus;
                            entry.ecx |= 2u32 << 8;
                        }
                        _ => {
                            entry.ebx = 0xff;
                        }
                    }
                    entry.ebx &= 0xffff;
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

        vcpu_fd.set_cpuid2(&cpuid).expect("Failed to set cpuid2");
    }
}
