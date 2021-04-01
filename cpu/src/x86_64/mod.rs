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

use std::sync::Arc;

use kvm_bindings::{
    kvm_fpu, kvm_msr_entry, kvm_regs, kvm_segment, kvm_sregs, Msrs, KVM_MAX_CPUID_ENTRIES,
};
use kvm_ioctls::{Kvm, VcpuFd};

use crate::errors::{Result, ResultExt};
use cpuid::host_cpuid;

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
];

const MSR_IA32_MISC_ENABLE: u32 = 0x01a0;
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 0x1;

#[derive(Default)]
/// X86 CPU booting configure information
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

#[derive(Default, Copy, Clone)]
pub struct X86CPU {
    id: u32,
    nr_vcpus: u32,
    prot64_mode: bool,
    boot_selector: u16,
    boot_ip: u64,
    boot_sp: u64,
    zero_page: u64,
    code_segment: kvm_segment,
    data_segment: kvm_segment,
    gdt_base: u64,
    gdt_size: u16,
    idt_base: u64,
    idt_size: u16,
    pml4_start: u64,
}

impl X86CPU {
    pub fn new(vcpuid: u32, nr_vcpus: u32) -> Self {
        X86CPU {
            id: vcpuid,
            nr_vcpus,
            ..Default::default()
        }
    }

    pub fn realize(&mut self, vcpu_fd: &Arc<VcpuFd>, boot_config: &X86CPUBootConfig) -> Result<()> {
        self.prot64_mode = boot_config.prot64_mode;
        self.boot_selector = boot_config.boot_selector;
        self.boot_ip = boot_config.boot_ip;
        self.boot_sp = boot_config.boot_sp;
        self.zero_page = boot_config.zero_page;
        self.code_segment = boot_config.code_segment;
        self.data_segment = boot_config.data_segment;
        self.gdt_base = boot_config.gdt_base;
        self.gdt_size = boot_config.gdt_size;
        self.idt_base = boot_config.idt_base;
        self.idt_size = boot_config.idt_size;
        self.pml4_start = boot_config.pml4_start;

        // Only setting vcpu lapic state, other registers should
        // reset when the vcpu start running.
        self.setup_lapic(vcpu_fd)
            .chain_err(|| format!("Failed to set lapic for CPU {}/KVM", self.id))?;

        Ok(())
    }

    fn setup_cpuid(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        let sys_fd = match Kvm::new() {
            Ok(fd) => fd,
            _ => bail!("setup_cpuid:Open /dev/kvm failed"),
        };
        let mut cpuid = sys_fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .chain_err(|| format!("Failed to get supported cpuid for CPU {}/KVM", self.id))?;
        let entries = cpuid.as_mut_slice();

        for entry in entries.iter_mut() {
            match entry.function {
                1 => {
                    if entry.index == 0 {
                        entry.ecx |= 1u32 << X86_FEATURE_HYPERVISOR;
                        entry.ecx |= 1u32 << X86_FEATURE_TSC_DEADLINE_TIMER;
                        entry.ebx = self.id << 24 | 8 << 8;
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
                    entry.edx = self.id as u32;
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

        vcpu_fd.set_cpuid2(&cpuid)?;
        Ok(())
    }

    fn set_prot64_sregs(&self, sregs: &mut kvm_sregs) {
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
        sregs.cs = self.code_segment;
        sregs.ds = self.data_segment;
        sregs.es = self.data_segment;
        sregs.fs = self.data_segment;
        sregs.gs = self.data_segment;
        sregs.ss = self.data_segment;

        // Init gdt table, gdt table has loaded to Guest Memory Space
        sregs.gdt.base = self.gdt_base;
        sregs.gdt.limit = self.gdt_size;

        // Init idt table, idt table has loaded to Guest Memory Space
        sregs.idt.base = self.idt_base;
        sregs.idt.limit = self.idt_size;

        // Open 64-bit protected mode, include
        // Protection enable, Long mode enable, Long mode active
        sregs.cr0 |= X86_CR0_PE;
        sregs.efer |= EFER_LME | EFER_LMA;

        // Setup page table
        sregs.cr3 = self.pml4_start;
        sregs.cr4 |= X86_CR4_PAE;
        sregs.cr0 |= X86_CR0_PG;
    }

    fn setup_sregs(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        let mut sregs: kvm_sregs = vcpu_fd
            .get_sregs()
            .chain_err(|| format!("Failed to get sregs for CPU {}/KVM", self.id))?;

        sregs.cs.base = (self.boot_selector as u64) << 4;
        sregs.cs.selector = self.boot_selector;
        sregs.ds.base = (self.boot_selector as u64) << 4;
        sregs.ds.selector = self.boot_selector;
        sregs.es.base = (self.boot_selector as u64) << 4;
        sregs.es.selector = self.boot_selector;
        sregs.fs.base = (self.boot_selector as u64) << 4;
        sregs.fs.selector = self.boot_selector;
        sregs.gs.base = (self.boot_selector as u64) << 4;
        sregs.gs.selector = self.boot_selector;
        sregs.ss.base = (self.boot_selector as u64) << 4;
        sregs.ss.selector = self.boot_selector;

        if self.prot64_mode {
            self.set_prot64_sregs(&mut sregs);
        }

        vcpu_fd.set_sregs(&sregs)?;

        Ok(())
    }

    #[allow(clippy::cast_ptr_alignment)]
    fn setup_lapic(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        // Disable nmi and external interrupt before enter protected mode
        // arch/x86/include/asm/apicdef.h
        // local_apic struct like:
        // struct local_apic {
        //     /*350*/  struct { /* LVT - LINT0 */
        //     u32   vector        :  8,
        //        delivery_mode   :  3,
        //        __reserved_1    :  1,
        //        delivery_status :  1,
        //        polarity    :  1,
        //        remote_irr  :  1,
        //        trigger     :  1,
        //        mask        :  1,
        //        __reserved_2    : 15;
        //        u32 __reserved_3[3];
        //    } lvt_lint0;
        //
        //    /*360*/ struct { /* LVT - LINT1 */
        //        u32   vector        :  8,
        //        delivery_mode   :  3,
        //        __reserved_1    :  1,
        //        delivery_status :  1,
        //        polarity    :  1,
        //        remote_irr  :  1,
        //        trigger     :  1,
        //        mask        :  1,
        //        __reserved_2    : 15;
        //        u32 __reserved_3[3];
        //    } lvt_lint1;
        // }
        //
        // #define     GET_APIC_DELIVERY_MODE(x)   (((x) >> 8) & 0x7)
        // #define     SET_APIC_DELIVERY_MODE(x, y)    (((x) & ~0x700) | ((y) << 8))
        const APIC_LVT0: usize = 0x350;
        const APIC_LVT1: usize = 0x360;
        const APIC_MODE_NMI: u32 = 0x4;
        const APIC_MODE_EXTINT: u32 = 0x7;

        let mut lapic = vcpu_fd
            .get_lapic()
            .chain_err(|| format!("Failed to get lapic for CPU {}/KVM", self.id))?;

        // The member regs in struct kvm_lapic_state is a u8 array with 1024 entries,
        // so it's saft to cast u8 pointer to u32 at position APIC_LVT0 and APIC_LVT1.
        unsafe {
            let apic_lvt_lint0 = &mut lapic.regs[APIC_LVT0..] as *mut [i8] as *mut u32;
            *apic_lvt_lint0 &= !0x700;
            *apic_lvt_lint0 |= APIC_MODE_EXTINT << 8;

            let apic_lvt_lint1 = &mut lapic.regs[APIC_LVT1..] as *mut [i8] as *mut u32;
            *apic_lvt_lint1 &= !0x700;
            *apic_lvt_lint1 |= APIC_MODE_NMI << 8;
        }

        vcpu_fd
            .set_lapic(&lapic)
            .chain_err(|| format!("Failed to set lapic for CPU {}/KVM", self.id))?;

        Ok(())
    }

    fn setup_regs(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        let mut regs: kvm_regs = kvm_regs {
            rflags: 0x0002, /* Means processor has been initialized */
            rip: self.boot_ip,
            rsp: self.boot_sp,
            rbp: self.boot_sp,
            ..Default::default()
        };
        if self.prot64_mode {
            regs.rsi = self.zero_page;
        }

        vcpu_fd.set_regs(&regs)?;

        Ok(())
    }

    fn setup_fpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        // Default value for fxregs_state.mxcsr
        // arch/x86/include/asm/fpu/types.h
        const MXCSR_DEFAULT: u32 = 0x1f80;

        let fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: MXCSR_DEFAULT,
            ..Default::default()
        };

        vcpu_fd.set_fpu(&fpu)?;

        Ok(())
    }

    fn setup_msrs(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        let mut entries = Vec::<kvm_msr_entry>::new();

        // Enable fast-string operation to improve string
        // store operations.
        for msr in MSR_LIST {
            let data = match *msr {
                MSR_IA32_MISC_ENABLE => MSR_IA32_MISC_ENABLE_FAST_STRING,
                _ => 0u64,
            };

            entries.push(kvm_msr_entry {
                index: *msr,
                data,
                ..Default::default()
            });
        }

        debug!("pushed msr entries[{:?}] {:?}", entries.len(), entries);

        vcpu_fd.set_msrs(&Msrs::from_entries(&entries))?;

        Ok(())
    }

    pub fn reset_vcpu(&self, vcpu_fd: &Arc<VcpuFd>) -> Result<()> {
        self.setup_cpuid(vcpu_fd)
            .chain_err(|| format!("Failed to set cpuid for CPU {}", self.id))?;
        self.setup_sregs(vcpu_fd)
            .chain_err(|| format!("Failed to set sregs for CPU {}/KVM", self.id))?;
        self.setup_regs(vcpu_fd)
            .chain_err(|| format!("Failed to set regs for CPU {}/KVM", self.id))?;
        self.setup_fpu(vcpu_fd)
            .chain_err(|| format!("Failed to set fpu for CPU {}/KVM", self.id))?;
        self.setup_msrs(vcpu_fd)
            .chain_err(|| format!("Failed to set Msrs for CPU {}/KVM", self.id))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hypervisor::{KVMFds, KVM_FDS};
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
        let mut x86_cpu = X86CPU::new(0, 1);
        //test realize function
        assert!(x86_cpu.realize(&vcpu, &cpu_config).is_ok());

        //test setup special registers
        assert!(x86_cpu.setup_sregs(&vcpu).is_ok());
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

        //test setup_regs function
        assert!(x86_cpu.setup_regs(&vcpu).is_ok());
        let x86_regs = vcpu.get_regs().unwrap();
        assert_eq!(x86_regs.rflags, 0x0002);
        assert_eq!(x86_regs.rip, 0);
        assert_eq!(x86_regs.rsp, 0);
        assert_eq!(x86_regs.rbp, 0);
        assert_eq!(x86_regs.rsi, 0x0000_7000);

        //test setup_fpu function
        assert!(x86_cpu.setup_fpu(&vcpu).is_ok());
        let x86_fpu = vcpu.get_fpu().unwrap();
        assert_eq!(x86_fpu.fcw, 0x37f);

        //test setup_msrs function
        assert!(x86_cpu.setup_msrs(&vcpu).is_ok());

        //test setup_cpuid function
        assert!(x86_cpu.setup_cpuid(&vcpu).is_ok());
    }
}
