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

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use kvm_bindings::*;
use kvm_ioctls::Kvm;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

use crate::kvm::listener::KvmIoListener;
use crate::kvm::{KvmCpu, KvmHypervisor};
use crate::HypervisorError;
use address_space::Listener;
use cpu::{ArchCPU, CPUBootConfig, RegsIndex, CPU};

// See: https://elixir.bootlin.com/linux/v4.19.123/source/include/uapi/linux/kvm.h
ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, KVMIO, 0x05, kvm_cpuid2);
ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
ioctl_iow_nr!(KVM_SET_XSAVE, KVMIO, 0xa5, kvm_xsave);
ioctl_iow_nr!(KVM_SET_XCRS, KVMIO, 0xa7, kvm_xcrs);
ioctl_iow_nr!(KVM_SET_DEBUGREGS, KVMIO, 0xa2, kvm_debugregs);
ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);
ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
ioctl_ior_nr!(KVM_GET_PIT2, KVMIO, 0x9f, kvm_pit_state2);
ioctl_ior_nr!(KVM_GET_XSAVE, KVMIO, 0xa4, kvm_xsave);
ioctl_ior_nr!(KVM_GET_XCRS, KVMIO, 0xa6, kvm_xcrs);
ioctl_ior_nr!(KVM_GET_DEBUGREGS, KVMIO, 0xa1, kvm_debugregs);
ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);

impl KvmHypervisor {
    pub fn arch_init(&self) -> Result<()> {
        // The identity_addr is set in the memory layout of x86 machine.
        let identity_addr: u64 = 0xFEF0_C000;
        let vm_fd = self.vm_fd.as_ref().unwrap();

        vm_fd
            .set_identity_map_address(identity_addr)
            .with_context(|| HypervisorError::SetIdentityMapAddr)?;

        // Page table takes 1 page, TSS takes the following 3 pages.
        vm_fd
            .set_tss_address((identity_addr + 0x1000) as usize)
            .with_context(|| HypervisorError::SetTssErr)?;

        let pit_config = kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            pad: Default::default(),
        };
        vm_fd
            .create_pit2(pit_config)
            .with_context(|| HypervisorError::CrtPitErr)
    }

    pub fn create_io_listener(&self) -> Arc<Mutex<dyn Listener>> {
        Arc::new(Mutex::new(KvmIoListener::new(self.vm_fd.clone())))
    }
}

impl KvmCpu {
    pub fn arch_init_pmu(&self) -> Result<()> {
        Ok(())
    }

    pub fn arch_vcpu_init(&self) -> Result<()> {
        Ok(())
    }

    pub fn arch_set_boot_config(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        boot_config: &CPUBootConfig,
    ) -> Result<()> {
        let mut locked_arch_cpu = arch_cpu.lock().unwrap();
        let apic_id = locked_arch_cpu.apic_id;
        let lapic = self
            .fd
            .get_lapic()
            .with_context(|| format!("Failed to get lapic for CPU {}/KVM", apic_id))?;
        locked_arch_cpu.setup_lapic(lapic)?;
        locked_arch_cpu.setup_regs(boot_config);
        let sregs = self
            .fd
            .get_sregs()
            .with_context(|| format!("Failed to get sregs for CPU {}/KVM", apic_id))?;
        locked_arch_cpu.setup_sregs(sregs, boot_config)?;
        locked_arch_cpu.setup_fpu();
        locked_arch_cpu.setup_msrs();

        Ok(())
    }

    pub fn arch_get_one_reg(&self, _reg_id: u64) -> Result<u128> {
        Ok(0)
    }

    pub fn arch_get_regs(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        regs_index: RegsIndex,
    ) -> Result<()> {
        let mut msr_entries = self.caps.create_msr_entries()?;
        let mut locked_arch_cpu = arch_cpu.lock().unwrap();
        match regs_index {
            RegsIndex::Regs => {
                locked_arch_cpu.regs = self.fd.get_regs()?;
            }
            RegsIndex::Sregs => {
                locked_arch_cpu.sregs = self.fd.get_sregs()?;
            }
            RegsIndex::Fpu => {
                if !self.caps.has_xsave {
                    locked_arch_cpu.fpu = self.fd.get_fpu()?;
                }
            }
            RegsIndex::MpState => {
                locked_arch_cpu.mp_state = self.fd.get_mp_state()?;
            }
            RegsIndex::LapicState => {
                locked_arch_cpu.lapic = self.fd.get_lapic()?;
            }
            RegsIndex::MsrEntry => {
                locked_arch_cpu.msr_len = self.fd.get_msrs(&mut msr_entries)?;
                for (i, entry) in msr_entries.as_slice().iter().enumerate() {
                    locked_arch_cpu.msr_list[i] = *entry;
                }
            }
            RegsIndex::VcpuEvents => {
                locked_arch_cpu.cpu_events = self.fd.get_vcpu_events()?;
            }
            RegsIndex::Xsave => {
                if self.caps.has_xsave {
                    locked_arch_cpu.xsave = self.fd.get_xsave()?;
                }
            }
            RegsIndex::Xcrs => {
                if self.caps.has_xcrs {
                    locked_arch_cpu.xcrs = self.fd.get_xcrs()?;
                }
            }
            RegsIndex::DebugRegs => {
                locked_arch_cpu.debugregs = self.fd.get_debug_regs()?;
            }
        }

        Ok(())
    }

    pub fn arch_set_regs(
        &self,
        arch_cpu: Arc<Mutex<ArchCPU>>,
        regs_index: RegsIndex,
    ) -> Result<()> {
        let locked_arch_cpu = arch_cpu.lock().unwrap();
        let apic_id = locked_arch_cpu.apic_id;
        match regs_index {
            RegsIndex::Regs => {
                self.fd
                    .set_regs(&locked_arch_cpu.regs)
                    .with_context(|| format!("Failed to set regs for CPU {}", apic_id))?;
            }
            RegsIndex::Sregs => {
                self.fd
                    .set_sregs(&locked_arch_cpu.sregs)
                    .with_context(|| format!("Failed to set sregs for CPU {}", apic_id))?;
            }
            RegsIndex::Fpu => {
                self.fd
                    .set_fpu(&locked_arch_cpu.fpu)
                    .with_context(|| format!("Failed to set fpu for CPU {}", apic_id))?;
            }
            RegsIndex::MpState => {
                self.fd
                    .set_mp_state(locked_arch_cpu.mp_state)
                    .with_context(|| format!("Failed to set mpstate for CPU {}", apic_id))?;
            }
            RegsIndex::LapicState => {
                self.fd
                    .set_lapic(&locked_arch_cpu.lapic)
                    .with_context(|| format!("Failed to set lapic for CPU {}", apic_id))?;
            }
            RegsIndex::MsrEntry => {
                self.fd
                    .set_msrs(&Msrs::from_entries(
                        &locked_arch_cpu.msr_list[0..locked_arch_cpu.msr_len],
                    )?)
                    .with_context(|| format!("Failed to set msrs for CPU {}", apic_id))?;
            }
            RegsIndex::VcpuEvents => {
                self.fd
                    .set_vcpu_events(&locked_arch_cpu.cpu_events)
                    .with_context(|| format!("Failed to set vcpu events for CPU {}", apic_id))?;
            }
            RegsIndex::Xsave => {
                self.fd
                    .set_xsave(&locked_arch_cpu.xsave)
                    .with_context(|| format!("Failed to set xsave for CPU {}", apic_id))?;
            }
            RegsIndex::Xcrs => {
                self.fd
                    .set_xcrs(&locked_arch_cpu.xcrs)
                    .with_context(|| format!("Failed to set xcrs for CPU {}", apic_id))?;
            }
            RegsIndex::DebugRegs => {
                self.fd
                    .set_debug_regs(&locked_arch_cpu.debugregs)
                    .with_context(|| format!("Failed to set debug register for CPU {}", apic_id))?;
            }
        }

        Ok(())
    }

    pub fn arch_put_register(&self, cpu: Arc<CPU>) -> Result<()> {
        let locked_arch_cpu = cpu.arch_cpu.lock().unwrap();
        let apic_id = locked_arch_cpu.apic_id;

        let sys_fd = match Kvm::new() {
            Ok(fd) => fd,
            _ => bail!("setup_cpuid: Open /dev/kvm failed"),
        };
        let mut cpuid = sys_fd
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .with_context(|| format!("Failed to get supported cpuid for CPU {}/KVM", apic_id))?;

        locked_arch_cpu
            .setup_cpuid(&mut cpuid)
            .with_context(|| format!("Failed to set cpuid for CPU {}", apic_id))?;

        self.fd
            .set_cpuid2(&cpuid)
            .with_context(|| format!("Failed to set cpuid for CPU {}/KVM", apic_id))?;

        self.fd
            .set_mp_state(locked_arch_cpu.mp_state)
            .with_context(|| format!("Failed to set mpstate for CPU {}", apic_id))?;
        self.fd
            .set_sregs(&locked_arch_cpu.sregs)
            .with_context(|| format!("Failed to set sregs for CPU {}", apic_id))?;
        self.fd
            .set_regs(&locked_arch_cpu.regs)
            .with_context(|| format!("Failed to set regs for CPU {}", apic_id))?;
        if self.caps.has_xsave {
            self.fd
                .set_xsave(&locked_arch_cpu.xsave)
                .with_context(|| format!("Failed to set xsave for CPU {}", apic_id))?;
        } else {
            self.fd
                .set_fpu(&locked_arch_cpu.fpu)
                .with_context(|| format!("Failed to set fpu for CPU {}", apic_id))?;
        }
        if self.caps.has_xcrs {
            self.fd
                .set_xcrs(&locked_arch_cpu.xcrs)
                .with_context(|| format!("Failed to set xcrs for CPU {}", apic_id))?;
        }
        self.fd
            .set_debug_regs(&locked_arch_cpu.debugregs)
            .with_context(|| format!("Failed to set debug register for CPU {}", apic_id))?;
        self.fd
            .set_lapic(&locked_arch_cpu.lapic)
            .with_context(|| format!("Failed to set lapic for CPU {}", apic_id))?;
        self.fd
            .set_msrs(&Msrs::from_entries(
                &locked_arch_cpu.msr_list[0..locked_arch_cpu.msr_len],
            )?)
            .with_context(|| format!("Failed to set msrs for CPU {}", apic_id))?;
        self.fd
            .set_vcpu_events(&locked_arch_cpu.cpu_events)
            .with_context(|| format!("Failed to set vcpu events for CPU {}", apic_id))?;

        Ok(())
    }

    pub fn arch_reset_vcpu(&self, cpu: Arc<CPU>) -> Result<()> {
        cpu.arch_cpu.lock().unwrap().set(&cpu.boot_state());
        self.arch_put_register(cpu)
    }
}
