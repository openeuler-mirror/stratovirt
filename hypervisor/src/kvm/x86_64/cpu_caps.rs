// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{bail, Context, Result};
use kvm_bindings::{kvm_msr_entry, CpuId, Msrs, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::Cap;
use kvm_ioctls::Kvm;
use vmm_sys_util::fam::Error;

/// KVM capabilities the x86 machine cannot run without.
const REQUIRED_CAPS: [Cap; 13] = [
    Cap::AdjustClock,        // KVM_GET/SET_CLOCK for migration.
    Cap::ExtCpuid,           // KVM_GET_SUPPORTED_CPUID for CPUID setup.
    Cap::ImmediateExit,      // KVM_RUN immediate exit for vCPU pause.
    Cap::Ioeventfd,          // ioeventfd offload for virtio notifications.
    Cap::Irqchip,            // In-kernel PIC/IOAPIC/LAPIC.
    Cap::Irqfd,              // irqfd for MSI-X interrupt injection.
    Cap::IrqRouting,         // GSI routing table for irqfd/MSI.
    Cap::MpState,            // KVM_GET/SET_MP_STATE for vCPU lifecycle.
    Cap::Pit2,               // In-kernel PIT created by arch_init.
    Cap::SetIdentityMapAddr, // arch_init identity map setup.
    Cap::SetTssAddr,         // arch_init TSS setup.
    Cap::UserMemory,         // KVM_SET_USER_MEMORY_REGION for guest memory.
    Cap::VcpuEvents,         // KVM_GET/SET_VCPU_EVENTS for migration.
];

/// See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/msr-index.h#L558
const MSR_IA32_MISC_ENABLE: ::std::os::raw::c_uint = 0x1a0;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/msr-index.h#L597
const MSR_IA32_MISC_ENABLE_FAST_STRING: ::std::os::raw::c_uint = 0x1;
/// Intel VT MSRs
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/msr-index.h#L777
const MSR_IA32_VMX_BASIC: ::std::os::raw::c_uint = 0x480;
/// See: https://elixir.bootlin.com/linux/v4.19.123/source/arch/x86/include/asm/msr-index.h#L794
const MSR_IA32_VMX_VMFUNC: ::std::os::raw::c_uint = 0x491;

/// Capabilities for x86 cpu.
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone)]
pub struct X86CPUCaps {
    pub has_xsave: bool,
    pub has_xcrs: bool,
    supported_msrs: Vec<u32>,
    supported_cpuid: CpuId,
}

impl X86CPUCaps {
    /// Preflight the KVM capabilities required by the x86 machine.
    pub fn check_required_extensions(kvm: &Kvm) -> Result<()> {
        for cap in REQUIRED_CAPS {
            if !kvm.check_extension(cap) {
                bail!("KVM capability {cap:?} is required for x86_64");
            }
        }
        Ok(())
    }

    /// Initialize X86CPUCaps instance.
    pub fn init_capabilities(kvm: &Kvm) -> Result<Self> {
        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .with_context(|| "Failed to get supported CPUID")?;

        Ok(X86CPUCaps {
            has_xsave: kvm.check_extension(Cap::Xsave),
            has_xcrs: kvm.check_extension(Cap::Xcrs),
            supported_msrs: kvm
                .get_msr_index_list()
                .with_context(|| "Failed to get supported MSR list")?
                .as_slice()
                .to_vec(),
            supported_cpuid,
        })
    }

    /// Create `Msrs` (a list of `kvm_msr_entry`) from capabilities supported_msrs.
    pub fn create_msr_entries(&self) -> Result<Msrs, Error> {
        let entry_vec: Vec<kvm_msr_entry> = self
            .supported_msrs
            .iter()
            // Intel VT MSRs is not necessary.
            .filter(|msr_support| {
                **msr_support < MSR_IA32_VMX_BASIC || **msr_support > MSR_IA32_VMX_VMFUNC
            })
            .map(|msr_support| {
                let data = match *msr_support {
                    MSR_IA32_MISC_ENABLE => u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
                    _ => 0u64,
                };
                kvm_msr_entry {
                    index: *msr_support,
                    data,
                    ..Default::default()
                }
            })
            .collect();
        Msrs::from_entries(&entry_vec)
    }

    pub fn supported_cpuid(&self) -> CpuId {
        self.supported_cpuid.clone()
    }
}
