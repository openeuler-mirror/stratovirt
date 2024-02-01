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

use std::sync::Arc;

use kvm_bindings::{kvm_msr_entry, Msrs};
use kvm_ioctls::Cap;
use vmm_sys_util::fam::Error;

use crate::CPUHypervisorOps;

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
}

impl X86CPUCaps {
    /// Initialize X86CPUCaps instance.
    pub fn init_capabilities(hypervisor_cpu: Arc<dyn CPUHypervisorOps>) -> Self {
        X86CPUCaps {
            has_xsave: hypervisor_cpu.check_extension(Cap::Xsave),
            has_xcrs: hypervisor_cpu.check_extension(Cap::Xcrs),
            supported_msrs: hypervisor_cpu.get_msr_index_list(),
        }
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
}
