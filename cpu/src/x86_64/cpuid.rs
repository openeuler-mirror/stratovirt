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

use core::arch::x86_64::__cpuid_count;

pub fn host_cpuid(
    leaf: u32,
    subleaf: u32,
    eax: *mut u32,
    ebx: *mut u32,
    ecx: *mut u32,
    edx: *mut u32,
) {
    // SAFETY: cpuid is created in get_supported_cpuid().
    unsafe {
        let cpuid = __cpuid_count(leaf, subleaf);

        *eax = cpuid.eax;
        *ebx = cpuid.ebx;
        *ecx = cpuid.ecx;
        *edx = cpuid.edx;
    }
}
