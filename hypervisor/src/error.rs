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

use thiserror::Error;

#[allow(clippy::upper_case_acronyms)]
#[derive(Error, Debug)]
pub enum HypervisorError {
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set identity map address.")]
    SetIdentityMapAddr,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set tss address.")]
    SetTssErr,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to create PIT.")]
    CrtPitErr,
    #[error("Failed to create irq chip.")]
    #[cfg(target_arch = "x86_64")]
    CrtIrqchipErr,
    #[error("Failed to create KVM device: {0:#?}.")]
    CreateKvmDevice(kvm_ioctls::Error),
    #[error("No available kvm_mem_slot, total count is {0}")]
    NoAvailKvmSlot(usize),
    #[error("Failed to find matched kvm_mem_slot, addr 0x{0:X}, size 0x{1:X}")]
    NoMatchedKvmSlot(u64, u64),
    #[error("Added KVM mem range (0x{:X}, 0x{:X}) overlaps with exist one (0x{:X}, 0x{:X})", add.0, add.1, exist.0, exist.1)]
    KvmSlotOverlap { add: (u64, u64), exist: (u64, u64) },
}
