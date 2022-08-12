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

/// The type of memory layout entry on aarch64
#[cfg(target_arch = "aarch64")]
#[repr(usize)]
pub enum LayoutEntryType {
    GicDist,
    GicCpu,
    GicIts,
    GicRedist,
    Uart,
    Rtc,
    Mmio,
    Mem,
    HighGicRedist,
}

/// Layout of aarch64
#[cfg(target_arch = "aarch64")]
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0801_0000, 0x0001_0000),    // GicCpu
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0900_0000, 0x0000_1000),    // Uart
    (0x0901_0000, 0x0000_1000),    // Rtc
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x4000_0000, 0x80_0000_0000), // Mem
    (256 << 30, 0x200_0000),       // HighGicRedist, (where remaining redistributors locates)
];

/// The type of memory layout entry on x86_64
#[cfg(target_arch = "x86_64")]
#[repr(usize)]
pub enum LayoutEntryType {
    MemBelow4g = 0_usize,
    Mmio,
    IoApic,
    LocalApic,
    MemAbove4g,
}

/// Layout of x86_64
#[cfg(target_arch = "x86_64")]
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0xC000_0000),                // MemBelow4g
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];
