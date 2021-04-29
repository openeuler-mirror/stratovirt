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

mod guest_memory;
mod host_mmap;

pub use guest_memory::GuestMemory;

#[derive(Debug)]
pub enum Error {
    // Overflow occurs when read/write memory, (offset, count, size).
    Overflow(u64, u64, u64),
    // Can not find corresponding HostMemMapping when read/write memory.
    HostMmapNotFound(u64),
    // Failed to mmap.
    Mmap(std::io::Error),
    // IO Error.
    IoError(std::io::Error),
    KvmSetMR(kvm_ioctls::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Overflow(offset, count, size) => write!(
                f,
                "Failed to read/write memory, offset in host_mmap 0x{:x}, count {}, host_mmap size {}",
                offset, count, size
            ),
            Error::HostMmapNotFound(addr) => write!(f, "Failed to find matched HostMemMapping, addr 0x{:x}", addr),
            Error::Mmap(ref e) => write!(
                f,
                "Failed to mmap, error is {}", e
            ),
            Error::IoError(ref e)=> write!(
                f,
                "IO errors occurs when read/write memory, error is {}",
                e
            ),
            Error::KvmSetMR(ref e) => write!(
                f,
                "Failed to set memory region to KVM, error is {}",
                e
            ),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

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

/// The type of memory layout entry on aarch64
#[cfg(target_arch = "aarch64")]
#[repr(usize)]
pub enum LayoutEntryType {
    GicDist,
    GicIts,
    GicRedist,
    Mmio,
    Mem,
}

/// Layout of aarch64
#[cfg(target_arch = "aarch64")]
pub const MEM_LAYOUT: &[(u64, u64)] = &[
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x4000_0000, 0x80_0000_0000), // Mem
];
