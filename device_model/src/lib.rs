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

//! Interfaces for simulating real hardware.
//!
//! This crate simulates:
//! - cpu
//! - interrupt controller (aarch64)
//! - legacy devices, such as serial devices
//! - MMIO bus
//! - devices with virtio support, such as virtio-blk and virtio-net
//! - mainboard for micro VM
//!
//! # Platform support
//!
//! - x86_64
//! - aarch64

#[macro_use]
extern crate log;
#[macro_use]
extern crate vmm_sys_util;
#[macro_use]
extern crate error_chain;
extern crate serde;
#[cfg(target_arch = "aarch64")]
#[macro_use]
extern crate util;
#[macro_use]
extern crate machine_manager;

mod cpu;
mod interrupt_controller;
mod legacy;
mod micro_vm;
mod mmio;
mod virtio;

pub use error_chain::*;
pub use micro_vm::{cmdline, main_loop::MainLoop, micro_syscall::register_seccomp, LightMachine};

use address_space::GuestAddress;

/// Basic device operations
pub trait DeviceOps: Send {
    /// Read function of device.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address of this device.
    /// * `offset` - Offset from base address.
    fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool;
    /// Write function of device.
    ///
    /// # Arguments
    ///
    /// * `data` - A u8-type array.
    /// * `base` - Base address of this device.
    /// * `offset` - Offset from base address.
    fn write(&mut self, data: &[u8], base: GuestAddress, offset: u64) -> bool;
}

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
            Util(util::errors::Error, util::errors::ErrorKind);
            BootLoader(boot_loader::errors::Error, boot_loader::errors::ErrorKind);
            Manager(machine_manager::errors::Error, machine_manager::errors::ErrorKind);
            Cpu(crate::cpu::errors::Error, crate::cpu::errors::ErrorKind);
            Mmio(crate::mmio::errors::Error, crate::mmio::errors::ErrorKind);
        }
        foreign_links {
            Io(std::io::Error);
            Kvm(kvm_ioctls::Error);
            Json(serde_json::Error);
            Nul(std::ffi::NulError);
        }
    }
}

/// The type of memory layout entry on aarch64
#[cfg(target_arch = "aarch64")]
#[repr(usize)]
pub enum LayoutEntryType {
    Flash = 0_usize,
    GicDist,
    GicCpu,
    GicIts,
    GicRedist,
    Uart,
    Rtc,
    FwCfg,
    Mmio,
    PcieMmio,
    PciePio,
    PcieEcam,
    Mem,
    HighGicRedist,
    HighPcieEcam,
    HighPcieMmio,
}

/// Layout of aarch64
#[cfg(target_arch = "aarch64")]
const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0x0800_0000),              // Flash
    (0x0800_0000, 0x0001_0000),    // GicDist
    (0x0801_0000, 0x0001_0000),    // GicCpu
    (0x0808_0000, 0x0002_0000),    // GicIts
    (0x080A_0000, 0x00F6_0000),    // GicRedist (max 123 redistributors)
    (0x0900_0000, 0x0000_1000),    // Uart
    (0x0901_0000, 0x0000_1000),    // Rtc
    (0x0902_0000, 0x0000_0018),    // FwCfg
    (0x0A00_0000, 0x0000_0200),    // Mmio
    (0x1000_0000, 0x2EFF_0000),    // PcieMmio
    (0x3EFF_0000, 0x0001_0000),    // PciePio
    (0x3F00_0000, 0x0100_0000),    // PcieEcam
    (0x4000_0000, 0x80_0000_0000), // Mem
    (256 << 30, 0x200_0000),       // HighGicRedist, (where remaining redistributors locates)
    (257 << 30, 0x1000_0000),      // HighPcieEcam
    (258 << 30, 512 << 30),        // HighPcieMmio
];

/// The type of memory layout entry on x86_64
#[cfg(target_arch = "x86_64")]
#[repr(usize)]
pub enum LayoutEntryType {
    MemBelow4g = 0_usize,
    PcieMmio,
    PcieEcam,
    AcpiGed,
    Mmio,
    IoApic,
    LocalApic,
    MemAbove4g,
}

/// Layout of x86_64
#[cfg(target_arch = "x86_64")]
const MEM_LAYOUT: &[(u64, u64)] = &[
    (0, 0xC000_0000),                // MemBelow4g
    (0xC000_0000, 0x2000_0000),      // PcieMmio
    (0xE000_0000, 0x1000_0000),      // PcieEcam
    (0xF000_0000, 0x10_0000),        // AcpiGed
    (0xF010_0000, 0x200),            // Mmio
    (0xFEC0_0000, 0x10_0000),        // IoApic
    (0xFEE0_0000, 0x10_0000),        // LocalApic
    (0x1_0000_0000, 0x80_0000_0000), // MemAbove4g
];
