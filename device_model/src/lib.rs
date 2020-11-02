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
