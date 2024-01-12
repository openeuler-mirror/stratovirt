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

//! # Boot Loader
//!
//! The crate to initialize memory state during booting VM.
//!
//! ## Design
//!
//! This crate offers support for:
//! 1. Loading PE (vmlinux.bin) kernel images and bzImage kernel images (only in x86_64).
//! 2. Loading initrd image.
//! 3. Initialization for architecture related information.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`
//!
//! ## Examples
//!
//! This example shows how to loading a PE linux kernel with the linux boot
//! protocol before VM start in both x86 and aarch64.
//!
//! ```no_run
//! # extern crate address_space;
//! # extern crate boot_loader;
//!
//! use address_space::{AddressSpace, Region};
//! use boot_loader::{load_linux, BootLoaderConfig};
//!
//! #[cfg(target_arch = "x86_64")]
//! fn main() {
//!     let guest_mem = AddressSpace::new(
//!         Region::init_container_region(std::u64::MAX, "guest_mem"),
//!         "guest_mem",
//!         None,
//!     )
//!     .unwrap();
//!     let kernel_file = std::path::PathBuf::from("/path/to/my/kernel");
//!     let bootloader_config = BootLoaderConfig {
//!         kernel: Some(kernel_file),
//!         initrd: None,
//!         kernel_cmdline: String::new(),
//!         cpu_count: 0,
//!         gap_range: (0xC000_0000, 0x4000_0000),
//!         ioapic_addr: 0xFEC0_0000,
//!         lapic_addr: 0xFEE0_0000,
//!         prot64_mode: true,
//!         ident_tss_range: None,
//!     };
//!
//!     let layout = load_linux(&bootloader_config, &guest_mem, None).unwrap();
//!     // Now PE linux kernel and kernel cmdline are loaded to guest memory...
//! }
//!
//! #[cfg(target_arch = "aarch64")]
//! fn main() {
//!     let guest_mem = AddressSpace::new(
//!         Region::init_container_region(u64::MAX, "guest_mem"),
//!         "guest_mem",
//!         None,
//!     )
//!     .unwrap();
//!     let kernel_file = std::path::PathBuf::from("/path/to/my/kernel");
//!     let bootloader_config = BootLoaderConfig {
//!         kernel: Some(kernel_file),
//!         initrd: None,
//!         mem_start: 0x4000_0000,
//!     };
//!
//!     let layout = load_linux(&bootloader_config, &guest_mem, None).unwrap();
//!     // Now PE linux kernel is loaded to guest memory...
//! }
//! ```

#[allow(clippy::upper_case_acronyms)]
#[cfg(target_arch = "aarch64")]
mod aarch64;
pub mod error;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::load_linux;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64BootLoader as BootLoader;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64BootLoaderConfig as BootLoaderConfig;
pub use error::BootLoaderError;

#[cfg(target_arch = "x86_64")]
pub use x86_64::load_linux;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86BootLoader as BootLoader;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86BootLoaderConfig as BootLoaderConfig;
