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
//! 1. Loading PE (vmlinux.bin) kernel images.
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
//! use boot_loader::{BootLoaderConfig, load_kernel};
//!
//! #[cfg(target_arch="x86_64")]
//! fn main() {
//!     let guest_mem = AddressSpace::new(Region::init_container_region(std::u64::MAX)).unwrap();
//!     let kernel_file = std::path::PathBuf::from("/path/to/my/kernel");
//!     let bootloader_config = BootLoaderConfig {
//!         kernel: kernel_file,
//!         initrd: None,
//!         initrd_size: 0,
//!         kernel_cmdline: String::new(),
//!         cpu_count: 0,
//!     };
//!
//!     let layout = load_kernel(&bootloader_config, &guest_mem).unwrap();
//!     // Now PE linux kernel and kernel cmdline are loaded to guest memory...
//! }
//!
//! #[cfg(target_arch="aarch64")]
//! fn main() {
//!     let guest_mem = AddressSpace::new(Region::init_container_region(u64::MAX)).unwrap();
//!     let kernel_file = std::path::PathBuf::from("/path/to/my/kernel");
//!     let bootloader_config = BootLoaderConfig {
//!         kernel: kernel_file,
//!         initrd: None,
//!         initrd_size: 0,
//!     };
//!
//!     let layout = load_kernel(&bootloader_config, &guest_mem).unwrap();
//!     // Now PE linux kernel is loaded to guest memory...
//! }
//! ```

#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use address_space::{AddressSpace, GuestAddress};

#[cfg(target_arch = "aarch64")]
use aarch64::linux_bootloader;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64BootLoader as BootLoader;
#[cfg(target_arch = "aarch64")]
pub use aarch64::AArch64BootLoaderConfig as BootLoaderConfig;

#[cfg(target_arch = "x86_64")]
use x86_64::linux_bootloader;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86BootLoader as BootLoader;
#[cfg(target_arch = "x86_64")]
pub use x86_64::X86BootLoaderConfig as BootLoaderConfig;

pub mod errors {
    #[cfg(target_arch = "aarch64")]
    use super::aarch64 as arch;
    #[cfg(target_arch = "x86_64")]
    use super::x86_64 as arch;

    error_chain! {
        links {
            ArchErrors(arch::errors::Error, arch::errors::ErrorKind);
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
        }
        errors {
            BootLoaderOpenKernel {
                description("Boot loader open kernel error")
                display("Failed to open kernel image or initrd")
            }
        }
    }
}

use self::errors::{ErrorKind, Result};

/// Load PE(vmlinux.bin) linux kernel to Guest Memory.
///
/// # Arguments
/// * `kernel_file` - host path for kernel.
/// * `kernel_start` - kernel start address in guest memory.
/// * `sys_mem` - guest memory.
///
/// # Errors
/// * `BootLoaderOpenKernel`: Open PE linux kernel failed.
/// * `AddressSpace`: Write PE linux kernel to guest memory failed.
fn load_image(kernel_file: &PathBuf, kernel_start: u64, sys_mem: &Arc<AddressSpace>) -> Result<()> {
    debug!("Loading image {:?}", kernel_file);
    let len = std::fs::metadata(kernel_file).unwrap().len();
    let mut kernel_image = match fs::File::open(kernel_file) {
        Ok(file) => file,
        _ => return Err(ErrorKind::BootLoaderOpenKernel.into()),
    };

    sys_mem.write(&mut kernel_image, GuestAddress(kernel_start), len)?;

    Ok(())
}

/// Load PE(vmlinux.bin) linux kernel and other boot source to Guest Memory.
///
/// # Steps
///
/// 1. Prepare for linux kernel boot env, return guest memory layout.
/// 2. According guest memory layout, load PE linux kernel to guest memory.
/// 3. According guest memory layout, load initrd image to guest memory.
/// 4. For `x86_64` arch, inject cmdline to guest memory.
///
/// # Arguments
///
/// * `config` - boot source config, contains kernel, initrd and kernel
///   cmdline(only `x86_64`).
/// * `sys_mem` - guest memory.
///
/// # Errors
///
/// Load kernel, initrd or kernel cmdline to guest memory failed. Boot source
/// is broken or guest memory is unnormal.
pub fn load_kernel(config: &BootLoaderConfig, sys_mem: &Arc<AddressSpace>) -> Result<BootLoader> {
    let boot_loader = linux_bootloader(config, sys_mem)?;

    load_image(&config.kernel, boot_loader.kernel_start, &sys_mem)?;
    match &config.initrd {
        Some(initrd) => {
            load_image(&initrd, boot_loader.initrd_start, &sys_mem)?;
        }
        None => {}
    };

    #[cfg(target_arch = "x86_64")]
    x86_64::setup_kernel_cmdline(&config, sys_mem)?;

    Ok(boot_loader)
}
