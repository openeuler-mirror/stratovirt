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

use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use crate::helper::device_tree;
use crate::memory::GuestMemory;

const AARCH64_KERNEL_OFFSET: u64 = 0x8_0000;

/// Boot loader config used for aarch64.
#[derive(Default, Debug)]
pub struct AArch64BootLoaderConfig {
    /// Path of kernel image.
    pub kernel: PathBuf,
    /// Path of initrd image.
    pub initrd: PathBuf,
    /// Start address of guest memory.
    pub mem_start: u64,
}

/// The start address for `kernel image`, `initrd image` and `dtb` in guest memory.
pub struct AArch64BootLoader {
    /// Start address for `kernel` execute binary in guest memory.
    pub kernel_start: u64,
    /// Start address for `initrd image` in guest memory.
    pub initrd_start: u64,
    /// Initrd file size, 0 means no initrd file.
    pub initrd_size: u64,
    /// Start address for `dtb` in guest memory.
    pub dtb_start: u64,
}

/// Load PE(vmlinux.bin) linux kernel and other boot source to Guest Memory.
///
/// # Steps
///
/// 1. Prepare for linux kernel boot env, return guest memory layout.
/// 2. According guest memory layout, load linux kernel to guest memory.
/// 3. According guest memory layout, load initrd image to guest memory.
///
/// # Arguments
///
/// * `config` - boot source config, contains kernel, initrd.
/// * `sys_mem` - guest memory.
///
/// # Errors
///
/// Load kernel, initrd to guest memory failed. Boot source is broken or
/// guest memory is abnormal.
pub fn load_kernel(
    config: &AArch64BootLoaderConfig,
    sys_mem: &Arc<GuestMemory>,
) -> AArch64BootLoader {
    let kernel_start = config.mem_start + AARCH64_KERNEL_OFFSET;
    let mut kernel_image = File::open(&config.kernel).expect("Failed to open kernel file");
    let kernel_size = kernel_image.metadata().unwrap().len();
    let kernel_end = kernel_start + kernel_size;
    sys_mem
        .write(&mut kernel_image, kernel_start, kernel_size)
        .expect("Failed to load kernel image to memory");

    let dtb_addr = sys_mem
        .memory_end_address()
        .checked_sub(u64::from(device_tree::FDT_MAX_SIZE))
        .filter(|addr| *addr > kernel_end)
        .expect("no memory to load DTB");

    let mut initrd_image = File::open(&config.initrd).expect("Failed to open initrd file");
    let initrd_size = initrd_image.metadata().unwrap().len();

    let initrd_start = dtb_addr
        .checked_sub(initrd_size)
        .filter(|addr| *addr > kernel_end)
        .expect("No memory to load initrd");

    sys_mem
        .write(&mut initrd_image, initrd_start, initrd_size)
        .expect("Failed to load initrd to memory");

    AArch64BootLoader {
        kernel_start,
        initrd_start,
        initrd_size,
        dtb_start: dtb_addr,
    }
}
