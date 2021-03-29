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
use std::sync::{Arc, Mutex};

use address_space::{AddressSpace, GuestAddress};
use devices::legacy::FwCfgOps;
use util::device_tree;

use crate::errors::{ErrorKind, Result, ResultExt};

const AARCH64_KERNEL_OFFSET: u64 = 0x8_0000;

/// Boot loader config used for aarch64.
#[derive(Default, Debug)]
pub struct AArch64BootLoaderConfig {
    /// Path of kernel image.
    pub kernel: PathBuf,
    /// Path of initrd image.
    pub initrd: Option<PathBuf>,
    /// Start address of guest memory.
    pub mem_start: u64,
}

/// The start address for `kernel image`, `initrd image` and `dtb` in guest memory.
pub struct AArch64BootLoader {
    /// Start address for `kernel` execute binary in guest memory.
    pub kernel_start: u64,
    /// Start address for `vmlinux` in guest memory.
    pub vmlinux_start: u64,
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
pub fn load_linux(
    config: &AArch64BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
) -> Result<AArch64BootLoader> {
    if fwcfg.is_some() {
        bail!("Failed to load linux: Booting from UEFI is not implemented");
    }

    let kernel_start = config.mem_start + AARCH64_KERNEL_OFFSET;
    let mut kernel_image =
        File::open(&config.kernel).chain_err(|| ErrorKind::BootLoaderOpenKernel)?;
    let kernel_size = kernel_image.metadata().unwrap().len();
    let kernel_end = kernel_start + kernel_size;
    sys_mem.write(&mut kernel_image, GuestAddress(kernel_start), kernel_size)?;

    let dtb_addr = if let Some(addr) = sys_mem
        .memory_end_address()
        .raw_value()
        .checked_sub(u64::from(device_tree::FDT_MAX_SIZE))
        .filter(|addr| addr > &kernel_end)
    {
        addr
    } else {
        return Err(ErrorKind::DTBOverflow(sys_mem.memory_end_address().raw_value()).into());
    };

    let mut initrd_start = 0_u64;
    let mut initrd_size = 0_u64;
    if config.initrd.is_some() {
        let mut initrd_image = File::open(config.initrd.as_ref().unwrap())
            .chain_err(|| ErrorKind::BootLoaderOpenInitrd)?;
        initrd_size = initrd_image.metadata().unwrap().len();

        initrd_start = if let Some(addr) = dtb_addr
            .checked_sub(initrd_size)
            .filter(|addr| addr > &kernel_end)
        {
            addr
        } else {
            return Err(ErrorKind::InitrdOverflow(dtb_addr, initrd_size).into());
        };

        sys_mem.write(&mut initrd_image, GuestAddress(initrd_start), initrd_size)?;
    } else {
        info!("No initrd image file.");
    }

    Ok(AArch64BootLoader {
        kernel_start,
        vmlinux_start: kernel_start,
        initrd_start,
        initrd_size,
        dtb_start: dtb_addr,
    })
}
