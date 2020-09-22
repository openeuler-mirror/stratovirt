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

use std::path::PathBuf;
use std::sync::Arc;

use self::errors::{ErrorKind, Result};
use address_space::{AddressSpace, GuestAddress};
use util::device_tree;

pub mod errors {
    use util::device_tree;
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
        }
        errors {
            DTBOverflow(size: u64) {
                display(
                    "guest memory size {} should bigger than {}",
                    size,
                    device_tree::FDT_MAX_SIZE
                )
            }
            InitrdOverflow(addr: u64, size: u32) {
                display(
                    "Failed to allocate initrd image {} to memory {}.",
                     size,
                     addr
                )
            }
        }
    }
}

const DRAM_MEM_START: u64 = 0x8000_0000;
const AARCH64_KERNEL_OFFSET: u64 = 0x8_0000;

/// Boot loader config used for aarch64.
#[derive(Default, Debug)]
pub struct AArch64BootLoaderConfig {
    /// Path of kernel image.
    pub kernel: PathBuf,
    /// Path of initrd image.
    pub initrd: Option<PathBuf>,
    /// Initrd file size, 0 means no initrd file.
    pub initrd_size: u32,
}

/// The start address for `kernel image`, `initrd image` and `dtb` in guest memory.
pub struct AArch64BootLoader {
    /// Start address for `kernel image` in guest memory.
    pub kernel_start: u64,
    /// Start address for `initrd image` in guest memory.
    pub initrd_start: u64,
    /// Start address for `dtb` in guest memory.
    pub dtb_start: u64,
}

pub fn linux_bootloader(
    config: &AArch64BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
) -> Result<AArch64BootLoader> {
    let dtb_addr =
        if sys_mem.memory_end_address().raw_value() > u64::from(device_tree::FDT_MAX_SIZE) {
            if let Some(addr) = sys_mem
                .memory_end_address()
                .raw_value()
                .checked_sub(u64::from(device_tree::FDT_MAX_SIZE))
            {
                if sys_mem.address_in_memory(GuestAddress(addr), 0) {
                    addr
                } else {
                    DRAM_MEM_START
                }
            } else {
                0
            }
        } else {
            0
        };

    if dtb_addr == 0 {
        return Err(ErrorKind::DTBOverflow(sys_mem.memory_end_address().raw_value()).into());
    }

    let mut initrd_addr = 0;
    if config.initrd_size > 0 {
        initrd_addr = if let Some(addr) = dtb_addr.checked_sub(u64::from(config.initrd_size)) {
            addr
        } else {
            return Err(ErrorKind::InitrdOverflow(dtb_addr, config.initrd_size).into());
        };

        if !sys_mem.address_in_memory(GuestAddress(initrd_addr), 0) {
            initrd_addr = DRAM_MEM_START + u64::from(device_tree::FDT_MAX_SIZE);
        }
    } else {
        info!("No initrd image file.");
    }

    Ok(AArch64BootLoader {
        kernel_start: DRAM_MEM_START + AARCH64_KERNEL_OFFSET,
        initrd_start: initrd_addr,
        dtb_start: dtb_addr,
    })
}
