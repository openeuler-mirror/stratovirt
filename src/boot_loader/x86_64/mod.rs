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

mod bootparam;
mod gdt;
mod loader;
mod mptable;

use std::fs::File;
use std::io::{Seek, SeekFrom};

pub use loader::{X86BootLoader, X86BootLoaderConfig};

use crate::memory::GuestMemory;
use loader::linux_bootloader;

fn load_image(image: &mut File, start_addr: u64, sys_mem: &GuestMemory) -> std::io::Result<()> {
    let len = image.seek(SeekFrom::End(0))?;
    image.seek(SeekFrom::Start(0))?;

    sys_mem
        .write(image, start_addr, len)
        .map_err(|_| std::io::ErrorKind::InvalidData)?;

    Ok(())
}

pub fn load_kernel(config: &X86BootLoaderConfig, sys_mem: &GuestMemory) -> X86BootLoader {
    let mut kernel_image = File::open(&config.kernel).expect("Invalid guest kernel path");
    let boot_loader = linux_bootloader(config, sys_mem);
    load_image(&mut kernel_image, boot_loader.vmlinux_start, &sys_mem)
        .expect("Failed to write guest kernel to guest memory");

    let mut initrd_image = File::open(&config.initrd).expect("Invalid initrd path");
    load_image(&mut initrd_image, boot_loader.initrd_start, &sys_mem)
        .expect("Failed to write initrd to guest memory");

    loader::setup_kernel_cmdline(&config, sys_mem);

    boot_loader
}
