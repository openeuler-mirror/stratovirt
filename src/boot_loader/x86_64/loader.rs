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

use super::{
    bootparam::{setup_boot_params, EBDA_START},
    gdt::{setup_gdt, BootGdtSegment},
    mptable::setup_isa_mptable,
};
use crate::GuestMemory;

const PDE_START: u64 = 0x0000_b000;
const PDPTE_START: u64 = 0x0000_a000;
const PML4_START: u64 = 0x0000_9000;
const CMDLINE_START: u64 = 0x0002_0000;
const VMLINUX_STARTUP: u64 = 0x0100_0000;
const BOOT_LOADER_SP: u64 = 0x0000_8ff0;
pub const VMLINUX_RAM_START: u64 = 0x0010_0000;

/// Boot loader config used for x86_64.
pub struct X86BootLoaderConfig {
    /// Path of the kernel image.
    pub kernel: PathBuf,
    /// Path of the initrd image.
    pub initrd: PathBuf,
    /// Initrd image size.
    pub initrd_size: u32,
    /// Kernel cmdline parameters.
    pub kernel_cmdline: String,
    /// VM's CPU count.
    pub cpu_count: u8,
    /// (gap start, gap size)
    pub gap_range: (u64, u64),
    /// IO APIC base address
    pub ioapic_addr: u32,
    /// Local APIC base address
    pub lapic_addr: u32,
}

/// The start address for some boot source in guest memory for `x86_64`.
pub struct X86BootLoader {
    pub vmlinux_start: u64,
    pub kernel_start: u64,
    pub kernel_sp: u64,
    pub initrd_start: u64,
    pub boot_pml4_addr: u64,
    pub zero_page_addr: u64,
    pub segments: BootGdtSegment,
}

fn setup_page_table(sys_mem: &GuestMemory) -> std::io::Result<u64> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = PML4_START;
    let boot_pdpte_addr = PDPTE_START;
    let boot_pde_addr = PDE_START;

    // Entry covering VA [0..512GB)
    let pdpte = boot_pdpte_addr | 0x03;
    sys_mem
        .write_object(&pdpte, boot_pml4_addr)
        .map_err(|_| std::io::ErrorKind::InvalidData)?;

    // Entry covering VA [0..1GB)
    let pde = boot_pde_addr | 0x03;
    sys_mem
        .write_object(&pde, boot_pdpte_addr)
        .map_err(|_| std::io::ErrorKind::InvalidData)?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512_u64 {
        let pde = (i << 21) + 0x83_u64;
        sys_mem
            .write_object(&pde, boot_pde_addr + i * 8)
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
    }

    Ok(boot_pml4_addr)
}

pub fn linux_bootloader(boot_config: &X86BootLoaderConfig, sys_mem: &GuestMemory) -> X86BootLoader {
    let (kernel_start, vmlinux_start) = (VMLINUX_STARTUP, VMLINUX_STARTUP);

    let boot_pml4 = setup_page_table(sys_mem).expect("Failed to setup page table");
    setup_isa_mptable(
        sys_mem,
        EBDA_START,
        boot_config.cpu_count,
        boot_config.ioapic_addr,
        boot_config.lapic_addr,
    )
    .expect("Failed to setup isa mptable into guest memory.");

    let (zero_page, initrd_addr) = setup_boot_params(&boot_config, sys_mem);
    let gdt_seg = setup_gdt(sys_mem);

    X86BootLoader {
        kernel_start,
        vmlinux_start,
        kernel_sp: BOOT_LOADER_SP,
        initrd_start: initrd_addr,
        boot_pml4_addr: boot_pml4,
        zero_page_addr: zero_page,
        segments: gdt_seg,
    }
}

pub fn setup_kernel_cmdline(config: &X86BootLoaderConfig, sys_mem: &GuestMemory) {
    let mut cmdline = config.kernel_cmdline.as_bytes();
    sys_mem
        .write(
            &mut cmdline,
            CMDLINE_START,
            config.kernel_cmdline.len() as u64,
        )
        .expect("Failed to write cmdline to guest memory.");
}
