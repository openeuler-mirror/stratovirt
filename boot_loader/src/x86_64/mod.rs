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

//! Boot Loader load PE and bzImage linux kernel image to guest memory according
//! [`x86 boot protocol`](https://www.kernel.org/doc/Documentation/x86/boot.txt).
//!
//! Below is x86_64 bootloader memory layout:
//!
//! ``` text
//!                 +------------------------+
//!   0x0000_0000   |  Real Mode IVT         |
//!                 |                        |
//!                 +------------------------+
//!   0x0000_7000   |                        |
//!                 |  Zero Page             |
//!                 |                        |
//!   0x0000_9000   +------------------------+
//!                 |  Page Map Level4       |
//!                 |                        |
//!   0x0000_a000   +------------------------+
//!                 |  Page Directory Pointer|
//!                 |                        |
//!   0x0000_b000   +------------------------+
//!                 |  Page Directory Entry  |
//!                 |                        |
//!   0x0002_0000   +------------------------+
//!                 |  Kernel Cmdline        |
//!                 |                        |
//!   0x0009_fc00   +------------------------+
//!                 |  EBDA - MPtable        |
//!                 |                        |
//!   0x000a_0000   +------------------------+
//!                 |  VGA_RAM               |
//!                 |                        |
//!   0x000f_0000   +------------------------+
//!                 |  MB_BIOS               |
//!                 |                        |
//!   0x0010_0000   +------------------------+
//!                 |  Kernel _setup         |
//!                 |                        |
//!                 ~------------------------~
//!                 |  Initrd Ram            |
//!   0x****_****   +------------------------+
//! ```

mod bootparam;
mod direct_boot;
mod standard_boot;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use kvm_bindings::kvm_segment;

use address_space::AddressSpace;
use devices::legacy::FwCfgOps;

const ZERO_PAGE_START: u64 = 0x0000_7000;
const PML4_START: u64 = 0x0000_9000;
const PDPTE_START: u64 = 0x0000_a000;
const PDE_START: u64 = 0x0000_b000;
const SETUP_START: u64 = 0x0001_0000;
const CMDLINE_START: u64 = 0x0002_0000;
const BOOT_HDR_START: u64 = 0x0000_01F1;
const BZIMAGE_BOOT_OFFSET: u64 = 0x0200;

const EBDA_START: u64 = 0x0009_fc00;
const VGA_RAM_BEGIN: u64 = 0x000a_0000;
const MB_BIOS_BEGIN: u64 = 0x000f_0000;
pub const VMLINUX_RAM_START: u64 = 0x0010_0000;
const INITRD_ADDR_MAX: u64 = 0x37ff_ffff;

const VMLINUX_STARTUP: u64 = 0x0100_0000;
const BOOT_LOADER_SP: u64 = 0x0000_8ff0;

const GDT_ENTRY_BOOT_CS: u8 = 2;
const GDT_ENTRY_BOOT_DS: u8 = 3;
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const REAL_MODE_IVT_BEGIN: u64 = 0x0000_0000;

/// Boot loader config used for x86_64.
pub struct X86BootLoaderConfig {
    /// Path of the kernel image.
    pub kernel: Option<std::path::PathBuf>,
    /// Path of the initrd image.
    pub initrd: Option<PathBuf>,
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
    /// Range of identity-map and TSS
    pub ident_tss_range: Option<(u64, u64)>,
    /// Boot from 64-bit protection mode or not.
    pub prot64_mode: bool,
}

/// The start address for some boot source in guest memory for `x86_64`.
#[derive(Debug, Default, Copy, Clone)]
pub struct X86BootLoader {
    pub boot_ip: u64,
    pub boot_sp: u64,
    pub boot_selector: u16,
    pub boot_pml4_addr: u64,
    pub zero_page_addr: u64,
    pub segments: BootGdtSegment,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct BootGdtSegment {
    pub code_segment: kvm_segment,
    pub data_segment: kvm_segment,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

pub fn load_linux(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
) -> Result<X86BootLoader> {
    if config.prot64_mode {
        direct_boot::load_linux(config, sys_mem)
    } else {
        let fwcfg = fwcfg.with_context(|| "Failed to load linux: No FwCfg provided")?;
        let mut locked_fwcfg = fwcfg.lock().unwrap();
        standard_boot::load_linux(config, sys_mem, &mut *locked_fwcfg)?;

        Ok(X86BootLoader {
            boot_ip: 0xFFF0,
            boot_sp: 0x8000,
            boot_selector: 0xF000,
            ..Default::default()
        })
    }
}
