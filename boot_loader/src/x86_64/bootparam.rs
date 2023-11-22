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

use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::{
    X86BootLoaderConfig, EBDA_START, MB_BIOS_BEGIN, REAL_MODE_IVT_BEGIN, VGA_RAM_BEGIN,
    VMLINUX_RAM_START,
};
use crate::error::BootLoaderError;
use address_space::AddressSpace;
use util::byte_code::ByteCode;

pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const BOOT_VERSION: u16 = 0x0200;
pub const BOOT_FLAG: u16 = 0xAA55;
pub const HDRS: u32 = 0x5372_6448;
pub const UNDEFINED_ID: u8 = 0xFF;
// Loader type ID: OVMF UEFI virtualization stack.
pub const UEFI_OVMF_ID: u8 = 0xB;

// Structures below sourced from:
// https://www.kernel.org/doc/html/latest/x86/boot.html
// https://www.kernel.org/doc/html/latest/x86/zero-page.html
#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct RealModeKernelHeader {
    pub setup_sects: u8,
    root_flags: u16,
    syssize: u32,
    ram_size: u16,
    video_mode: u16,
    root_dev: u16,
    boot_flag: u16,
    jump: u16,
    pub header: u32,
    pub version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    setup_move_size: u16,
    pub code32_start: u32,
    ramdisk_image: u32,
    ramdisk_size: u32,
    bootsect_kludge: u32,
    heap_end_ptr: u16,
    ext_loader_ver: u8,
    ext_loader_type: u8,
    cmdline_ptr: u32,
    initrd_addr_max: u32,
    kernel_alignment: u32,
    relocatable_kernel: u8,
    min_alignment: u8,
    xloadflags: u16,
    cmdline_size: u32,
    hardware_subarch: u32,
    hardware_subarch_data: u64,
    payload_offset: u32,
    payload_length: u32,
    setup_data: u64,
    pref_address: u64,
    init_size: u32,
    handover_offset: u32,
    kernel_info_offset: u32,
}

impl ByteCode for RealModeKernelHeader {}

impl RealModeKernelHeader {
    pub fn new() -> Self {
        RealModeKernelHeader {
            boot_flag: BOOT_FLAG,
            header: HDRS,
            type_of_loader: UNDEFINED_ID,
            ..Default::default()
        }
    }

    pub fn check_valid_kernel(&self) -> Result<()> {
        if self.header != HDRS {
            return Err(anyhow!(BootLoaderError::ElfKernel));
        }
        if (self.version < BOOT_VERSION) || ((self.loadflags & 0x1) == 0x0) {
            return Err(anyhow!(BootLoaderError::InvalidBzImage));
        }
        if self.version < 0x202 {
            return Err(anyhow!(BootLoaderError::OldVersionKernel));
        }
        Ok(())
    }

    pub fn set_cmdline(&mut self, cmdline_addr: u32, cmdline_size: u32) {
        self.cmdline_ptr = cmdline_addr;
        self.cmdline_size = cmdline_size;
    }

    pub fn set_ramdisk(&mut self, addr: u32, size: u32) {
        self.ramdisk_image = addr;
        self.ramdisk_size = size;
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct E820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

impl E820Entry {
    pub(crate) fn new(addr: u64, size: u64, type_: u32) -> E820Entry {
        E820Entry { addr, size, type_ }
    }
}

impl ByteCode for E820Entry {}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct BootParams {
    screen_info: [u8; 0x40],
    apm_bios_info: [u8; 0x14],
    pad1: u32,
    tboot_addr: [u8; 0x8],
    ist_info: [u8; 0x10],
    pad2: [u8; 0x10],
    hd0_info: [u8; 0x10],
    hd1_info: [u8; 0x10],
    sys_desc_table: [u8; 0x10],
    olpc_ofw_header: [u8; 0x10],
    ext_ramdisk_image: u32,
    ext_ramdisk_size: u32,
    ext_cmd_line_ptr: u32,
    pad3: [u8; 0x74],
    edid_info: [u8; 0x80],
    efi_info: [u8; 0x20],
    alt_mem_k: u32,
    scratch: u32,
    e820_entries: u8,
    eddbuf_entries: u8,
    edd_mbr_sig_buf_entries: u8,
    kbd_status: u8,
    secure_boot: u8,
    pad4: u16,
    sentinel: u8,
    pad5: u8,
    kernel_header: RealModeKernelHeader, // offset: 0x1f1
    pad6: [u8; 0x24],
    edd_mbr_sig_buffer: [u8; 0x40],
    e820_table: [E820Entry; 0x80],
    pad8: [u8; 0x30],
    eddbuf: [u8; 0x1ec],
}

impl ByteCode for BootParams {}

impl Default for BootParams {
    fn default() -> Self {
        // SAFETY: The function of default is only used in trait of ByteCode,
        // it can be sure all member variables will be initialized later.
        unsafe { ::std::mem::zeroed() }
    }
}

impl BootParams {
    pub fn new(kernel_header: RealModeKernelHeader) -> Self {
        BootParams {
            kernel_header,
            ..Default::default()
        }
    }

    pub fn add_e820_entry(&mut self, addr: u64, size: u64, type_: u32) {
        self.e820_table[self.e820_entries as usize] = E820Entry::new(addr, size, type_);
        self.e820_entries += 1;
    }

    pub fn setup_e820_entries(
        &mut self,
        config: &X86BootLoaderConfig,
        sys_mem: &Arc<AddressSpace>,
    ) {
        self.add_e820_entry(
            REAL_MODE_IVT_BEGIN,
            EBDA_START - REAL_MODE_IVT_BEGIN,
            E820_RAM,
        );
        self.add_e820_entry(EBDA_START, VGA_RAM_BEGIN - EBDA_START, E820_RESERVED);
        self.add_e820_entry(MB_BIOS_BEGIN, 0, E820_RESERVED);

        let high_memory_start = VMLINUX_RAM_START;
        let layout_32bit_gap_end = config.gap_range.0 + config.gap_range.1;
        let mem_end = sys_mem.memory_end_address().raw_value();
        if mem_end < layout_32bit_gap_end {
            self.add_e820_entry(high_memory_start, mem_end - high_memory_start, E820_RAM);
        } else {
            self.add_e820_entry(
                high_memory_start,
                config.gap_range.0 - high_memory_start,
                E820_RAM,
            );
            self.add_e820_entry(
                layout_32bit_gap_end,
                mem_end - layout_32bit_gap_end,
                E820_RAM,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::super::X86BootLoaderConfig;
    use super::*;
    use address_space::{AddressSpace, GuestAddress, HostMemMapping, Region};

    #[test]
    fn test_boot_param() {
        let root = Region::init_container_region(0x2000_0000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let ram1 = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                0x1000_0000,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        let region_a = Region::init_ram_region(ram1.clone(), "region_a");
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();

        let config = X86BootLoaderConfig {
            kernel: Some(PathBuf::new()),
            initrd: Some(PathBuf::new()),
            kernel_cmdline: String::from("this_is_a_piece_of_test_string"),
            cpu_count: 2,
            gap_range: (0xC000_0000, 0x4000_0000),
            ioapic_addr: 0xFEC0_0000,
            lapic_addr: 0xFEE0_0000,
            prot64_mode: false,
            ident_tss_range: None,
        };

        let boot_hdr = RealModeKernelHeader::default();
        let mut boot_params = BootParams::new(boot_hdr);
        boot_params.setup_e820_entries(&config, &space);
        assert_eq!(boot_params.e820_entries, 4);

        assert!(boot_params.e820_table[0].addr == 0);

        assert!(boot_params.e820_table[0].addr == 0);
        assert!(boot_params.e820_table[0].size == 0x0009_FC00);
        assert!(boot_params.e820_table[0].type_ == 1);

        assert!(boot_params.e820_table[1].addr == 0x0009_FC00);
        assert!(boot_params.e820_table[1].size == 0x400);
        assert!(boot_params.e820_table[1].type_ == 2);

        assert!(boot_params.e820_table[2].addr == 0x000F_0000);
        assert!(boot_params.e820_table[2].size == 0);
        assert!(boot_params.e820_table[2].type_ == 2);

        assert!(boot_params.e820_table[3].addr == 0x0010_0000);
        assert!(boot_params.e820_table[3].size == 0x0ff0_0000);
        assert!(boot_params.e820_table[3].type_ == 1);
    }
}
