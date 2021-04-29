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

use super::loader::X86BootLoaderConfig;
use crate::helper::byte_code::ByteCode;
use crate::GuestMemory;

pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const BOOT_FLAG: u16 = 0xAA55;
pub const HDRS: u32 = 0x5372_6448;
pub const UNDEFINED_ID: u8 = 0xFF;

const INITRD_ADDR_MAX: u64 = 0x37ff_ffff;
const CMDLINE_START: u64 = 0x0002_0000;
const REAL_MODE_IVT_BEGIN: u64 = 0x0000_0000;
pub const EBDA_START: u64 = 0x0009_fc00;
const VGA_RAM_BEGIN: u64 = 0x000a_0000;
const MB_BIOS_BEGIN: u64 = 0x000f_0000;
const ZERO_PAGE_START: u64 = 0x0000_7000;

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
    vid_mode: u16,
    root_dev: u16,
    boot_flag: u16,
    jump: u16,
    header: u32,
    version: u16,
    realmode_swtch: u32,
    start_sys_seg: u16,
    kernel_version: u16,
    type_of_loader: u8,
    loadflags: u8,
    setup_move_size: u16,
    code32_start: u32,
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
    pub fn new(cmdline_ptr: u32, cmdline_size: u32, ramdisk_image: u32, ramdisk_size: u32) -> Self {
        RealModeKernelHeader {
            boot_flag: BOOT_FLAG,
            header: HDRS,
            type_of_loader: UNDEFINED_ID,
            cmdline_ptr,
            cmdline_size,
            ramdisk_image,
            ramdisk_size,
            ..Default::default()
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
pub struct E820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

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
        self.e820_table[self.e820_entries as usize] = E820Entry { addr, size, type_ };
        self.e820_entries += 1;
    }
}

pub fn setup_boot_params(config: &X86BootLoaderConfig, sys_mem: &GuestMemory) -> (u64, u64) {
    let (ramdisk_size, ramdisk_image, initrd_addr) = if config.initrd_size > 0 {
        let mut initrd_addr_max = INITRD_ADDR_MAX as u32;
        if initrd_addr_max as u64 > sys_mem.memory_end_address() as u64 {
            initrd_addr_max = sys_mem.memory_end_address() as u32;
        };

        let img = (initrd_addr_max - config.initrd_size as u32) & !0xfff_u32;
        (config.initrd_size as u32, img, img as u64)
    } else {
        (0_u32, 0_u32, 0_u64)
    };

    let mut boot_params = BootParams::new(RealModeKernelHeader::new(
        CMDLINE_START as u32,
        config.kernel_cmdline.len() as u32,
        ramdisk_image,
        ramdisk_size,
    ));

    boot_params.add_e820_entry(
        REAL_MODE_IVT_BEGIN,
        EBDA_START - REAL_MODE_IVT_BEGIN,
        E820_RAM,
    );
    boot_params.add_e820_entry(EBDA_START, VGA_RAM_BEGIN - EBDA_START, E820_RESERVED);
    boot_params.add_e820_entry(MB_BIOS_BEGIN, 0, E820_RESERVED);

    let high_memory_start = super::loader::VMLINUX_RAM_START;
    let layout_32bit_gap_end = config.gap_range.0 + config.gap_range.1;
    let mem_end = sys_mem.memory_end_address();
    if mem_end < layout_32bit_gap_end {
        boot_params.add_e820_entry(high_memory_start, mem_end - high_memory_start, E820_RAM);
    } else {
        boot_params.add_e820_entry(
            high_memory_start,
            config.gap_range.0 - high_memory_start,
            E820_RAM,
        );
        boot_params.add_e820_entry(
            layout_32bit_gap_end,
            mem_end - layout_32bit_gap_end,
            E820_RAM,
        );
    }

    sys_mem
        .write_object(&boot_params, ZERO_PAGE_START)
        .expect("Failed to write bootparam to guest memory.");

    (ZERO_PAGE_START, initrd_addr)
}
