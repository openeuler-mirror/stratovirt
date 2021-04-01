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

use std::mem::{size_of, size_of_val};

use kvm_bindings::kvm_segment;

use crate::GuestMemory;

const GDT_ENTRY_BOOT_CS: u8 = 2;
const GDT_ENTRY_BOOT_DS: u8 = 3;
const BOOT_GDT_MAX: usize = 4;
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

#[derive(Debug, Default, Copy, Clone)]
pub struct BootGdtSegment {
    pub code_segment: kvm_segment,
    pub data_segment: kvm_segment,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

// /*
//  * Constructor for a conventional segment GDT (or LDT) entry.
//  * This is a macro so it can be used in initializers.
//  */
// #define GDT_ENTRY(flags, base, limit)           \
//     ((((base)  & _AC(0xff000000,ULL)) << (56-24)) | \
//      (((flags) & _AC(0x0000f0ff,ULL)) << 40) |  \
//      (((limit) & _AC(0x000f0000,ULL)) << (48-16)) | \
//      (((base)  & _AC(0x00ffffff,ULL)) << 16) |  \
//      (((limit) & _AC(0x0000ffff,ULL))))
//
pub struct GdtEntry(pub u64);

impl GdtEntry {
    pub fn new(flags: u64, base: u64, limit: u64) -> Self {
        let base = (base & 0xff00_0000) << (56 - 24) | (base & 0x00ff_ffff) << 16;
        let limit = (limit & 0x000f_0000) << (48 - 16) | (limit & 0x0000_ffff);
        let flags = (flags & 0x0000_f0ff) << 40;

        GdtEntry(base | limit | flags)
    }
}

// Intel SDM 3A 3.4.5, segment descriptor has two
// words(8 byte):
// Word 1st:
//   Bits(0 - 15): Segment Limit
//   Bits(16 - 31): Base Address 0:15
//
// Word 2nd:
//   Bits(0 - 7): Base Address 23:16
//   Bits(8 - 11): Type, Segment type
//   Bits(12): S, Descriptor type
//   Bits(13 - 14): DPL, Descriptor privilege level
//   Bits(15): P, Segment present
//   Bits(16 - 19): Segment Limit
//   Bits(20): AVL, Available for use by system software
//   Bits(21): L, 64-bit code segment
//   Bits(22): D/B, Default Operation Size
//   Bits(23): G, Granularity
//   Bits(24 - 31): Base Address 24, 31
impl From<GdtEntry> for kvm_bindings::kvm_segment {
    fn from(item: GdtEntry) -> Self {
        let base = (item.0 >> 16 & 0x00ff_ffff) | (item.0 >> (56 - 24) & 0xff00_0000);
        let limit = (item.0 >> (48 - 16) & 0x000f_0000) | (item.0 & 0x0000_ffff);
        let flags = (item.0 >> 40) & 0x0000_f0ff;

        kvm_bindings::kvm_segment {
            base,
            limit: limit as u32,
            type_: (flags & 0xf) as u8,
            present: ((flags >> (15 - 8)) & 0x1) as u8,
            dpl: ((flags >> (13 - 8)) & 0x3) as u8,
            db: ((flags >> (22 - 8)) & 0x1) as u8,
            s: ((flags >> (12 - 8)) & 0x1) as u8,
            l: ((flags >> (21 - 8)) & 0x1) as u8,
            g: ((flags >> (23 - 8)) & 0x1) as u8,
            avl: ((flags >> (20 - 8)) & 0x1) as u8,
            ..Default::default()
        }
    }
}

impl From<GdtEntry> for u64 {
    fn from(item: GdtEntry) -> Self {
        item.0
    }
}

fn write_gdt_table(table: &[u64], guest_mem: &GuestMemory) {
    let mut boot_gdt_addr = BOOT_GDT_OFFSET as u64;
    for (_, entry) in table.iter().enumerate() {
        guest_mem
            .write_object(entry, boot_gdt_addr)
            .expect("Failed to write gdt table to guest memory.");
        boot_gdt_addr += 8
    }
}

fn write_idt_value(val: u64, guest_mem: &GuestMemory) {
    let boot_idt_addr = BOOT_IDT_OFFSET;
    guest_mem
        .write_object(&val, boot_idt_addr)
        .expect("Failed to write idt table to guest memory.");
}

pub fn setup_gdt(guest_mem: &GuestMemory) -> BootGdtSegment {
    let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
        GdtEntry::new(0, 0, 0).into(),            // NULL
        GdtEntry::new(0, 0, 0).into(),            // NULL
        GdtEntry::new(0xa09b, 0, 0xfffff).into(), // CODE
        GdtEntry::new(0xc093, 0, 0xfffff).into(), // DATA
    ];

    let mut code_seg: kvm_segment = GdtEntry(gdt_table[GDT_ENTRY_BOOT_CS as usize]).into();
    code_seg.selector = GDT_ENTRY_BOOT_CS as u16 * 8;
    let mut data_seg: kvm_segment = GdtEntry(gdt_table[GDT_ENTRY_BOOT_DS as usize]).into();
    data_seg.selector = GDT_ENTRY_BOOT_DS as u16 * 8;

    write_gdt_table(&gdt_table[..], guest_mem);
    write_idt_value(0, guest_mem);

    BootGdtSegment {
        code_segment: code_seg,
        data_segment: data_seg,
        gdt_base: BOOT_GDT_OFFSET,
        gdt_limit: size_of_val(&gdt_table) as u16 - 1,
        idt_base: BOOT_IDT_OFFSET,
        idt_limit: size_of::<u64>() as u16 - 1,
    }
}
