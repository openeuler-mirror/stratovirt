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

use std::convert::Into;

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
impl Into<kvm_bindings::kvm_segment> for GdtEntry {
    fn into(self) -> kvm_bindings::kvm_segment {
        let base = (self.0 >> 16 & 0x00ff_ffff) | (self.0 >> (56 - 24) & 0xff00_0000);
        let limit = (self.0 >> (48 - 16) & 0x000f_0000) | (self.0 & 0x0000_ffff);
        let flags = (self.0 >> 40) & 0x0000_f0ff;

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

impl Into<u64> for GdtEntry {
    fn into(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kvm_bindings::kvm_segment;

    #[test]
    fn test_gdt_entry() {
        assert_eq!(GdtEntry::new(0xa09b, 0x0, 0xfffff).0, 0xaf9b000000ffff);
        assert_eq!(GdtEntry::new(0xc093, 0x0, 0xfffff).0, 0xcf93000000ffff);
    }

    #[test]
    fn test_segment() {
        let gdt_entry = GdtEntry(0xaf9b000000ffff);
        let seg: kvm_segment = gdt_entry.into();

        assert_eq!(1, seg.g);
        assert_eq!(0, seg.db);
        assert_eq!(1, seg.l);
        assert_eq!(0, seg.avl);
        assert_eq!(1, seg.present);
        assert_eq!(0, seg.dpl);
        assert_eq!(1, seg.s);
        assert_eq!(11, seg.type_);
        assert_eq!(0, seg.base);
        assert_eq!(1048575, seg.limit);
        assert_eq!(0, seg.unusable);
    }
}
