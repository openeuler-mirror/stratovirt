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

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ByteOrder};

use crate::UtilError;

pub const CLK_PHANDLE: u32 = 1;
pub const GIC_PHANDLE: u32 = 2;
pub const GIC_ITS_PHANDLE: u32 = 3;
pub const PPI_CLUSTER_PHANDLE: u32 = 4;
pub const FIRST_VCPU_PHANDLE: u32 = 6;
pub const CPU_PHANDLE_START: u32 = 10;

pub const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
pub const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
pub const IRQ_TYPE_EDGE_RISING: u32 = 1;
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

pub const FDT_MAX_SIZE: u32 = 0x1_0000;

// Magic number in fdt header(big-endian).
const FDT_MAGIC: u32 = 0xd00dfeed;
// Fdt Header default information.
const FDT_HEADER_SIZE: usize = 40;
const FDT_VERSION: u32 = 17;
const FDT_LAST_COMP_VERSION: u32 = 16;
// Beginning token type of structure block.
const FDT_BEGIN_NODE: u32 = 0x00000001;
const FDT_END_NODE: u32 = 0x00000002;
const FDT_PROP: u32 = 0x00000003;
const FDT_END: u32 = 0x00000009;
// Memory reservation block alignment.
const MEM_RESERVE_ALIGNMENT: usize = 8;
// Structure block alignment.
const STRUCTURE_BLOCK_ALIGNMENT: usize = 4;

pub const FDT_PCI_RANGE_IOPORT: u32 = 0x0100_0000;
pub const FDT_PCI_RANGE_MMIO: u32 = 0x0200_0000;
pub const FDT_PCI_RANGE_MMIO_64BIT: u32 = 0x0300_0000;

/// FdtBuilder structure.
pub struct FdtBuilder {
    /// The header of flattened device tree.
    fdt_header: Vec<u8>,
    /// The memory reservation block of flattened device tree.
    /// It provides the client program with a list of areas
    /// in physical memory which are reserved.
    mem_reserve: Vec<u8>,
    /// The structure block of flattened device tree.
    /// It describes the structure and contents of the tree.
    structure_blk: Vec<u8>,
    /// The strings block of flattened device tree.
    /// It contains strings representing all the property names used in the tree.
    strings_blk: Vec<u8>,
    /// The physical ID of the system’s boot CPU.
    boot_cpuid_phys: u32,
    /// The depth of nested node.
    subnode_depth: u32,
    /// Is there a open node or not.
    begin_node: bool,
}

/// FdtReserveEntry structure.
#[derive(Clone, Debug)]
pub struct FdtReserveEntry {
    /// The address of reserved memory.
    /// On 32-bit CPUs the upper 32-bits of the value are ignored.
    address: u64,
    /// The size of reserved memory.
    size: u64,
}

fn check_mem_reserve_overlap(mem_reservations: &[FdtReserveEntry]) -> bool {
    if mem_reservations.len() <= 1 {
        return true;
    }

    let mut mem_reser = mem_reservations.to_vec();
    mem_reser.sort_by_key(|m| m.address);

    for i in 0..(mem_reser.len() - 1) {
        if mem_reser[i].address + mem_reser[i].size > mem_reser[i + 1].address {
            return false;
        }
    }
    true
}

// If there is null character in string, return false.
fn check_string_legality(s: &str) -> bool {
    !s.contains('\0')
}

impl Default for FdtBuilder {
    fn default() -> Self {
        Self {
            fdt_header: vec![0_u8; FDT_HEADER_SIZE],
            mem_reserve: Vec::new(),
            structure_blk: Vec::new(),
            strings_blk: Vec::new(),
            boot_cpuid_phys: 0,
            subnode_depth: 0,
            begin_node: false,
        }
    }
}

impl FdtBuilder {
    pub fn new() -> Self {
        FdtBuilder::default()
    }

    pub fn finish(mut self) -> Result<Vec<u8>> {
        if self.subnode_depth > 0 {
            return Err(anyhow!(UtilError::NodeUnclosed(self.subnode_depth)));
        }
        self.structure_blk
            .extend_from_slice(&FDT_END.to_be_bytes()[..]);

        // According to the spec, mem_reserve blocks shall be ended
        // with an entry where both address and size are equal to 0.
        self.mem_reserve.extend_from_slice(&0_u64.to_be_bytes());
        self.mem_reserve.extend_from_slice(&0_u64.to_be_bytes());

        // Fill fdt header.
        let total_size = FDT_HEADER_SIZE
            + self.mem_reserve.len()
            + self.structure_blk.len()
            + self.strings_blk.len();
        let off_dt_struct = FDT_HEADER_SIZE + self.mem_reserve.len();
        let off_dt_strings = FDT_HEADER_SIZE + self.mem_reserve.len() + self.structure_blk.len();
        let off_mem_rsvmap = FDT_HEADER_SIZE;

        BigEndian::write_u32(&mut self.fdt_header[0..4], FDT_MAGIC);
        BigEndian::write_u32(&mut self.fdt_header[4..8], total_size as u32);
        BigEndian::write_u32(&mut self.fdt_header[8..12], off_dt_struct as u32);
        BigEndian::write_u32(&mut self.fdt_header[12..16], off_dt_strings as u32);
        BigEndian::write_u32(&mut self.fdt_header[16..20], off_mem_rsvmap as u32);
        BigEndian::write_u32(&mut self.fdt_header[20..24], FDT_VERSION);
        BigEndian::write_u32(&mut self.fdt_header[24..28], FDT_LAST_COMP_VERSION);
        BigEndian::write_u32(&mut self.fdt_header[28..32], self.boot_cpuid_phys);
        BigEndian::write_u32(&mut self.fdt_header[32..36], self.strings_blk.len() as u32);
        BigEndian::write_u32(
            &mut self.fdt_header[36..40],
            self.structure_blk.len() as u32,
        );

        self.fdt_header.extend_from_slice(&self.mem_reserve);
        self.fdt_header.extend_from_slice(&self.structure_blk);
        self.fdt_header.extend_from_slice(&self.strings_blk);
        Ok(self.fdt_header)
    }

    pub fn add_mem_reserve(&mut self, mem_reservations: &[FdtReserveEntry]) -> Result<()> {
        if !check_mem_reserve_overlap(mem_reservations) {
            return Err(anyhow!(UtilError::MemReserveOverlap));
        }

        for mem_reser in mem_reservations {
            self.mem_reserve
                .extend_from_slice(&mem_reser.address.to_be_bytes());
            self.mem_reserve
                .extend_from_slice(&mem_reser.size.to_be_bytes());
        }
        self.align_structure_blk(MEM_RESERVE_ALIGNMENT);

        Ok(())
    }

    pub fn begin_node(&mut self, node_name: &str) -> Result<u32> {
        if !check_string_legality(node_name) {
            return Err(anyhow!(UtilError::IllegalString(node_name.to_string())));
        }

        self.structure_blk
            .extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes()[..]);
        if node_name.is_empty() {
            self.structure_blk
                .extend_from_slice(&0_u32.to_be_bytes()[..]);
        } else {
            let mut val_array = node_name.as_bytes().to_vec();
            // The node’s name string should end with null('\0').
            val_array.push(0x0_u8);
            self.structure_blk.extend_from_slice(&val_array);
        }
        self.align_structure_blk(STRUCTURE_BLOCK_ALIGNMENT);
        self.subnode_depth += 1;
        self.begin_node = true;
        Ok(self.subnode_depth)
    }

    pub fn end_node(&mut self, begin_node_depth: u32) -> Result<()> {
        if begin_node_depth != self.subnode_depth {
            return Err(anyhow!(UtilError::NodeDepthMismatch(
                begin_node_depth,
                self.subnode_depth
            )));
        }

        self.structure_blk
            .extend_from_slice(&FDT_END_NODE.to_be_bytes()[..]);
        self.subnode_depth -= 1;
        self.begin_node = false;
        Ok(())
    }

    pub fn set_boot_cpuid_phys(&mut self, boot_cpuid: u32) {
        self.boot_cpuid_phys = boot_cpuid;
    }

    pub fn set_property_string(&mut self, prop: &str, val: &str) -> Result<()> {
        let mut val_array = val.as_bytes().to_vec();
        // The string property should end with null('\0').
        val_array.push(0x0_u8);
        self.set_property(prop, &val_array)
            .with_context(|| UtilError::SetPropertyErr("string".to_string()))
    }

    pub fn set_property_u32(&mut self, prop: &str, val: u32) -> Result<()> {
        self.set_property(prop, &val.to_be_bytes()[..])
            .with_context(|| UtilError::SetPropertyErr("u32".to_string()))
    }

    pub fn set_property_u64(&mut self, prop: &str, val: u64) -> Result<()> {
        self.set_property(prop, &val.to_be_bytes()[..])
            .with_context(|| UtilError::SetPropertyErr("u64".to_string()))
    }

    pub fn set_property_array_u32(&mut self, prop: &str, array: &[u32]) -> Result<()> {
        let mut prop_array = Vec::with_capacity(std::mem::size_of_val(array));
        for element in array {
            prop_array.extend_from_slice(&element.to_be_bytes()[..]);
        }
        self.set_property(prop, &prop_array)
            .with_context(|| UtilError::SetPropertyErr("u32 array".to_string()))
    }

    pub fn set_property_array_u64(&mut self, prop: &str, array: &[u64]) -> Result<()> {
        let mut prop_array = Vec::with_capacity(std::mem::size_of_val(array));
        for element in array {
            prop_array.extend_from_slice(&element.to_be_bytes()[..]);
        }
        self.set_property(prop, &prop_array)
            .with_context(|| UtilError::SetPropertyErr("u64 array".to_string()))
    }

    pub fn set_property(&mut self, property_name: &str, property_val: &[u8]) -> Result<()> {
        if !check_string_legality(property_name) {
            return Err(anyhow!(UtilError::IllegalString(property_name.to_string())));
        }

        if !self.begin_node {
            return Err(anyhow!(UtilError::IllegelPropertyPos));
        }

        let len = property_val.len() as u32;
        let nameoff = self.strings_blk.len() as u32;
        self.structure_blk
            .extend_from_slice(&FDT_PROP.to_be_bytes()[..]);
        self.structure_blk.extend_from_slice(&len.to_be_bytes()[..]);
        self.structure_blk
            .extend_from_slice(&nameoff.to_be_bytes()[..]);
        self.structure_blk.extend_from_slice(property_val);
        self.align_structure_blk(STRUCTURE_BLOCK_ALIGNMENT);

        self.strings_blk.extend_from_slice(property_name.as_bytes());
        // These strings in strings block should end with null('\0').
        self.strings_blk.extend_from_slice("\0".as_bytes());

        Ok(())
    }

    fn align_structure_blk(&mut self, alignment: usize) {
        let remainder = self.structure_blk.len() % alignment;
        if remainder != 0 {
            self.structure_blk.extend(vec![0_u8; alignment - remainder]);
        }
    }
}

/// Trait for devices to be added to the Flattened Device Tree.
#[allow(clippy::upper_case_acronyms)]
pub trait CompileFDT {
    /// function to generate fdt node
    ///
    /// # Arguments
    ///
    /// * `fdt` - the FdtBuilder to be filled.
    fn generate_fdt_node(&self, fdt: &mut FdtBuilder) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_all_properties() {
        let mut fdt_builder = FdtBuilder::new();
        let root_node = fdt_builder.begin_node("").unwrap();
        fdt_builder.set_property("null", &[]).unwrap();
        fdt_builder.set_property_u32("u32", 0x01234567).unwrap();
        fdt_builder
            .set_property_u64("u64", 0x0123456789abcdef)
            .unwrap();
        fdt_builder
            .set_property_array_u32(
                "u32_array",
                &vec![0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00],
            )
            .unwrap();
        fdt_builder
            .set_property_array_u64("u64_array", &vec![0x0011223344556677, 0x8899aabbccddeeff])
            .unwrap();
        fdt_builder
            .set_property_string("string", "hello fdt")
            .unwrap();
        fdt_builder.end_node(root_node).unwrap();
        let right_fdt: Vec<u8> = vec![
            0xd0, 0x0d, 0xfe, 0xed, // 00: magic (0xd00dfeed)
            0x00, 0x00, 0x00, 0xf0, // 04: totalsize (0xf0)
            0x00, 0x00, 0x00, 0x38, // 08: off_dt_struct (0x38)
            0x00, 0x00, 0x00, 0xc8, // 0c: off_dt_strings (0xc8)
            0x00, 0x00, 0x00, 0x28, // 10: off_mem_rsvmap (0x28)
            0x00, 0x00, 0x00, 0x11, // 14: version (17)
            0x00, 0x00, 0x00, 0x10, // 18: last_comp_version (16)
            0x00, 0x00, 0x00, 0x00, // 1c: boot_cpuid_phys (0)
            0x00, 0x00, 0x00, 0x28, // 20: size_dt_strings (0x28)
            0x00, 0x00, 0x00, 0x90, // 24: size_dt_struct (0x90)
            0x00, 0x00, 0x00, 0x00, // 28: high address of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 2c: low address of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 30: high size of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 34: low size of memory reservation block terminator
            0x00, 0x00, 0x00, 0x01, // 38: FDT_BEGIN_NODE
            0x00, 0x00, 0x00, 0x00, // 3c: node name ("") with 4-byte alignment
            0x00, 0x00, 0x00, 0x03, // 40: FDT_PROP ("null")
            0x00, 0x00, 0x00, 0x00, // 44: property len (0)
            0x00, 0x00, 0x00, 0x00, // 48: property nameoff (0x00)
            0x00, 0x00, 0x00, 0x03, // 4c: FDT_PROP ("u32")
            0x00, 0x00, 0x00, 0x04, // 50: property len (4)
            0x00, 0x00, 0x00, 0x05, // 54: property nameoff (0x05)
            0x01, 0x23, 0x45, 0x67, // 58: property’s value (0x01234567)
            0x00, 0x00, 0x00, 0x03, // 5c: FDT_PROP ("u64")
            0x00, 0x00, 0x00, 0x08, // 60: property len (8)
            0x00, 0x00, 0x00, 0x09, // 64: property nameoff (0x09)
            0x01, 0x23, 0x45, 0x67, // 68: property’s value (0x01234567)
            0x89, 0xab, 0xcd, 0xef, // 6c: property’s value (0x89abcdef)
            0x00, 0x00, 0x00, 0x03, // 70: FDT_PROP ("u32_array")
            0x00, 0x00, 0x00, 0x10, // 74: property len (16)
            0x00, 0x00, 0x00, 0x0d, // 78: property nameoff (0x0d)
            0x11, 0x22, 0x33, 0x44, // 7c: property’s value (0x11223344)
            0x55, 0x66, 0x77, 0x88, // 80: property’s value (0x55667788)
            0x99, 0xaa, 0xbb, 0xcc, // 84: property’s value (0x99aabbcc)
            0xdd, 0xee, 0xff, 0x00, // 88: property’s value (0xddeeff00)
            0x00, 0x00, 0x00, 0x03, // 8c: FDT_PROP ("u64_array")
            0x00, 0x00, 0x00, 0x10, // 90: property len (16)
            0x00, 0x00, 0x00, 0x17, // 94: property nameoff (0x17)
            0x00, 0x11, 0x22, 0x33, // 98: property’s value (0x00112233)
            0x44, 0x55, 0x66, 0x77, // 9c: property’s value (0x44556677)
            0x88, 0x99, 0xaa, 0xbb, // a0: property’s value (0x8899aabb)
            0xcc, 0xdd, 0xee, 0xff, // a4: property’s value (0xccddeeff)
            0x00, 0x00, 0x00, 0x03, // a8: FDT_PROP ("string")
            0x00, 0x00, 0x00, 0x0a, // ac: property len (10)
            0x00, 0x00, 0x00, 0x21, // b0: property nameoff (0x21)
            b'h', b'e', b'l', b'l', // b4: property’s value ("hell")
            b'o', b' ', b'f', b'd', // b8: property’s value ("o fd")
            b't', b'\0', 0x00, 0x00, // bc: property’s value ("t\0" with padding)
            0x00, 0x00, 0x00, 0x02, // c0: FDT_END_NODE
            0x00, 0x00, 0x00, 0x09, // c4: FDT_END
            b'n', b'u', b'l', b'l', b'\0', // c8: "null" with offset 0x00
            b'u', b'3', b'2', b'\0', // cd: "u32" with offset 0x05
            b'u', b'6', b'4', b'\0', // d1: "u64" with offset 0x09
            b'u', b'3', b'2', b'_', b'a', b'r', b'r', b'a', b'y',
            b'\0', // d5: "u32_array" with offset 0x0d
            b'u', b'6', b'4', b'_', b'a', b'r', b'r', b'a', b'y',
            b'\0', // df: "u64_array" with offset 0x17
            b's', b't', b'r', b'i', b'n', b'g', b'\0', // e9: "string" with offset 0x21
        ];
        let sample_fdt = fdt_builder.finish().unwrap();
        assert_eq!(right_fdt, sample_fdt);
    }

    #[test]
    fn test_nested_node() {
        let mut fdt_builder = FdtBuilder::new();
        let root_node = fdt_builder.begin_node("").unwrap();

        let cpus_node = fdt_builder.begin_node("cpus").unwrap();
        fdt_builder.set_property_u32("addrcells", 0x02).unwrap();
        fdt_builder.set_property_u32("sizecells", 0x0).unwrap();

        let cpu_map_node = fdt_builder.begin_node("cpu-map").unwrap();
        fdt_builder.set_property_u32("cpu", 10).unwrap();

        fdt_builder.end_node(cpu_map_node).unwrap();
        fdt_builder.end_node(cpus_node).unwrap();
        fdt_builder.end_node(root_node).unwrap();

        fdt_builder.set_boot_cpuid_phys(1);

        let right_fdt: Vec<u8> = vec![
            0xd0, 0x0d, 0xfe, 0xed, // 00: magic (0xd00dfeed)
            0x00, 0x00, 0x00, 0xb0, // 04: totalsize (0xb0)
            0x00, 0x00, 0x00, 0x38, // 08: off_dt_struct (0x38)
            0x00, 0x00, 0x00, 0x98, // 0c: off_dt_strings (0x98)
            0x00, 0x00, 0x00, 0x28, // 10: off_mem_rsvmap (0x28)
            0x00, 0x00, 0x00, 0x11, // 14: version (17)
            0x00, 0x00, 0x00, 0x10, // 18: last_comp_version (16)
            0x00, 0x00, 0x00, 0x01, // 1c: boot_cpuid_phys (1)
            0x00, 0x00, 0x00, 0x18, // 20: size_dt_strings (0x18)
            0x00, 0x00, 0x00, 0x60, // 24: size_dt_struct (0x60)
            0x00, 0x00, 0x00, 0x00, // 28: high address of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 2c: low address of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 30: high size of memory reservation block terminator
            0x00, 0x00, 0x00, 0x00, // 34: low size of memory reservation block terminator
            0x00, 0x00, 0x00, 0x01, // 38: FDT_BEGIN_NODE
            0x00, 0x00, 0x00, 0x00, // 3c: node name ("")
            0x00, 0x00, 0x00, 0x01, // 40: FDT_BEGIN_NODE
            b'c', b'p', b'u', b's', // 44: node name ("cpus") with 4-byte alignment
            b'\0', 0x00, 0x00, 0x00, // 48: padding
            0x00, 0x00, 0x00, 0x03, // 4c: FDT_PROP ("addrcells")
            0x00, 0x00, 0x00, 0x04, // 50: property len (4)
            0x00, 0x00, 0x00, 0x00, // 54: property nameoff (0x00)
            0x00, 0x00, 0x00, 0x02, // 58: property’s value (0x02)
            0x00, 0x00, 0x00, 0x03, // 5c: FDT_PROP ("sizecells")
            0x00, 0x00, 0x00, 0x04, // 60: property len (4)
            0x00, 0x00, 0x00, 0x0a, // 64: property nameoff (0xa)
            0x00, 0x00, 0x00, 0x00, // 68: property’s value (0x0)
            0x00, 0x00, 0x00, 0x01, // 6c: FDT_BEGIN_NODE
            b'c', b'p', b'u', b'-', // 70: node name ("cpu-map")
            b'm', b'a', b'p', b'\0', // 74: node name ("cpu-map")
            0x00, 0x00, 0x00, 0x03, // 78: FDT_PROP ("cpu")
            0x00, 0x00, 0x00, 0x04, // 7c: property len (4)
            0x00, 0x00, 0x00, 0x14, // 80: property nameoff (0x14)
            0x00, 0x00, 0x00, 0x0a, // 84: property’s value (10)
            0x00, 0x00, 0x00, 0x02, // 88: FDT_END_NODE
            0x00, 0x00, 0x00, 0x02, // 8c: FDT_END_NODE
            0x00, 0x00, 0x00, 0x02, // 90: FDT_END_NODE
            0x00, 0x00, 0x00, 0x09, // 94: FDT_END
            b'a', b'd', b'd', b'r', b'c', b'e', b'l', b'l', b's',
            b'\0', // 98: "addrcells" with offset 0x00
            b's', b'i', b'z', b'e', b'c', b'e', b'l', b'l', b's',
            b'\0', // a2: "sizecells" with offset 0x0a
            b'c', b'p', b'u', b'\0', // ac: "cpu" with offset 0x14
        ];
        let sample_fdt = fdt_builder.finish().unwrap();
        assert_eq!(right_fdt, sample_fdt);
    }

    #[test]
    fn test_illegeal_string() {
        let mut fdt_builder = FdtBuilder::new();
        assert!(fdt_builder.begin_node("bad\0string").is_err());

        fdt_builder.begin_node("good string").unwrap();
        assert!(fdt_builder.set_property("bad property\0name", &[]).is_err());
        assert!(fdt_builder
            .set_property_string("good property name", "test\0val")
            .is_ok());
    }

    #[test]
    fn test_unclose_nested_node() {
        let mut fdt_builder = FdtBuilder::new();
        let root_node = fdt_builder.begin_node("").unwrap();
        fdt_builder.begin_node("nested node").unwrap();
        assert!(fdt_builder.end_node(root_node).is_err());
        assert!(fdt_builder.finish().is_err());
    }

    #[test]
    fn test_mem_reserve_overlap() {
        let mut fdt_builder = FdtBuilder::new();
        let mem_reservations = [
            FdtReserveEntry {
                address: 0x100,
                size: 0x100,
            },
            FdtReserveEntry {
                address: 0x150,
                size: 0x100,
            },
        ];
        assert!(fdt_builder.add_mem_reserve(&mem_reservations).is_err());
    }
}
