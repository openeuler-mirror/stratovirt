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

use std::mem::size_of;

use crate::errors::{ErrorKind, Result, ResultExt};
use byteorder::{BigEndian, ByteOrder};

pub const CLK_PHANDLE: u32 = 1;
pub const GIC_PHANDLE: u32 = 2;
pub const GIC_ITS_PHANDLE: u32 = 3;
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
            return Err(ErrorKind::NodeUnclosed(self.subnode_depth).into());
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
            return Err(ErrorKind::MemReserveOverlap.into());
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
            return Err(ErrorKind::IllegalString(node_name.to_string()).into());
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
            return Err(ErrorKind::NodeDepthMismatch(begin_node_depth, self.subnode_depth).into());
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
            .chain_err(|| ErrorKind::SetPropertyErr("string".to_string()))
    }

    pub fn set_property_u32(&mut self, prop: &str, val: u32) -> Result<()> {
        self.set_property(prop, &val.to_be_bytes()[..])
            .chain_err(|| ErrorKind::SetPropertyErr("u32".to_string()))
    }

    pub fn set_property_u64(&mut self, prop: &str, val: u64) -> Result<()> {
        self.set_property(prop, &val.to_be_bytes()[..])
            .chain_err(|| ErrorKind::SetPropertyErr("u64".to_string()))
    }

    pub fn set_property_array_u32(&mut self, prop: &str, array: &[u32]) -> Result<()> {
        let mut prop_array = Vec::with_capacity(array.len() * size_of::<u32>());
        for element in array {
            prop_array.extend_from_slice(&element.to_be_bytes()[..]);
        }
        self.set_property(prop, &prop_array)
            .chain_err(|| ErrorKind::SetPropertyErr("u32 array".to_string()))
    }

    pub fn set_property_array_u64(&mut self, prop: &str, array: &[u64]) -> Result<()> {
        let mut prop_array = Vec::with_capacity(array.len() * size_of::<u64>());
        for element in array {
            prop_array.extend_from_slice(&element.to_be_bytes()[..]);
        }
        self.set_property(prop, &prop_array)
            .chain_err(|| ErrorKind::SetPropertyErr("u64 array".to_string()))
    }

    pub fn set_property(&mut self, property_name: &str, property_val: &[u8]) -> Result<()> {
        if !check_string_legality(property_name) {
            return Err(ErrorKind::IllegalString(property_name.to_string()).into());
        }

        if !self.begin_node {
            return Err(ErrorKind::IllegelPropertyPos.into());
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
            self.structure_blk
                .extend(vec![0_u8; (alignment - remainder) as usize]);
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

pub fn dump_dtb(fdt: &[u8], file_path: &str) {
    use std::fs::File;
    use std::io::Write;
    let mut f = File::create(file_path).unwrap();
    f.write_all(fdt).expect("Unable to write data");
}
