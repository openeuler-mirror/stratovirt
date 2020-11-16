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

use util::byte_code::ByteCode;

use super::aml_compiler::AmlBuilder;

/// The common ACPI table header.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiTableHeader {
    /// Signature of this table.
    pub signature: [u8; 4],
    /// The total length of this table, including this header.
    pub length: u32,
    /// The revision of this table.
    pub revision: u8,
    /// The checksum of this table, including this header.
    pub checksum: u8,
    /// OEM ID.
    pub oem_id: [u8; 6],
    /// OEM table ID.
    pub oem_table_id: [u8; 8],
    /// OEM revision of this table.
    pub oem_revision: u32,
    /// Vendor ID for the ASL Compiler, default zero.
    pub asl_compiler_id: [u8; 4],
    /// Revision number of the ASL Compiler, default zero.
    pub asl_compiler_revision: u32,
}

impl ByteCode for AcpiTableHeader {}

impl AmlBuilder for AcpiTableHeader {
    fn aml_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// ACPI table.
pub struct AcpiTable {
    entries: Vec<u8>,
}

impl AcpiTable {
    /// The construct function of ACPI table.
    ///
    /// # Arguments
    ///
    /// `signature` - The signature of this table.
    /// `revision` - The revision of this table.
    /// `oem_id` - OEM ID.
    /// `oem_table_id` - OEM table ID.
    /// `oem_revision` - OEM revision.
    pub fn new(
        signature: [u8; 4],
        revision: u8,
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
    ) -> AcpiTable {
        AcpiTable {
            entries: AcpiTableHeader {
                signature,
                length: 0,
                revision,
                checksum: 0,
                oem_id,
                oem_table_id,
                oem_revision,
                asl_compiler_id: [0_u8; 4],
                asl_compiler_revision: 0_u32,
            }
            .aml_bytes(),
        }
    }

    /// Get the length of this table.
    pub fn table_len(&self) -> usize {
        self.entries.len()
    }

    /// Append the length of this table, do not support truncation.
    pub fn set_table_len(&mut self, new_size: usize) {
        if new_size < self.entries.len() {
            panic!("New size is smaller than old-size, truncation is not supported.");
        }
        self.entries
            .extend(vec![0_u8; new_size - self.entries.len()].as_slice());
        self.entries[4..=7].copy_from_slice((new_size as u32).as_bytes());
    }

    /// Set the value of one field in table.
    ///
    /// # Arguments
    ///
    /// `byte_index` - The location of field in this table.
    /// `new_value` - The new value that will be set in the field.
    pub fn set_field<T: ByteCode>(&mut self, byte_index: usize, new_value: T) {
        let value_len = std::mem::size_of::<T>();
        if byte_index >= self.entries.len() || byte_index + value_len >= self.entries.len() {
            panic!("Set field in table failed: overflow occurs.");
        }
        self.entries[byte_index..(byte_index + value_len)].copy_from_slice(new_value.as_bytes());
    }

    /// Append byte stream to the end of table.
    pub fn append_child(&mut self, bytes: &[u8]) {
        self.entries.extend(bytes);

        let table_len = self.entries.len() as u32;
        self.entries[4..=7].copy_from_slice(table_len.as_bytes());
    }
}

impl AmlBuilder for AcpiTable {
    fn aml_bytes(&self) -> Vec<u8> {
        self.entries.clone()
    }
}

/// ACPI RSDP structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiRsdp {
    /// The signature of RSDP, which is "RSD PTR ".
    signature: [u8; 8],
    /// The checksum of the first 20 bytes of RSDP.
    checksum: u8,
    /// OEM ID.
    oem_id: [u8; 6],
    /// The revision of this structure, only revision 2 is supported.
    revision: u8,
    /// 32-bit address of RSDT table.
    rsdt_tlb_addr: u32,
    /// The length of this table.
    length: u32,
    /// 64-bit address of XSDT table.
    xsdt_tlb_addr: u64,
    /// Extended checksum of this RSDP structure.
    extended_checksum: u8,
    /// Reserved field.
    reserved: [u8; 3],
}

impl AcpiRsdp {
    pub fn new(oem_id: [u8; 6]) -> AcpiRsdp {
        AcpiRsdp {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id,
            revision: 2,
            rsdt_tlb_addr: 0_u32,
            length: std::mem::size_of::<AcpiRsdp>() as u32,
            xsdt_tlb_addr: 0_u64,
            extended_checksum: 0,
            reserved: [0_u8; 3],
        }
    }
}

impl ByteCode for AcpiRsdp {}

impl AmlBuilder for AcpiRsdp {
    fn aml_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
