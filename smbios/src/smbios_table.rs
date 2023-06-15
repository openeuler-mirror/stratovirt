// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use machine_manager::config::{SmbiosConfig, SmbiosType0Config, SmbiosType1Config};
use std::mem::size_of;
use util::byte_code::ByteCode;

const TYPE0_HANDLE: u16 = 0x0;
const TYPE1_HANDLE: u16 = 0x100;
const TYPE127_HANDLE: u16 = 0x7F00;

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosHeader {
    type_num: u8,
    len: u8,
    handle: u16,
}

impl SmbiosHeader {
    pub fn new(type_num: u8, len: u8, handle: u16) -> SmbiosHeader {
        SmbiosHeader {
            type_num,
            len,
            handle,
        }
    }
}

/// Type0: BIOS information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType0 {
    header: SmbiosHeader,
    pub vendor_idx: u8,
    pub bios_version_idx: u8,
    bios_starting_addr_seg: [u8; 2],
    bios_release_date_idx: u8,
    bios_rom_size: u8,
    bios_characteristics: [u8; 8],
    bios_characteristics_ext: [u8; 2],
    system_bios_major_release: u8,
    system_bios_minor_release: u8,
    embedded_controller_major_release: u8,
    embedded_controller_minor_release: u8,
}

impl ByteCode for SmbiosType0 {}

impl SmbiosType0 {
    pub fn new() -> SmbiosType0 {
        SmbiosType0 {
            header: SmbiosHeader::new(0_u8, size_of::<SmbiosType0>() as u8, TYPE0_HANDLE),
            bios_starting_addr_seg: 0xE800_u16.to_le_bytes(),
            bios_rom_size: 0_u8,
            bios_characteristics: 0x08_u64.to_le_bytes(),
            bios_characteristics_ext: [0, 0x1C],
            embedded_controller_major_release: 0xFF,
            embedded_controller_minor_release: 0xFF,
            ..Default::default()
        }
    }
}
#[derive(Default, Clone)]
struct SmbiosType0Table {
    header: SmbiosType0,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType0Table {
    pub fn new() -> SmbiosType0Table {
        SmbiosType0Table {
            header: SmbiosType0::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    pub fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    pub fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type1: System information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType1 {
    header: SmbiosHeader,
    pub manufacturer: u8,
    pub product_name: u8,
    pub version: u8,
    serial_num: u8,
    uuid: [u8; 16],
    wake_up_type: u8,
    sku_num: u8,
    family: u8,
}

impl ByteCode for SmbiosType1 {}

impl SmbiosType1 {
    pub fn new() -> SmbiosType1 {
        SmbiosType1 {
            header: SmbiosHeader::new(1_u8, size_of::<SmbiosType1>() as u8, TYPE1_HANDLE),
            wake_up_type: 0x6_u8,
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType1Table {
    header: SmbiosType1,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType1Table {
    pub fn new() -> SmbiosType1Table {
        SmbiosType1Table {
            header: SmbiosType1::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    pub fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    pub fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type127: End of table
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType127 {
    header: SmbiosHeader,
}

impl SmbiosType127 {
    pub fn new() -> SmbiosType127 {
        SmbiosType127 {
            header: SmbiosHeader::new(127_u8, size_of::<SmbiosType127>() as u8, TYPE127_HANDLE),
        }
    }
}

impl ByteCode for SmbiosType127 {}

#[derive(Default, Clone)]
struct SmbiosType127Table {
    header: SmbiosType127,
    body: Vec<u8>,
}

impl SmbiosType127Table {
    pub fn new() -> SmbiosType127Table {
        SmbiosType127Table {
            header: SmbiosType127::new(),
            body: Vec::new(),
        }
    }

    pub fn finish(&mut self) {
        self.body.append(&mut vec![0; 2]);
    }
}

#[derive(Default)]
pub struct SmbiosTable {
    entries: Vec<u8>,
}

impl SmbiosTable {
    pub fn new() -> SmbiosTable {
        SmbiosTable {
            entries: Vec::new(),
        }
    }

    fn build_type0(&mut self, type0: SmbiosType0Config) {
        let mut table0: SmbiosType0Table = SmbiosType0Table::new();

        if let Some(vender) = type0.vender {
            table0.header.vendor_idx = table0.str_index + 1;
            table0.set_str(vender);
        }

        if let Some(version) = type0.version {
            table0.header.bios_version_idx = table0.str_index + 1;
            table0.set_str(version);
        }

        if let Some(date) = type0.date {
            table0.header.bios_release_date_idx = table0.str_index + 1;
            table0.set_str(date);
        }
        table0.finish();

        self.entries.append(&mut table0.header.as_bytes().to_vec());
        self.entries.append(&mut table0.body);
    }

    fn build_type1(&mut self, type1: SmbiosType1Config) {
        let mut table1: SmbiosType1Table = SmbiosType1Table::new();

        table1.header.manufacturer = table1.str_index + 1;
        if let Some(manufacturer) = type1.manufacturer {
            table1.set_str(manufacturer);
        } else {
            table1.set_str(String::from("Stratovirt"));
        }

        table1.header.product_name = table1.str_index + 1;
        if let Some(product) = type1.product {
            table1.set_str(product);
        } else {
            table1.set_str(String::from("Virtual Machine"));
        }

        if let Some(version) = type1.version {
            table1.header.version = table1.str_index + 1;
            table1.set_str(version);
        }

        if let Some(serial) = type1.serial {
            table1.header.serial_num = table1.str_index + 1;
            table1.set_str(serial);
        }

        if let Some(sku) = type1.sku {
            table1.header.sku_num = table1.str_index + 1;
            table1.set_str(sku);
        }

        if let Some(family) = type1.family {
            table1.header.family = table1.str_index + 1;
            table1.set_str(family);
        }

        if let Some(uuid) = type1.uuid {
            for (idx, data) in uuid.name.iter().enumerate() {
                table1.header.uuid[idx] = *data;
            }
        }
        table1.finish();

        self.entries.append(&mut table1.header.as_bytes().to_vec());
        self.entries.append(&mut table1.body);
    }

    fn build_type127(&mut self) {
        let mut table127 = SmbiosType127Table::new();

        table127.finish();

        self.entries
            .append(&mut table127.header.as_bytes().to_vec());
        self.entries.append(&mut table127.body);
    }

    pub fn build_smbios_tables(&mut self, smbios: SmbiosConfig) -> Vec<u8> {
        self.build_type0(smbios.type0);
        self.build_type1(smbios.type1);
        self.build_type127();

        self.entries.clone()
    }
}

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosEntryPoint30 {
    anchor_str: [u8; 5],
    checksum: u8,
    len: u8,
    smbios_major_version: u8,
    smbios_minor_version: u8,
    smbios_doc_rev: u8,
    entry_point_revision: u8,
    reserved: u8,
    structure_table_max_size: [u8; 4],
    structure_table_address: u64,
}

impl ByteCode for SmbiosEntryPoint30 {}
impl SmbiosEntryPoint30 {
    pub fn new(table_len: u32) -> SmbiosEntryPoint30 {
        let anchor: [u8; 5] = [b'_', b'S', b'M', b'3', b'_'];
        SmbiosEntryPoint30 {
            anchor_str: anchor,
            len: size_of::<SmbiosEntryPoint30>() as u8,
            entry_point_revision: 1_u8,
            smbios_major_version: 3_u8,
            smbios_minor_version: 0_u8,
            structure_table_max_size: table_len.to_le_bytes(),
            ..Default::default()
        }
    }
}

pub fn build_smbios_ep30(table_len: u32) -> Vec<u8> {
    let ep = SmbiosEntryPoint30::new(table_len);

    ep.as_bytes().to_vec()
}
