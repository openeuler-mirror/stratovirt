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

use std::mem::size_of;

use machine_manager::config::{
    MachineConfig, SmbiosConfig, SmbiosType0Config, SmbiosType17Config, SmbiosType1Config,
    SmbiosType2Config, SmbiosType3Config, SmbiosType4Config,
};
use util::byte_code::ByteCode;

const TYPE0_HANDLE: u16 = 0x0;
const TYPE1_HANDLE: u16 = 0x100;
const TYPE2_HANDLE: u16 = 0x200;
const TYPE3_HANDLE: u16 = 0x300;
const TYPE4_HANDLE: u16 = 0x400;
const TYPE16_HANDLE: u16 = 0x1000;
const TYPE17_HANDLE: u16 = 0x1100;
const TYPE19_HANDLE: u16 = 0x1300;
const TYPE32_HANDLE: u16 = 0x2000;
const TYPE127_HANDLE: u16 = 0x7F00;

const GB_SIZE: u64 = 1_u64 << 30;
const KB_2T_SIZE: u32 = 0x80000000;
const HYPERVISOR_STR: &str = "StratoVirt";

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosHeader {
    type_num: u8,
    len: u8,
    handle: u16,
}

impl SmbiosHeader {
    fn new(type_num: u8, len: u8, handle: u16) -> SmbiosHeader {
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
    vendor_idx: u8,
    bios_version_idx: u8,
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
    fn new() -> SmbiosType0 {
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
    fn new() -> SmbiosType0Table {
        SmbiosType0Table {
            header: SmbiosType0::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
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
    manufacturer: u8,
    product_name: u8,
    version: u8,
    serial_num: u8,
    uuid: [u8; 16],
    wake_up_type: u8,
    sku_num: u8,
    family: u8,
}

impl ByteCode for SmbiosType1 {}

impl SmbiosType1 {
    fn new() -> SmbiosType1 {
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
    fn new() -> SmbiosType1Table {
        SmbiosType1Table {
            header: SmbiosType1::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type2: Baseboard information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType2 {
    header: SmbiosHeader,
    manufacturer: u8,
    product_name: u8,
    version: u8,
    serial_num: u8,
    asset_tag_num: u8,
    feature_flags: u8,
    location: u8,
    chassis_handle: [u8; 2],
    board_type: u8,
    contained_element_count: u8,
}

impl ByteCode for SmbiosType2 {}

impl SmbiosType2 {
    fn new() -> SmbiosType2 {
        SmbiosType2 {
            header: SmbiosHeader::new(2_u8, size_of::<SmbiosType2>() as u8, TYPE2_HANDLE),
            feature_flags: 1_u8,
            chassis_handle: 0x300_u16.to_le_bytes(),
            board_type: 0x0A_u8,
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType2Table {
    header: SmbiosType2,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType2Table {
    fn new() -> SmbiosType2Table {
        SmbiosType2Table {
            header: SmbiosType2::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type3: System enclosure information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType3 {
    header: SmbiosHeader,
    manufacturer: u8,
    type_id: u8,
    version: u8,
    serial_num: u8,
    asset_tag_num: u8,
    boot_up_state: u8,
    power_supply_state: u8,
    thermal_state: u8,
    security_status: u8,
    oem_defined: [u8; 4],
    height: u8,
    number_of_power_cords: u8,
    contained_element_count: u8,
    contained_element_record_length: u8,
    sku_num: u8,
}

impl ByteCode for SmbiosType3 {}

impl SmbiosType3 {
    fn new() -> SmbiosType3 {
        SmbiosType3 {
            header: SmbiosHeader::new(3_u8, size_of::<SmbiosType3>() as u8, TYPE3_HANDLE),
            type_id: 0x1_u8,
            boot_up_state: 0x03_u8,
            power_supply_state: 0x03_u8,
            thermal_state: 0x03_u8,
            security_status: 0x02_u8,
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType3Table {
    header: SmbiosType3,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType3Table {
    fn new() -> SmbiosType3Table {
        SmbiosType3Table {
            header: SmbiosType3::new(),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type4: Processor information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType4 {
    header: SmbiosHeader,
    socket_design: u8,
    processor_type: u8,
    processor_family: u8,
    processor_manufacturer: u8,
    processor_id0: [u8; 4],
    processor_id1: [u8; 4],
    processor_version: u8,
    voltage: u8,
    external_clock: [u8; 2],
    max_speed: [u8; 2],
    current_speed: [u8; 2],
    status: u8,
    processor_upgrade: u8,
    l1_cache_handle: [u8; 2],
    l2_cache_handle: [u8; 2],
    l3_cache_handle: [u8; 2],
    serial_num: u8,
    asset_tag_num: u8,
    part_num: u8,
    core_count: u8,
    core_enabled: u8,
    thread_count: u8,
    processor_characteristics: [u8; 2],
    processor_family2: [u8; 2],
    core_count2: [u8; 2],
    core_enabled2: [u8; 2],
    thread_count2: [u8; 2],
}

impl ByteCode for SmbiosType4 {}

impl SmbiosType4 {
    fn new(instance: u16) -> SmbiosType4 {
        SmbiosType4 {
            header: SmbiosHeader::new(
                4_u8,
                size_of::<SmbiosType4>() as u8,
                TYPE4_HANDLE + instance,
            ),
            processor_type: 0x03_u8,
            processor_family: 0x01_u8,
            status: 0x41_u8,
            processor_upgrade: 0x01_u8,
            l1_cache_handle: 0xFFFF_u16.to_le_bytes(),
            l2_cache_handle: 0xFFFF_u16.to_le_bytes(),
            l3_cache_handle: 0xFFFF_u16.to_le_bytes(),
            processor_characteristics: 0x02_u16.to_le_bytes(),
            processor_family2: 0x01_u16.to_le_bytes(),
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType4Table {
    header: SmbiosType4,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType4Table {
    fn new(instance: u16) -> SmbiosType4Table {
        SmbiosType4Table {
            header: SmbiosType4::new(instance),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type16: Physical memory array information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType16 {
    header: SmbiosHeader,
    location: u8,
    used: u8,
    error_correction: u8,
    maximum_capacity: [u8; 4],
    memory_error_information_handle: [u8; 2],
    number_of_memory_devices: [u8; 2],
    extended_maximum_capacity: [u8; 8],
}

impl ByteCode for SmbiosType16 {}

impl SmbiosType16 {
    fn new(cnt: u16) -> SmbiosType16 {
        SmbiosType16 {
            header: SmbiosHeader::new(16_u8, size_of::<SmbiosType16>() as u8, TYPE16_HANDLE),
            location: 0x01,
            used: 0x03,
            error_correction: 0x06,
            memory_error_information_handle: 0xFFFE_u16.to_le_bytes(),
            number_of_memory_devices: cnt.to_le_bytes(),
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType16Table {
    header: SmbiosType16,
    body: Vec<u8>,
}

impl SmbiosType16Table {
    fn new(cnt: u16) -> SmbiosType16Table {
        SmbiosType16Table {
            header: SmbiosType16::new(cnt),
            body: Vec::new(),
        }
    }

    fn finish(&mut self) {
        self.body.append(&mut vec![0; 2]);
    }
}

/// Type17: memory device
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType17 {
    header: SmbiosHeader,
    physical_memory_array_handle: [u8; 2],
    memory_error_information_handle: [u8; 2],
    total_width: [u8; 2],
    data_width: [u8; 2],
    size: [u8; 2],
    form_factor: u8,
    device_set: u8,
    device_locator_str: u8,
    bank_locator_str: u8,
    memory_type: u8,
    type_detail: [u8; 2],
    speed: [u8; 2],
    manufacturer_str: u8,
    serial_number_str: u8,
    asset_tag_number_str: u8,
    part_number_str: u8,
    attributes: u8,
    extended_size: [u8; 4],
    configured_clock_speed: [u8; 2],
    minimum_voltage: [u8; 2],
    maximum_voltage: [u8; 2],
    configured_voltage: [u8; 2],
}

impl ByteCode for SmbiosType17 {}

impl SmbiosType17 {
    fn new(ins: u16) -> SmbiosType17 {
        SmbiosType17 {
            header: SmbiosHeader::new(17_u8, size_of::<SmbiosType17>() as u8, TYPE17_HANDLE + ins),
            physical_memory_array_handle: 0x1000_u16.to_le_bytes(),
            memory_error_information_handle: 0xFFFE_u16.to_le_bytes(),
            total_width: 0xFFFF_u16.to_le_bytes(),
            data_width: 0xFFFF_u16.to_le_bytes(),
            form_factor: 0x09,
            memory_type: 0x07,
            type_detail: 0x02_u16.to_le_bytes(),
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType17Table {
    header: SmbiosType17,
    body: Vec<u8>,
    str_index: u8,
}

impl SmbiosType17Table {
    fn new(ins: u16) -> SmbiosType17Table {
        SmbiosType17Table {
            header: SmbiosType17::new(ins),
            body: Vec::new(),
            str_index: 0_u8,
        }
    }

    fn set_str(&mut self, str: String) {
        self.str_index += 1;
        self.body.append(&mut str.as_bytes().to_vec());
        self.body.append(&mut vec![0]);
    }

    fn finish(&mut self) {
        if self.str_index == 0 {
            self.body.append(&mut vec![0; 2]);
        } else {
            self.body.append(&mut vec![0]);
        }
    }
}

/// Type19: Memory device information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType19 {
    header: SmbiosHeader,
    starting_address: [u8; 4],
    ending_address: [u8; 4],
    memory_array_handle: [u8; 2],
    partition_width: u8,
    extended_starting_address: [u8; 8],
    extended_ending_address: [u8; 8],
}

impl ByteCode for SmbiosType19 {}

impl SmbiosType19 {
    fn new(ins: u16) -> SmbiosType19 {
        SmbiosType19 {
            header: SmbiosHeader::new(19_u8, size_of::<SmbiosType19>() as u8, TYPE19_HANDLE + ins),
            memory_array_handle: 0x1000_u16.to_le_bytes(),
            partition_width: 1,
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType19Table {
    header: SmbiosType19,
    body: Vec<u8>,
}

impl SmbiosType19Table {
    fn new(ins: u16) -> SmbiosType19Table {
        SmbiosType19Table {
            header: SmbiosType19::new(ins),
            body: Vec::new(),
        }
    }

    fn finish(&mut self) {
        self.body.append(&mut vec![0; 2]);
    }
}

/// Type32: boot information
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType32 {
    header: SmbiosHeader,
    reserved: [u8; 6],
    boot_status: u8,
}

impl ByteCode for SmbiosType32 {}

impl SmbiosType32 {
    fn new() -> SmbiosType32 {
        SmbiosType32 {
            header: SmbiosHeader::new(32_u8, size_of::<SmbiosType32>() as u8, TYPE32_HANDLE),
            ..Default::default()
        }
    }
}

#[derive(Default, Clone)]
struct SmbiosType32Table {
    header: SmbiosType32,
    body: Vec<u8>,
}

impl SmbiosType32Table {
    fn new() -> SmbiosType32Table {
        SmbiosType32Table {
            header: SmbiosType32::new(),
            body: Vec::new(),
        }
    }

    fn finish(&mut self) {
        self.body.append(&mut vec![0; 2]);
    }
}

/// Type127: End of table
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
struct SmbiosType127 {
    header: SmbiosHeader,
}

impl SmbiosType127 {
    fn new() -> SmbiosType127 {
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
    fn new() -> SmbiosType127Table {
        SmbiosType127Table {
            header: SmbiosType127::new(),
            body: Vec::new(),
        }
    }

    fn finish(&mut self) {
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
            table1.set_str(String::from(HYPERVISOR_STR));
        }

        table1.header.product_name = table1.str_index + 1;
        if let Some(product) = type1.product {
            table1.set_str(product);
        } else {
            table1.set_str(String::from("Virtual Machine"));
        }

        table1.header.version = table1.str_index + 1;
        if let Some(version) = type1.version {
            table1.set_str(version);
        } else {
            table1.set_str(String::from(HYPERVISOR_STR));
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

    fn build_type2(&mut self, type2: SmbiosType2Config) {
        if !type2.added {
            return;
        }
        let mut table2 = SmbiosType2Table::new();

        table2.header.manufacturer = table2.str_index + 1;
        if let Some(manufacturer) = type2.manufacturer {
            table2.set_str(manufacturer);
        } else {
            table2.set_str(String::from(HYPERVISOR_STR));
        }

        table2.header.product_name = table2.str_index + 1;
        if let Some(product) = type2.product {
            table2.set_str(product);
        } else {
            table2.set_str(String::from("Virtual Machine"));
        }

        table2.header.version = table2.str_index + 1;
        if let Some(version) = type2.version {
            table2.set_str(version);
        } else {
            table2.set_str(String::from(HYPERVISOR_STR));
        }

        if let Some(serial) = type2.serial {
            table2.header.serial_num = table2.str_index + 1;
            table2.set_str(serial);
        }

        if let Some(location) = type2.location {
            table2.header.location = table2.str_index + 1;
            table2.set_str(location);
        }

        if let Some(asset) = type2.asset {
            table2.header.asset_tag_num = table2.str_index + 1;
            table2.set_str(asset);
        }

        table2.finish();

        self.entries.append(&mut table2.header.as_bytes().to_vec());
        self.entries.append(&mut table2.body);
    }

    fn build_type3(&mut self, type3: SmbiosType3Config) {
        let mut table3 = SmbiosType3Table::new();

        table3.header.manufacturer = table3.str_index + 1;
        if let Some(manufacturer) = type3.manufacturer {
            table3.set_str(manufacturer);
        } else {
            table3.set_str(String::from(HYPERVISOR_STR));
        }

        table3.header.version = table3.str_index + 1;
        if let Some(version) = type3.version {
            table3.set_str(version);
        } else {
            table3.set_str(String::from(HYPERVISOR_STR));
        }

        if let Some(serial) = type3.serial {
            table3.header.serial_num = table3.str_index + 1;
            table3.set_str(serial);
        }

        if let Some(sku) = type3.sku {
            table3.header.sku_num = table3.str_index + 1;
            table3.set_str(sku);
        }

        if let Some(asset) = type3.asset {
            table3.header.asset_tag_num = table3.str_index + 1;
            table3.set_str(asset);
        }

        table3.finish();

        self.entries.append(&mut table3.header.as_bytes().to_vec());
        self.entries.append(&mut table3.body);
    }

    fn build_type4(&mut self, type4: SmbiosType4Config, instance: u16, mach_cfg: &MachineConfig) {
        let mut table4 = SmbiosType4Table::new(instance);

        table4.header.socket_design = table4.str_index + 1;
        if let Some(sock_str) = type4.sock_pfx {
            table4.set_str(std::format!("{}{:2x}", sock_str, instance));
        } else {
            table4.set_str(std::format!("CPU{:2x}", instance));
        }

        table4.header.processor_manufacturer = table4.str_index + 1;
        if let Some(manufacturer) = type4.manufacturer {
            table4.set_str(manufacturer);
        } else {
            table4.set_str(String::from(HYPERVISOR_STR));
        }

        table4.header.processor_version = table4.str_index + 1;
        if let Some(version) = type4.version {
            table4.set_str(version);
        } else {
            table4.set_str(String::from(HYPERVISOR_STR));
        }

        if let Some(serial) = type4.serial {
            table4.header.serial_num = table4.str_index + 1;
            table4.set_str(serial);
        }

        if let Some(asset) = type4.asset {
            table4.header.asset_tag_num = table4.str_index + 1;
            table4.set_str(asset);
        }

        if let Some(part) = type4.part {
            table4.header.part_num = table4.str_index + 1;
            table4.set_str(part);
        }

        if let Some(max_speed) = type4.max_speed {
            table4.header.max_speed = (max_speed as u16).to_le_bytes();
        } else {
            table4.header.max_speed = 2000_u16.to_le_bytes();
        }

        if let Some(current_speed) = type4.current_speed {
            table4.header.current_speed = (current_speed as u16).to_le_bytes();
        } else {
            table4.header.current_speed = 2000_u16.to_le_bytes();
        }

        table4.header.core_count = mach_cfg.nr_cores;
        table4.header.core_enabled = mach_cfg.nr_cores;

        table4.header.core_count2 = (mach_cfg.nr_cores as u16).to_le_bytes();
        table4.header.core_enabled2 = (mach_cfg.nr_cores as u16).to_le_bytes();

        table4.header.thread_count = mach_cfg.nr_threads;
        table4.header.thread_count2 = (mach_cfg.nr_threads as u16).to_le_bytes();
        table4.finish();

        self.entries.append(&mut table4.header.as_bytes().to_vec());
        self.entries.append(&mut table4.body);
    }

    fn build_type16(&mut self, size: u64, number_device: u16) {
        let mut table16 = SmbiosType16Table::new(1);

        let size_kb = (size / 1024) as u32;
        if size_kb < KB_2T_SIZE {
            table16.header.maximum_capacity = size_kb.to_le_bytes();
        } else {
            table16.header.maximum_capacity = KB_2T_SIZE.to_le_bytes();
            table16.header.extended_maximum_capacity = size.to_le_bytes();
        }
        table16.header.number_of_memory_devices = number_device.to_le_bytes();
        table16.finish();

        self.entries.append(&mut table16.header.as_bytes().to_vec());
        self.entries.append(&mut table16.body);
    }

    fn build_type17(&mut self, type17: SmbiosType17Config, ins: u16, size: u64) {
        let mut table17 = SmbiosType17Table::new(ins);

        let size_mb = (size / 1024 / 1024) as u16;
        table17.header.size = size_mb.to_le_bytes();

        table17.header.manufacturer_str = table17.str_index + 1;
        if let Some(manufacturer) = type17.manufacturer {
            table17.set_str(manufacturer);
        } else {
            table17.set_str(String::from(HYPERVISOR_STR));
        }
        table17.header.device_locator_str = table17.str_index + 1;
        if let Some(loc_pfx) = type17.loc_pfx {
            table17.set_str(std::format!("{} {}", loc_pfx, ins));
        } else {
            table17.set_str(std::format!("DIMM {}", ins));
        }

        if let Some(bank) = type17.bank {
            table17.header.bank_locator_str = table17.str_index + 1;
            table17.set_str(bank);
        }

        if let Some(serial) = type17.serial {
            table17.header.serial_number_str = table17.str_index + 1;
            table17.set_str(serial);
        }

        if let Some(part) = type17.part {
            table17.header.part_number_str = table17.str_index + 1;
            table17.set_str(part);
        }

        if let Some(asset) = type17.asset {
            table17.header.asset_tag_number_str = table17.str_index + 1;
            table17.set_str(asset);
        }
        table17.header.speed = type17.speed.to_le_bytes();
        table17.header.configured_clock_speed = type17.speed.to_le_bytes();
        table17.finish();

        self.entries.append(&mut table17.header.as_bytes().to_vec());
        self.entries.append(&mut table17.body);
    }

    fn build_type19(&mut self, ins: u16, start: u64, size: u64) {
        let mut table19 = SmbiosType19Table::new(ins);

        let start_kb = start / 1024;
        let end_kb = (start + size - 1) / 1024;

        if start_kb < u32::MAX as u64 && end_kb < u32::MAX as u64 {
            table19.header.starting_address = (start_kb as u32).to_le_bytes();
            table19.header.ending_address = (end_kb as u32).to_le_bytes();
        } else {
            table19.header.starting_address = u32::MAX.to_le_bytes();
            table19.header.ending_address = u32::MAX.to_le_bytes();
            table19.header.extended_starting_address = start.to_le_bytes();
            table19.header.extended_ending_address = (start + size - 1).to_le_bytes();
        }

        table19.finish();

        self.entries.append(&mut table19.header.as_bytes().to_vec());
        self.entries.append(&mut table19.body);
    }

    fn build_type32(&mut self) {
        let mut table32 = SmbiosType32Table::new();

        table32.finish();

        self.entries.append(&mut table32.header.as_bytes().to_vec());
        self.entries.append(&mut table32.body);
    }

    fn build_type127(&mut self) {
        let mut table127 = SmbiosType127Table::new();

        table127.finish();

        self.entries
            .append(&mut table127.header.as_bytes().to_vec());
        self.entries.append(&mut table127.body);
    }

    pub fn build_smbios_tables(
        &mut self,
        smbios: SmbiosConfig,
        mach_cfg: &MachineConfig,
        mem_arr: Vec<(u64, u64)>,
    ) -> Vec<u8> {
        self.build_type0(smbios.type0);
        self.build_type1(smbios.type1);
        self.build_type2(smbios.type2);
        self.build_type3(smbios.type3);

        let smbios_sockets = mach_cfg.nr_cpus / (mach_cfg.nr_cores * mach_cfg.nr_threads);
        for i in 0..smbios_sockets {
            self.build_type4(smbios.type4.clone(), i as u16, mach_cfg);
        }
        let mem_num = ((mach_cfg.mem_config.mem_size + 16 * GB_SIZE - 1) / (16 * GB_SIZE)) as u16;
        self.build_type16(mach_cfg.mem_config.mem_size, mem_num);

        for i in 0..mem_num {
            let memdev_size = if i < mem_num - 1 {
                16 * GB_SIZE
            } else {
                (mach_cfg.mem_config.mem_size - 1) % (16 * GB_SIZE) + 1
            };
            self.build_type17(smbios.type17.clone(), i, memdev_size);
        }

        let offset = if mem_num > (TYPE19_HANDLE - TYPE17_HANDLE) {
            mem_num - (TYPE19_HANDLE - TYPE17_HANDLE)
        } else {
            0_u16
        };
        for (index, (start, size)) in mem_arr.iter().enumerate() {
            self.build_type19(offset + index as u16, *start, *size);
        }
        self.build_type32();
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
    fn new(table_len: u32) -> SmbiosEntryPoint30 {
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
