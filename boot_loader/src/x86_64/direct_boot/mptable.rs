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

use crate::error::BootLoaderError;
use address_space::{AddressSpace, GuestAddress};
use util::byte_code::ByteCode;
use util::checksum::obj_checksum;

const SPEC_VERSION: u8 = 4; // version 1.4
const APIC_VERSION: u8 = 0x14;

// Variables and Structures below sourced from:
// Intel MultiProcessor Specification 1.4
const CPU_FLAGS_ENABLE: u8 = 0x1;
const CPU_FLAGS_BSP: u8 = 0x2;
const APIC_FLAGS_ENABLE: u8 = 0x1;

pub const INTERRUPT_TYPE_INT: u8 = 0;
pub const INTERRUPT_TYPE_NMI: u8 = 1;
pub const INTERRUPT_TYPE_EXTINT: u8 = 3;
pub const DEST_ALL_LAPIC_MASK: u8 = 0xff;

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct FloatingPointer {
    signature: [u8; 4],
    pointer: u32,
    length: u8,
    spec: u8,
    checksum: u8,
    feature1: u8,
    feature2: u32,
}

impl ByteCode for FloatingPointer {}

impl FloatingPointer {
    pub fn new(pointer: u32) -> Self {
        let mut fp = FloatingPointer {
            signature: [b'_', b'M', b'P', b'_'],
            pointer,
            length: 1, // spec: 01h
            spec: SPEC_VERSION,
            checksum: 0,
            feature1: 0,
            feature2: 0,
        };

        let sum = obj_checksum(&fp);
        fp.checksum = (-(sum as i8)) as u8;

        fp
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ConfigTableHeader {
    signature: [u8; 4],
    length: u16,
    spec: u8,
    checksum: u8,
    oem_id: [u8; 8],
    product_id: [u8; 12],
    oem_table_pointer: u32,
    oem_table_size: u16,
    entry_count: u16,
    lapic_addr: u32,
    ext_table_length: u16,
    ext_table_checksum: u8,
    reserved: u8,
}

impl ByteCode for ConfigTableHeader {}

impl ConfigTableHeader {
    pub fn new(length: u16, sum: u8, lapic_addr: u32) -> Self {
        let mut ct = ConfigTableHeader {
            signature: [b'P', b'C', b'M', b'P'],
            length,
            spec: SPEC_VERSION,
            checksum: 0,
            oem_id: [b'S', b'T', b'R', b'A', b'T', b'O', 0x0, 0x0],
            product_id: [
                b'1', b'.', b'0', 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            ],
            oem_table_pointer: 0,
            oem_table_size: 0,
            entry_count: 0,
            lapic_addr,
            ext_table_length: 0,
            ext_table_checksum: 0,
            reserved: 0,
        };

        let sum = sum.wrapping_add(obj_checksum(&ct));
        ct.checksum = (-(sum as i8)) as u8;

        ct
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ProcessEntry {
    type_: u8,
    lapic_id: u8,
    lapic_version: u8,
    cpu_flags: u8,
    cpu_signature: u32,
    feature_flags: u32,
    reserved: u32,
    reserved1: u32,
}

impl ByteCode for ProcessEntry {}

impl ProcessEntry {
    pub fn new(lapic_id: u8, enable: bool, bsp: bool) -> Self {
        let mut cpu_flags = if enable { CPU_FLAGS_ENABLE } else { 0 };
        if bsp {
            cpu_flags |= CPU_FLAGS_BSP;
        }

        ProcessEntry {
            type_: 0,
            lapic_id,
            lapic_version: APIC_VERSION,
            cpu_flags,
            cpu_signature: 0x600, // Intel CPU Family Number: 0x6
            feature_flags: 0x201, // APIC & FPU
            reserved: 0,
            reserved1: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BusEntry {
    type_: u8,
    bus_id: u8,
    bus_type: [u8; 6],
}

impl ByteCode for BusEntry {}

impl BusEntry {
    pub fn new(bus_id: u8) -> Self {
        BusEntry {
            type_: 1,
            bus_id,
            bus_type: [b'I', b'S', b'A', 0x0, 0x0, 0x0],
        }
    }
}

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IOApicEntry {
    type_: u8,
    ioapic_id: u8,
    ioapic_version: u8,
    ioapic_flags: u8,
    ioapic_addr: u32,
}

impl ByteCode for IOApicEntry {}

impl IOApicEntry {
    pub fn new(ioapic_id: u8, enable: bool, ioapic_addr: u32) -> Self {
        let ioapic_flags = if enable { APIC_FLAGS_ENABLE } else { 0 };

        IOApicEntry {
            type_: 2,
            ioapic_id,
            ioapic_version: APIC_VERSION,
            ioapic_flags,
            ioapic_addr,
        }
    }
}

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IOInterruptEntry {
    type_: u8,
    interrupt_type: u8,
    interrupt_flags: u16,
    source_bus_id: u8,
    source_bus_irq: u8,
    dest_ioapic_id: u8,
    dest_ioapic_int: u8,
}

impl ByteCode for IOInterruptEntry {}

impl IOInterruptEntry {
    pub fn new(
        interrupt_type: u8,
        source_bus_id: u8,
        source_bus_irq: u8,
        dest_ioapic_id: u8,
        dest_ioapic_int: u8,
    ) -> Self {
        IOInterruptEntry {
            type_: 3,
            interrupt_type,
            interrupt_flags: 0, // conforms to spec of bus
            source_bus_id,
            source_bus_irq,
            dest_ioapic_id,
            dest_ioapic_int,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct LocalInterruptEntry {
    type_: u8,
    interrupt_type: u8,
    interrupt_flags: u16,
    source_bus_id: u8,
    source_bus_irq: u8,
    dest_lapic_id: u8,
    dest_lapic_lint: u8,
}

impl ByteCode for LocalInterruptEntry {}

impl LocalInterruptEntry {
    pub fn new(
        interrupt_type: u8,
        source_bus_id: u8,
        source_bus_irq: u8,
        dest_lapic_id: u8,
        dest_lapic_lint: u8,
    ) -> Self {
        LocalInterruptEntry {
            type_: 4,
            interrupt_type,
            interrupt_flags: 0, // conforms to spec of bus
            source_bus_id,
            source_bus_irq,
            dest_lapic_id,
            dest_lapic_lint,
        }
    }
}

macro_rules! write_entry {
    ( $d:expr, $t:ty, $m:expr, $o:expr, $s:expr ) => {
        let entry = $d;
        $m.write_object(&entry, GuestAddress($o))?;
        $o += std::mem::size_of::<$t>() as u64;
        $s = $s.wrapping_add(obj_checksum(&entry));
    };
}

pub fn setup_isa_mptable(
    sys_mem: &Arc<AddressSpace>,
    start_addr: u64,
    num_cpus: u8,
    ioapic_addr: u32,
    lapic_addr: u32,
) -> Result<()> {
    const BUS_ID: u8 = 0;
    // mptable max support 255 cpus, reserve one for ioapic id
    const MPTABLE_MAX_CPUS: u32 = 254;
    const MPTABLE_IOAPIC_NR: u8 = 16;

    if u32::from(num_cpus) > MPTABLE_MAX_CPUS {
        return Err(anyhow!(BootLoaderError::MaxCpus(num_cpus)));
    }

    let ioapic_id: u8 = num_cpus + 1;
    let header = start_addr + std::mem::size_of::<FloatingPointer>() as u64;
    sys_mem.write_object(
        &FloatingPointer::new(header as u32),
        GuestAddress(start_addr),
    )?;

    let mut offset = header + std::mem::size_of::<ConfigTableHeader>() as u64;
    let mut sum = 0u8;
    for cpu_id in 0..num_cpus {
        write_entry!(
            ProcessEntry::new(cpu_id, true, cpu_id == 0),
            ProcessEntry,
            sys_mem,
            offset,
            sum
        );
    }

    write_entry!(BusEntry::new(BUS_ID), BusEntry, sys_mem, offset, sum);
    write_entry!(
        IOApicEntry::new(ioapic_id, true, ioapic_addr),
        IOApicEntry,
        sys_mem,
        offset,
        sum
    );

    for i in 0..MPTABLE_IOAPIC_NR {
        write_entry!(
            IOInterruptEntry::new(INTERRUPT_TYPE_INT, BUS_ID, i, ioapic_id, i),
            IOInterruptEntry,
            sys_mem,
            offset,
            sum
        );
    }

    write_entry!(
        LocalInterruptEntry::new(INTERRUPT_TYPE_EXTINT, BUS_ID, 0, ioapic_id, 0),
        LocalInterruptEntry,
        sys_mem,
        offset,
        sum
    );
    write_entry!(
        LocalInterruptEntry::new(INTERRUPT_TYPE_NMI, BUS_ID, 0, DEST_ALL_LAPIC_MASK, 1),
        LocalInterruptEntry,
        sys_mem,
        offset,
        sum
    );

    sys_mem.write_object(
        &ConfigTableHeader::new((offset - header) as u16, sum, lapic_addr),
        GuestAddress(header),
    )?;

    Ok(())
}
