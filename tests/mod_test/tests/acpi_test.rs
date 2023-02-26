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

use acpi::{
    AcpiGicCpu, AcpiGicDistributor, AcpiGicRedistributor, AcpiRsdp, AcpiSratGiccAffinity,
    AcpiSratMemoryAffinity, AcpiTableHeader, ProcessorHierarchyNode,
};
use byteorder::{ByteOrder, LittleEndian};
use machine::standard_vm::aarch64::{LayoutEntryType, MEM_LAYOUT};
use mod_test::libdriver::machine::TestStdMachine;
use mod_test::libdriver::malloc::GuestAllocator;
use std::{cell::RefCell, mem, rc::Rc};

use mod_test::libdriver::fwcfg::bios_args;
use mod_test::libtest::{test_init, TestState};

fn test_rsdp(test_state: &TestState, alloc: &mut GuestAllocator) -> u64 {
    let file_name = "etc/acpi/rsdp";
    let mut read_data: Vec<u8> = Vec::with_capacity(mem::size_of::<AcpiRsdp>());

    // Select FileDir entry and read it.
    let file_size = test_state.fw_cfg_read_file(
        alloc,
        file_name,
        &mut read_data,
        mem::size_of::<AcpiRsdp>() as u32,
    );

    assert_eq!(file_size, mem::size_of::<AcpiRsdp>() as u32);
    // Check RSDP signature: "RSD PTR".
    assert_eq!(String::from_utf8_lossy(&read_data[..8]), "RSD PTR ");
    // Check RSDP revison: 2.
    assert_eq!(read_data[15], 2);

    // Check 32-bit address of RSDT table: 0
    let rsdt_addr = LittleEndian::read_u32(&read_data[16..]);
    assert_eq!(rsdt_addr, 0);

    // Check 64-bit address of XSDT table.
    let xsdt_addr = LittleEndian::read_u64(&read_data[24..]);
    assert_ne!(xsdt_addr, 0);

    xsdt_addr
}

fn check_dsdt(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "DSDT");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 736); // Check length
}

fn check_fadt(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "FACP");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 276); // Check length

    assert_eq!(LittleEndian::read_i32(&data[112..]), 0x10_0500); // Enable HW_REDUCED_ACPI bit
    assert_eq!(LittleEndian::read_u16(&data[129..]), 0x3); // ARM Boot Architecture Flags
    assert_eq!(LittleEndian::read_i32(&data[131..]), 3); // FADT minor revision
}

fn check_madt(data: &[u8], cpu: u8) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "APIC");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 744); // Check length

    let mut offset = 44;

    // Check GIC Distributor
    assert_eq!(
        data[offset + 1] as usize,
        mem::size_of::<AcpiGicDistributor>()
    );
    let gicd_addr = LittleEndian::read_u64(&data[(offset + 8)..]);
    assert_eq!(gicd_addr, MEM_LAYOUT[LayoutEntryType::GicDist as usize].0);

    // Check GIC verison
    assert_eq!(data[offset + 20], 3);

    // Check GIC CPU
    offset = offset + mem::size_of::<AcpiGicDistributor>();
    for i in 0..cpu {
        assert_eq!(data[offset + 1], 80); // The length of this structure
        assert_eq!(LittleEndian::read_u32(&data[(offset + 4)..]), i as u32); // CPU interface number
        assert_eq!(LittleEndian::read_u32(&data[(offset + 8)..]), i as u32); // ACPI processor UID
        assert_eq!(LittleEndian::read_u32(&data[(offset + 12)..]), 5); // Flags
        assert_eq!(LittleEndian::read_u32(&data[(offset + 20)..]), 23); // Performance monitoring interrupts
        assert_eq!(LittleEndian::read_u64(&data[(offset + 56)..]), 25); // Virtual GIC maintenance interrupt
        assert_eq!(LittleEndian::read_u64(&data[(offset + 68)..]), i as u64); // MPIDR
        offset = offset + mem::size_of::<AcpiGicCpu>();
    }

    // Check GIC Redistributor
    let mut addr = LittleEndian::read_u64(&data[(offset + 4)..]);
    assert_eq!(MEM_LAYOUT[LayoutEntryType::GicRedist as usize].0, addr);

    // Check GIC Its
    offset = offset + mem::size_of::<AcpiGicRedistributor>();
    addr = LittleEndian::read_u64(&data[(offset + 8)..]);
    assert_eq!(MEM_LAYOUT[LayoutEntryType::GicIts as usize].0, addr);
}

fn check_gtdt(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "GTDT");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 96); // Check length

    assert_eq!(LittleEndian::read_u32(&data[48..]), 29); // Secure EL1 interrupt
    assert_eq!(LittleEndian::read_u32(&data[52..]), 0); // Secure EL1 flags
    assert_eq!(LittleEndian::read_u32(&data[56..]), 30); // Non secure EL1 interrupt
    assert_eq!(LittleEndian::read_u32(&data[60..]), 4); // Non secure EL1 flags
    assert_eq!(LittleEndian::read_u32(&data[64..]), 27); // Virtual timer interrupt
    assert_eq!(LittleEndian::read_u32(&data[68..]), 0); // Virtual timer flags
    assert_eq!(LittleEndian::read_u32(&data[72..]), 26); // Non secure EL2 interrupt
    assert_eq!(LittleEndian::read_u32(&data[76..]), 0); // Non secure EL2 flags
}

fn check_iort(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "IORT");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 128); // Check length

    // Check IORT nodes is 2: ITS group node and Root Complex Node.
    assert_eq!(LittleEndian::read_u32(&data[36..]), 2);
    assert_eq!(LittleEndian::read_u32(&data[40..]), 48); // Node offset
    assert_eq!(data[48], 0); // ITS group node
    assert_eq!(LittleEndian::read_u16(&data[49..]), 24); // ITS node length
    assert_eq!(LittleEndian::read_u32(&data[64..]), 1); // ITS count
    assert_eq!(data[72], 2); // Root Complex Node
    assert_eq!(LittleEndian::read_u16(&data[73..]), 56); // Length of Root Complex Node
    assert_eq!(LittleEndian::read_u32(&data[80..]), 1); // Mapping counts of Root Complex Node
    assert_eq!(LittleEndian::read_u32(&data[84..]), 36); // Mapping offset of Root Complex Node
    assert_eq!(LittleEndian::read_u32(&data[88..]), 1); // Cache of coherent device
    assert_eq!(data[95], 3); // Memory flags of coherent device
    assert_eq!(LittleEndian::read_u32(&data[112..]), 0xffff); // Identity RID mapping
    assert_eq!(LittleEndian::read_u32(&data[120..]), 48); // Without SMMU, id mapping is the first node in ITS group node
}

fn check_spcr(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "SPCR");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 80); // Check length

    assert_eq!(data[36], 3); // Interface type: ARM PL011 UART
    assert_eq!(data[41], 8); // Bit width of AcpiGenericAddress
    assert_eq!(data[43], 1); // Access width of AcpiGenericAddress
    assert_eq!(
        LittleEndian::read_u64(&data[44..]),
        MEM_LAYOUT[LayoutEntryType::Uart as usize].0
    );
    assert_eq!(data[52], 1_u8 << 3); // Interrupt Type: Arm GIC interrupu
    assert_eq!(LittleEndian::read_u32(&data[54..]), 65); // Irq number used by the UART
    assert_eq!(data[58], 3); // Set baud rate: 3 = 9600
    assert_eq!(data[60], 1); // Stop bit
    assert_eq!(data[61], 2); // Hardware flow control
    assert_eq!(LittleEndian::read_u16(&data[64..]), 0xffff); // PCI Device ID: it is not a PCI device
    assert_eq!(LittleEndian::read_u16(&data[66..]), 0xffff); // PCI Vendor ID: it is not a PCI device
}

fn check_mcfg(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "MCFG");
    assert_eq!(LittleEndian::read_u32(&data[4..]), 60); // Check length

    assert_eq!(
        LittleEndian::read_u64(&data[44..]),
        MEM_LAYOUT[LayoutEntryType::HighPcieEcam as usize].0
    );
    assert_eq!(LittleEndian::read_u16(&data[52..]), 0); // PCI Segment Group Number
    assert_eq!(data[54], 0); // Start Bus Number
    assert_eq!(data[55], 255); // End Bus Number
}

fn check_srat(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "SRAT");

    // offset = AcpiTable.len = 36 + reserved.len = 12
    let mut offset = 36 + 12;
    let mut base_addr = MEM_LAYOUT[LayoutEntryType::Mem as usize].0;
    // Check Numa Node:
    // -object memory-backend-ram,size=2G,id=mem0,host-nodes=0-1,policy=bind
    // -object memory-backend-ram,size=2G,id=mem1,host-nodes=0-1,policy=bind
    // -numa node,nodeid=0,cpus=0-3,memdev=mem0
    // -numa node,nodeid=1,cpus=4-7,memdev=mem1
    for i in 0..2 {
        for j in 0..4 {
            let proximity_domian = LittleEndian::read_u32(&data[(offset + 2)..]);
            assert_eq!(proximity_domian, i);
            let process_uid = LittleEndian::read_u32(&data[(offset + 6)..]);
            assert_eq!(process_uid, (i * 4) + j);
            offset = offset + mem::size_of::<AcpiSratGiccAffinity>();
        }
        assert_eq!(LittleEndian::read_u64(&data[(offset + 8)..]), base_addr);
        let size = LittleEndian::read_u64(&data[(offset + 16)..]);
        assert_eq!(size, 0x8000_0000);
        base_addr = base_addr + size;
        offset = offset + mem::size_of::<AcpiSratMemoryAffinity>();
    }
}

fn check_slit(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "SLIT");

    // offset = AcpiTable.len + NumaNode.len
    let mut offset = 44;
    // -numa dist,src=0,dst=1,val=30
    // -numa dist,src=1,dst=0,val=30
    for i in 0..2 {
        for j in 0..2 {
            if i == j {
                assert_eq!(data[offset], 10);
            } else {
                assert_eq!(data[offset], 30);
            }
            offset = offset + 1;
        }
    }
}

fn check_pptt(data: &[u8]) {
    assert_eq!(String::from_utf8_lossy(&data[..4]), "PPTT");

    // offset = AcpiTable.len = 36
    let mut offset = 36;
    // sockets = 1, clusters = 1, cores = 4, threads = 2
    // Check sockets flags and processor_id.
    assert_eq!(LittleEndian::read_u32(&data[(offset + 4)..]), 1);
    assert_eq!(LittleEndian::read_u32(&data[(offset + 12)..]), 0);

    // Check clusters flags and processor_id.
    offset = offset + mem::size_of::<ProcessorHierarchyNode>();
    assert_eq!(LittleEndian::read_u32(&data[(offset + 4)..]), 0);
    assert_eq!(LittleEndian::read_u32(&data[(offset + 12)..]), 0);

    // Check cores flags and processor_id.
    for i in 0..4 {
        offset = offset + mem::size_of::<ProcessorHierarchyNode>();
        assert_eq!(LittleEndian::read_u32(&data[(offset + 4)..]), 0);
        assert_eq!(LittleEndian::read_u32(&data[(offset + 12)..]), i);
        for j in 0..2 {
            // Check threads flags and processor_id.
            offset = offset + mem::size_of::<ProcessorHierarchyNode>();
            assert_eq!(LittleEndian::read_u32(&data[(offset + 4)..]), 0xE);
            assert_eq!(LittleEndian::read_u32(&data[(offset + 12)..]), i * 2 + j);
        }
    }
}

fn test_tables(test_state: &TestState, alloc: &mut GuestAllocator, xsdt_addr: usize, cpu: u8) {
    let file_name = "etc/acpi/tables";
    // Now acpi tables data length is 2864.
    let mut read_data: Vec<u8> = Vec::with_capacity(2864);

    // Select FileDir entry and read it.
    let file_size = test_state.fw_cfg_read_file(alloc, file_name, &mut read_data, 2864);
    assert_eq!(file_size, 2864);

    // Check XSDT
    assert_eq!(
        String::from_utf8_lossy(&read_data[xsdt_addr..(xsdt_addr + 4)]),
        "XSDT"
    );

    // XSDT entry: An array of 64-bit physical addresses that point to other DESCRIPTION_HEADERs.
    // DESCRIPTION_HEADERs: DSDT, FADT, MADT, GTDT, IORT, SPCR, MCFG, SRAT, SLIT, PPTT
    let entry_addr = xsdt_addr + mem::size_of::<AcpiTableHeader>() - 8;

    // Check DSDT
    let mut offset = entry_addr;
    let dsdt_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_dsdt(&read_data[(dsdt_addr as usize)..]);

    // Check FADT
    offset = entry_addr + 1 * 8;
    let fadt_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_fadt(&read_data[(fadt_addr as usize)..]);

    // Check MADT
    offset = entry_addr + 2 * 8;
    let madt_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_madt(&read_data[(madt_addr as usize)..], cpu);

    // Check GTDT
    offset = entry_addr + 3 * 8;
    let gtdt_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_gtdt(&read_data[(gtdt_addr as usize)..]);

    // Check IORT
    offset = entry_addr + 4 * 8;
    let iort_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_iort(&read_data[(iort_addr as usize)..]);

    // Check SPCR
    offset = entry_addr + 5 * 8;
    let spcr_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_spcr(&read_data[(spcr_addr as usize)..]);

    // Check MCFG
    offset = entry_addr + 6 * 8;
    let mcfg_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_mcfg(&read_data[(mcfg_addr as usize)..]);

    // Check SRAT
    offset = entry_addr + 7 * 8;
    let srat_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_srat(&read_data[(srat_addr as usize)..]);

    // Check SLIT
    offset = entry_addr + 8 * 8;
    let slit_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_slit(&read_data[(slit_addr as usize)..]);

    // Check PPTT
    offset = entry_addr + 9 * 8;
    let pptt_addr = LittleEndian::read_u64(&read_data[offset..]);
    check_pptt(&read_data[(pptt_addr as usize)..]);
}

fn check_madt_of_two_gicr(
    test_state: &TestState,
    alloc: &mut GuestAllocator,
    xsdt_addr: usize,
    cpus: usize,
) {
    let file_name = "etc/acpi/tables";
    // Now acpi tables data length is 29212.
    let mut read_data: Vec<u8> = Vec::with_capacity(29212);

    // Select FileDir entry and read it.
    test_state.fw_cfg_read_file(alloc, file_name, &mut read_data, 29212);

    // XSDT entry: An array of 64-bit physical addresses that point to other DESCRIPTION_HEADERs.
    // DESCRIPTION_HEADERs: DSDT, FADT, MADT, GTDT, IORT, SPCR, MCFG, SRAT, SLIT, PPTT
    let entry_addr = xsdt_addr + mem::size_of::<AcpiTableHeader>() - 8;

    // MADT offset base on XSDT
    let mut offset = entry_addr + 2 * 8;
    let madt_addr = LittleEndian::read_u64(&read_data[offset..]) as usize;

    // Check second GIC Redistributor
    // Second GIC Redistributor addr offset base on MADT: header len = 44
    offset = 44
        + mem::size_of::<AcpiGicDistributor>()
        + mem::size_of::<AcpiGicCpu>() * cpus
        + mem::size_of::<AcpiGicRedistributor>();
    let addr = LittleEndian::read_u64(&read_data[(madt_addr + offset + 4)..]);
    assert_eq!(MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize].0, addr);
    let len = LittleEndian::read_u32(&read_data[(madt_addr + offset + 12)..]);
    assert_eq!(
        MEM_LAYOUT[LayoutEntryType::HighGicRedist as usize].1,
        len as u64
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_acpi_virt() {
    let mut args = Vec::new();
    bios_args(&mut args);

    let cpu = 8;
    let cpu_args = format!(
        "-smp {},sockets=1,cores=4,threads=2 -cpu host,pmu=on -m 4G",
        cpu
    );
    let mut extra_args = cpu_args.split(' ').collect();
    args.append(&mut extra_args);
    extra_args = "-object memory-backend-ram,size=2G,id=mem0,host-nodes=0-1,policy=bind"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-object memory-backend-ram,size=2G,id=mem1,host-nodes=0-1,policy=bind"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa node,nodeid=0,cpus=0-3,memdev=mem0"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa node,nodeid=1,cpus=4-7,memdev=mem1"
        .split(' ')
        .collect();
    args.append(&mut extra_args);
    extra_args = "-numa dist,src=0,dst=1,val=30".split(' ').collect();
    args.append(&mut extra_args);
    extra_args = "-numa dist,src=1,dst=0,val=30".split(' ').collect();
    args.append(&mut extra_args);
    extra_args = "-serial pty".split(' ').collect();
    args.append(&mut extra_args);

    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let alloc = machine.allocator.clone();

    let xsdt_addr = test_rsdp(&test_state.borrow(), &mut alloc.borrow_mut());
    test_tables(
        &test_state.borrow(),
        &mut alloc.borrow_mut(),
        xsdt_addr as usize,
        cpu,
    );

    test_state.borrow_mut().stop();
}

#[cfg(target_arch = "aarch64")]
#[test]
fn test_acpi_two_gicr() {
    let mut args = Vec::new();
    bios_args(&mut args);

    let cpus = 200;
    let cpu_args = format!(
        "-smp {},sockets=2,cores=50,threads=2 -cpu host,pmu=on -m 4G",
        cpus
    );
    let mut extra_args = cpu_args.split(' ').collect();
    args.append(&mut extra_args);

    let test_state = Rc::new(RefCell::new(test_init(args)));
    let machine = TestStdMachine::new(test_state.clone());
    let alloc = machine.allocator.clone();

    let xsdt_addr = test_rsdp(&test_state.borrow(), &mut alloc.borrow_mut());
    check_madt_of_two_gicr(
        &test_state.borrow(),
        &mut alloc.borrow_mut(),
        xsdt_addr as usize,
        cpus,
    );

    test_state.borrow_mut().stop();
}
