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

/// Offset of checksum field in ACPI table.
pub const TABLE_CHECKSUM_OFFSET: u32 = 9;
pub const INTERRUPT_PPIS_COUNT: u32 = 16;
pub const INTERRUPT_SGIS_COUNT: u32 = 16;
/// GTDT irq number for timer.
pub const ACPI_GTDT_ARCH_TIMER_VIRT_IRQ: u32 = 11;
pub const ACPI_GTDT_ARCH_TIMER_S_EL1_IRQ: u32 = 13;
pub const ACPI_GTDT_ARCH_TIMER_NS_EL1_IRQ: u32 = 14;
pub const ACPI_GTDT_ARCH_TIMER_NS_EL2_IRQ: u32 = 10;
pub const ACPI_GTDT_INTERRUPT_MODE_LEVEL: u32 = 0;
pub const ACPI_GTDT_CAP_ALWAYS_ON: u32 = 4;
/// IORT node types, reference: ARM Document number: ARM DEN 0049B, October 2015.
pub const ACPI_IORT_NODE_ITS_GROUP: u8 = 0x00;
pub const ACPI_IORT_NODE_PCI_ROOT_COMPLEX: u8 = 0x02;
/// Root Complex Node in IORT
pub const ROOT_COMPLEX_ENTRY_SIZE: u16 = 36;
pub const ID_MAPPING_ENTRY_SIZE: u16 = 20;
/// Interrupt controller structure types for MADT.
pub const ACPI_MADT_GENERIC_CPU_INTERFACE: u8 = 11;
pub const ACPI_MADT_GENERIC_DISTRIBUTOR: u8 = 12;
pub const ACPI_MADT_GENERIC_REDISTRIBUTOR: u8 = 14;
pub const ACPI_MADT_GENERIC_TRANSLATOR: u8 = 15;

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiGenericAddress {
    space_id: u8,
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64,
}

impl AcpiGenericAddress {
    pub fn new_io_address<T: Into<u64>>(addr: T) -> AcpiGenericAddress {
        AcpiGenericAddress {
            space_id: 1,
            bit_width: 8 * std::mem::size_of::<T>() as u8,
            bit_offset: 0,
            access_size: std::mem::size_of::<T>() as u8,
            address: addr.into(),
        }
    }
}

impl ByteCode for AcpiGenericAddress {}

impl AmlBuilder for AcpiGenericAddress {
    fn aml_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

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

#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct ProcessorHierarchyNode {
    pub r#type: u8,
    pub length: u8,
    pub reserved: u16,
    pub flags: u32,
    pub parent: u32,
    pub acpi_processor_id: u32,
    pub num_private_resources: u32,
}

impl ByteCode for ProcessorHierarchyNode {}

impl AmlBuilder for ProcessorHierarchyNode {
    fn aml_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ProcessorHierarchyNode {
    pub fn new(r#type: u8, flags: u32, parent: u32, acpi_processor_id: u32) -> Self {
        Self {
            r#type,
            length: 20,
            reserved: 0,
            flags,
            parent,
            acpi_processor_id,
            num_private_resources: 0,
        }
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

/// ACPI SRAT processor affinity structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiSratProcessorAffinity {
    /// Type ID.
    pub type_id: u8,
    /// The length of this structure.
    pub length: u8,
    /// Bit `\[`7:0`\]` of the proximity domain to which the processor belongs.
    pub proximity_lo: u8,
    /// The processor local APIC ID.
    pub local_apic_id: u8,
    /// The processor affinity flags.
    pub flags: u32,
    /// The processor local SAPIC EID.
    pub local_sapic_eid: u8,
    /// Bit `\[`31:8`\]` of the proximity domain to which the processor belongs.
    pub proximity_hi: [u8; 3],
    /// The clock domain to which the processor belongs.
    pub clock_domain: u32,
}

impl ByteCode for AcpiSratProcessorAffinity {}

impl AmlBuilder for AcpiSratProcessorAffinity {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::from(self.as_bytes())
    }
}

/// ACPI SRAT GICC affinity structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiSratGiccAffinity {
    /// Type ID.
    pub type_id: u8,
    /// The length of this structure.
    pub length: u8,
    /// Represents the proximity domain to which the "range of memory" belongs.
    pub proximity_domain: u32,
    /// The ACPI processor UID of the associated GICC
    pub process_uid: u32,
    /// The GICC affinity flags.
    pub flags: u32,
    /// The clock domain to which the processor belongs.
    pub clock_domain: u32,
}

impl ByteCode for AcpiSratGiccAffinity {}

impl AmlBuilder for AcpiSratGiccAffinity {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::from(self.as_bytes())
    }
}

/// ACPI SRAT memory affinity structure.
#[repr(C, packed)]
#[derive(Default, Copy, Clone)]
pub struct AcpiSratMemoryAffinity {
    /// Type ID.
    pub type_id: u8,
    /// The length of this structure.
    pub length: u8,
    /// Represents the proximity domain to which the "range of memory" belongs.
    pub proximity_domain: u32,
    /// Reserved field.
    pub reserved1: u16,
    /// The base address of the memory range.
    pub base_addr: u64,
    /// The length of the memory range.
    pub range_length: u64,
    /// Reserved field.
    pub reserved2: u32,
    /// Indicates whether memory is enabled and can be hot plugged.
    pub flags: u32,
    /// Reserved field.
    pub reserved3: u64,
}

impl ByteCode for AcpiSratMemoryAffinity {}

impl AmlBuilder for AcpiSratMemoryAffinity {
    fn aml_bytes(&self) -> Vec<u8> {
        Vec::from(self.as_bytes())
    }
}

/// This module describes ACPI MADT's sub-tables on x86_64 platform.
#[cfg(target_arch = "x86_64")]
pub mod madt_subtable {
    use super::*;
    pub const IOAPIC_BASE_ADDR: u32 = 0xfec0_0000;
    pub const LAPIC_BASE_ADDR: u32 = 0xfee0_0000;

    /// MADT processor Local APIC structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiLocalApic {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// ACPI processor UID.
        pub processor_uid: u8,
        /// The processor's Local APIC ID.
        pub apic_id: u8,
        /// Local APIC flags.
        pub flags: u32,
    }

    impl ByteCode for AcpiLocalApic {}

    impl AmlBuilder for AcpiLocalApic {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }

    /// IO APIC structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiIoApic {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// This IO APIC's ID.
        pub io_apic_id: u8,
        /// Reserved field.
        pub reserved: u8,
        /// The 32-bit address of this IO APIC.
        pub io_apic_addr: u32,
        /// The GSI number where this I/O APIC’s interrupt inputs start.
        pub gsi_base: u32,
    }

    impl ByteCode for AcpiIoApic {}

    impl AmlBuilder for AcpiIoApic {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }
}

/// This module describes ACPI MADT's sub-tables on aarch64 platform.
#[cfg(target_arch = "aarch64")]
pub mod madt_subtable {
    use super::*;

    pub const ARCH_GIC_MAINT_IRQ: u32 = 9;

    /// GIC CPU Interface structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiGicCpu {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// Reserved field.
        reserved_1: u16,
        /// CPU interface number.
        pub cpu_interface_num: u32,
        /// ACPI processor UID.
        pub processor_uid: u32,
        /// Flags.
        pub flags: u32,
        /// The version of Arm processor parking protocol.
        pub parking_version: u32,
        /// The GSIV used for performance monitoring interrupts.
        pub perf_interrupt: u32,
        /// The 64-bit address of the processor’s parking protocol mailbox.
        pub parked_addr: u64,
        /// CPU can access this CPU interface via this 64-bit address.
        pub base_addr: u64,
        /// Address of the GIC virtual CPU interface registers.
        pub gicv_addr: u64,
        /// Address of the GIC virtual interface control block registers.
        pub gich_addr: u64,
        /// GSIV for Virtual GIC maintenance interrupt.
        pub vgic_interrupt: u32,
        /// If GIC's version is above 3, this field is 64-bit address of redistributor.
        pub gicr_addr: u64,
        /// MPIDR.
        pub mpidr: u64,
        /// Reserved field.
        reserved_2: u32,
    }

    impl ByteCode for AcpiGicCpu {}

    impl AmlBuilder for AcpiGicCpu {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }

    /// GIC distributor structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiGicDistributor {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// Reserved field.
        reserved_1: u16,
        /// This distributor's hardware ID.
        pub gic_id: u32,
        /// The 64-bit address of this distributor.
        pub base_addr: u64,
        /// System vector base, must be zero.
        pub sys_vector_base: u32,
        /// GIC version.
        pub gic_version: u8,
        /// Reserved field.
        reserved_2: [u8; 3],
    }

    impl ByteCode for AcpiGicDistributor {}

    impl AmlBuilder for AcpiGicDistributor {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }

    /// GIC Redistributor structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiGicRedistributor {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// Reserved field.
        reserved_1: u16,
        /// The 64-bit address of this redistributor.
        pub base_addr: u64,
        /// Length of the GIC redistributor discovery page range.
        pub range_length: u32,
    }

    impl ByteCode for AcpiGicRedistributor {}

    impl AmlBuilder for AcpiGicRedistributor {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }

    /// GIC Interrupt Translation Service (ITS) Structure.
    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct AcpiGicIts {
        /// Type ID.
        pub type_id: u8,
        /// The length of this structure.
        pub length: u8,
        /// Reserved field.
        reserved_1: u16,
        /// ITS ID, must be unique.
        pub its_id: u32,
        /// The 64-bit address of this ITS.
        pub base_addr: u64,
        /// Reserved field.
        reserved_2: u32,
    }

    impl ByteCode for AcpiGicIts {}

    impl AmlBuilder for AcpiGicIts {
        fn aml_bytes(&self) -> Vec<u8> {
            Vec::from(self.as_bytes())
        }
    }
}
