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

//! Boot Loader load PE linux kernel image to guest memory according
//! [`x86 boot protocol`](https://www.kernel.org/doc/Documentation/x86/boot.txt).
//!
//! Below is x86_64 bootloader memory layout:
//!
//! ``` text
//!                 +------------------------+
//!   0x0000_0000   |  Real Mode IVT         |
//!                 |                        |
//!                 +------------------------+
//!   0x0000_7000   |                        |
//!                 |  Zero Page             |
//!                 |                        |
//!   0x0000_9000   +------------------------+
//!                 |  Page Map Level4       |
//!                 |                        |
//!   0x0000_a000   +------------------------+
//!                 |  Page Directory Pointer|
//!                 |                        |
//!   0x0000_b000   +------------------------+
//!                 |  Page Directory Entry  |
//!                 |                        |
//!   0x0002_0000   +------------------------+
//!                 |  Kernel Cmdline        |
//!                 |                        |
//!   0x0009_fc00   +------------------------+
//!                 |  EBDA - MPtable        |
//!                 |                        |
//!   0x000a_0000   +------------------------+
//!                 |  VGA_RAM               |
//!                 |                        |
//!   0x000f_0000   +------------------------+
//!                 |  MB_BIOS               |
//!                 |                        |
//!   0x0010_0000   +------------------------+
//!                 |  Kernel _setup         |
//!                 |                        |
//!                 ~------------------------~
//!                 |  Initrd Ram            |
//!   0x****_****   +------------------------+
//! ```

const REAL_MODE_IVT_BEGIN: u64 = 0x0000_0000;

extern crate address_space;

mod bootparam;
mod gdt;
mod mptable;

use std::path::PathBuf;
use std::string::String;
use std::sync::Arc;

use kvm_bindings::kvm_segment;

use self::errors::{ErrorKind, Result, ResultExt};
use address_space::{AddressSpace, GuestAddress};
use bootparam::{BootParams, RealModeKernelHeader, E820_RAM, E820_RESERVED};
use gdt::GdtEntry;
use mptable::{
    BusEntry, ConfigTableHeader, FloatingPointer, IOApicEntry, IOInterruptEntry,
    LocalInterruptEntry, ProcessEntry, DEST_ALL_LAPIC_MASK, INTERRUPT_TYPE_EXTINT,
    INTERRUPT_TYPE_INT, INTERRUPT_TYPE_NMI, IOAPIC_BASE_ADDR, LAPIC_BASE_ADDR,
};
use util::checksum::obj_checksum;

pub mod errors {
    error_chain! {
        links {
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
        }
        errors {
            MaxCpus(cpus: u8) {
                display("Configure cpu number({}) above supported max cpu numbers(254)", cpus)
            }
        }
    }
}

const ZERO_PAGE_START: u64 = 0x0000_7000;
const PML4_START: u64 = 0x0000_9000;
const PDPTE_START: u64 = 0x0000_a000;
const PDE_START: u64 = 0x0000_b000;
const CMDLINE_START: u64 = 0x0002_0000;

const EBDA_START: u64 = 0x0009_fc00;
const VGA_RAM_BEGIN: u64 = 0x000a_0000;
const MB_BIOS_BEGIN: u64 = 0x000f_0000;
const VMLINUX_RAM_START: u64 = 0x0010_0000;
const KVM_32BIT_GAP_SIZE: u64 = 0x0300 << 20; /* 3GB */
const KVM_32BIT_MAX_MEM_SIZE: u64 = 1 << 32; /* 4GB */
const KVM_32BIT_GAP_START: u64 = KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE;
const INITRD_ADDR_MAX: u64 = 0x37ff_ffff;

const VMLINUX_STARTUP: u64 = 0x0100_0000;
const BOOT_LOADER_SP: u64 = 0x0000_8ff0;

const GDT_ENTRY_BOOT_CS: u8 = 2;
const GDT_ENTRY_BOOT_DS: u8 = 3;
const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

/// Boot loader config used for x86_64.
pub struct X86BootLoaderConfig {
    /// Path of the kernel image.
    pub kernel: PathBuf,
    /// Path of the initrd image.
    pub initrd: Option<PathBuf>,
    /// Initrd image size.
    pub initrd_size: u32,
    /// Kernel cmdline parameters.
    pub kernel_cmdline: String,
    /// VM's CPU count.
    pub cpu_count: u8,
}

/// The start address for some boot source in guest memory for `x86_64`.
pub struct X86BootLoader {
    pub kernel_start: u64,
    pub kernel_sp: u64,
    pub initrd_start: u64,
    pub boot_pml4_addr: u64,
    pub zero_page_addr: u64,
    pub segments: BootGdtSegment,
}

#[derive(Debug, Default, Copy, Clone)]
pub struct BootGdtSegment {
    pub code_segment: kvm_segment,
    pub data_segment: kvm_segment,
    pub gdt_base: u64,
    pub gdt_limit: u16,
    pub idt_base: u64,
    pub idt_limit: u16,
}

fn setup_page_table(sys_mem: &Arc<AddressSpace>) -> Result<u64> {
    // Initial pagetables.

    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = PML4_START;
    let boot_pdpte_addr = PDPTE_START;
    let boot_pde_addr = PDE_START;

    // Entry covering VA [0..512GB)
    let pdpte = boot_pdpte_addr | 0x03;
    sys_mem
        .write_object(&pdpte, GuestAddress(boot_pml4_addr))
        .chain_err(|| format!("Failed to load PD PTE to 0x{:x}", boot_pml4_addr))?;

    // Entry covering VA [0..1GB)
    let pde = boot_pde_addr | 0x03;
    sys_mem
        .write_object(&pde, GuestAddress(boot_pdpte_addr))
        .unwrap();

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512u64 {
        let pde = (i << 21) + 0x83u64;
        sys_mem
            .write_object(&pde, GuestAddress(boot_pde_addr + i * 8))
            .chain_err(|| format!("Failed to load PDE to 0x{:x}", boot_pde_addr + i * 8))?;
    }

    Ok(boot_pml4_addr)
}

macro_rules! write_entry {
    ( $d:expr, $t:ty, $m:expr, $o:expr, $s:expr ) => {
        let entry = $d;
        $m.write_object(&entry, GuestAddress($o))?;
        $o += std::mem::size_of::<$t>() as u64;
        $s = $s.wrapping_add(obj_checksum(&entry));
    };
}

fn setup_isa_mptable(sys_mem: &Arc<AddressSpace>, start_addr: u64, num_cpus: u8) -> Result<()> {
    const BUS_ID: u8 = 0;
    const MPTABLE_MAX_CPUS: u32 = 254; // mptable max support 255 cpus, reserve one for ioapic id
    const MPTABLE_IOAPIC_NR: u8 = 16;

    if u32::from(num_cpus) > MPTABLE_MAX_CPUS {
        return Err(ErrorKind::MaxCpus(num_cpus).into());
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
            ProcessEntry::new(cpu_id as u8, true, cpu_id == 0),
            ProcessEntry,
            sys_mem,
            offset,
            sum
        );
    }

    write_entry!(BusEntry::new(BUS_ID), BusEntry, sys_mem, offset, sum);

    write_entry!(
        IOApicEntry::new(ioapic_id, true, IOAPIC_BASE_ADDR),
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
        &ConfigTableHeader::new((offset - header) as u16, sum, LAPIC_BASE_ADDR),
        GuestAddress(header),
    )?;

    Ok(())
}

fn setup_boot_params(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
) -> Result<(u64, u64)> {
    let (ramdisk_size, ramdisk_image, initrd_addr) = if config.initrd_size > 0 {
        let mut initrd_addr_max = INITRD_ADDR_MAX as u32;
        if initrd_addr_max as u64 > sys_mem.memory_end_address().raw_value() as u64 {
            initrd_addr_max = sys_mem.memory_end_address().raw_value() as u32;
        };

        let img = (initrd_addr_max - config.initrd_size as u32) & !0xfffu32;
        (config.initrd_size as u32, img, img as u64)
    } else {
        info!("No initrd image file.");
        (0u32, 0u32, 0u64)
    };

    let mut boot_params = BootParams::new(RealModeKernelHeader::new(
        CMDLINE_START as u32,
        config.kernel_cmdline.len() as u32,
        ramdisk_image,
        ramdisk_size,
    ));

    boot_params.add_e820_entry(
        REAL_MODE_IVT_BEGIN,
        EBDA_START - REAL_MODE_IVT_BEGIN,
        E820_RAM,
    );
    boot_params.add_e820_entry(EBDA_START, VGA_RAM_BEGIN - EBDA_START, E820_RESERVED);
    boot_params.add_e820_entry(MB_BIOS_BEGIN, 0, E820_RESERVED);

    let high_memory_start = GuestAddress(VMLINUX_RAM_START);
    let end_32bit_gap_start = GuestAddress(KVM_32BIT_GAP_START);
    let first_addr_past_32bits = GuestAddress(KVM_32BIT_MAX_MEM_SIZE);
    let mem_end = sys_mem.memory_end_address();
    if mem_end < end_32bit_gap_start {
        boot_params.add_e820_entry(
            high_memory_start.raw_value() as u64,
            mem_end.offset_from(high_memory_start) as u64,
            E820_RAM,
        );
    } else {
        boot_params.add_e820_entry(
            high_memory_start.raw_value() as u64,
            end_32bit_gap_start.offset_from(high_memory_start) as u64,
            E820_RAM,
        );
        if mem_end > first_addr_past_32bits {
            boot_params.add_e820_entry(
                first_addr_past_32bits.raw_value() as u64,
                mem_end.offset_from(first_addr_past_32bits) as u64,
                E820_RAM,
            );
        }
    }

    sys_mem
        .write_object(&boot_params, GuestAddress(ZERO_PAGE_START))
        .chain_err(|| format!("Failed to load zero page to 0x{:x}", ZERO_PAGE_START))?;

    Ok((ZERO_PAGE_START, initrd_addr))
}

fn write_gdt_table(table: &[u64], guest_mem: &Arc<AddressSpace>) -> Result<()> {
    let mut boot_gdt_addr = BOOT_GDT_OFFSET as u64;
    for (_, entry) in table.iter().enumerate() {
        guest_mem
            .write_object(entry, GuestAddress(boot_gdt_addr))
            .chain_err(|| format!("Failed to load gdt to 0x{:x}", boot_gdt_addr))?;
        boot_gdt_addr += 8;
    }
    Ok(())
}

fn write_idt_value(val: u64, guest_mem: &Arc<AddressSpace>) -> Result<()> {
    let boot_idt_addr = BOOT_IDT_OFFSET;
    guest_mem
        .write_object(&val, GuestAddress(boot_idt_addr))
        .chain_err(|| format!("Failed to load gdt to 0x{:x}", boot_idt_addr))?;

    Ok(())
}

pub fn setup_gdt(guest_mem: &Arc<AddressSpace>) -> Result<BootGdtSegment> {
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

    write_gdt_table(&gdt_table[..], guest_mem)?;
    write_idt_value(0, guest_mem)?;

    Ok(BootGdtSegment {
        code_segment: code_seg,
        data_segment: data_seg,
        gdt_base: BOOT_GDT_OFFSET,
        gdt_limit: std::mem::size_of_val(&gdt_table) as u16 - 1,
        idt_base: BOOT_IDT_OFFSET,
        idt_limit: std::mem::size_of::<u64>() as u16 - 1,
    })
}

pub fn linux_bootloader(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
) -> Result<X86BootLoader> {
    let boot_pml4 = setup_page_table(sys_mem)?;

    setup_isa_mptable(sys_mem, EBDA_START, config.cpu_count)?;

    let (zero_page, initrd_addr) = setup_boot_params(&config, sys_mem)?;

    let gdt_seg = setup_gdt(sys_mem)?;

    Ok(X86BootLoader {
        kernel_start: VMLINUX_STARTUP,
        kernel_sp: BOOT_LOADER_SP,
        initrd_start: initrd_addr,
        boot_pml4_addr: boot_pml4,
        zero_page_addr: zero_page,
        segments: gdt_seg,
    })
}

pub fn setup_kernel_cmdline(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
) -> Result<()> {
    let mut cmdline = config.kernel_cmdline.as_bytes();
    sys_mem.write(
        &mut cmdline,
        GuestAddress(CMDLINE_START),
        config.kernel_cmdline.len() as u64,
    )?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use address_space::*;
    use std::sync::Arc;
    use std::vec::Vec;
    #[test]
    fn test_x86_bootloader_and_kernel_cmdline() {
        let root = Region::init_container_region(0x2000_0000);
        let space = AddressSpace::new(root.clone()).unwrap();
        let ram1 = Arc::new(HostMemMapping::new(GuestAddress(0), 0x1000_0000, false).unwrap());
        let region_a = Region::init_ram_region(ram1.clone());
        root.add_subregion(region_a, ram1.start_address().raw_value())
            .unwrap();
        assert_eq!(setup_page_table(&space).unwrap(), 0x0000_9000);
        assert_eq!(
            space.read_object::<u64>(GuestAddress(0x0000_9000)).unwrap(),
            0x0000_a003
        );
        assert_eq!(
            space.read_object::<u64>(GuestAddress(0x0000_a000)).unwrap(),
            0x0000_b003
        );
        let mut page_addr: u64 = 0x0000_b000;
        let mut tmp_value: u64 = 0x83;
        for _ in 0..512u64 {
            assert_eq!(
                space.read_object::<u64>(GuestAddress(page_addr)).unwrap(),
                tmp_value
            );
            page_addr += 8;
            tmp_value += 0x20_0000;
        }

        let config = X86BootLoaderConfig {
            kernel: PathBuf::new(),
            initrd: Some(PathBuf::new()),
            initrd_size: 0x1_0000,
            kernel_cmdline: String::from("this_is_a_piece_of_test_string"),
            cpu_count: 2,
        };
        let (_, initrd_addr_tmp) = setup_boot_params(&config, &space).unwrap();
        assert_eq!(initrd_addr_tmp, 0xfff_0000);

        //test setup_gdt function
        let c_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 16,
            type_: 11,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };
        let d_seg = kvm_segment {
            base: 0,
            limit: 1048575,
            selector: 24,
            type_: 3,
            present: 1,
            dpl: 0,
            db: 1,
            s: 1,
            l: 0,
            g: 1,
            avl: 0,
            unusable: 0,
            padding: 0,
        };

        let boot_gdt_seg = setup_gdt(&space).unwrap();

        assert_eq!(boot_gdt_seg.code_segment, c_seg);
        assert_eq!(boot_gdt_seg.data_segment, d_seg);
        assert_eq!(boot_gdt_seg.gdt_limit, 31);
        assert_eq!(boot_gdt_seg.idt_limit, 7);
        let mut arr: Vec<u64> = Vec::new();
        let mut boot_addr: u64 = 0x500;
        for _ in 0..BOOT_GDT_MAX {
            arr.push(space.read_object(GuestAddress(boot_addr)).unwrap());
            boot_addr += 8;
        }
        assert_eq!(arr[0], 0);
        assert_eq!(arr[1], 0);
        assert_eq!(arr[2], 0xaf9b000000ffff);
        assert_eq!(arr[3], 0xcf93000000ffff);

        //test setup_kernel_cmdline function
        let cmd_len: u64 = config.kernel_cmdline.len() as u64;
        let mut read_buffer: [u8; 30] = [0; 30];
        //let mut read_buffer:Vec<u8> = Vec::with_capacity();
        assert!(setup_kernel_cmdline(&config, &space).is_ok());
        space
            .read(
                &mut read_buffer.as_mut(),
                GuestAddress(0x0002_0000),
                cmd_len,
            )
            .unwrap();
        let s = String::from_utf8(read_buffer.to_vec()).unwrap();
        assert_eq!(s, "this_is_a_piece_of_test_string".to_string());
    }
}
