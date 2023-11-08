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

mod gdt;
mod mptable;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{Context, Result};
use log::info;

use self::gdt::setup_gdt;
use self::mptable::setup_isa_mptable;
use super::bootparam::{BootParams, RealModeKernelHeader, UNDEFINED_ID};
use super::{X86BootLoader, X86BootLoaderConfig};
use super::{
    BOOT_HDR_START, BOOT_LOADER_SP, BZIMAGE_BOOT_OFFSET, CMDLINE_START, EBDA_START,
    INITRD_ADDR_MAX, PDE_START, PDPTE_START, PML4_START, VMLINUX_STARTUP, ZERO_PAGE_START,
};
use crate::error::BootLoaderError;
use address_space::{AddressSpace, GuestAddress};
use util::byte_code::ByteCode;

/// Load bzImage linux kernel to Guest Memory.
///
/// # Notes
/// According to Linux `Documentation/x86/boot.txt`, bzImage includes two parts:
/// * the setup
/// * the compressed kernel
/// The setup `RealModeKernelHeader` can be load at offset `0x01f1` in bzImage kernel image.
/// The compressed kernel will be loaded into guest memory at `code32_start` in
/// `RealModeKernelHeader`.
/// The start address of compressed kernel is the loader address + 0x200. It will be
/// set in `kernel_start` in `BootLoader` structure set.
///
/// # Arguments
///
/// * `kernel_image` - Guest kernel image.
///
/// # Errors
///
/// * Invalid BzImage header or version.
/// * Failed to write bzImage linux kernel to guest memory.
fn load_bzimage(kernel_image: &mut File) -> Result<RealModeKernelHeader> {
    let mut boot_hdr = RealModeKernelHeader::new();

    kernel_image.seek(SeekFrom::Start(BOOT_HDR_START))?;
    kernel_image
        .read_exact(boot_hdr.as_mut_bytes())
        .with_context(|| "Failed to read boot_hdr from bzImage kernel")?;
    boot_hdr.type_of_loader = UNDEFINED_ID;

    if let Err(e) = boot_hdr.check_valid_kernel() {
        kernel_image.rewind()?;
        return Err(e);
    }

    let mut setup_size = boot_hdr.setup_sects as u64;
    if setup_size == 0 {
        setup_size = 4;
    }
    setup_size = (setup_size + 1) << 9;
    kernel_image.seek(SeekFrom::Start(setup_size))?;

    Ok(boot_hdr)
}

/// Load linux kernel or initrd image file to Guest Memory.
///
/// # Arguments
/// * `image` - image file for kernel or initrd.
/// * `start_addr` - image start address in guest memory.
/// * `sys_mem` - guest memory.
///
/// # Errors
///
/// * Write image to guest memory failed.
fn load_image(image: &mut File, start_addr: u64, sys_mem: &Arc<AddressSpace>) -> Result<()> {
    let curr_loc = image.stream_position()?;
    let len = image.seek(SeekFrom::End(0))?;
    image.seek(SeekFrom::Start(curr_loc))?;

    sys_mem.write(image, GuestAddress(start_addr), len - curr_loc)?;

    Ok(())
}

fn load_kernel_image(
    kernel_path: &std::path::Path,
    sys_mem: &Arc<AddressSpace>,
    boot_layout: &mut X86BootLoader,
) -> Result<RealModeKernelHeader> {
    let mut kernel_image =
        File::open(kernel_path).with_context(|| BootLoaderError::BootLoaderOpenKernel)?;

    let (boot_hdr, kernel_start, vmlinux_start) = if let Ok(hdr) = load_bzimage(&mut kernel_image) {
        (
            hdr,
            hdr.code32_start as u64 + BZIMAGE_BOOT_OFFSET,
            hdr.code32_start as u64,
        )
    } else {
        (
            RealModeKernelHeader::new(),
            VMLINUX_STARTUP,
            VMLINUX_STARTUP,
        )
    };

    load_image(&mut kernel_image, vmlinux_start, sys_mem)
        .with_context(|| "Failed to load image")?;

    boot_layout.boot_ip = kernel_start;

    Ok(boot_hdr)
}

fn load_initrd(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    header: &mut RealModeKernelHeader,
) -> Result<()> {
    if config.initrd.is_none() {
        info!("No initrd image file.");
        return Ok(());
    };

    let mut initrd_addr_max = INITRD_ADDR_MAX;
    if initrd_addr_max > sys_mem.memory_end_address().raw_value() {
        initrd_addr_max = sys_mem.memory_end_address().raw_value();
    };

    let mut initrd_image = File::open(config.initrd.as_ref().unwrap())
        .with_context(|| BootLoaderError::BootLoaderOpenInitrd)?;
    let initrd_size = initrd_image.metadata().unwrap().len();
    let initrd_addr = (initrd_addr_max - initrd_size) & !0xfff_u64;

    load_image(&mut initrd_image, initrd_addr, sys_mem).with_context(|| "Failed to load image")?;

    header.set_ramdisk(initrd_addr as u32, initrd_size as u32);

    Ok(())
}

/// Initial pagetables.
fn setup_page_table(sys_mem: &Arc<AddressSpace>) -> Result<u64> {
    // Puts PML4 right after zero page but aligned to 4k.
    let boot_pml4_addr = PML4_START;
    let boot_pdpte_addr = PDPTE_START;
    let boot_pde_addr = PDE_START;

    // Entry covering VA [0..512GB)
    let pdpte = boot_pdpte_addr | 0x03;
    sys_mem
        .write_object(&pdpte, GuestAddress(boot_pml4_addr))
        .with_context(|| format!("Failed to load PD PTE to 0x{:x}", boot_pml4_addr))?;

    // Entry covering VA [0..1GB)
    let pde = boot_pde_addr | 0x03;
    sys_mem
        .write_object(&pde, GuestAddress(boot_pdpte_addr))
        .with_context(|| format!("Failed to load PDE to 0x{:x}", boot_pdpte_addr))?;

    // 512 2MB entries together covering VA [0..1GB). Note we are assuming
    // CPU supports 2MB pages (/proc/cpuinfo has 'pse'). All modern CPUs do.
    for i in 0..512u64 {
        let pde = (i << 21) + 0x83u64;
        sys_mem
            .write_object(&pde, GuestAddress(boot_pde_addr + i * 8))
            .with_context(|| format!("Failed to load PDE to 0x{:x}", boot_pde_addr + i * 8))?;
    }

    Ok(boot_pml4_addr)
}

fn setup_boot_params(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    boot_hdr: &RealModeKernelHeader,
) -> Result<()> {
    let mut boot_params = BootParams::new(*boot_hdr);
    boot_params.setup_e820_entries(config, sys_mem);
    sys_mem
        .write_object(&boot_params, GuestAddress(ZERO_PAGE_START))
        .with_context(|| format!("Failed to load zero page to 0x{:x}", ZERO_PAGE_START))?;

    Ok(())
}

fn setup_kernel_cmdline(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    boot_hdr: &mut RealModeKernelHeader,
) -> Result<()> {
    let cmdline_len = config.kernel_cmdline.len() as u32;
    boot_hdr.set_cmdline(CMDLINE_START as u32, cmdline_len);

    sys_mem.write(
        &mut config.kernel_cmdline.as_bytes(),
        GuestAddress(CMDLINE_START),
        cmdline_len as u64,
    )?;

    Ok(())
}

/// Load PE(vmlinux.bin) linux kernel / bzImage linux kernel and
/// other boot source to Guest Memory.
///
/// # Steps
///
/// 1. Prepare for linux kernel boot env, return guest memory layout.
/// 2. According guest memory layout, load linux kernel to guest memory.
/// 3. According guest memory layout, load initrd image to guest memory.
/// 4. Inject cmdline to guest memory.
///
/// # Arguments
///
/// * `config` - boot source config, contains kernel, initrd and kernel cmdline.
/// * `sys_mem` - guest memory.
///
/// # Errors
///
/// Load kernel, initrd or kernel cmdline to guest memory failed. Boot source
/// is broken or guest memory is abnormal.
pub fn load_linux(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
) -> Result<X86BootLoader> {
    let kernel_path = config
        .kernel
        .as_ref()
        .with_context(|| "Kernel is required for direct-boot mode.")?;
    let mut boot_loader_layout = X86BootLoader {
        boot_sp: BOOT_LOADER_SP,
        zero_page_addr: ZERO_PAGE_START,
        ..Default::default()
    };
    let mut boot_header = load_kernel_image(kernel_path, sys_mem, &mut boot_loader_layout)?;

    load_initrd(config, sys_mem, &mut boot_header)
        .with_context(|| "Failed to load initrd to vm memory")?;

    setup_kernel_cmdline(config, sys_mem, &mut boot_header)
        .with_context(|| "Failed to setup kernel cmdline")?;

    setup_boot_params(config, sys_mem, &boot_header)
        .with_context(|| "Failed to setup boot params")?;

    setup_isa_mptable(
        sys_mem,
        EBDA_START,
        config.cpu_count,
        config.ioapic_addr,
        config.lapic_addr,
    )?;

    boot_loader_layout.boot_pml4_addr =
        setup_page_table(sys_mem).with_context(|| "Failed to setup page table")?;
    boot_loader_layout.segments = setup_gdt(sys_mem).with_context(|| "Failed to setup gdt")?;

    Ok(boot_loader_layout)
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;
    use std::sync::Arc;

    use kvm_bindings::kvm_segment;

    use super::super::BOOT_GDT_MAX;
    use super::*;
    use address_space::*;

    #[test]
    fn test_x86_bootloader_and_kernel_cmdline() {
        let root = Region::init_container_region(0x2000_0000, "root");
        let space = AddressSpace::new(root.clone(), "space", None).unwrap();
        let ram1 = Arc::new(
            HostMemMapping::new(
                GuestAddress(0),
                None,
                0x1000_0000,
                None,
                false,
                false,
                false,
            )
            .unwrap(),
        );
        let region_a = Region::init_ram_region(ram1.clone(), "region_a");
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
            kernel: Some(PathBuf::new()),
            initrd: Some(PathBuf::new()),
            kernel_cmdline: String::from("this_is_a_piece_of_test_string"),
            cpu_count: 2,
            gap_range: (0xC000_0000, 0x4000_0000),
            ioapic_addr: 0xFEC0_0000,
            lapic_addr: 0xFEE0_0000,
            prot64_mode: false,
            ident_tss_range: None,
        };
        let mut boot_hdr = RealModeKernelHeader::new();
        assert!(setup_boot_params(&config, &space, &boot_hdr).is_ok());

        // test setup_gdt function
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

        // test setup_kernel_cmdline function
        let cmd_len: u64 = config.kernel_cmdline.len() as u64;
        let mut read_buffer: [u8; 30] = [0; 30];
        assert!(setup_kernel_cmdline(&config, &space, &mut boot_hdr).is_ok());
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
