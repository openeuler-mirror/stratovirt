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

#[allow(non_camel_case_types)]
mod elf;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use log::{error, info};

use self::elf::load_elf_kernel;
use super::bootparam::RealModeKernelHeader;
use super::X86BootLoaderConfig;
use super::{BOOT_HDR_START, CMDLINE_START};
use crate::error::BootLoaderError;
use crate::x86_64::bootparam::{E820Entry, E820_RAM, E820_RESERVED, UEFI_OVMF_ID};
use crate::x86_64::{INITRD_ADDR_MAX, SETUP_START};
use address_space::AddressSpace;
use devices::legacy::{FwCfgEntryType, FwCfgOps};
use util::byte_code::ByteCode;

fn load_image(
    image: &mut File,
    file_offset: u64,
    key: FwCfgEntryType,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<()> {
    let file_len = image.metadata().unwrap().len();
    if file_offset >= file_len {
        bail!(
            "File offset 0x{:x} overflows file length 0x{:x}",
            file_offset,
            file_len
        );
    }

    image.seek(SeekFrom::Start(file_offset))?;
    let mut bytes = vec![0_u8; (file_len - file_offset) as usize];
    image.read_exact(bytes.as_mut_slice())?;

    fwcfg.add_data_entry(key, bytes)?;
    Ok(())
}

fn load_kernel_image(
    kernel_image: &mut File,
    header: &RealModeKernelHeader,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<Vec<u8>> {
    let mut setup_size = header.setup_sects as u64;
    if setup_size == 0 {
        setup_size = 4;
    }
    setup_size = (setup_size + 1) << 9;

    let mut setup_data = vec![0_u8; setup_size as usize];
    kernel_image.rewind()?;
    kernel_image.read_exact(setup_data.as_mut_slice())?;

    let kernel_size = kernel_image.metadata().unwrap().len() - setup_size;
    load_image(kernel_image, setup_size, FwCfgEntryType::KernelData, fwcfg)
        .with_context(|| "Failed to load kernel image")?;

    let kernel_start = header.code32_start; // boot_hdr.code32_start = 0x100000
    fwcfg
        .add_data_entry(FwCfgEntryType::KernelAddr, kernel_start.as_bytes().to_vec())
        .with_context(|| "Failed to add kernel-addr entry to FwCfg")?;
    fwcfg
        .add_data_entry(
            FwCfgEntryType::KernelSize,
            (kernel_size as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add kernel-size entry to FwCfg")?;

    Ok(setup_data)
}

fn load_initrd(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    header: &mut RealModeKernelHeader,
    fwcfg: &mut dyn FwCfgOps,
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

    load_image(&mut initrd_image, 0, FwCfgEntryType::InitrdData, fwcfg)
        .with_context(|| "Failed to load initrd")?;
    fwcfg
        .add_data_entry(
            FwCfgEntryType::InitrdAddr,
            (initrd_addr as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add initrd-addr entry to FwCfg")?;
    fwcfg
        .add_data_entry(
            FwCfgEntryType::InitrdSize,
            (initrd_size as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add initrd-size to FwCfg")?;

    header.set_ramdisk(initrd_addr as u32, initrd_size as u32);
    Ok(())
}

fn setup_e820_table(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<()> {
    let mut e820_table: Vec<E820Entry> = Vec::new();
    let mem_end = sys_mem.memory_end_address().raw_value();
    let mem_below_4g = std::cmp::min(mem_end, config.gap_range.0);

    e820_table.push(E820Entry::new(0, mem_below_4g, E820_RAM));
    let mem_above_4g_start = config.gap_range.0 + config.gap_range.1;
    if mem_end > mem_above_4g_start {
        e820_table.push(E820Entry::new(
            mem_above_4g_start,
            mem_end - mem_above_4g_start,
            E820_RAM,
        ));
    }

    if let Some(identity_range) = config.ident_tss_range {
        let identity_entry = E820Entry::new(identity_range.0, identity_range.1, E820_RESERVED);
        e820_table.push(identity_entry);
    } else {
        error!("The page-table and TSS address is not provided");
    }

    let bytes = e820_table.iter().fold(Vec::new(), |mut bytes, entry| {
        bytes.extend(entry.as_bytes());
        bytes
    });
    fwcfg
        .add_file_entry("etc/e820", bytes)
        .with_context(|| "Failed to add e820 file entry to FwCfg")?;
    Ok(())
}

fn load_kernel_cmdline(
    config: &X86BootLoaderConfig,
    boot_hdr: &mut RealModeKernelHeader,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<()> {
    let cmdline_len = config.kernel_cmdline.len() as u32;
    boot_hdr.set_cmdline(CMDLINE_START as u32, cmdline_len);

    fwcfg
        .add_data_entry(
            FwCfgEntryType::CmdlineAddr,
            (CMDLINE_START as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add cmdline-addr entry to FwCfg")?;
    // The length of cmdline should add the tailing `\0`.
    fwcfg
        .add_data_entry(
            FwCfgEntryType::CmdlineSize,
            (cmdline_len + 1).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add cmdline-size entry to FwCfg")?;
    fwcfg
        .add_string_entry(FwCfgEntryType::CmdlineData, config.kernel_cmdline.as_ref())
        .with_context(|| "Failed to add cmdline-data entry to FwCfg")?;

    Ok(())
}

/// Load ELF-format / bzImage linux kernel and other boot source.
///
/// # Arguments
///
/// * `config` - Boot source config, contains kernel, initrd and kernel cmdline.
/// * `sys_mem` - Guest memory.
/// * `fwcfg` - FwCfg device.
pub fn load_linux(
    config: &X86BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<()> {
    if config.kernel.is_none() {
        setup_e820_table(config, sys_mem, fwcfg)?;
        return Ok(());
    }

    let mut kernel_image = File::open(config.kernel.as_ref().unwrap().clone())
        .with_context(|| BootLoaderError::BootLoaderOpenKernel)?;

    let mut boot_header = RealModeKernelHeader::default();
    kernel_image.seek(SeekFrom::Start(BOOT_HDR_START))?;
    kernel_image.read_exact(boot_header.as_mut_bytes())?;
    boot_header.type_of_loader = UEFI_OVMF_ID;

    load_kernel_cmdline(config, &mut boot_header, fwcfg)?;
    setup_e820_table(config, sys_mem, fwcfg)?;
    load_initrd(config, sys_mem, &mut boot_header, fwcfg)?;
    if let Err(e) = boot_header.check_valid_kernel() {
        if let Some(err) = e.downcast_ref::<BootLoaderError>() {
            match err {
                BootLoaderError::ElfKernel => {
                    load_elf_kernel(&mut kernel_image, sys_mem, fwcfg)?;
                    return Ok(());
                }
                _ => return Err(e),
            }
        }
    }

    let mut setup_data = load_kernel_image(&mut kernel_image, &boot_header, fwcfg)?;
    let min_setup_len = std::cmp::min(
        setup_data.len(),
        BOOT_HDR_START as usize + boot_header.as_bytes().len(),
    );
    setup_data.as_mut_slice()[BOOT_HDR_START as usize..min_setup_len]
        .copy_from_slice(&boot_header.as_bytes()[0..(min_setup_len - BOOT_HDR_START as usize)]);

    fwcfg
        .add_data_entry(
            FwCfgEntryType::SetupAddr,
            (SETUP_START as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add setup-addr to FwCfg")?;
    fwcfg
        .add_data_entry(
            FwCfgEntryType::SetupSize,
            (setup_data.len() as u32).as_bytes().to_vec(),
        )
        .with_context(|| "Failed to add setup-size entry to FwCfg")?;
    fwcfg
        .add_data_entry(FwCfgEntryType::SetupData, setup_data)
        .with_context(|| "Failed to add setup-data entry to FwCfg")?;

    Ok(())
}
