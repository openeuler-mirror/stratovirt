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

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use address_space::{AddressSpace, GuestAddress};
use devices::legacy::{FwCfgEntryType, FwCfgOps};
use util::byte_code::ByteCode;
use util::num_ops::round_up;

const EI_MAG0: usize = 0;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const ELFMAG0: u8 = 0x7F;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

const ELFCLASS64: u8 = 2;

const ELFDATA2LSB: u8 = 1;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;

type Elf64_Addr = u64;
type Elf64_Half = u16;
type Elf64_Off = u64;
type Elf64_Word = u32;
type Elf64_Xword = u64;

const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 0x12;

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
struct Elf64Header {
    e_ident: [u8; 16usize],
    e_type: Elf64_Half,
    e_machine: Elf64_Half,
    e_version: Elf64_Word,
    e_entry: Elf64_Addr,
    e_phoff: Elf64_Off,
    e_shoff: Elf64_Off,
    e_flags: Elf64_Word,
    e_ehsize: Elf64_Half,
    e_phentsize: Elf64_Half,
    e_phnum: Elf64_Half,
    e_shentsize: Elf64_Half,
    e_shnum: Elf64_Half,
    e_shstrndx: Elf64_Half,
}

impl ByteCode for Elf64Header {}

impl Elf64Header {
    fn is_valid(&self) -> Result<()> {
        let elf_magic = vec![ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3];

        if self.e_ident[EI_MAG0..=EI_MAG3].to_vec() != elf_magic {
            bail!("Invalid magic in ELF header");
        }
        if self.e_ident[EI_DATA] != ELFDATA2LSB {
            bail!("Big endian ELF file is not supported");
        }
        if self.e_ident[EI_CLASS] != ELFCLASS64 {
            bail!("Only 64-bit ELF image is supported");
        }
        Ok(())
    }

    fn parse_prog_hdrs(&self, kernel_image: &mut File) -> Result<Vec<Elf64ProgHeader>> {
        kernel_image.seek(SeekFrom::Start(self.e_phoff))?;

        let mut elf_phs = Vec::with_capacity(self.e_phnum as usize);
        for _ in 0..self.e_phnum {
            let mut ph = Elf64ProgHeader::default();
            kernel_image.read_exact(ph.as_mut_bytes())?;
            elf_phs.push(ph);
        }
        Ok(elf_phs)
    }
}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
struct Elf64ProgHeader {
    p_type: Elf64_Word,
    p_flags: Elf64_Word,
    p_offset: Elf64_Off,
    p_vaddr: Elf64_Addr,
    p_paddr: Elf64_Addr,
    p_filesz: Elf64_Xword,
    p_memsz: Elf64_Xword,
    p_align: Elf64_Xword,
}

impl ByteCode for Elf64ProgHeader {}

#[repr(C, packed)]
#[derive(Debug, Default, Copy, Clone)]
struct Elf64NoteHeader {
    namesz: Elf64_Word,
    descsz: Elf64_Word,
    type_: Elf64_Word,
}

impl ByteCode for Elf64NoteHeader {}

/// Parse ELF_format kernel file and find the PVH entry.
///
/// # Arguments
///
/// `kernel_image` - ELF-format kernel file.
/// `sys_mem` - Guest memory.
/// `fwcfg` - FwCfg device.
pub fn load_elf_kernel(
    kernel_image: &mut File,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: &mut dyn FwCfgOps,
) -> Result<()> {
    kernel_image.rewind()?;
    let kernel_length = kernel_image.metadata().map(|m| m.len())?;

    let mut elf_header = Elf64Header::default();
    kernel_image.read_exact(elf_header.as_mut_bytes())?;
    elf_header
        .is_valid()
        .with_context(|| "ELF header is invalid")?;

    let ep_hdrs = elf_header
        .parse_prog_hdrs(kernel_image)
        .with_context(|| "Failed to parse ELF program header")?;

    let mut pvh_start_addr: Option<u64> = None;
    let mut addr_low = u64::MAX;
    let mut addr_max = 0_u64;
    for ph in &ep_hdrs {
        let ph_offset = ph.p_offset;
        let ph_size = ph.p_filesz;
        if ph_offset + ph_size > kernel_length {
            bail!(
                "ELF program header overflows: offset 0x{:x}, size 0x{:x}, ELF file size 0x{:x}",
                ph_offset,
                ph_size,
                kernel_length,
            );
        }

        if ph.p_type == PT_LOAD {
            kernel_image.seek(SeekFrom::Start(ph.p_offset))?;
            sys_mem.write(kernel_image, GuestAddress(ph.p_paddr), ph.p_filesz)?;

            addr_low = std::cmp::min(addr_low, ph.p_paddr);
            addr_max = std::cmp::max(addr_max, ph.p_paddr);
        }
        if ph.p_type == PT_NOTE {
            kernel_image.seek(SeekFrom::Start(ph.p_offset))?;
            let mut note_hdr = Elf64NoteHeader::default();
            let note_size = std::mem::size_of::<Elf64NoteHeader>() as u64;

            // Search for the target note header that contains PVH entry.
            let mut offset = 0;
            while offset + note_size <= ph.p_filesz {
                kernel_image.read_exact(note_hdr.as_mut_bytes())?;
                offset += note_size;

                let p_align = ph.p_align;
                let aligned_namesz =
                    round_up(note_hdr.namesz as u64, p_align).with_context(|| {
                        format!(
                            "Overflows when align up: num 0x{:x}, alignment 0x{:x}",
                            note_hdr.namesz as u64, p_align,
                        )
                    })?;
                if note_hdr.type_ == XEN_ELFNOTE_PHYS32_ENTRY {
                    kernel_image.seek(SeekFrom::Current(aligned_namesz as i64))?;

                    let mut entry_addr = 0_u64;
                    kernel_image.read_exact(entry_addr.as_mut_bytes())?;
                    pvh_start_addr = Some(entry_addr);
                    break;
                } else {
                    let aligned_descsz =
                        round_up(note_hdr.descsz as u64, p_align).with_context(|| {
                            format!(
                                "Overflows when align up, num 0x{:x}, alignment 0x{:x}",
                                note_hdr.descsz as u64, p_align,
                            )
                        })?;
                    let tail_size = aligned_namesz + aligned_descsz;

                    kernel_image.seek(SeekFrom::Current(tail_size as i64))?;
                    offset += tail_size;
                    continue;
                }
            }
        }
    }

    let pvh_start_addr = pvh_start_addr
        .with_context(|| "No Note header contains PVH entry info in ELF kernel image.")?;
    fwcfg.add_data_entry(
        FwCfgEntryType::KernelEntry,
        (pvh_start_addr as u32).as_bytes().to_vec(),
    )?;
    fwcfg.add_data_entry(
        FwCfgEntryType::KernelAddr,
        (addr_low as u32).as_bytes().to_vec(),
    )?;
    fwcfg.add_data_entry(
        FwCfgEntryType::KernelSize,
        (addr_max as u32 - addr_low as u32).as_bytes().to_vec(),
    )?;
    Ok(())
}
