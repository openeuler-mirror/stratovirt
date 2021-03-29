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

use util::byte_code::ByteCode;

use crate::errors::Result;

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;

const ELFMAG0: u8 = 0x7F;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

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
            bail!("Big endian ELF file is not suppored");
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
