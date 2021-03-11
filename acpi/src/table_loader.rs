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

use std::sync::{Arc, Mutex};

use util::byte_code::ByteCode;

use crate::AmlBuilder;

const TABLE_LOADER_FILE_NAME_SZ: usize = 56;
const TABLE_LOADER_ENTRY_SZ: usize = 124;

#[repr(u32)]
enum LoaderCmdType {
    Allocate = 1_u32,
    AddPointer,
    AddCksum,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct AllocateEntry {
    file: [u8; TABLE_LOADER_FILE_NAME_SZ],
    align: u32,
    zone: u8,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct AddPointerEntry {
    dst_file: [u8; TABLE_LOADER_FILE_NAME_SZ],
    src_file: [u8; TABLE_LOADER_FILE_NAME_SZ],
    // The location where the pointer stored in dst file.
    offset: u32,
    // The size of pointer which stored in dst file.
    size: u8,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct AddCksumEntry {
    file: [u8; TABLE_LOADER_FILE_NAME_SZ],
    // Offset that checksum locates in file.
    offset: u32,
    start: u32,
    length: u32,
}

/// The union that stores the content of command.
#[derive(Copy, Clone)]
union EntryContent {
    alloc: AllocateEntry,
    add_pointer: AddPointerEntry,
    add_cksum: AddCksumEntry,
    padding: [u8; TABLE_LOADER_ENTRY_SZ],
}

impl Default for EntryContent {
    fn default() -> Self {
        Self {
            padding: [0_u8; TABLE_LOADER_ENTRY_SZ],
        }
    }
}

impl ByteCode for EntryContent {}

/// Stores the command and corresponding content of entry.
/// - For `AllocateEntry`, Guest will alloc guest memory resource.
/// - For `AddPointerEntry`, Guest will update pointer at specified offset of dst file
///   by adding base address of source file.
/// - For `AddPointerEntry`, Guest will calculate u8-type checksum of a range in file
///   and store it at specified offset of the same file.
#[derive(Copy, Clone, Default)]
struct TableLoaderEntry {
    /// The Type of command.
    cmd: u32,
    /// The content of command.
    entry: EntryContent,
}

impl TableLoaderEntry {
    fn new_allocate_entry(file: String, align: u32, zone: u8) -> TableLoaderEntry {
        let mut file_bytes = [0_u8; TABLE_LOADER_FILE_NAME_SZ];
        let name_bytes = file.as_bytes();
        file_bytes[0..name_bytes.len()].copy_from_slice(name_bytes);

        TableLoaderEntry {
            cmd: LoaderCmdType::Allocate as u32,
            entry: EntryContent {
                alloc: AllocateEntry {
                    file: file_bytes,
                    align,
                    zone,
                },
            },
        }
    }

    fn new_add_pointer_entry(
        dst_file: String,
        src_file: String,
        offset: u32,
        size: u8,
    ) -> TableLoaderEntry {
        let mut dst_file_bytes = [0_u8; TABLE_LOADER_FILE_NAME_SZ];
        let dst_name_bytes = dst_file.as_bytes();
        dst_file_bytes[0..dst_name_bytes.len()].copy_from_slice(dst_name_bytes);

        let mut src_file_bytes = [0_u8; TABLE_LOADER_FILE_NAME_SZ];
        let src_name_bytes = src_file.as_bytes();
        src_file_bytes[0..src_name_bytes.len()].copy_from_slice(src_name_bytes);

        TableLoaderEntry {
            cmd: LoaderCmdType::AddPointer as u32,
            entry: EntryContent {
                add_pointer: AddPointerEntry {
                    dst_file: dst_file_bytes,
                    src_file: src_file_bytes,
                    offset,
                    size,
                },
            },
        }
    }

    fn new_add_cksum_entry(
        file: String,
        cksum_offset: u32,
        start: u32,
        length: u32,
    ) -> TableLoaderEntry {
        let mut file_bytes = [0_u8; TABLE_LOADER_FILE_NAME_SZ];
        let name_bytes = file.as_bytes();
        file_bytes[0..name_bytes.len()].copy_from_slice(name_bytes);
        TableLoaderEntry {
            cmd: LoaderCmdType::AddCksum as u32,
            entry: EntryContent {
                add_cksum: AddCksumEntry {
                    file: file_bytes,
                    offset: cksum_offset,
                    start,
                    length,
                },
            },
        }
    }
}

impl AmlBuilder for TableLoaderEntry {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.cmd.as_bytes());
        bytes.extend(self.entry.as_bytes());
        bytes
    }
}

/// Represents file blob data and corresponding file name.
struct TableLoaderFileEntry {
    /// File name.
    file_name: String,
    /// File blob data.
    file_blob: Arc<Mutex<Vec<u8>>>,
}
