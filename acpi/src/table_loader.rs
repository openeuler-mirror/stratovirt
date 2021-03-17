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

use crate::errors::{ErrorKind, Result, ResultExt};
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

/// Represents loader-entries that contents file and blob data of file.
#[derive(Default)]
pub struct TableLoader {
    /// Command entries.
    cmds: Vec<TableLoaderEntry>,
    /// File entries.
    files: Vec<TableLoaderFileEntry>,
}

impl TableLoader {
    /// Construct function.
    pub fn new() -> TableLoader {
        TableLoader {
            cmds: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Get byte stream of all loader-entries.
    pub fn cmd_entries(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        for entry in self.cmds.iter() {
            bytes.extend(entry.aml_bytes());
        }
        bytes
    }

    /// Find matched file entry according to `file_name` argument.
    ///
    /// # Arguments
    ///
    /// * `file_name` - The name of file to find.
    fn find_matched_file(&self, file_name: &str) -> Option<&TableLoaderFileEntry> {
        for file_entry in &self.files {
            if file_entry.file_name == file_name {
                return Some(file_entry);
            }
        }
        None
    }

    /// Add loader entry of type `Allocate`.
    ///
    /// # Arguments
    ///
    /// * `file` - File name.
    /// * `file_blob` - File blob data.
    /// * `align` - Required alignment of this blob.
    /// * `is_fseg` - Represents range where Guest will allocate for this entry.
    ///               If true, Guest will allocate in FSEG zone.
    pub fn add_alloc_entry(
        &mut self,
        file: &str,
        file_blob: Arc<Mutex<Vec<u8>>>,
        align: u32,
        is_fseg: bool,
    ) -> Result<()> {
        let file = file.to_string();
        if align & (align - 1) != 0 {
            return Err(ErrorKind::Alignment(align).into());
        }
        if self.find_matched_file(&file).is_some() {
            return Err(ErrorKind::FileEntryExist(file).into());
        }

        self.files.push(TableLoaderFileEntry {
            file_name: file.clone(),
            file_blob,
        });

        let zone = if is_fseg { 0x2 } else { 0x1 };
        self.cmds
            .push(TableLoaderEntry::new_allocate_entry(file, align, zone));

        Ok(())
    }

    /// Add loader entry of type `AddChecksum`.
    ///
    /// # Arguments
    ///
    /// * `file` - File name, must already stored in `files` field of `TableLoader`.
    /// * `cksum_offset` - Offset that checksum locates in file blob.
    /// * `start` - Start address of range.
    /// * `length` - Length of range.
    pub fn add_cksum_entry(
        &mut self,
        file: &str,
        cksum_offset: u32,
        start: u32,
        length: u32,
    ) -> Result<()> {
        let file = file.to_string();
        let file_entry = self
            .find_matched_file(&file)
            .chain_err(|| ErrorKind::NoMatchedFile(file.clone()))?;

        let file_entry_len = file_entry.file_blob.lock().unwrap().len();

        if cksum_offset as usize + 1 > file_entry_len {
            return Err(ErrorKind::AddrOverflow(cksum_offset, 1, file_entry_len).into());
        }
        if start as usize >= file_entry_len || (start + length) as usize > file_entry_len {
            return Err(ErrorKind::AddrOverflow(start, length, file_entry_len).into());
        }
        if cksum_offset < start {
            bail!("The offset of checksum should larger offset of start of range in file blob");
        }
        *file_entry
            .file_blob
            .lock()
            .unwrap()
            .get_mut(cksum_offset as usize)
            .unwrap() = 0_u8;

        self.cmds.push(TableLoaderEntry::new_add_cksum_entry(
            file,
            cksum_offset,
            start,
            length,
        ));

        Ok(())
    }

    /// Add LoaderEntry of type `AddPointer`.
    ///
    /// # Arguments
    ///
    /// * `dst_file` - Dst file name where pointer is stored.
    /// * `offset` - Offset where pointer locates in dst file.
    /// * `size` - Size of pointer.
    /// * `src_file` - Src file name where pointer points to.
    /// * `src_offset` - Offset in src file where pointer points to.
    pub fn add_pointer_entry(
        &mut self,
        dst_file: &str,
        offset: u32,
        size: u8,
        src_file: &str,
        src_offset: u32,
    ) -> Result<()> {
        let dst_file = dst_file.to_string();
        let src_file = src_file.to_string();
        let dst_file_entry = self
            .find_matched_file(&dst_file)
            .chain_err(|| ErrorKind::NoMatchedFile(dst_file.clone()))?;
        let src_file_entry = self
            .find_matched_file(&src_file)
            .chain_err(|| ErrorKind::NoMatchedFile(src_file.clone()))?;

        let dst_file_len = dst_file_entry.file_blob.lock().unwrap().len();
        let src_file_len = src_file_entry.file_blob.lock().unwrap().len();
        if src_offset as usize >= src_file_len
            || (src_offset + u32::from(size)) as usize > src_file_len
        {
            return Err(ErrorKind::AddrOverflow(src_offset, u32::from(size), src_file_len).into());
        }
        if offset as usize >= dst_file_len || (offset + u32::from(size)) as usize > dst_file_len {
            return Err(ErrorKind::AddrOverflow(offset, u32::from(size), dst_file_len).into());
        }
        if size != 1 && size != 2 && size != 4 && size != 8 {
            return Err(ErrorKind::AddPointerLength(size).into());
        }

        dst_file_entry.file_blob.lock().unwrap()
            [offset as usize..(offset as usize + size as usize)]
            .copy_from_slice(&(src_offset as u64).as_bytes()[0..size as usize]);

        self.cmds.push(TableLoaderEntry::new_add_pointer_entry(
            dst_file, src_file, offset, size,
        ));

        Ok(())
    }
}
