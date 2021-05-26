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

use std::io::{Read, Write};
use std::mem::size_of;

use crate::errors::{ErrorKind, Result, ResultExt};
use crate::header::{FileFormat, MigrationHeader};
use crate::manager::MigrationManager;
use util::byte_code::ByteCode;

/// The length of `MigrationHeader` part occupies bytes in snapshot file.
const HEADER_LENGTH: usize = 4096;

impl MigrationManager {
    /// Write `MigrationHeader` to `Write` trait object as bytes.
    /// `MigrationHeader` will occupy the first 4096 bytes in snapshot file.
    ///
    /// # Arguments
    ///
    /// * `file_format` - confirm snapshot file / migration stream file format.
    /// * `writer` - The `Write` trait object to write to receive header message.
    fn save_header(file_format: FileFormat, writer: &mut dyn Write) -> Result<()> {
        let mut header = MigrationHeader::default();
        header.format = file_format;
        let header_bytes = header.as_bytes();
        let mut input_slice = [0u8; HEADER_LENGTH];

        input_slice[0..size_of::<MigrationHeader>()].copy_from_slice(header_bytes);
        writer
            .write(&input_slice)
            .chain_err(|| "Failed to save migration header")?;

        Ok(())
    }

    /// Load and parse `MigrationHeader` from `Read` object.
    ///
    /// # Arguments
    ///
    /// * `reader` - The `Read` trait object.
    fn load_header(reader: &mut dyn Read) -> Result<MigrationHeader> {
        let mut header_bytes = [0u8; size_of::<MigrationHeader>()];
        reader.read_exact(&mut header_bytes)?;

        let mut place_holder = [0u8; HEADER_LENGTH - size_of::<MigrationHeader>()];
        reader.read_exact(&mut place_holder)?;

        Ok(*MigrationHeader::from_bytes(&header_bytes)
            .ok_or(ErrorKind::FromBytesError("HEADER"))?)
    }
}
