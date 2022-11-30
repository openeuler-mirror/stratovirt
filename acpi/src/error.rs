// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcpiError {
    #[error("Failed to add AllocateEntry in TableLoader, file_blob {0} already exists.")]
    FileEntryExist(String),
    #[error("Failed to find matched file_blob in TableLoader, file name: {0}.")]
    NoMatchedFile(String),
    #[error("Invalid alignment {0}. Alignment is in bytes, and must be a power of 2.")]
    Alignment(u32),
    #[error("Address overflows, offset {0}, size {1}, max size {2}.")]
    AddrOverflow(u32, u32, usize),
    #[error("Failed to add pointer command: pointer length {0}, which is expected to be 1/2/4/8.")]
    AddPointerLength(u8),
}
