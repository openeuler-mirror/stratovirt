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

use crate::protocol::MigrationStatus;

#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("UtilError")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Json")]
    Json {
        #[from]
        source: serde_json::Error,
    },
    #[error("Migration compat_version {0} higher than current version {1}")]
    VersionNotFit(u32, u32),
    #[error("{0} for snapshot file / migration stream is not fit")]
    HeaderItemNotFit(String),
    #[error("Failed to transfer migration status from {0} to {1}.")]
    InvalidStatusTransfer(MigrationStatus, MigrationStatus),
    #[error("Can't restore structure from raw slice: {0}")]
    FromBytesError(&'static str),
    #[error("Failed to get GIC {0} register: {1}")]
    GetGicRegsError(&'static str, String),
    #[error("Failed to set GIC {0} register: {1}")]
    SetGicRegsError(&'static str, String),
    #[error("Failed to save vm memory: {0}")]
    SaveVmMemoryErr(String),
    #[error("Failed to restore vm memory: {0}")]
    RestoreVmMemoryErr(String),
    #[error("Failed to send vm memory: {0}")]
    SendVmMemoryErr(String),
    #[error("Failed to receive vm memory: {0}")]
    RecvVmMemoryErr(String),
    #[error("Response error")]
    ResponseErr,
    #[error("Migration status mismatch: source {0}, destination {1}.")]
    MigrationStatusErr(String, String),
    #[error("Migration config {0} mismatch: source {1}, destination {2}.")]
    MigrationConfigErr(String, String, String),
    #[error("Invalid snapshot path for restoring snapshot")]
    InvalidSnapshotPath,
}
