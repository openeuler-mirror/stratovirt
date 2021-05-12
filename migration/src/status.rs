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

use crate::errors::{ErrorKind, Result};

/// This status for migration in migration process.
///
/// # Notes
///
/// State transfer:
/// None -----------> Setup: set up migration resource.
/// Setup ----------> Active: start to migrate.
/// Active ---------> Completed: migrate completed successfully.
/// Completed ------> Active: start to migrate again after a successfully migration.
/// Failed ---------> Setup: reset migration resource.
/// Any ------------> Failed: Something wrong in migration.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MigrationStatus {
    /// Migration resource is not prepared all
    None = 0,
    /// Migration resource(desc_db, device_instance, ...) is setup.
    Setup = 1,
    /// In migration or incoming migrating.
    Active = 2,
    /// Migration finished.
    Completed = 3,
    /// Migration failed.
    Failed = 4,
}

impl std::fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MigrationStatus::None => "none",
                MigrationStatus::Setup => "setup",
                MigrationStatus::Active => "active",
                MigrationStatus::Completed => "completed",
                MigrationStatus::Failed => "failed",
            }
        )
    }
}

impl MigrationStatus {
    pub fn transfer(self, new_status: MigrationStatus) -> Result<MigrationStatus> {
        match self {
            MigrationStatus::None => match new_status {
                MigrationStatus::Setup => Ok(new_status),
                _ => Err(ErrorKind::InvalidStatusTransfer(self, new_status).into()),
            },
            MigrationStatus::Setup => match new_status {
                MigrationStatus::Active | MigrationStatus::Failed => Ok(new_status),
                _ => Err(ErrorKind::InvalidStatusTransfer(self, new_status).into()),
            },
            MigrationStatus::Active => match new_status {
                MigrationStatus::Completed | MigrationStatus::Failed => Ok(new_status),
                _ => Err(ErrorKind::InvalidStatusTransfer(self, new_status).into()),
            },
            MigrationStatus::Completed => match new_status {
                MigrationStatus::Active => Ok(new_status),
                _ => Err(ErrorKind::InvalidStatusTransfer(self, new_status).into()),
            },
            MigrationStatus::Failed => match new_status {
                MigrationStatus::Setup => Ok(new_status),
                _ => Err(ErrorKind::InvalidStatusTransfer(self, new_status).into()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_transfer() {
        let mut status = MigrationStatus::None;

        // None to Setup.
        assert!(status.transfer(MigrationStatus::Setup).is_ok());
        status = status.transfer(MigrationStatus::Setup).unwrap();

        // Setup to Active.
        assert!(status.transfer(MigrationStatus::Active).is_ok());
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Active to Completed.
        assert!(status.transfer(MigrationStatus::Completed).is_ok());
        status = status.transfer(MigrationStatus::Completed).unwrap();

        // Completed to Active.
        assert!(status.transfer(MigrationStatus::Active).is_ok());
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Any to Failed.
        assert!(status.transfer(MigrationStatus::Failed).is_ok());
        status = status.transfer(MigrationStatus::Failed).unwrap();

        // Failed to Setup.
        assert!(status.transfer(MigrationStatus::Setup).is_ok());
        status = status.transfer(MigrationStatus::Setup).unwrap();

        assert_eq!(status, MigrationStatus::Setup);
    }

    #[test]
    fn test_abnormal_transfer_with_error() {
        let mut status = MigrationStatus::None;

        // None to Active.
        if let Err(e) = status.transfer(MigrationStatus::Active) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::None,
                    MigrationStatus::Active
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Setup).unwrap();

        // Setup to Complete.
        if let Err(e) = status.transfer(MigrationStatus::Completed) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Setup,
                    MigrationStatus::Completed
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Active).unwrap();

        // Active to Setup.
        if let Err(e) = status.transfer(MigrationStatus::Setup) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Active,
                    MigrationStatus::Setup
                )
            );
        } else {
            assert!(false)
        }
        status = status.transfer(MigrationStatus::Completed).unwrap();

        // Completed to Setup.
        if let Err(e) = status.transfer(MigrationStatus::Setup) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Completed,
                    MigrationStatus::Setup
                )
            );
        } else {
            assert!(false)
        }

        // Complete to failed.
        if let Err(e) = status.transfer(MigrationStatus::Failed) {
            assert_eq!(
                e.to_string(),
                format!(
                    "Failed to transfer migration status from {} to {}.",
                    MigrationStatus::Completed,
                    MigrationStatus::Failed
                )
            );
        } else {
            assert!(false)
        }
    }
}
