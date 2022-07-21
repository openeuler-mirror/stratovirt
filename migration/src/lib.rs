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

//! # Migration
//!
//! Offer snapshot and migration interface for VM.

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

pub mod general;
pub mod manager;
pub mod migration;
pub mod protocol;
pub mod snapshot;

pub use manager::{MigrationHook, MigrationManager};
pub use protocol::{DeviceStateDesc, FieldDesc, MemBlock, MigrationStatus, StateTransfer};

pub mod errors {
    use super::protocol::MigrationStatus;

    error_chain! {
        links {
            Util(util::errors::Error, util::errors::ErrorKind);
            Hypervisor(hypervisor::errors::Error, hypervisor::errors::ErrorKind);
        }
        foreign_links {
            Io(std::io::Error);
            Ioctl(kvm_ioctls::Error);
            Json(serde_json::Error);
        }
        errors {
            VersionNotFit(compat_version: u32, current_version: u32) {
                display("Migration compat_version {} higher than current version {}", compat_version, current_version)
            }
            HeaderItemNotFit(item: String) {
                display("{} for snapshot file / migration stream is not fit", item)
            }
            InvalidStatusTransfer(status1: MigrationStatus, status2: MigrationStatus) {
                display("Failed to transfer migration status from {} to {}.", status1, status2)
            }
            FromBytesError(name: &'static str) {
                display("Can't restore structure from raw slice: {}", name)
            }
            GetGicRegsError(reg: &'static str, ret: String) {
                display("Failed to get GIC {} register: {}", reg, ret)
            }
            SetGicRegsError(reg: &'static str, ret: String) {
                display("Failed to set GIC {} register: {}", reg, ret)
            }
            SaveVmMemoryErr(e: String) {
                display("Failed to save vm memory: {}", e)
            }
            RestoreVmMemoryErr(e: String) {
                display("Failed to restore vm memory: {}", e)
            }
            SendVmMemoryErr(e: String) {
                display("Failed to send vm memory: {}", e)
            }
            RecvVmMemoryErr(e: String) {
                display("Failed to receive vm memory: {}", e)
            }
            ResponseErr {
                display("Response error")
            }
            MigrationStatusErr(source: String, destination: String) {
                display("Migration status mismatch: source {}, destination {}.", source, destination)
            }
            MigrationConfigErr(config_type: String, source: String, destination: String) {
                display("Migration config {} mismatch: source {}, destination {}.", config_type, source, destination)
            }
            InvalidSnapshotPath {
                display("Invalid snapshot path for restoring snapshot")
            }
        }
    }
}
