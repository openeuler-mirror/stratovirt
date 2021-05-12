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

//! # Migration
//!
//! Offer snapshot and migration interface for VM.

#[macro_use]
extern crate error_chain;

mod device_state;
#[allow(dead_code)]
mod header;

pub use device_state::{DeviceStateDesc, FieldDesc, StateTransfer};

pub mod errors {
    error_chain! {
        foreign_links {
            Io(std::io::Error);
        }
        errors {
            VersionNotFit(compat_version: u32, current_version: u32) {
                display("Migration compat_version {} higher than current version {}", compat_version, current_version)
            }
            HeaderItemNotFit(item: String) {
                display("{} for snapshot file / migration stream is not fit", item)
            }
        }
    }
}
