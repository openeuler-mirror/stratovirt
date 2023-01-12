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

//! # Machine Manager
//!
//! API Interface and configuration over virtual machine.
//!
//! ## Design
//!
//! This crate offers support for:
//! 1. A communication way to handle VM outside.
//! 2. The API interface over VM inside and outside.
//! 3. Configuration for VM and its devices.

pub mod cmdline;
pub mod config;
pub mod error;
pub mod event_loop;
pub mod machine;
pub mod qmp;
pub mod signal_handler;
pub mod socket;
pub mod temp_cleaner;
pub use error::MachineManagerError;
pub mod test_server;
