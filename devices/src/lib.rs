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

//! Interfaces for simulating various devices.
//!
//! This crate simulates:
//! - interrupt controller (aarch64)
//! - legacy devices, such as serial devices

mod interrupt_controller;
pub mod legacy;

#[cfg(target_arch = "aarch64")]
pub use interrupt_controller::{
    ICGICConfig, ICGICv2Config, ICGICv3Config, InterruptController, InterruptError as IntCtrlErrs,
    GIC_IRQ_MAX,
};
pub use legacy::error::LegacyError as LegacyErrs;
