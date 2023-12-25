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

//! # Interrupt Controller
//!
//! This module is to create and manager interrupt controller.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Create hypervisor-based interrupt controller.
//! 2. Manager lifecycle for `GIC`.
//!
//! ## Platform Support
//!
//! - `aarch64`

#[allow(clippy::upper_case_acronyms)]
mod aarch64;
mod error;

pub use anyhow::Result;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    GICConfig as ICGICConfig, GICDevice, GICVersion, GICv2, GICv2Access,
    GICv2Config as ICGICv2Config, GICv3, GICv3Access, GICv3Config as ICGICv3Config, GICv3ItsAccess,
    GICv3ItsState, GICv3State, GicRedistRegion, InterruptController, GIC_IRQ_INTERNAL, GIC_IRQ_MAX,
};
pub use error::InterruptError;
