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
//! 1. Create kvm-based interrupt controller.
//! 2. Manager lifecycle for `GIC`.
//!
//! ## Platform Support
//!
//! - `aarch64`

#[allow(clippy::upper_case_acronyms)]
mod aarch64;
mod error;

pub use anyhow::Result;

pub use aarch64::GICConfig as ICGICConfig;
pub use aarch64::GICv2Config as ICGICv2Config;
pub use aarch64::GICv3Config as ICGICv3Config;
pub use aarch64::InterruptController;
pub use aarch64::GIC_IRQ_INTERNAL;
pub use aarch64::GIC_IRQ_MAX;
pub use error::InterruptError;
