// Copyright (c) 2026 Huawei Technologies Co.,Ltd. All rights reserved.
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

pub mod tpm_crb;
pub mod tpm_tis;

pub use tpm_crb::TpmCrb;
pub use tpm_tis::TpmTis;

use std::fmt;

use clap::{Parser, ValueEnum};
use machine_manager::config::valid_id;

#[derive(Parser, Clone, Debug, Default)]
#[command(no_binary_name(true))]
pub struct TpmConfig {
    #[arg(long)]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    id: Option<String>,
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value_t = TpmInterfaceType::Tis)]
    pub interface_type: TpmInterfaceType,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum TpmInterfaceType {
    Crb,
    #[default]
    Tis,
}

impl fmt::Display for TpmInterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmInterfaceType::Crb => write!(f, "crb"),
            TpmInterfaceType::Tis => write!(f, "tis"),
        }
    }
}

/// TPM Address Range
pub const TPM_START: u64 = 0x0909_1000;
pub const TPM_CRB_SIZE: u64 = 0x1000;
pub const TPM_TIS_SIZE: u64 = 0x5000;

/// ACPI Start Method
pub const TPM2_START_METHOD_MMIO: u32 = 6;
pub const TPM2_START_METHOD_CRB: u32 = 7;

pub const TPM_DISCONNECTED_NOTIFY_CODE: u32 = 1;
