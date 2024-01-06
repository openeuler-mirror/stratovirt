// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

#[allow(clippy::upper_case_acronyms)]
#[derive(Error, Debug)]
pub enum HypervisorError {
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set identity map address.")]
    SetIdentityMapAddr,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to set tss address.")]
    SetTssErr,
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to create PIT.")]
    CrtPitErr,
}
