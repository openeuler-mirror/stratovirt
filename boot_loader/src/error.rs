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

#[derive(Error, Debug)]
pub enum BootLoaderError {
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("FwCfg")]
    FwCfg {
        #[from]
        source: devices::legacy::error::LegacyError,
    },
    #[allow(clippy::upper_case_acronyms)]
    #[cfg(target_arch = "aarch64")]
    #[error(
        "guest memory size {0} should bigger than {}",
        util::device_tree::FDT_MAX_SIZE
    )]
    DTBOverflow(u64),
    #[error("Failed to load kernel image {0} to memory {1}.")]
    KernelOverflow(u64, u64),
    #[error("Failed to load initrd image {0} to memory {1}.")]
    InitrdOverflow(u64, u64),
    #[error("Failed to open kernel image")]
    BootLoaderOpenKernel,
    #[error("Failed to open initrd image")]
    BootLoaderOpenInitrd,
    #[error("Configure cpu number({0}) above supported max cpu numbers(254)")]
    MaxCpus(u8),
    #[error("Invalid bzImage kernel file")]
    #[cfg(target_arch = "x86_64")]
    InvalidBzImage,
    #[error("Kernel version is too old.")]
    #[cfg(target_arch = "x86_64")]
    OldVersionKernel,
    #[error("ELF-format kernel is not supported")]
    #[cfg(target_arch = "x86_64")]
    ElfKernel,
}
