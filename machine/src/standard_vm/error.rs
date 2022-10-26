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

#[allow(clippy::upper_case_acronyms)]
#[derive(Error, Debug)]
pub enum StandardVmError {
    #[error("")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("")]
    Cpu {
        #[from]
        source: cpu::error::CpuError,
    },
    #[error("")]
    Legacy {
        #[from]
        source: devices::legacy::error::LegacyError,
    },
    #[error("")]
    PciErr {
        #[from]
        source: pci::error::PciError,
    },
    #[error("")]
    Acpi {
        #[from]
        source: acpi::error::AcpiError,
    },
    #[error("")]
    MachineManager {
        #[from]
        source: machine_manager::config::error::ConfigError,
    },
    #[error("")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Failed to init PCIe host.")]
    InitPCIeHostErr,
    #[error("Failed to open file: {0}.")]
    OpenFileErr(String),
    #[error("Failed to init pflash device.")]
    InitPflashErr,
    #[error("Failed to realize pflash device.")]
    RlzPflashErr,
}
