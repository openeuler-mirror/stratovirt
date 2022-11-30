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
pub enum VfioError {
    #[error("PciErr")]
    PciErr {
        #[from]
        source: pci::error::PciError,
    },
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("Hypervisor")]
    Hypervisor {
        #[from]
        source: hypervisor::error::HypervisorError,
    },
    #[error("Failed to add sub region at the BAR {0} in memory space.")]
    AddRegBar(usize),
    #[error("Vfio ioctl failed: {0}, error is: {1:?}")]
    VfioIoctl(String, std::io::Error),
}
