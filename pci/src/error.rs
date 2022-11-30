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
pub enum PciError {
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("Failed to add PCI capability: id 0x{0:x}, size: 0x{1:x}.")]
    AddPciCap(u8, usize),
    #[error("Failed to add PCIe extended capability: id 0x{0:x}, size: 0x{1:x}.")]
    AddPcieExtCap(u16, usize),
    #[error("Failed to unmap BAR {0} in memory space.")]
    UnregMemBar(usize),
    #[error("Invalid device status 0x{0:x}")]
    DeviceStatus(u32),
    #[error("Unsupported pci register, 0x{0:x}")]
    PciRegister(u64),
    #[error("Invalid features select 0x{0:x}")]
    FeaturesSelect(u32),
    #[error("HotPlug is not supported for device with devfn {0}")]
    HotplugUnsupported(u8),
    #[error("Invalid PCI configuration, key:{0}, value:{1}")]
    InvalidConf(String, String),
    #[error("Failed to enable queue, value is 0x{0:x}")]
    QueueEnable(u32),
}
