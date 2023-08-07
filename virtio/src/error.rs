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
pub enum VirtioError {
    #[error("Io")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("Util")]
    Util {
        #[from]
        source: util::error::UtilError,
    },
    #[error("AddressSpace")]
    AddressSpace {
        #[from]
        source: address_space::error::AddressSpaceError,
    },
    #[error("SysBus")]
    SysBus {
        #[from]
        source: devices::sysbus::error::SysBusError,
    },
    #[error("Failed to create eventfd.")]
    EventFdCreate,
    #[error("Failed to write eventfd.")]
    EventFdWrite,
    #[error("Failed to create {0} thread")]
    ThreadCreate(String),
    #[error("Failed to send {0} on the channel")]
    ChannelSend(String),
    #[error("Queue index {0} invalid, queue size is {1}")]
    QueueIndex(u16, u16),
    #[error("Vring descriptor is invalid")]
    QueueDescInvalid,
    #[error("Address overflows for {0}, address: 0x{1:x}, offset: {2}")]
    AddressOverflow(&'static str, u64, u64),
    #[error("Failed to r/w dev config space: overflows, offset {0}, len {1}, space size {2}")]
    DevConfigOverflow(u64, u64, u64),
    #[error("Failed to trigger interrupt for {0}, int-type {1:#?}")]
    InterruptTrigger(&'static str, super::VirtioInterruptType),
    #[error("Vhost ioctl failed: {0}")]
    VhostIoctl(String),
    #[error("Failed to get iovec from element!")]
    ElementEmpty,
    #[error("Virt queue is none!")]
    VirtQueueIsNone,
    #[error("Device {0} virt queue {1} is not enabled!")]
    VirtQueueNotEnabled(String, usize),
    #[error("Cannot perform activate. Expected {0} queue(s), got {1}")]
    IncorrectQueueNum(usize, usize),
    #[error("Incorrect offset, expected {0}, got {1}")]
    IncorrectOffset(u64, u64),
    #[error("Device {0} not activated")]
    DeviceNotActivated(String),
    #[error("Failed to write config")]
    FailedToWriteConfig,
    #[error("Failed to read object for {0}, address: 0x{1:x}")]
    ReadObjectErr(&'static str, u64),
    #[error("Invalid device status: 0x{0:x}.")]
    DevStatErr(u32),
    #[error("Unsupported mmio register at offset 0x{0:x}.")]
    MmioRegErr(u64),
}
