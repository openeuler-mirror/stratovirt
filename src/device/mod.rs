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

#[cfg(target_arch = "aarch64")]
mod gicv3;
mod serial;

#[cfg(target_arch = "aarch64")]
pub use gicv3::GICv3;
pub use serial::{
    judge_serial_addr, Serial, MMIO_SERIAL_ADDR, MMIO_SERIAL_ADDR_SIZE, MMIO_SERIAL_IRQ,
};

#[derive(Debug)]
pub enum Error {
    Overflow(usize, usize),
    IoError(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Overflow(len, max_len) => write!(
                f,
                "The received buffer {} overflow, max_len: {}",
                len, max_len
            ),
            Error::IoError(ref e) => {
                write!(f, "IO errors occurs when read/write memory, error is {}", e)
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
