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

//! # Legacy
//!
//! This mod emulate legacy devices include RTC and Serial.
//!
//! ## Design
//!
//! This module offers support for:
//! 1. Pl031 device, Arm PrimeCell Real Time Clock.
//! 2. Serial device, Serial UART.
//!
//! ## Platform Support
//!
//! - `x86_64`
//! - `aarch64`

pub mod errors {
    error_chain! {
        links {
            SysBus(sysbus::errors::Error, sysbus::errors::ErrorKind);
            AddressSpace(address_space::errors::Error, address_space::errors::ErrorKind);
        }

        foreign_links {
            Io(std::io::Error);
        }

        errors {
            SetSysResErr {
                display("Failed to allocate system bus resource.")
            }
        }
    }
}

#[allow(dead_code)]
#[cfg(target_arch = "aarch64")]
mod pl011;
#[cfg(target_arch = "aarch64")]
mod pl031;
#[allow(dead_code)]
#[cfg(target_arch = "x86_64")]
mod rtc;
mod serial;

#[cfg(target_arch = "x86_64")]
pub use self::rtc::{RTC, RTC_IRQ, RTC_PORT_INDEX};
#[cfg(target_arch = "aarch64")]
pub use pl011::PL011;
#[cfg(target_arch = "aarch64")]
pub use pl031::PL031;
pub use serial::{Serial, SERIAL_ADDR};
