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
            AddEntryErr(key: String) {
                display("Failed to add FwCfg entry, key is {}", key)
            }
            EntryNotFound(key: String) {
                display("Failed to find FwCfg entry, key is {}.", key)
            }
            DuplicateFile(key: String) {
                display("Duplicate FwCfg file-entry, name is {}", key)
            }
            FileSlotsNotAvailable(key: String) {
                display("No available FwCfg file-slot for this file entry with filename {}", key)
            }
            ReadDmaRequest(addr: u64, size: u64) {
                display("Failed to read DMA request, dma_addr=0x{:x} size=0x{:x}", addr, size)
            }
            InvalidFwCfgEntry(key: u16) {
                display("Invalid FwCfg entry key {}", key)
            }
            PFlashWriteOverflow(size:u64, offset: u64, data_len: u64) {
                display("Flash size is 0x{:x}, offset 0x{:x} and size 0x{:x} in write request overflows", size, offset, data_len)
            }
            PFlashReadOverflow(size:u64, offset: u64, data_len: u64) {
                display("Flash size is 0x{:x}, offset 0x{:x} and size 0x{:x} in read request overflows", size, offset, data_len)
            }
            PFlashFileSeekErr(offset: u64) {
                display("Failed to seek to offset 0x{:x} of PFlash file", offset)
            }
            PFlashIndexOverflow(index: u64, len: usize) {
                display("Flash CFI table len is 0x{:x}, request 0x{:x} overflows", len, index)
            }
            PFlashDevConfigErr(dev_width: u32, bank_width: u32) {
                display("Unsupported device configuration: device width {}, bank width {}", dev_width, bank_width)
            }
            WritePFlashRomErr {
                display("Failed to write to Flash ROM")
            }
            RegNotifierErr {
                display("Failed to register event notifier.")
            }
        }
    }
}

mod chardev;
#[allow(dead_code)]
mod fwcfg;
#[allow(dead_code)]
mod pflash;
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
pub use chardev::{Chardev, InputReceiver};
#[cfg(target_arch = "x86_64")]
pub use fwcfg::FwCfgIO;
#[cfg(target_arch = "aarch64")]
pub use fwcfg::FwCfgMem;
pub use fwcfg::{FwCfgEntryType, FwCfgOps};
pub use pflash::PFlash;
#[cfg(target_arch = "aarch64")]
pub use pl011::PL011;
#[cfg(target_arch = "aarch64")]
pub use pl031::PL031;
pub use serial::{Serial, SERIAL_ADDR};
