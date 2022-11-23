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

use std::time::Instant;

use address_space::GuestAddress;
use log::error;

use util::{
    num_ops::{read_data_u16, write_data_u16},
    time::NANOSECONDS_PER_SECOND,
};

// Frequency of PM Timer in HZ.
const PM_TIMER_FREQUENCY: u128 = 3_579_545;
pub const ACPI_BITMASK_SLEEP_ENABLE: u16 = 0x2000;

/// ACPI Power Management Timer
#[allow(clippy::upper_case_acronyms)]
pub struct AcpiPMTimer {
    start: Instant,
}

impl Default for AcpiPMTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl AcpiPMTimer {
    pub fn new() -> AcpiPMTimer {
        AcpiPMTimer {
            start: Instant::now(),
        }
    }

    pub fn read(&mut self, data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
        if data.len() != 4 {
            error!(
                "PM Timer read: invalid data length {}, required length is 4",
                data.len()
            );
        }
        let now = Instant::now();
        let time_nanos = now.duration_since(self.start).as_nanos();
        let counter: u128 = (time_nanos * PM_TIMER_FREQUENCY) / (NANOSECONDS_PER_SECOND as u128);

        data.copy_from_slice(&((counter & 0xFFFF_FFFF) as u32).to_le_bytes());
        true
    }
}

#[derive(Default)]
pub struct AcpiPmEvent {
    // PM1 Status Registers, location: PM1a_EVT_BLK.
    status: u16,
    // PM1Enable Registers, location: PM1a_EVT_BLK + PM1_EVT_LEN / 2.
    enable: u16,
}

impl AcpiPmEvent {
    pub fn new() -> AcpiPmEvent {
        AcpiPmEvent {
            status: 0,
            enable: 0,
        }
    }

    pub fn read(&mut self, data: &mut [u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0 => write_data_u16(data, self.status),
            2 => write_data_u16(data, self.enable),
            _ => {
                error!("Invalid offset");
                false
            }
        }
    }

    pub fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        match offset {
            0 => {
                let mut value = 0;
                if !read_data_u16(data, &mut value) {
                    return false;
                }
                self.status &= !value;
            }
            2 => {
                let mut value = 0;
                if !read_data_u16(data, &mut value) {
                    return false;
                }
                self.enable = value;
            }
            _ => {
                error!("Invalid offset");
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
pub struct AcpiPmCtrl {
    control: u16,
}

impl AcpiPmCtrl {
    pub fn new() -> AcpiPmCtrl {
        AcpiPmCtrl { control: 0 }
    }

    pub fn read(&mut self, data: &mut [u8], _base: GuestAddress, _offset: u64) -> bool {
        write_data_u16(data, self.control)
    }

    // Return true when guest want poweroff.
    pub fn write(&mut self, data: &[u8], _base: GuestAddress, _offset: u64) -> bool {
        let mut value = 0;
        if !read_data_u16(data, &mut value) {
            return false;
        }
        self.control = value & !ACPI_BITMASK_SLEEP_ENABLE;
        value & ACPI_BITMASK_SLEEP_ENABLE != 0
    }
}
