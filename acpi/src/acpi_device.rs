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

// Frequency of PM Timer in HZ.
const PM_TIMER_FREQUENCY: u128 = 3_579_545;
const NANOSECONDS_PER_SECOND: u128 = 1_000_000_000;

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
        let counter: u128 = (time_nanos * PM_TIMER_FREQUENCY) / NANOSECONDS_PER_SECOND;

        data.copy_from_slice(&((counter & 0xFFFF_FFFF) as u32).to_le_bytes());
        true
    }
}
