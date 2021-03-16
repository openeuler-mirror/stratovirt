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

use sysbus::SysRes;
use vmm_sys_util::eventfd::EventFd;

use super::errors::Result;

/// IO port of RTC device to select Register to read/write.
pub const RTC_PORT_INDEX: u64 = 0x70;
/// IO port of RTC device to read/write data from selected register.
pub const RTC_PORT_DATA: u64 = 0x71;
/// IRQ number of RTC device.
pub const RTC_IRQ: u32 = 8;

/// Index of register of time in RTC static RAM.
const RTC_SECONDS: u8 = 0x00;
const RTC_SECONDS_ALARM: u8 = 0x01;
const RTC_MINUTES: u8 = 0x02;
const RTC_MINUTES_ALARM: u8 = 0x03;
const RTC_HOURS: u8 = 0x04;
const RTC_HOURS_ARARM: u8 = 0x05;
const RTC_DAY_OF_WEAK: u8 = 0x06;
const RTC_DAY_OF_MONTH: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_REG_A: u8 = 0x0A;
const RTC_REG_B: u8 = 0x0B;
const RTC_REG_C: u8 = 0x0C;
const RTC_REG_D: u8 = 0x0D;
const RTC_CENTURY_BCD: u8 = 0x32;

fn get_utc_time() -> libc::tm {
    let time_val: libc::time_t = 0_i64;

    // Safe bacause `libc::time` only get time.
    unsafe { libc::time(time_val as *mut i64) };

    let mut dest_tm = libc::tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null_mut(),
    };

    // Safe because `libc::gmtime_r` just convert calendar time to
    // broken-down format, and saved to `dest_tm`.
    unsafe { libc::gmtime_r(&time_val, &mut dest_tm) };

    dest_tm
}

/// Transfer binary coded decimal to BCD coded decimal.
fn bin_to_bcd(src: u8) -> u8 {
    ((src / 10) << 4) + (src % 10)
}

/// RTC device.
pub struct RTC {
    /// Static CMOS RAM.
    cmos_data: [u8; 128],
    /// Index of Selected register.
    cur_index: u8,
    /// Interrupt eventfd.
    interrupt_evt: EventFd,
    /// Resource of RTC.
    res: SysRes,
}

impl RTC {
    /// Construct function of RTC device.
    pub fn new() -> Result<RTC> {
        let mut rtc = RTC {
            cmos_data: [0_u8; 128],
            cur_index: 0_u8,
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            res: SysRes::default(),
        };

        // Set VRT bit in Register-D, indicates that RAM and time are valid.
        rtc.cmos_data[RTC_REG_D as usize] = 0x80;

        Ok(rtc)
    }

    fn read_data(&self, data: &mut [u8]) -> bool {
        if data.len() != 1 {
            error!("RTC only support reading data byte by byte.");
            return false;
        }

        let tm = get_utc_time();
        match self.cur_index {
            RTC_SECONDS => {
                data[0] = bin_to_bcd(tm.tm_sec as u8);
            }
            RTC_MINUTES => {
                data[0] = bin_to_bcd(tm.tm_min as u8);
            }
            RTC_HOURS => {
                data[0] = bin_to_bcd(tm.tm_hour as u8);
            }
            RTC_DAY_OF_WEAK => {
                data[0] = bin_to_bcd((tm.tm_wday + 1) as u8);
            }
            RTC_DAY_OF_MONTH => {
                data[0] = bin_to_bcd(tm.tm_mday as u8);
            }
            RTC_MONTH => {
                data[0] = bin_to_bcd((tm.tm_mon + 1) as u8);
            }
            RTC_YEAR => {
                let year = tm.tm_year + 1900;
                data[0] = bin_to_bcd((year % 100) as u8);
            }
            RTC_CENTURY_BCD => {
                data[0] = bin_to_bcd(((tm.tm_year + 1900) % 100) as u8);
            }
            _ => {
                data[0] = self.cmos_data[self.cur_index as usize];
            }
        }

        true
    }

    fn write_data(&mut self, data: &[u8]) -> bool {
        if data.len() != 1 {
            error!("RTC only support writing data byte by byte.");
            return false;
        }

        match self.cur_index {
            RTC_REG_C | RTC_REG_D => {
                error!(
                    "read-only register , index: {}, data {}",
                    self.cur_index, data[0]
                );
                return false;
            }
            _ => {
                self.cmos_data[self.cur_index as usize] = data[0];
            }
        }
        true
    }
}
