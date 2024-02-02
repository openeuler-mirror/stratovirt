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

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use log::{debug, error, warn};
use vmm_sys_util::eventfd::EventFd;

use crate::sysbus::{SysBus, SysBusDevBase, SysBusDevOps, SysBusDevType, SysRes};
use crate::{Device, DeviceBase};
use acpi::{
    AmlBuilder, AmlDevice, AmlEisaId, AmlIoDecode, AmlIoResource, AmlIrqNoFlags, AmlNameDecl,
    AmlResTemplate, AmlScopeBuilder,
};
use address_space::GuestAddress;
use util::time::{mktime64, NANOSECONDS_PER_SECOND};

/// IO port of RTC device to select Register to read/write.
pub const RTC_PORT_INDEX: u64 = 0x70;

/// Index of register of time in RTC static RAM.
const RTC_SECONDS: u8 = 0x00;
const RTC_MINUTES: u8 = 0x02;
const RTC_HOURS: u8 = 0x04;
const RTC_DAY_OF_WEEK: u8 = 0x06;
const RTC_DAY_OF_MONTH: u8 = 0x07;
const RTC_MONTH: u8 = 0x08;
const RTC_YEAR: u8 = 0x09;
const RTC_REG_A: u8 = 0x0A;
const RTC_REG_B: u8 = 0x0B;
const RTC_REG_C: u8 = 0x0C;
const RTC_REG_D: u8 = 0x0D;
const RTC_CENTURY_BCD: u8 = 0x32;

// Update in progress (UIP) bit.
const REG_A_UIP: u8 = 0x80;
// UIP bit held for last 244 us of every second.
const UIP_HOLD_LENGTH: u64 = 8 * NANOSECONDS_PER_SECOND / 32768;

// Index of memory data in RTC static RAM.
// 0x15/0x16 stores low/high byte below 1MB, range is [0, 640KB].
const CMOS_BASE_MEM: (u8, u8) = (0x15, 0x16);
// 0x17/0x18 stores low/high byte of memory between [1MB, 64MB], unit is KB.
const CMOS_EXT_MEM: (u8, u8) = (0x17, 0x18);
// 0x30/0x31 stores low/high byte of memory between [1MB, 64MB], unit is KB.
const CMOS_ACTUAL_EXT_MEM: (u8, u8) = (0x30, 0x31);
// 0x34/0x35 stores low/high byte of memory between [16MB, 4GB], unit is 64KB.
const CMOS_MEM_BELOW_4GB: (u8, u8) = (0x34, 0x35);
// 0x5B/0x5C/0x5D stores low/middle/high byte of memory above 4GB, unit is 64KB.
const CMOS_MEM_ABOVE_4GB: (u8, u8, u8) = (0x5B, 0x5C, 0x5D);

fn rtc_time_to_tm(time_val: i64) -> libc::tm {
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

    // SAFETY: `libc::gmtime_r` just convert calendar time to
    // broken-down format, and saved to `dest_tm`.
    unsafe { libc::gmtime_r(&time_val, &mut dest_tm) };

    dest_tm
}

/// Transfer binary coded decimal to BCD coded decimal.
fn bin_to_bcd(src: u8) -> u8 {
    ((src / 10) << 4) + (src % 10)
}

/// Transfer BCD coded decimal to binary coded decimal.
fn bcd_to_bin(src: u8) -> u64 {
    if (src >> 4) > 9 || (src & 0x0f) > 9 {
        warn!("RTC: The BCD coded format is wrong.");
        return 0_u64;
    }

    (((src >> 4) * 10) + (src & 0x0f)) as u64
}

#[allow(clippy::upper_case_acronyms)]
/// RTC device.
pub struct RTC {
    base: SysBusDevBase,
    /// Static CMOS RAM.
    cmos_data: [u8; 128],
    /// Index of Selected register.
    cur_index: u8,
    /// Guest memory size.
    mem_size: u64,
    /// The start address of gap.
    gap_start: u64,
    /// The tick offset.
    tick_offset: u64,
    /// Record the real time.
    base_time: Instant,
}

impl RTC {
    /// Construct function of RTC device.
    pub fn new() -> Result<RTC> {
        let mut rtc = RTC {
            base: SysBusDevBase {
                dev_type: SysBusDevType::Rtc,
                res: SysRes {
                    region_base: RTC_PORT_INDEX,
                    region_size: 8,
                    irq: -1,
                },
                interrupt_evt: Some(Arc::new(EventFd::new(libc::EFD_NONBLOCK)?)),
                ..Default::default()
            },
            cmos_data: [0_u8; 128],
            cur_index: 0_u8,
            mem_size: 0,
            gap_start: 0,
            // Since 1970-01-01 00:00:00, it never cause overflow.
            tick_offset: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time wrong")
                .as_secs(),
            base_time: Instant::now(),
        };

        let tm = rtc_time_to_tm(rtc.get_current_value());
        rtc.set_rtc_cmos(tm);

        rtc.init_rtc_reg();

        Ok(rtc)
    }

    /// Set memory info stored in RTC static RAM.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - Guest memory size.
    /// * `gap_start` - The start address of gap on x86_64 platform. This value can be found in
    ///   memory layout.
    pub fn set_memory(&mut self, mem_size: u64, gap_start: u64) {
        self.mem_size = mem_size;
        self.gap_start = gap_start;
        let (mem_below_4g, mem_above_4g) = if mem_size > gap_start {
            (gap_start, mem_size - gap_start)
        } else {
            (mem_size, 0)
        };

        let kb = 1024_u64;
        let base_mem_kb = 640;
        self.cmos_data[CMOS_BASE_MEM.0 as usize] = base_mem_kb as u8;
        self.cmos_data[CMOS_BASE_MEM.1 as usize] = (base_mem_kb >> 8) as u8;

        let ext_mem_kb = 63_u64 * kb;
        self.cmos_data[CMOS_EXT_MEM.0 as usize] = ext_mem_kb as u8;
        self.cmos_data[CMOS_EXT_MEM.1 as usize] = (ext_mem_kb >> 8) as u8;
        self.cmos_data[CMOS_ACTUAL_EXT_MEM.0 as usize] = ext_mem_kb as u8;
        self.cmos_data[CMOS_ACTUAL_EXT_MEM.1 as usize] = (ext_mem_kb >> 8) as u8;

        let mem_data = (mem_below_4g - 16 * kb * kb) / (64 * kb);
        self.cmos_data[CMOS_MEM_BELOW_4GB.0 as usize] = mem_data as u8;
        self.cmos_data[CMOS_MEM_BELOW_4GB.1 as usize] = (mem_data >> 8) as u8;

        if mem_above_4g > 0 {
            let mem_data = mem_above_4g / (64 * kb);
            self.cmos_data[CMOS_MEM_ABOVE_4GB.0 as usize] = mem_data as u8;
            self.cmos_data[CMOS_MEM_ABOVE_4GB.1 as usize] = (mem_data >> 8) as u8;
            self.cmos_data[CMOS_MEM_ABOVE_4GB.2 as usize] = (mem_data >> 16) as u8;
        }
    }

    fn init_rtc_reg(&mut self) {
        // Set Time frequency divider and Rate selection frequency in Register-A.
        // Bits 6-4 = Time frequency divider (010 = 32.768KHz).
        // Bits 3-0 = Rate selection frequency (110 = 1.024KHz, 976.562s).
        self.cmos_data[RTC_REG_A as usize] = 0x26;

        // Set 24 hour mode in Register-B.
        self.cmos_data[RTC_REG_B as usize] = 0x02;

        // Set VRT bit in Register-D, indicates that RAM and time are valid.
        self.cmos_data[RTC_REG_D as usize] = 0x80;
    }

    fn read_data(&mut self, data: &mut [u8]) -> bool {
        if data.len() != 1 {
            error!("RTC only supports reading data byte by byte.");
            return false;
        }

        let tm = rtc_time_to_tm(self.get_current_value());
        self.set_rtc_cmos(tm);
        match self.cur_index {
            RTC_REG_A => {
                data[0] = self.cmos_data[RTC_REG_A as usize];
                // UIP(update in progress) bit will be set at last 244us of every second.
                if self.update_in_progress() {
                    data[0] |= REG_A_UIP;
                    self.inject_interrupt();
                    trace::rtc_inject_interrupt();
                }
            }
            RTC_REG_C => {
                // The interrupt request flag (IRQF), alarm interrupt flag (AF).
                data[0] = 1 << 7 | 1 << 5;
            }
            _ => {
                data[0] = self.cmos_data[self.cur_index as usize];
            }
        }
        trace::rtc_read(self.cur_index, data[0]);

        true
    }

    fn write_data(&mut self, data: &[u8]) -> bool {
        if data.len() != 1 {
            error!("RTC only supports writing data byte by byte.");
            return false;
        }
        trace::rtc_write(self.cur_index, data[0]);

        match self.cur_index {
            RTC_SECONDS | RTC_MINUTES | RTC_HOURS | RTC_DAY_OF_WEEK | RTC_DAY_OF_MONTH
            | RTC_MONTH | RTC_YEAR | RTC_CENTURY_BCD => {
                if self.rtc_valid_check(data[0]) {
                    self.cmos_data[self.cur_index as usize] = data[0];
                    self.update_rtc_time();
                } else {
                    warn!(
                        "Set invalid RTC time, index {}, data {}",
                        self.cur_index, data[0]
                    );
                }
            }
            RTC_REG_C | RTC_REG_D => {
                warn!(
                    "Failed to write: read-only register, index {}, data {}",
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

    pub fn realize(mut self, sysbus: &mut SysBus) -> Result<()> {
        let region_base = self.base.res.region_base;
        let region_size = self.base.res.region_size;
        self.set_sys_resource(sysbus, region_base, region_size)?;

        let dev = Arc::new(Mutex::new(self));
        sysbus.attach_device(&dev, region_base, region_size, "RTC")?;
        Ok(())
    }

    /// Get current clock value.
    fn get_current_value(&self) -> i64 {
        (self.base_time.elapsed().as_secs() as i128 + self.tick_offset as i128) as i64
    }

    fn set_rtc_cmos(&mut self, tm: libc::tm) {
        self.cmos_data[RTC_SECONDS as usize] = bin_to_bcd(tm.tm_sec as u8);
        self.cmos_data[RTC_MINUTES as usize] = bin_to_bcd(tm.tm_min as u8);
        self.cmos_data[RTC_HOURS as usize] = bin_to_bcd(tm.tm_hour as u8);
        self.cmos_data[RTC_DAY_OF_WEEK as usize] = bin_to_bcd((tm.tm_wday + 1) as u8);
        self.cmos_data[RTC_DAY_OF_MONTH as usize] = bin_to_bcd(tm.tm_mday as u8);
        self.cmos_data[RTC_MONTH as usize] = bin_to_bcd((tm.tm_mon + 1) as u8);
        self.cmos_data[RTC_YEAR as usize] = bin_to_bcd(((tm.tm_year + 1900) % 100) as u8);
        self.cmos_data[RTC_CENTURY_BCD as usize] = bin_to_bcd(((tm.tm_year + 1900) / 100) as u8);
    }

    fn rtc_valid_check(&self, val: u8) -> bool {
        let range = [
            [0, 59], // Seconds
            [0, 59], // Seconds Alarm
            [0, 59], // Minutes
            [0, 59], // Minutes Alarm
            [0, 23], // Hours
            [0, 23], // Hours Alarm
            [1, 7],  // Day of the Week
            [1, 31], // Day of the Month
            [1, 12], // Month
            [0, 99], // Year
        ];

        if (val >> 4) > 9 || (val & 0x0f) > 9 {
            return false;
        }

        let value = bcd_to_bin(val);

        if self.cur_index <= 9
            && (value < range[self.cur_index as usize][0]
                || value > range[self.cur_index as usize][1])
        {
            return false;
        }

        true
    }

    fn update_rtc_time(&mut self) {
        let sec = bcd_to_bin(self.cmos_data[RTC_SECONDS as usize]);
        let min = bcd_to_bin(self.cmos_data[RTC_MINUTES as usize]);
        let hour = bcd_to_bin(self.cmos_data[RTC_HOURS as usize]);
        let day = bcd_to_bin(self.cmos_data[RTC_DAY_OF_MONTH as usize]);
        let mon = bcd_to_bin(self.cmos_data[RTC_MONTH as usize]);
        let year = bcd_to_bin(self.cmos_data[RTC_YEAR as usize])
            + bcd_to_bin(self.cmos_data[RTC_CENTURY_BCD as usize]) * 100;

        // Check rtc time is valid to prevent tick_offset overflow.
        if year < 1970 || !(1..=12).contains(&mon) || !(1..=31).contains(&day) {
            warn!(
                "RTC: the updated rtc time {}-{}-{} may be invalid.",
                year, mon, day
            );
            return;
        }

        self.tick_offset = mktime64(year, mon, day, hour, min, sec);

        self.base_time = Instant::now();
    }

    fn update_in_progress(&self) -> bool {
        self.base_time.elapsed().subsec_nanos() >= (NANOSECONDS_PER_SECOND - UIP_HOLD_LENGTH) as u32
    }
}

impl Device for RTC {
    fn device_base(&self) -> &DeviceBase {
        &self.base.base
    }

    fn device_base_mut(&mut self) -> &mut DeviceBase {
        &mut self.base.base
    }
}

impl SysBusDevOps for RTC {
    fn sysbusdev_base(&self) -> &SysBusDevBase {
        &self.base
    }

    fn sysbusdev_base_mut(&mut self) -> &mut SysBusDevBase {
        &mut self.base
    }

    fn read(&mut self, data: &mut [u8], base: GuestAddress, offset: u64) -> bool {
        if offset == 0 {
            debug!(
                "Reading from ioport 0x{:x} is not supported yet",
                base.0 + offset
            );
            data[0] = 0xFF;
            false
        } else {
            self.read_data(data)
        }
    }

    fn write(&mut self, data: &[u8], _base: GuestAddress, offset: u64) -> bool {
        if offset == 0 {
            self.cur_index = data[0] & 0x7F;
            true
        } else {
            self.write_data(data)
        }
    }

    fn get_sys_resource_mut(&mut self) -> Option<&mut SysRes> {
        Some(&mut self.base.res)
    }

    fn reset(&mut self) -> Result<()> {
        self.cmos_data.fill(0);
        self.init_rtc_reg();
        self.set_memory(self.mem_size, self.gap_start);
        Ok(())
    }
}

impl AmlBuilder for RTC {
    fn aml_bytes(&self) -> Vec<u8> {
        let mut acpi_dev = AmlDevice::new("RTC");
        acpi_dev.append_child(AmlNameDecl::new("_HID", AmlEisaId::new("PNP0B00")));

        let mut res = AmlResTemplate::new();
        res.append_child(AmlIoResource::new(
            AmlIoDecode::Decode16,
            self.base.res.region_base as u16,
            self.base.res.region_base as u16,
            0x01,
            self.base.res.region_size as u8,
        ));
        res.append_child(AmlIrqNoFlags::new(self.base.res.irq as u8));
        acpi_dev.append_child(AmlNameDecl::new("_CRS", res));

        acpi_dev.aml_bytes()
    }
}

#[cfg(test)]
mod test {
    use anyhow::Context;

    use super::*;
    use address_space::GuestAddress;

    const WIGGLE: u8 = 2;

    fn cmos_read(rtc: &mut RTC, index: u8) -> u8 {
        let mut data: [u8; 1] = [index; 1];
        RTC::write(rtc, &mut data, GuestAddress(0), 0);
        RTC::read(rtc, &mut data, GuestAddress(0), 1);
        data[0]
    }

    fn cmos_write(rtc: &mut RTC, index: u8, val: u8) {
        let mut data: [u8; 1] = [index; 1];
        RTC::write(rtc, &mut data, GuestAddress(0), 0);
        data[0] = val;
        RTC::write(rtc, &mut data, GuestAddress(0), 1);
    }

    #[test]
    fn test_set_year_20xx() -> Result<()> {
        let mut rtc = RTC::new().with_context(|| "Failed to create RTC device")?;
        // Set rtc time: 2013-11-13 02:04:56
        cmos_write(&mut rtc, RTC_CENTURY_BCD, 0x20);
        cmos_write(&mut rtc, RTC_YEAR, 0x13);
        cmos_write(&mut rtc, RTC_MONTH, 0x11);
        cmos_write(&mut rtc, RTC_DAY_OF_MONTH, 0x13);
        cmos_write(&mut rtc, RTC_HOURS, 0x02);
        cmos_write(&mut rtc, RTC_MINUTES, 0x04);
        cmos_write(&mut rtc, RTC_SECONDS, 0x56);

        assert!((cmos_read(&mut rtc, RTC_SECONDS) - 0x56) <= WIGGLE);
        assert_eq!(cmos_read(&mut rtc, RTC_MINUTES), 0x04);
        assert_eq!(cmos_read(&mut rtc, RTC_HOURS), 0x02);
        assert_eq!(cmos_read(&mut rtc, RTC_DAY_OF_MONTH), 0x13);
        assert_eq!(cmos_read(&mut rtc, RTC_MONTH), 0x11);
        assert_eq!(cmos_read(&mut rtc, RTC_YEAR), 0x13);
        assert_eq!(cmos_read(&mut rtc, RTC_CENTURY_BCD), 0x20);

        // Set rtc time: 2080-11-13 02:04:56, ensure there is no year-2080 overflow.
        cmos_write(&mut rtc, RTC_YEAR, 0x80);

        assert!((cmos_read(&mut rtc, RTC_SECONDS) - 0x56) <= WIGGLE);
        assert_eq!(cmos_read(&mut rtc, RTC_MINUTES), 0x04);
        assert_eq!(cmos_read(&mut rtc, RTC_HOURS), 0x02);
        assert_eq!(cmos_read(&mut rtc, RTC_DAY_OF_MONTH), 0x13);
        assert_eq!(cmos_read(&mut rtc, RTC_MONTH), 0x11);
        assert_eq!(cmos_read(&mut rtc, RTC_YEAR), 0x80);
        assert_eq!(cmos_read(&mut rtc, RTC_CENTURY_BCD), 0x20);

        Ok(())
    }

    #[test]
    fn test_set_year_1970() -> Result<()> {
        let mut rtc = RTC::new().with_context(|| "Failed to create RTC device")?;
        // Set rtc time (min): 1970-01-01 00:00:00
        cmos_write(&mut rtc, RTC_CENTURY_BCD, 0x19);
        cmos_write(&mut rtc, RTC_YEAR, 0x70);
        cmos_write(&mut rtc, RTC_MONTH, 0x01);
        cmos_write(&mut rtc, RTC_DAY_OF_MONTH, 0x01);
        cmos_write(&mut rtc, RTC_HOURS, 0x00);
        cmos_write(&mut rtc, RTC_MINUTES, 0x00);
        cmos_write(&mut rtc, RTC_SECONDS, 0x00);

        assert!((cmos_read(&mut rtc, RTC_SECONDS) - 0x00) <= WIGGLE);
        assert_eq!(cmos_read(&mut rtc, RTC_MINUTES), 0x00);
        assert_eq!(cmos_read(&mut rtc, RTC_HOURS), 0x00);
        assert_eq!(cmos_read(&mut rtc, RTC_DAY_OF_MONTH), 0x01);
        assert_eq!(cmos_read(&mut rtc, RTC_MONTH), 0x01);
        assert_eq!(cmos_read(&mut rtc, RTC_YEAR), 0x70);
        assert_eq!(cmos_read(&mut rtc, RTC_CENTURY_BCD), 0x19);

        Ok(())
    }

    #[test]
    fn test_invalid_rtc_time() -> Result<()> {
        let mut rtc = RTC::new().with_context(|| "Failed to create RTC device")?;
        // Set rtc year: 1969
        cmos_write(&mut rtc, RTC_CENTURY_BCD, 0x19);
        cmos_write(&mut rtc, RTC_YEAR, 0x69);
        assert_ne!(cmos_read(&mut rtc, RTC_YEAR), 0x69);

        // Set rtc month: 13
        cmos_write(&mut rtc, RTC_MONTH, 0x13);
        assert_ne!(cmos_read(&mut rtc, RTC_MONTH), 0x13);

        // Set rtc day: 32
        cmos_write(&mut rtc, RTC_DAY_OF_MONTH, 0x32);
        assert_ne!(cmos_read(&mut rtc, RTC_DAY_OF_MONTH), 0x32);

        // Set rtc hour: 25
        cmos_write(&mut rtc, RTC_HOURS, 0x25);
        assert_ne!(cmos_read(&mut rtc, RTC_HOURS), 0x25);

        // Set rtc minute: 60
        cmos_write(&mut rtc, RTC_MINUTES, 0x60);
        assert_ne!(cmos_read(&mut rtc, RTC_MINUTES), 0x60);

        // Set rtc second: 60
        cmos_write(&mut rtc, RTC_SECONDS, 0x60);
        assert_ne!(cmos_read(&mut rtc, RTC_SECONDS), 0x60);

        Ok(())
    }
}
