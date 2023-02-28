// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use devices::legacy::{RTC_CR, RTC_DR, RTC_IMSC, RTC_LR};
use mod_test::libtest::{test_init, TestState};
use rand::{thread_rng, Rng};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RTC_ADDR_BASE: u64 = 0x0901_0000;

fn pl031_read_time(ts: &TestState) -> u32 {
    ts.readl(RTC_ADDR_BASE + RTC_DR)
}

fn pl031_set_time(ts: &TestState, time: u32) {
    ts.writel(RTC_ADDR_BASE + RTC_LR, time);
}

fn get_wall_time() -> u32 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(tick) => tick.as_secs() as u32,
        _ => panic!("Failed to get wall time."),
    }
}

fn pl031_read_reg(ts: &TestState, reg: u64) -> u32 {
    ts.readl(RTC_ADDR_BASE + reg)
}

fn pl031_write_reg(ts: &TestState, reg: u64, val: u32) {
    ts.writel(RTC_ADDR_BASE + reg, val);
}

fn set_up() -> TestState {
    let extra_args: Vec<&str> = "-machine virt".split(' ').collect();
    test_init(extra_args)
}

#[test]
#[cfg(target_arch = "aarch64")]
fn check_time() {
    let mut ts = set_up();

    let time1 = pl031_read_time(&ts);
    let time2 = pl031_read_time(&ts);

    sleep(Duration::from_millis(2000));
    let time3 = pl031_read_time(&ts);
    let time4 = pl031_read_time(&ts);
    let wall_time = get_wall_time();

    assert!((time2 - time1) <= 1);
    assert!((time3 - time2) <= 3);
    assert!((time3 - time2) >= 2);
    assert!((time4 - time3) <= 1);
    assert!((wall_time - time4) <= 1);

    ts.stop();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn set_time() {
    let mut ts = set_up();
    let time1 = pl031_read_time(&ts);

    // Time passes about 5 years.
    let time_lapse = 1_5768_0000;
    pl031_set_time(&ts, time1 + time_lapse);

    let time2 = pl031_read_time(&ts);

    assert!((time2 - time1) >= time_lapse);
    assert!((time2 - time1) <= time_lapse + 1);

    ts.stop();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn rtc_enable() {
    let mut ts = set_up();

    assert_eq!(pl031_read_reg(&ts, RTC_CR), 1);
    ts.stop();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn set_mask() {
    let mut ts = set_up();

    pl031_write_reg(&ts, RTC_IMSC, 1);

    assert_eq!(pl031_read_reg(&ts, RTC_IMSC), 1);
    ts.stop();
}

#[test]
#[cfg(target_arch = "aarch64")]
fn reg_fuzz() {
    let mut ts = set_up();
    let mut rng = thread_rng();

    for _ in 0..1000 {
        let reg = rng.gen_range(0..=32);
        let val = rng.gen_range(0..=1024);
        pl031_read_reg(&ts, reg);
        pl031_write_reg(&ts, reg, val);
    }

    ts.stop();
}
