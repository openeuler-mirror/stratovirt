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

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use once_cell::sync::{Lazy, OnceCell};

#[derive(Default, Clone, Copy)]
struct MsixMsg {
    addr: u64,
    data: u32,
}

impl MsixMsg {
    fn new(addr: u64, data: u32) -> Self {
        MsixMsg { addr, data }
    }
}

#[derive(Default, Clone, Copy, Debug)]
struct IntxInfo {
    irq: u32,
    level: i8,
}

impl IntxInfo {
    fn new(irq: u32, level: i8) -> Self {
        IntxInfo { irq, level }
    }
}

static TEST_ENABLED: OnceCell<bool> = OnceCell::new();
static TEST_BASE_TIME: OnceCell<Instant> = OnceCell::new();
static mut TEST_CLOCK: Option<Arc<RwLock<u64>>> = None;
static TEST_MSIX_LIST: Lazy<Mutex<Vec<MsixMsg>>> = Lazy::new(|| Mutex::new(Vec::new()));
static TEST_INTX_LIST: Lazy<Mutex<Vec<IntxInfo>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn set_test_enabled() {
    if let Err(_e) = TEST_ENABLED.set(true) {
        panic!("Failed to enable test server.");
    }
    if let Err(_e) = TEST_BASE_TIME.set(Instant::now()) {
        panic!("Failed to initialize clock");
    }
    // SAFETY: This module is only used for test.
    unsafe {
        if TEST_CLOCK.is_none() {
            TEST_CLOCK = Some(Arc::new(RwLock::new(0)));
        }
    }
}

pub fn is_test_enabled() -> bool {
    *TEST_ENABLED.get_or_init(|| false)
}

pub fn set_test_clock(value: u64) {
    // SAFETY: This module is only used for test.
    unsafe {
        if TEST_CLOCK.is_none() {
            panic!("TEST_CLOCK has not been initialized.");
        }
        if value <= get_test_clock() {
            return;
        }

        let mut test_clock = TEST_CLOCK.as_ref().unwrap().write().unwrap();
        *test_clock = value;
    }
}

pub fn get_test_clock() -> u64 {
    // SAFETY: This module is only used for test.
    unsafe {
        if TEST_CLOCK.is_none() {
            panic!("TEST_CLOCK has not been initialized.");
        }

        *TEST_CLOCK.as_ref().unwrap().read().unwrap()
    }
}

pub fn get_test_time() -> Instant {
    // SAFETY: This module is only used for test.
    unsafe {
        if TEST_CLOCK.is_none() {
            panic!("TEST_CLOCK has not been initialized.");
        }

        TEST_BASE_TIME
            .get()
            .unwrap()
            .checked_add(Duration::from_nanos(get_test_clock()))
            .unwrap()
    }
}

pub fn add_msix_msg(addr: u64, data: u32) {
    let new_msg = MsixMsg::new(addr, data);
    let mut msix_list_lock = TEST_MSIX_LIST.lock().unwrap();

    for msg in msix_list_lock.iter() {
        if new_msg.addr == msg.addr && new_msg.data == msg.data {
            return;
        }
    }

    msix_list_lock.push(new_msg);
}

pub fn has_msix_msg(addr: u64, data: u32) -> bool {
    let target_msg = MsixMsg::new(addr, data);
    let mut target_index: Option<usize> = None;
    let mut msix_list_lock = TEST_MSIX_LIST.lock().unwrap();

    for (index, msg) in msix_list_lock.iter().enumerate() {
        if target_msg.addr == msg.addr && target_msg.data == msg.data {
            target_index = Some(index);
            break;
        }
    }

    match target_index {
        Some(i) => {
            msix_list_lock.remove(i);
            true
        }
        None => false,
    }
}

pub fn trigger_intx(irq: u32, change: i8) {
    let new_intx = IntxInfo::new(irq, change);
    let mut intx_list_lock = TEST_INTX_LIST.lock().unwrap();

    for intx in intx_list_lock.iter_mut() {
        if intx.irq == new_intx.irq {
            intx.level += new_intx.level;
            return;
        }
    }

    intx_list_lock.push(new_intx);
}

pub fn query_intx(irq: u32) -> bool {
    let mut intx_list_lock = TEST_INTX_LIST.lock().unwrap();
    for intx in intx_list_lock.iter_mut() {
        if intx.irq == irq {
            return intx.level > 0;
        }
    }

    false
}

pub fn eoi_intx(irq: u32) -> bool {
    let mut intx_list_lock = TEST_INTX_LIST.lock().unwrap();

    for intx in intx_list_lock.iter_mut() {
        if intx.irq == irq {
            if intx.level == 0 {
                return false;
            } else {
                intx.level -= 1;
                return true;
            }
        }
    }

    false
}
