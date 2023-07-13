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

use std::time::{Duration, Instant};

use crate::{
    loop_context::EventLoopContext,
    test_helper::{get_test_time, is_test_enabled},
};

pub fn get_current_time() -> Instant {
    if is_test_enabled() {
        get_test_time()
    } else {
        Instant::now()
    }
}

/// Recording VM timer state.
pub struct ClockState {
    enable: bool,
    offset: Instant,
    paused: Duration,
    elapsed: Duration,
}

impl Default for ClockState {
    fn default() -> Self {
        Self {
            enable: false,
            offset: Instant::now(),
            paused: Duration::default(),
            elapsed: Duration::default(),
        }
    }
}

impl ClockState {
    pub fn get_virtual_clock(&mut self) -> Duration {
        let mut time = self.paused;
        if self.enable {
            time = self.offset.elapsed() - self.elapsed;
        }
        time
    }

    pub fn enable(&mut self) {
        self.elapsed = self.offset.elapsed() - self.paused;
        self.enable = true;
    }

    pub fn disable(&mut self) {
        self.paused = self.offset.elapsed() - self.elapsed;
        self.enable = false;
    }
}

impl EventLoopContext {
    /// Returns the clock based on the type.
    pub fn get_virtual_clock(&self) -> Duration {
        self.clock_state.lock().unwrap().get_virtual_clock()
    }

    /// The clock running when VCPU in running.
    pub fn enable_clock(&self) {
        self.clock_state.lock().unwrap().enable();
    }

    /// The clock is stopped when VCPU in paused.
    pub fn disable_clock(&self) {
        self.clock_state.lock().unwrap().disable();
    }
}

#[cfg(test)]
mod test {
    use std::{thread, time::Duration};

    use super::ClockState;

    #[test]
    fn test_virtual_clock() {
        let mut clock = ClockState::default();
        clock.enable();
        thread::sleep(Duration::from_secs(5));
        let virtual_clock = clock.get_virtual_clock();
        assert_eq!(virtual_clock.as_secs(), 5);
        clock.disable();
        thread::sleep(Duration::from_secs(10));
        let virtual_clock = clock.get_virtual_clock();
        assert_eq!(virtual_clock.as_secs(), 5);
        clock.enable();
        thread::sleep(Duration::from_secs(5));
        let virtual_clock = clock.get_virtual_clock();
        assert_eq!(virtual_clock.as_secs(), 10);

        clock.disable();
        thread::sleep(Duration::from_secs(10));
        let virtual_clock = clock.get_virtual_clock();
        assert_eq!(virtual_clock.as_secs(), 10);
        clock.enable();
        thread::sleep(Duration::from_secs(5));
        let virtual_clock = clock.get_virtual_clock();
        assert_eq!(virtual_clock.as_secs(), 15);
    }
}
