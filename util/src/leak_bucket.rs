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

/// We use Leaky Bucket Algorithm to limit iops of block device and qmp.
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::clock::get_current_time;
use crate::loop_context::{create_new_eventfd, EventLoopContext};
use crate::time::NANOSECONDS_PER_SECOND;

/// Used to improve the accuracy of bucket level.
const ACCURACY_SCALE: u64 = 1000;

/// Structure used to describe a Leaky Bucket.
pub struct LeakBucket {
    /// Indicate the capacity of bucket, which is config by user.
    capacity: u64,
    /// Current water level.
    level: u64,
    /// Internal used to calculate the delay of timer.
    prev_time: Instant,
    /// Indicate whether the timer started.
    timer_started: bool,
    /// When bucket is ready for allowing more IO operation, the internal callback will write this
    /// FD. This FD should be listened by IO thread.
    timer_wakeup: Arc<EventFd>,
}

impl LeakBucket {
    /// Construct function
    ///
    /// # Arguments
    ///
    /// * `units_ps` - units per second.
    pub fn new(units_ps: u64) -> Result<Self> {
        Ok(LeakBucket {
            capacity: units_ps
                .checked_mul(ACCURACY_SCALE)
                .with_context(|| "capacity overflow")?,
            level: 0,
            prev_time: get_current_time(),
            timer_started: false,
            timer_wakeup: Arc::new(create_new_eventfd()?),
        })
    }

    /// Return true if the bucket is full, and caller must return directly instead of launching IO.
    /// Otherwise, caller should not be affected.
    ///
    /// # Arguments
    ///
    /// * `loop_context` - used for delay function call.
    pub fn throttled(&mut self, loop_context: &mut EventLoopContext, need_units: u32) -> bool {
        // capacity value is zero, indicating that there is no need to limit
        if self.capacity == 0 {
            return false;
        }
        if self.timer_started {
            return true;
        }

        // update the water level
        let now = get_current_time();
        let nanos = (now - self.prev_time).as_nanos();
        let throttle_timeout =
            u128::from(self.level) * u128::from(NANOSECONDS_PER_SECOND) / u128::from(self.capacity);
        if nanos > throttle_timeout {
            self.level = 0;
        } else {
            self.level -=
                (nanos * u128::from(self.capacity) / u128::from(NANOSECONDS_PER_SECOND)) as u64;
        }

        self.prev_time = now;

        // need to be throttled
        if self.level > self.capacity {
            let wakeup_clone = self.timer_wakeup.clone();
            let func = Box::new(move || {
                wakeup_clone
                    .write(1)
                    .unwrap_or_else(|e| error!("LeakBucket send event to device failed {:?}", e));
            });

            let timeout =
                (self.level - self.capacity).saturating_mul(NANOSECONDS_PER_SECOND) / self.capacity;
            loop_context.timer_add(func, Duration::from_nanos(timeout));

            self.timer_started = true;

            return true;
        }

        let scaled_need = u64::from(need_units) * ACCURACY_SCALE;
        self.level = self.level.saturating_add(scaled_need);

        false
    }

    /// Clear the timer state.
    pub fn clear_timer(&mut self) {
        self.timer_started = false;
    }

    /// Get raw fd of wakeup event.
    pub fn as_raw_fd(&self) -> RawFd {
        self.timer_wakeup.as_raw_fd()
    }
}
