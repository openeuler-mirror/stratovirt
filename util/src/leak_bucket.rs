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

use anyhow::Result;
use log::error;
use vmm_sys_util::eventfd::EventFd;

use crate::clock::get_current_time;
use crate::loop_context::EventLoopContext;
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
            capacity: units_ps * ACCURACY_SCALE,
            level: 0,
            prev_time: get_current_time(),
            timer_started: false,
            timer_wakeup: Arc::new(EventFd::new(libc::EFD_NONBLOCK)?),
        })
    }

    /// Return true if the bucket is full, and caller must return directly instead of launching IO.
    /// Otherwise, caller should not be affected.
    ///
    /// # Arguments
    ///
    /// * `loop_context` - used for delay function call.
    pub fn throttled(&mut self, loop_context: &mut EventLoopContext, need_units: u64) -> bool {
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
        if nanos > (self.level * NANOSECONDS_PER_SECOND / self.capacity) as u128 {
            self.level = 0;
        } else {
            self.level -= nanos as u64 * self.capacity / NANOSECONDS_PER_SECOND;
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

            loop_context.timer_add(
                func,
                Duration::from_nanos(
                    (self.level - self.capacity) * NANOSECONDS_PER_SECOND / self.capacity,
                ),
            );

            self.timer_started = true;

            return true;
        }

        self.level += need_units * ACCURACY_SCALE;

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
