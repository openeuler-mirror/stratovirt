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

extern crate util;

use std::sync::Arc;

use util::epoll_context::{EventNotifier, MainLoopContext, MainLoopManager};

static mut CURRENT_MAINLOOP: Option<MainLoopContext> = None;

/// The struct `MainLoop` is the only struct can handle Global variable
/// `CURRENT_MAINLOOP`. It can manage events add and adjust or start to
/// run `main_loop`.
pub struct MainLoop {}

impl MainLoop {
    /// Constructs a `MainLoopContext` in global `QMP_CHANNEL`.
    pub fn object_init() {
        unsafe {
            if CURRENT_MAINLOOP.is_none() {
                CURRENT_MAINLOOP = Some(MainLoopContext::new());
            }
        }
    }

    /// Set a `manager` to `CURRENT_MAINLOOP`.
    ///
    /// # Arguments
    ///
    /// * `manager` - The main part to manager `CURRENT_MAINLOOP`.
    pub fn set_manager(manager: Arc<dyn MainLoopManager>) {
        Self::locked_inner().set_manager(manager);
    }

    /// Update event notifiers to `CURRENT_MAINLOOP`.
    ///
    /// * `notifiers` - The wrapper of events will be handled in
    /// `CURRENT_MAINLOOP`.
    ///
    /// # Errors
    ///
    /// Update event failed.
    pub fn update_event(notifiers: Vec<EventNotifier>) -> util::errors::Result<()> {
        Self::locked_inner().update_events(notifiers)
    }

    /// Start to run `CURRENT_MAINLOOP` according `epoll`.
    ///
    /// # Notes
    ///
    /// Once run `CURRENT_MAINLOOP`, `epoll` in `MainLoopContext` will execute
    /// `epoll_wait()` function to wait for events.
    pub fn run() -> util::errors::Result<bool> {
        Self::locked_inner().run()
    }

    fn locked_inner() -> &'static mut MainLoopContext {
        unsafe {
            match &mut CURRENT_MAINLOOP {
                Some(main_loop) => main_loop,
                None => {
                    panic!("Main loop not initialized");
                }
            }
        }
    }
}
