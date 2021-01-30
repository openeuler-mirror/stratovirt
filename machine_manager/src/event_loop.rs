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

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use super::config::IothreadConfig;
use util::loop_context::{EventLoopContext, EventLoopManager, EventNotifier};

/// This struct used to manage all events occur during VM lifetime.
/// # Notes
///
/// When vm started with `-iothread` params,
/// a certain number of io-threads used to handle events from device will be spawned.
/// Otherwise, all the events will be handled by `main_loop`
pub struct EventLoop {
    /// Used to handle all events which are not monitored by io-threads
    main_loop: EventLoopContext,
    /// Used to monitor events of specified device.
    io_threads: HashMap<String, EventLoopContext>,
}

static mut GLOBAL_EVENT_LOOP: Option<EventLoop> = None;

impl EventLoop {
    /// Init GLOBAL_EVENT_LOOP, include main loop and io-threads loop
    ///
    /// # Arguments
    ///
    /// * `iothreads` - refer to `-iothread` params
    pub fn object_init(iothreads: &Option<Vec<IothreadConfig>>) -> util::errors::Result<()> {
        let mut io_threads = HashMap::new();
        if let Some(thrs) = iothreads {
            for thr in thrs {
                io_threads.insert(thr.id.clone(), EventLoopContext::new());
            }
        }

        unsafe {
            if GLOBAL_EVENT_LOOP.is_none() {
                GLOBAL_EVENT_LOOP = Some(EventLoop {
                    main_loop: EventLoopContext::new(),
                    io_threads,
                });
            }

            if let Some(event_loop) = GLOBAL_EVENT_LOOP.as_mut() {
                for (id, ctx) in &mut event_loop.io_threads {
                    thread::Builder::new().name(id.to_string()).spawn(move || {
                        while let Ok(ret) = ctx.run() {
                            if !ret {
                                break;
                            }
                        }
                    })?;
                }
            } else {
                bail!("Global Event Loop have not been initialized.")
            }
        }

        Ok(())
    }

    /// Return main loop or io-thread loop specified by input `name`
    ///
    /// # Arguments
    ///
    /// * `name` - if None, return main loop, OR return io-thread-loop which is related to `name`.
    pub fn get_ctx(name: Option<&String>) -> &mut EventLoopContext {
        unsafe {
            if let Some(event_loop) = GLOBAL_EVENT_LOOP.as_mut() {
                if let Some(name) = name {
                    if let Some(ctx) = event_loop.io_threads.get_mut(name) {
                        return ctx;
                    }
                }

                return &mut event_loop.main_loop;
            }
        }

        panic!("Global Event Loop have not been initialized.");
    }

    /// Set a `manager` to event loop
    ///
    /// # Arguments
    ///
    /// * `manager` - The main part to manager the event loop specified by name.
    /// * `name` - specify which event loop to manage
    pub fn set_manager(manager: Arc<dyn EventLoopManager>, name: Option<&String>) {
        Self::get_ctx(name).set_manager(manager)
    }

    /// Update event notifiers to  event loop
    ///
    /// # Arguments
    ///
    /// * `notifiers` - The wrapper of events will be handled in the event loop specified by name.
    /// * `name` - specify which event loop to manage
    pub fn update_event(
        notifiers: Vec<EventNotifier>,
        name: Option<&String>,
    ) -> util::errors::Result<()> {
        Self::get_ctx(name).update_events(notifiers)
    }

    /// Start to run main loop
    ///
    /// # Notes
    ///
    /// Once run main loop, `epoll` in `MainLoopContext` will execute
    /// `epoll_wait()` function to wait for events.
    pub fn loop_run() -> util::errors::Result<()> {
        unsafe {
            if let Some(event_loop) = GLOBAL_EVENT_LOOP.as_mut() {
                loop {
                    if !event_loop.main_loop.run()? {
                        info!("MainLoop exits due to guest internal operation.");
                        return Ok(());
                    }
                }
            } else {
                bail!("Global Event Loop have not been initialized.")
            }
        }
    }

    /// Exit vm and clean environment.
    ///
    /// # Notes
    ///
    /// Set CURRENT_MAINLOOP to None to release MainLoopContext,
    /// otherwise, it will not be released automatically.
    pub fn clean() -> bool {
        let ret = Self::get_ctx(None).exit();
        unsafe {
            if GLOBAL_EVENT_LOOP.is_some() {
                GLOBAL_EVENT_LOOP = None;
            }
        }
        ret
    }
}
