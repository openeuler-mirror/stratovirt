// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use log::error;

use crate::link_list::{List, Node};

const MIN_THREADS: u64 = 1;
const MAX_THREADS: u64 = 64;
type PoolTask = Box<dyn TaskOperation>;

pub trait TaskOperation: Sync + Send {
    fn run(&mut self);
}

struct PoolState {
    /// The total number of current threads in thread pool.
    /// Including the number of threads need to be created and the number of running threads.
    total_threads: u64,
    /// The current number of blocking threads, they will be blocked
    /// until awakened by request_cond or timeout.
    blocked_threads: u64,
    /// The number of threads need to be created. It could be created
    /// in the main loop or another thread in thread pool later.
    new_threads: u64,
    /// The number of threads that have been created but
    /// have not yet entered the work loop.
    pending_threads: u64,
    /// The minimum number of threads residing in the thread pool.
    min_threads: u64,
    /// The maximum number of threads that thread pool can create.
    max_threads: u64,
    /// List of pending tasks in the thread pool.
    req_lists: List<PoolTask>,
}

/// SAFETY: All the operations on req_lists are protected by the mutex,
/// so there is no synchronization problem.
unsafe impl Send for PoolState {}

impl PoolState {
    fn new() -> Self {
        Self {
            total_threads: 0,
            blocked_threads: 0,
            new_threads: 0,
            pending_threads: 0,
            min_threads: MIN_THREADS,
            max_threads: MAX_THREADS,
            req_lists: List::new(),
        }
    }

    fn spawn_thread_needed(&self) -> bool {
        self.blocked_threads == 0 && self.total_threads < self.max_threads
    }

    fn is_running(&self) -> bool {
        self.total_threads <= self.max_threads
    }

    fn spawn_thread(&mut self, pool: Arc<ThreadPool>) -> Result<()> {
        self.total_threads += 1;
        self.new_threads += 1;

        if self.pending_threads == 0 {
            self.do_spawn_thread(pool)?;
        }
        Ok(())
    }

    fn do_spawn_thread(&mut self, pool: Arc<ThreadPool>) -> Result<()> {
        if self.new_threads == 0 {
            return Ok(());
        }

        self.new_threads -= 1;
        self.pending_threads += 1;
        trace::thread_pool_spawn_thread(
            &self.total_threads,
            &self.blocked_threads,
            &self.new_threads,
            &self.pending_threads,
        );
        thread::Builder::new()
            .name("thread-pool".to_string())
            .spawn(move || worker_thread(pool))
            .with_context(|| "Failed to create thread in pool!")?;
        Ok(())
    }
}

pub struct ThreadPool {
    /// Data shared by all threads in the pool.
    pool_state: Arc<Mutex<PoolState>>,
    /// Notify the thread in the pool that there are some work to do.
    request_cond: Condvar,
    /// Notify threadpool that the current thread has exited.
    stop_cond: Condvar,
}

impl Default for ThreadPool {
    fn default() -> Self {
        Self {
            pool_state: Arc::new(Mutex::new(PoolState::new())),
            request_cond: Condvar::new(),
            stop_cond: Condvar::new(),
        }
    }
}

impl ThreadPool {
    /// Submit task to thread pool.
    pub fn submit_task(pool: Arc<ThreadPool>, task: Box<dyn TaskOperation>) -> Result<()> {
        trace::thread_pool_submit_task();
        let mut locked_state = pool.pool_state.lock().unwrap();
        if locked_state.spawn_thread_needed() {
            locked_state.spawn_thread(pool.clone())?
        }
        locked_state.req_lists.add_tail(Box::new(Node::new(task)));
        drop(locked_state);

        pool.request_cond.notify_one();
        Ok(())
    }

    /// It should be confirmed that all threads have successfully exited
    /// before function return.
    pub fn cancel(&self) -> Result<()> {
        let mut locked_state = self.pool_state.lock().unwrap();
        locked_state.total_threads -= locked_state.new_threads;
        locked_state.new_threads = 0;
        locked_state.max_threads = 0;
        self.request_cond.notify_all();

        while locked_state.total_threads > 0 {
            match self.stop_cond.wait(locked_state) {
                Ok(lock) => locked_state = lock,
                Err(e) => bail!("{:?}", e),
            }
        }
        Ok(())
    }
}

fn worker_thread(pool: Arc<ThreadPool>) {
    let mut locked_state = pool.pool_state.lock().unwrap();
    locked_state.pending_threads -= 1;
    locked_state
        .do_spawn_thread(pool.clone())
        .unwrap_or_else(|e| error!("Thread pool error: {:?}", e));

    while locked_state.is_running() {
        let result;

        if locked_state.req_lists.len == 0 {
            locked_state.blocked_threads += 1;
            match pool
                .request_cond
                .wait_timeout(locked_state, Duration::from_secs(10))
            {
                Ok((guard, ret)) => {
                    locked_state = guard;
                    result = ret;
                }
                Err(e) => {
                    error!("Unknown errors have occurred thread pool: {:?}", e);
                    locked_state = e.into_inner().0;
                    break;
                }
            }
            locked_state.blocked_threads -= 1;

            if result.timed_out()
                && locked_state.req_lists.len == 0
                && locked_state.total_threads > locked_state.min_threads
            {
                // If wait time_out and no pending task and current total number
                // of threads exceeds the minimum, then exit.
                break;
            }

            continue;
        }

        let mut req = locked_state.req_lists.pop_head().unwrap();
        drop(locked_state);

        (*req.value).run();

        locked_state = pool.pool_state.lock().unwrap();
    }
    locked_state.total_threads -= 1;
    trace::thread_pool_exit_thread(&locked_state.total_threads, &locked_state.req_lists.len);

    pool.stop_cond.notify_one();
    pool.request_cond.notify_one();
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::{thread, time};

    use super::{TaskOperation, ThreadPool};

    struct PoolTask {
        count: Arc<AtomicU64>,
    }

    impl TaskOperation for PoolTask {
        fn run(&mut self) {
            std::thread::sleep(std::time::Duration::from_millis(500));
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_pool_exit() {
        let pool = Arc::new(ThreadPool::default());
        let count = Arc::new(AtomicU64::new(0));
        let begin = time::SystemTime::now();
        for _ in 0..10 {
            let task = Box::new(PoolTask {
                count: count.clone(),
            });
            assert!(ThreadPool::submit_task(pool.clone(), task).is_ok());
        }

        // Waiting for creating.
        while pool.pool_state.lock().unwrap().req_lists.len != 0 {
            thread::sleep(time::Duration::from_millis(10));

            let now = time::SystemTime::now();
            let duration = now.duration_since(begin).unwrap().as_millis();
            assert!(duration < 500 * 10);
        }

        assert!(pool.cancel().is_ok());
        let end = time::SystemTime::now();
        let duration = end.duration_since(begin).unwrap().as_millis();
        // All tasks are processed in parallel.
        assert!(duration < 500 * 10);
        // All the task has been finished.
        assert_eq!(count.load(Ordering::SeqCst), 10);
    }
}
