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

use libc::{c_int, c_void, sighandler_t, signal};
use vmm_sys_util::terminal::Terminal;

use crate::event_loop::EventLoop;

const VM_EXIT_GENE_ERR: i32 = -1;

extern "C" fn signal_handler(_sig: c_int) {
    info!("Received kill signal, removing env and exiting...");
    if !EventLoop::clean() {
        error!("Clean environment failed!");
    }
    std::io::stdin()
        .lock()
        .set_canon_mode()
        .expect("Failed to set terminal to canon mode.");
    unsafe {
        libc::_exit(VM_EXIT_GENE_ERR);
    }
}

fn get_handler() -> sighandler_t {
    signal_handler as extern "C" fn(c_int) as *mut c_void as sighandler_t
}

pub fn register_kill_signal() {
    unsafe {
        signal(libc::SIGTERM, get_handler());
    }
}
