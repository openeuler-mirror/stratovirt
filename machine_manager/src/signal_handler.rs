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
extern crate vmm_sys_util;
use crate::event_loop::EventLoop;
use std::io::Write;

use libc::{c_int, c_void, siginfo_t};
use vmm_sys_util::signal::register_signal_handler;
use vmm_sys_util::terminal::Terminal;

const VM_EXIT_GENE_ERR: i32 = -1;
const SYSTEMCALL_OFFSET: isize = 6;

fn basic_clean() {
    info!("Removing environment and exiting...");
    if !EventLoop::clean() {
        error!("Clean environment failed!");
    }
    std::io::stdin()
        .lock()
        .set_canon_mode()
        .expect("Failed to set terminal to canon mode.");
}

fn exit_with_code(code: i32) {
    // Safe, because the basic_clean function has been executed before exit.
    unsafe {
        libc::_exit(code);
    }
}

extern "C" fn handle_signal_term(num: c_int, _: *mut siginfo_t, _: *mut c_void) {
    info!("Received kill signal, signal num: {}", num);
    basic_clean();
    exit_with_code(VM_EXIT_GENE_ERR);
}

extern "C" fn handle_signal_sys(_: c_int, info: *mut siginfo_t, _: *mut c_void) {
    let badcall = unsafe { *(info as *const i32).offset(SYSTEMCALL_OFFSET) as usize };
    error!("Received a bad system call, number: {}", badcall);
    basic_clean();
    write!(&mut std::io::stderr(), "Bad system call").expect("Failed to write to stderr");
    exit_with_code(VM_EXIT_GENE_ERR);
}

/// Register kill signal handler. Signals suported now are SIGTERM and SIGSYS.
pub fn register_kill_signal() {
    register_signal_handler(libc::SIGTERM, handle_signal_term)
        .expect("Register signal handler for SIGTERM failed!");
    register_signal_handler(libc::SIGSYS, handle_signal_sys)
        .expect("Register signal handler for SIGSYS failed!");
}
