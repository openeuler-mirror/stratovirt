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

use std::io::Write;

use libc::{c_int, c_void, siginfo_t};
use util::set_termi_canon_mode;
use vmm_sys_util::signal::register_signal_handler;

use crate::{
    event,
    qmp::{qmp_schema, QmpChannel},
    temp_cleaner::TempCleaner,
};

const VM_EXIT_SUCCESS: i32 = 0;
pub const VM_EXIT_GENE_ERR: i32 = 1;
const SYSTEMCALL_OFFSET: isize = 6;

fn basic_clean() {
    // clean temporary file
    TempCleaner::clean();

    set_termi_canon_mode().expect("Failed to set terminal to canon mode.");
}

pub fn exit_with_code(code: i32) {
    // Safe, because the basic_clean function has been executed before exit.
    unsafe {
        libc::_exit(code);
    }
}

extern "C" fn handle_signal_kill(num: c_int, _: *mut siginfo_t, _: *mut c_void) {
    if QmpChannel::is_connected() {
        let shutdown_msg = qmp_schema::Shutdown {
            guest: false,
            reason: "Guest shutdown by signal ".to_string() + &num.to_string(),
        };
        event!(Shutdown; shutdown_msg);
    }

    basic_clean();
    write!(
        &mut std::io::stderr(),
        "Received kill signal, signal number: {} \r\n",
        num
    )
    .expect("Failed to write to stderr");
    exit_with_code(VM_EXIT_SUCCESS);
}

extern "C" fn handle_signal_sys(_: c_int, info: *mut siginfo_t, _: *mut c_void) {
    basic_clean();
    let badcall = unsafe { *(info as *const i32).offset(SYSTEMCALL_OFFSET) as usize };
    write!(
        &mut std::io::stderr(),
        "Received a bad system call, number: {} \r\n",
        badcall
    )
    .expect("Failed to write to stderr");
    exit_with_code(VM_EXIT_GENE_ERR);
}

/// Register kill signal handler. Signals supported now are SIGTERM and SIGSYS.
pub fn register_kill_signal() {
    register_signal_handler(libc::SIGTERM, handle_signal_kill)
        .expect("Register signal handler for SIGTERM failed!");
    register_signal_handler(libc::SIGSYS, handle_signal_sys)
        .expect("Register signal handler for SIGSYS failed!");
    register_signal_handler(libc::SIGINT, handle_signal_kill)
        .expect("Register signal handler for SIGINT failed!");
    register_signal_handler(libc::SIGHUP, handle_signal_kill)
        .expect("Register signal handler for SIGHUP failed!");
}
