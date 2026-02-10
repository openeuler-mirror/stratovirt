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

use std::{
    io::Write,
    sync::atomic::{AtomicI32, Ordering},
};

use libc::{c_int, c_void, siginfo_t};
use vmm_sys_util::signal::register_signal_handler;

use crate::{
    event,
    event_loop::EventLoop,
    qmp::{qmp_channel::QmpChannel, qmp_schema},
};
use util::set_termi_canon_mode;

pub const VM_EXIT_GENE_ERR: i32 = 1;
const SYSTEMCALL_OFFSET: isize = 6;
const SYS_SECCOMP: i32 = 1;

static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

pub fn exit_with_code(code: i32) {
    // SAFETY: The basic_clean function has been executed before exit.
    unsafe {
        libc::_exit(code);
    }
}

pub fn set_signal(num: c_int) {
    /*
     * Compared to the SIGSYS signal, the other three signals require
     * additional shutdown information to be sent via the QMP channel.
     * Therefore, if any of the other three signals are received, the
     * previously received SIGSYS signal must be replaced in the global
     * variable. The SIGTERM/SIGINT/SIGHUP signals are handled in the
     * same way.
     * Retry on CAS fail.
     */
    loop {
        let prev = get_signal();
        if prev != 0 && prev != libc::SIGSYS {
            break;
        }

        if RECEIVED_SIGNAL
            .compare_exchange(prev, num, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // CAS success，kick main loop
            EventLoop::get_ctx(None).unwrap().kick();
            break;
        }
    }
}

pub fn get_signal() -> i32 {
    RECEIVED_SIGNAL.load(Ordering::SeqCst)
}

pub fn handle_signal() {
    let sig_num = get_signal();
    if sig_num != 0 {
        set_termi_canon_mode().expect("Failed to set terminal to canonical mode.");
        if [libc::SIGTERM, libc::SIGINT, libc::SIGHUP].contains(&sig_num)
            && QmpChannel::is_connected()
        {
            let shutdown_msg = qmp_schema::Shutdown {
                guest: false,
                reason: "Guest shutdown by signal ".to_string() + &sig_num.to_string(),
            };
            event!(Shutdown; shutdown_msg);
        }
    }
}

extern "C" fn receive_signal_kill(num: c_int, _: *mut siginfo_t, _: *mut c_void) {
    hisysevent::STRATOVIRT_KILLED(num);
    set_signal(num);
    write!(
        &mut std::io::stderr(),
        "Received kill signal, signal number: {} \r\n",
        num
    )
    .expect("Failed to write to stderr");
}

extern "C" fn receive_signal_sys(num: c_int, info: *mut siginfo_t, _: *mut c_void) {
    hisysevent::STRATOVIRT_KILLED(num);
    set_signal(num);
    // SAFETY: The safety of this function is guaranteed by caller.
    if let Some(sig_info) = unsafe { info.as_ref() } {
        if SYS_SECCOMP == sig_info.si_code {
            eprintln!("seccomp violation, Try running with `strace -ff` to identify the cause.");
        }

        // SAFETY: the pointer is not null.
        let badcall = unsafe { *(info.cast::<i32>().offset(SYSTEMCALL_OFFSET)) };
        write!(
            &mut std::io::stderr(),
            "Received a bad system call, number: {} \r\n",
            badcall
        )
        .expect("Failed to write to stderr");
    }
}

/// Register kill signal handler. Signals supported now are SIGTERM and SIGSYS.
pub fn register_kill_signal() {
    register_signal_handler(libc::SIGTERM, receive_signal_kill)
        .expect("Register signal handler for SIGTERM failed!");
    register_signal_handler(libc::SIGSYS, receive_signal_sys)
        .expect("Register signal handler for SIGSYS failed!");
    register_signal_handler(libc::SIGINT, receive_signal_kill)
        .expect("Register signal handler for SIGINT failed!");
    register_signal_handler(libc::SIGHUP, receive_signal_kill)
        .expect("Register signal handler for SIGHUP failed!");
}
