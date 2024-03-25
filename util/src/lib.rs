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

pub mod aio;
pub mod arg_parser;
pub mod bitmap;
pub mod byte_code;
pub mod checksum;
pub mod clock;
pub mod daemonize;
#[cfg(target_arch = "aarch64")]
pub mod device_tree;
pub mod edid;
pub mod error;
pub mod file;
pub mod leak_bucket;
pub mod link_list;
pub mod logger;
pub mod loop_context;
pub mod num_ops;
pub mod offsetof;
#[cfg(target_env = "ohos")]
pub mod ohos_binding;
#[cfg(feature = "pixman")]
pub mod pixman;
pub mod seccomp;
pub mod socket;
pub mod syscall;
pub mod tap;
pub mod test_helper;
pub mod thread_pool;
pub mod time;
pub mod unix;
#[cfg(feature = "usb_camera_v4l2")]
pub mod v4l2;

pub use error::UtilError;

use std::{any::Any, sync::Mutex};

use log::debug;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr, OutputFlags, SetArg, Termios};
use once_cell::sync::Lazy;
use vmm_sys_util::terminal::Terminal;

/// Read the program version in `Cargo.toml` and concat with git commit id.
pub const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " commit-id ",
    include_str!(concat!(env!("OUT_DIR"), "/GIT_COMMIT"))
);

pub static TERMINAL_MODE: Lazy<Mutex<Option<Termios>>> = Lazy::new(|| Mutex::new(None));

pub fn set_termi_raw_mode() -> std::io::Result<()> {
    let tty_fd = std::io::stdin().lock().tty_fd();

    let old_term_mode = match tcgetattr(tty_fd) {
        Ok(tm) => tm,
        Err(_) => return Err(std::io::Error::last_os_error()),
    };

    *TERMINAL_MODE.lock().unwrap() = Some(old_term_mode.clone());

    let mut new_term_mode = old_term_mode;
    cfmakeraw(&mut new_term_mode);
    new_term_mode.output_flags = new_term_mode.output_flags.union(OutputFlags::OPOST);

    if tcsetattr(tty_fd, SetArg::TCSANOW, &new_term_mode).is_err() {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

pub fn set_termi_canon_mode() -> std::io::Result<()> {
    let tty_fd = std::io::stdin().lock().tty_fd();
    if let Some(old_term_mode) = TERMINAL_MODE.lock().unwrap().as_ref() {
        if tcsetattr(tty_fd, SetArg::TCSANOW, old_term_mode).is_err() {
            return Err(std::io::Error::last_os_error());
        }
    } else {
        debug!("stdin's mode is not initialized: please check the config");
    }

    Ok(())
}

/// This trait is to cast trait object to struct.
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
