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

use std::io::prelude::*;
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};

use crate::time::{get_format_time, gettime};
use crate::unix::gettid;

fn format_now() -> String {
    let (sec, nsec) = gettime();
    let format_time = get_format_time(sec as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}",
        format_time[0],
        format_time[1],
        format_time[2],
        format_time[3],
        format_time[4],
        format_time[5],
        nsec
    )
}

/// Format like "%year-%mon-%dayT%hour:%min:%sec.%nsec
struct VmLogger {
    handler: Option<Mutex<Box<dyn Write + Send>>>,
    level: Level,
}

impl Log for VmLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.handler.is_some() && metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let pid = unsafe { libc::getpid() };
            let tid = gettid();

            self.handler.as_ref().map(|writer| {
                writer.lock().unwrap().write_fmt(format_args!(
                    "{:<5}: [{}][{}][{}: {}]:{}: {}\n",
                    format_now(),
                    pid,
                    tid,
                    record.file().unwrap_or(""),
                    record.line().unwrap_or(0),
                    record.level(),
                    record.args()
                ))
            });
        }
    }

    fn flush(&self) {}
}

fn init_vm_logger(
    level: Option<Level>,
    logfile: Option<Box<dyn Write + Send>>,
) -> Result<(), log::SetLoggerError> {
    let buffer = logfile.map(Mutex::new);
    let logger = VmLogger {
        level: level.unwrap_or(Level::Info),
        handler: buffer,
    };

    log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Trace))
}

pub fn init_logger_with_env(logfile: Option<Box<dyn Write + Send>>) -> Result<(), SetLoggerError> {
    let level = match std::env::var("STRATOVIRT_LOG_LEVEL") {
        Ok(l) => match l.to_lowercase().as_str() {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => Level::Info,
        },
        _ => Level::Info,
    };

    init_vm_logger(Some(level), logfile)?;

    Ok(())
}
