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

use std::fs::File;
use std::io::Write;
use std::num::Wrapping;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use log::{Level, LevelFilter, Log, Metadata, Record};
use nix::unistd::{getpid, gettid};

use crate::time::{get_format_time, gettime};

// Max size of the log file is 100MB.
const LOG_ROTATE_SIZE_MAX: usize = 100 * 1024 * 1024;
// Logs are retained for seven days.
const LOG_ROTATE_COUNT_MAX: u32 = 7;

fn format_now() -> String {
    let (sec, nsec) = gettime().unwrap_or_else(|e| {
        println!("{:?}", e);
        (0, 0)
    });
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

struct FileRotate {
    handler: Box<dyn Write + Send>,
    path: String,
    current_size: Wrapping<usize>,
    create_day: i32,
}

impl FileRotate {
    fn rotate_file(&mut self, size_inc: usize) -> Result<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        self.current_size += Wrapping(size_inc);
        let sec = gettime()?.0;
        let today = get_format_time(sec as i64)[2];
        if self.current_size < Wrapping(LOG_ROTATE_SIZE_MAX) && self.create_day == today {
            return Ok(());
        }

        // Remove the oldest log file.
        let mut rotate_count = LOG_ROTATE_COUNT_MAX - 1;
        let old_name = format!("{}{}", self.path, rotate_count);
        if Path::new(&old_name).exists() {
            std::fs::remove_file(&old_name)
                .with_context(|| format! {"Failed to remove log file {}", old_name})?;
        }

        // Rename files to older file name.
        let mut path_from;
        let mut path_to = old_name;
        while rotate_count != 0 {
            rotate_count -= 1;
            path_from = self.path.clone();
            if rotate_count != 0 {
                path_from += &rotate_count.to_string();
            }
            if Path::new(&path_from).exists() {
                std::fs::rename(&path_from, &path_to).with_context(
                    || format! {"Failed to rename log file from {} to {}", path_from, path_to},
                )?;
            }
            path_to = path_from;
        }

        // Update log file.
        self.handler = Box::new(open_log_file(&self.path)?);
        self.current_size = Wrapping(0);
        self.create_day = today;
        Ok(())
    }
}

/// Format like "%year-%mon-%dayT%hour:%min:%sec.%nsec
struct VmLogger {
    rotate: Mutex<FileRotate>,
    level: Level,
}

impl Log for VmLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let pid = getpid().as_raw();
        let tid = gettid().as_raw();
        let formatmsg = format_args!(
            "{:<5}: [{}][{}][{}: {}]:{}: {}\n",
            format_now(),
            pid,
            tid,
            record.file().unwrap_or(""),
            record.line().unwrap_or(0),
            record.level(),
            record.args()
        )
        .to_string();

        let mut rotate = self.rotate.lock().unwrap();
        if let Err(e) = rotate.handler.write_all(formatmsg.as_bytes()) {
            println!("Failed to log message {:?}", e);
            return;
        }
        if let Err(e) = rotate.rotate_file(formatmsg.as_bytes().len()) {
            println!("Failed to rotate log files {:?}", e);
        }
    }

    fn flush(&self) {}
}

fn init_vm_logger(
    level: Level,
    logfile: Box<dyn Write + Send>,
    logfile_path: String,
) -> Result<()> {
    let current_size;
    let create_day;
    if logfile_path.is_empty() {
        current_size = Wrapping(0);
        create_day = 0;
    } else {
        let metadata = File::open(&logfile_path)?.metadata()?;
        current_size = Wrapping(metadata.len() as usize);
        let mod_time = metadata.modified()?;
        let sec = mod_time.duration_since(UNIX_EPOCH)?.as_secs();
        create_day = get_format_time(sec as i64)[2];
    };
    let rotate = Mutex::new(FileRotate {
        handler: logfile,
        path: logfile_path,
        current_size,
        create_day,
    });

    let logger = VmLogger { rotate, level };
    log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Trace))?;
    Ok(())
}

fn init_logger_with_env(logfile: Box<dyn Write + Send>, logfile_path: String) -> Result<()> {
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

    init_vm_logger(level, logfile, logfile_path)?;
    Ok(())
}

fn open_log_file(path: &str) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(false)
        .write(true)
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .with_context(|| format!("Failed to open log file {}", path))
}

pub fn init_log(path: String) -> Result<()> {
    let logfile: Box<dyn Write + Send> = if path.is_empty() {
        Box::new(std::io::stderr())
    } else {
        Box::new(open_log_file(&path)?)
    };
    init_logger_with_env(logfile, path.clone())
        .with_context(|| format!("Failed to init logger: {}", path))
}
