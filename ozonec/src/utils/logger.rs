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

use std::{
    fs::{remove_file, rename, File, OpenOptions},
    io::{stderr, Write},
    num::Wrapping,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::UNIX_EPOCH,
};

use anyhow::{Context, Result};
use log::{set_boxed_logger, set_max_level, Level, LevelFilter, Log, Metadata, Record};
use nix::unistd::{getpid, gettid};

use super::OzonecErr;

// Maximum size of log file is 100MB.
const LOG_ROTATE_SIZE_MAX: usize = 100 * 1024 * 1024;
// Logs are retained for seven days at most.
const LOG_ROTATE_CNT_MAX: u8 = 7;

struct LogRotate {
    handler: Box<dyn Write + Send>,
    path: String,
    size: Wrapping<usize>,
    created_day: i32,
}

impl LogRotate {
    fn rotate(&mut self, inc_size: usize) -> Result<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        self.size += Wrapping(inc_size);
        let seconds = wall_time().0;
        let today = formatted_time(seconds)[2];
        if self.size < Wrapping(LOG_ROTATE_SIZE_MAX) && self.created_day == today {
            return Ok(());
        }

        // Delete oldest log file.
        let mut rotate_cnt = LOG_ROTATE_CNT_MAX - 1;
        let olddest = format!("{}{}", self.path, rotate_cnt);
        if Path::new(&olddest).exists() {
            remove_file(&olddest).with_context(|| "Failed to delete olddest log")?;
        }

        // Rename remaining logs.
        let mut new_log = olddest;
        while rotate_cnt != 0 {
            let mut old_log = self.path.clone();

            rotate_cnt -= 1;
            if rotate_cnt != 0 {
                old_log += &rotate_cnt.to_string();
            }

            if Path::new(&old_log).exists() {
                rename(&old_log, &new_log)
                    .with_context(|| format!("Failed to rename {} to {}", old_log, new_log))?;
            }
            new_log = old_log;
        }

        self.handler = Box::new(
            open_log_file(&PathBuf::from(self.path.clone()))
                .with_context(|| format!("Failed to convert {}", self.path))?,
        );
        self.size = Wrapping(0);
        self.created_day = today;
        Ok(())
    }
}

fn open_log_file(path: &PathBuf) -> Result<File> {
    OpenOptions::new()
        .read(false)
        .append(true)
        .create(true)
        .mode(0o640)
        .open(path)
        .with_context(|| OzonecErr::OpenFile(path.to_string_lossy().to_string()))
}

fn formatted_time(seconds: i64) -> [i32; 6] {
    // SAFETY: an all-zero value is valid for libc::tm.
    let mut ti: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: seconds and ti are both local variables and valid.
    unsafe {
        libc::localtime_r(&seconds, &mut ti);
    }
    [
        ti.tm_year + 1900,
        ti.tm_mon + 1,
        ti.tm_mday,
        ti.tm_hour,
        ti.tm_min,
        ti.tm_sec,
    ]
}

fn wall_time() -> (i64, i64) {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a local variable and valid.
    unsafe {
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
    }
    (ts.tv_sec, ts.tv_nsec)
}

fn formatted_now() -> String {
    let (sec, nsec) = wall_time();
    let formatted_time = formatted_time(sec);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}:{:09}",
        formatted_time[0],
        formatted_time[1],
        formatted_time[2],
        formatted_time[3],
        formatted_time[4],
        formatted_time[5],
        nsec
    )
}

struct Logger {
    rotate: Mutex<LogRotate>,
    level: Level,
}

impl Logger {
    fn new(path: &Option<PathBuf>, level: Level) -> Result<Self> {
        let (log_file, log_size, created_day) = match path {
            Some(p) => {
                let file = Box::new(open_log_file(p)?);
                let metadata = file.metadata().with_context(|| "Failed to get metadata")?;
                let mod_time = metadata
                    .modified()
                    .with_context(|| "Failed to get modify time")?;
                let seconds = mod_time
                    .duration_since(UNIX_EPOCH)
                    .with_context(|| "Failed to get duration time")?
                    .as_secs();
                let log_size = Wrapping(metadata.len() as usize);
                let created_day = formatted_time(seconds as i64)[2];
                (file as Box<dyn Write + Send>, log_size, created_day)
            }
            None => (Box::new(stderr()) as Box<dyn Write + Send>, Wrapping(0), 0),
        };

        let rotate = Mutex::new(LogRotate {
            handler: log_file,
            path: path
                .as_ref()
                .unwrap_or(&PathBuf::new())
                .to_string_lossy()
                .to_string(),
            size: log_size,
            created_day,
        });
        Ok(Self { rotate, level })
    }
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let fmt_msg = format_args!(
            "{:<5}: [{}][{}][{}: {}]:{}: {}\n",
            formatted_now(),
            getpid(),
            gettid(),
            record.file().unwrap_or(""),
            record.line().unwrap_or(0),
            record.level(),
            record.args()
        )
        .to_string();

        let mut log_rotate = self.rotate.lock().unwrap();
        if let Err(e) = log_rotate.handler.write_all(fmt_msg.as_bytes()) {
            eprintln!("Failed to log message: {:?}", e);
            return;
        }
        if let Err(e) = log_rotate.rotate(fmt_msg.as_bytes().len()) {
            eprintln!("Failed to rotate log files: {:?}", e);
        }
    }

    fn flush(&self) {}
}

pub fn init(path: &Option<PathBuf>, debug: bool) -> Result<()> {
    let log_level = if debug {
        Level::Debug
    } else {
        match std::env::var("OZONEC_LOG_LEVEL") {
            Ok(level) => match level.to_lowercase().as_str() {
                "error" => Level::Error,
                "warn" => Level::Warn,
                "info" => Level::Info,
                "debug" => Level::Debug,
                "trace" => Level::Trace,
                _ => Level::Info,
            },
            _ => Level::Info,
        }
    };

    let logger = Box::new(Logger::new(path, log_level)?);
    set_boxed_logger(logger)
        .map(|_| set_max_level(LevelFilter::Trace))
        .with_context(|| "Logger has been already set")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::MetadataExt};

    use super::*;

    #[test]
    fn test_logger_init() {
        assert!(init(&Some(PathBuf::from("/tmp/ozonec.log")), false).is_ok());
        remove_file(Path::new("/tmp/ozonec.log")).unwrap();
    }

    #[test]
    fn test_logger_rotate() {
        let log_file = PathBuf::from("/tmp/ozonec.log");
        let logger = Logger::new(&Some(log_file.clone()), Level::Debug).unwrap();
        let mut locked_rotate = logger.rotate.lock().unwrap();
        // Time in metadata are not changed as the file descriptor is still opened.
        let inode = fs::metadata(&log_file).unwrap().ino();
        for i in 1..LOG_ROTATE_CNT_MAX {
            let file = format!("{}{}", locked_rotate.path, i);
            let path = Path::new(&file);
            File::create(path).unwrap();
        }

        locked_rotate.size = Wrapping(0);
        assert!(locked_rotate.rotate(1024).is_ok());
        let mut new_inode = fs::metadata(&log_file).unwrap().ino();
        assert_eq!(inode, new_inode);

        locked_rotate.size = Wrapping(LOG_ROTATE_SIZE_MAX);
        assert!(locked_rotate.rotate(1024).is_ok());
        new_inode = fs::metadata(&log_file).unwrap().ino();
        assert_ne!(inode, new_inode);
        assert_eq!(locked_rotate.size, Wrapping(0));

        locked_rotate.size = Wrapping(0);
        locked_rotate.created_day = formatted_time(wall_time().0)[2] - 1;
        assert!(locked_rotate.rotate(1024).is_ok());
        new_inode = fs::metadata(&log_file).unwrap().ino();
        assert_ne!(inode, new_inode);
        assert_eq!(locked_rotate.size, Wrapping(0));

        for i in 1..LOG_ROTATE_CNT_MAX {
            let file = format!("{}{}", locked_rotate.path, i);
            let path = Path::new(&file);
            remove_file(path).unwrap();
        }
        remove_file(Path::new("/tmp/ozonec.log")).unwrap();
    }
}
