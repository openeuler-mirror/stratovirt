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

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

static mut GLOBAL_TEMP_CLEANER: Option<TempCleaner> = None;

pub type ExitNotifier = dyn Fn() + Send + Sync;

/// This structure used to keep temporary file which was created by program, and would be deleted
/// when Vm exit.
pub struct TempCleaner {
    /// Path of files that should be removed after exiting the vm.
    paths: Vec<String>,
    /// Notifiers are used to release residual resources after exiting the vm.
    notifiers: HashMap<String, Arc<ExitNotifier>>,
}

impl TempCleaner {
    pub fn object_init() {
        // SAFETY: This global variable is only used in single thread,
        // so there is no data competition or synchronization problem.
        unsafe {
            if GLOBAL_TEMP_CLEANER.is_none() {
                GLOBAL_TEMP_CLEANER = Some(TempCleaner {
                    paths: Vec::new(),
                    notifiers: HashMap::new(),
                });
            }
        }
    }

    /// Add to be removed file path
    pub fn add_path(path: String) {
        // SAFETY: This global variable is only used in single thread,
        // so there is no data competition or synchronization problem.
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                tmp.paths.push(path);
            }
        }
    }

    /// Add exit notifier.
    pub fn add_exit_notifier(id: String, exit: Arc<ExitNotifier>) {
        // SAFETY: This global variable is only used in single thread,
        // so there is no data competition or synchronization problem.
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                tmp.notifiers.insert(id, exit);
            }
        }
    }

    /// Remove exit notifier by id.
    pub fn remove_exit_notifier(id: &str) {
        // SAFETY: This global variable is only used in single thread,
        // so there is no data competition or synchronization problem.
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                tmp.notifiers.remove(id);
            }
        }
    }

    fn clean_files(&mut self) {
        while let Some(path) = self.paths.pop() {
            if Path::new(&path).exists() {
                if let Err(ref e) = fs::remove_file(&path) {
                    write!(
                        &mut std::io::stderr(),
                        "Failed to delete console / socket file:{} :{} \r\n",
                        &path,
                        e
                    )
                    .expect("Failed to write to stderr");
                } else {
                    write!(
                        &mut std::io::stdout(),
                        "Delete file: {} successfully.\r\n",
                        &path
                    )
                    .expect("Failed to write to stdout");
                }
            } else {
                write!(
                    &mut std::io::stdout(),
                    "file: {} has been removed \r\n",
                    &path
                )
                .expect("Failed to write to stdout");
            }
        }
    }

    fn exit_notifier(&mut self) {
        for (_id, exit) in self.notifiers.iter() {
            exit();
        }
    }

    /// Clean the resources
    pub fn clean() {
        // SAFETY: This global variable is only used in single thread,
        // so there is no data competition or synchronization problem.
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                tmp.clean_files();
                tmp.exit_notifier();
            }
        }
    }
}
