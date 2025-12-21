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
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use log::{error, info};

static GLOBAL_TEMP_CLEANER: OnceLock<TempCleaner> = OnceLock::new();

pub type ExitNotifier = dyn Fn() + Send + Sync;

/// This structure used to keep temporary file which was created by program, and would be deleted
/// when Vm exit.
pub struct TempCleaner {
    /// Path of files that should be removed after exiting the vm.
    paths: Mutex<Vec<String>>,
    /// Notifiers are used to release residual resources after exiting the vm.
    notifiers: Mutex<HashMap<String, Arc<ExitNotifier>>>,
    /// Indicate whether clean has been done.
    executed: AtomicBool,
}

impl TempCleaner {
    pub fn object_init() {
        let _ = GLOBAL_TEMP_CLEANER.set(TempCleaner {
            paths: Mutex::new(Vec::new()),
            notifiers: Mutex::new(HashMap::new()),
            executed: AtomicBool::new(false),
        });
    }

    /// Add to be removed file path
    pub fn add_path(path: String) {
        if let Some(tmp) = GLOBAL_TEMP_CLEANER.get() {
            tmp.paths.lock().unwrap().push(path);
        }
    }

    /// Add exit notifier.
    pub fn add_exit_notifier(id: String, exit: Arc<ExitNotifier>) {
        if let Some(tmp) = GLOBAL_TEMP_CLEANER.get() {
            tmp.notifiers.lock().unwrap().insert(id, exit);
        }
    }

    /// Remove exit notifier by id.
    pub fn remove_exit_notifier(id: &str) {
        if let Some(tmp) = GLOBAL_TEMP_CLEANER.get() {
            tmp.notifiers.lock().unwrap().remove(id);
        }
    }

    fn clean_files(&self) {
        while let Some(path) = self.paths.lock().unwrap().pop() {
            if Path::new(&path).exists() {
                if let Err(ref e) = fs::remove_file(&path) {
                    error!("Failed to delete console / socket file:{} :{}", &path, e);
                } else {
                    info!("Delete file: {} successfully", &path);
                }
            } else {
                info!("file: {} has been removed", &path);
            }
        }
    }

    fn exit_notifier(&self) {
        for (_id, exit) in self.notifiers.lock().unwrap().iter() {
            exit();
        }
    }

    /// Clean the resources
    pub fn clean() {
        if let Some(tmp) = GLOBAL_TEMP_CLEANER.get() {
            tmp.clean_files();
            tmp.exit_notifier();
            tmp.paths.lock().unwrap().clear();
            tmp.notifiers.lock().unwrap().clear();
            tmp.executed.store(true, Ordering::SeqCst);
        }
    }

    pub fn is_cleaned() -> bool {
        if let Some(tmp) = GLOBAL_TEMP_CLEANER.get() {
            return tmp.executed.load(Ordering::SeqCst);
        }
        true
    }
}
