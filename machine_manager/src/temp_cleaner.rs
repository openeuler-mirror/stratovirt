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

use std::fs;
use std::io::Write;

static mut GLOBAL_TEMP_CLEANER: Option<TempCleaner> = None;

/// This structure used to keep temporary file which was created by program, and would be deleted
/// when Vm exit.
pub struct TempCleaner {
    /// Path of files that should be removed after exiting the vm.
    paths: Vec<String>,
}

impl TempCleaner {
    pub fn object_init() {
        unsafe {
            if GLOBAL_TEMP_CLEANER.is_none() {
                GLOBAL_TEMP_CLEANER = Some(TempCleaner { paths: Vec::new() });
            }
        }
    }

    /// Add to be removed file path
    pub fn add_path(path: String) {
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                tmp.paths.push(path);
            }
        }
    }

    /// Clean the temporary files
    pub fn clean() {
        unsafe {
            if let Some(tmp) = GLOBAL_TEMP_CLEANER.as_mut() {
                while let Some(path) = tmp.paths.pop() {
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
                }
            }
        }
    }
}
