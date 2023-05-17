// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::{env, fs::File, io::Write, path::Path, process::Command};

fn get_git_commit() -> String {
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs");
    println!("cargo:rerun-if-changed=build.rs");

    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8(o.stdout).expect("Failed to read git commit id")
        }
        Ok(o) => {
            println!("Get git commit id failed with status: {}", o.status);
            String::from("unknown")
        }
        Err(e) => {
            println!("Get git commit id failed: {:?}", e);
            String::from("unknown")
        }
    }
}

fn main() {
    let commit = get_git_commit();
    // Save commit id to pkg build out directory.
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("GIT_COMMIT");
    let mut file = File::create(path).unwrap();
    file.write_all(commit.as_bytes()).unwrap();
}
