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

mod cmdline;
mod img;

use std::{
    env,
    process::{ExitCode, Termination},
};

use anyhow::{bail, Result};

use crate::img::{image_check, image_create, image_snapshot, print_help};

const BINARY_NAME: &str = "stratovirt-img";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    match run(args) {
        Ok(ret) => ret.report(),
        Err(e) => {
            println!("{:?}", e);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<()> {
    if args.len() < 2 {
        bail!(
            "{0}: Not enough arguments\n\
            Try '{0} --help' for more information",
            BINARY_NAME
        );
    }

    let opt = args[1].clone();

    match opt.as_str() {
        "create" => {
            if let Err(e) = image_create(args[2..].to_vec()) {
                bail!("{}: {:?}", BINARY_NAME, e);
            }
        }
        "check" => {
            if let Err(e) = image_check(args[2..].to_vec()) {
                bail!("{}: {:?}", BINARY_NAME, e);
            }
        }
        "snapshot" => {
            if let Err(e) = image_snapshot(args[2..].to_vec()) {
                bail!("{}: {:?}", BINARY_NAME, e);
            }
        }
        "-v" | "--version" => {
            println!(
                "{} version {}\
                Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.",
                BINARY_NAME,
                util::VERSION,
            )
        }
        "-h" | "--help" => {
            print_help();
        }
        _ => {
            bail!(
                "{}: Command not found: {}\n\
                Try 'stratovirt-img --help' for more information.",
                BINARY_NAME,
                opt.as_str()
            );
        }
    }

    Ok(())
}
