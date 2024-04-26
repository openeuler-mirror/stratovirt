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

use crate::img::{
    image_check, image_create, image_info, image_resize, image_snapshot, print_help, print_version,
};

const BINARY_NAME: &str = "stratovirt-img";

macro_rules! image_operation_matches {
    ( $cmd:expr;
        $(($($opt_0:tt)|+, $function_0:tt, $arg:expr)),*;
        $(($($opt_1:tt)|+, $function_1:tt)),*
    ) => {
        match $cmd {
            $(
                $($opt_0)|+ => {
                    if let Err(e) = $function_0($arg) {
                        bail!("{}: {:?}", BINARY_NAME, e);
                    }
                },
            )*
            $(
                $($opt_1)|+ => {
                    $function_1()
                },
            )*
            _ => {
                bail!(
                    "{}: Command not found: {}\n\
                    Try 'stratovirt-img --help' for more information.",
                    BINARY_NAME,
                    $cmd
                );
            }
        }
    }
}

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
    let cmd_args = args[2..].to_vec();

    image_operation_matches!(
        opt.as_str();
        ("create", image_create, cmd_args),
        ("info", image_info, cmd_args),
        ("check", image_check, cmd_args),
        ("resize", image_resize, cmd_args),
        ("snapshot", image_snapshot, cmd_args);
        ("-v" | "--version", print_version),
        ("-h" | "--help", print_help)
    );

    Ok(())
}
