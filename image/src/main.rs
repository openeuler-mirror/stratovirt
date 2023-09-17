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

mod img;

use std::env;

use crate::img::{image_check, image_create, image_snapshot, print_help};

const BINARY_NAME: &str = "stratovirt-img";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!(
            "{0}: Not enough arguments\n\
            Try '{0} --help' for more information",
            BINARY_NAME
        );
        return;
    }

    let opt = args[1].clone();

    match opt.as_str() {
        "create" => {
            if let Err(e) = image_create(args[2..].to_vec()) {
                println!("{}: {:?}", BINARY_NAME, e);
            }
        }
        "check" => {
            if let Err(e) = image_check(args[2..].to_vec()) {
                println!("{}: {:?}", BINARY_NAME, e);
            }
        }
        "snapshot" => {
            if let Err(e) = image_snapshot(args[2..].to_vec()) {
                println!("{}: {:?}", BINARY_NAME, e);
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
            println!(
                "{}: Command not found: {}\n\
                Try 'stratovirt-img --help' for more information.",
                BINARY_NAME,
                opt.as_str()
            );
        }
    }
}
