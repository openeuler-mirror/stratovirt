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

pub mod error;
use anyhow::{Context, Result};
pub use error::OzoneError;

use crate::args::create_args_parser;
use crate::handler::OzoneHandler;

mod args;
mod capability;
mod cgroup;
mod handler;
mod namespace;
mod syscall;

pub trait ExitCode {
    /// Returns the value to use as the exit status.
    fn code(self) -> i32;
}

impl ExitCode for i32 {
    fn code(self) -> i32 {
        self
    }
}

impl ExitCode for () {
    fn code(self) -> i32 {
        0
    }
}

fn main() {
    use std::io::Write;

    ::std::process::exit(match run() {
        Ok(ret) => ExitCode::code(ret),
        Err(ref e) => {
            write!(&mut ::std::io::stderr(), "{}", format_args!("{:?}", e))
                .expect("Error writing to stderr");

            1
        }
    });
}

fn run() -> Result<()> {
    let args = create_args_parser().get_matches()?;
    let handler = OzoneHandler::new(&args).with_context(|| "Failed to parse cmdline args")?;

    if args.is_present("clean_resource") {
        handler.teardown()?;
    } else {
        handler.realize()?;
    }
    Ok(())
}
