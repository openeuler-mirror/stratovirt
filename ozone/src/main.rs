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

#[macro_use]
extern crate error_chain;

use args::create_args_parser;

mod args;

error_chain! {
    links {
        Util(util::errors::Error, util::errors::ErrorKind);
    }
    foreign_links {
        Io(std::io::Error);
    }
    errors {
        ExecError(e: std::io::Error) {
            display("Failed to run binary file in ozone environment: {}", e)
        }
        DigitalParseError(column: &'static str, item: String) {
            display("Failed to parse {} to {}", item, column)
        }
    }
}

quick_main!(run);

fn run() -> Result<()> {
    #[allow(unused_variables)]
    let args = create_args_parser().get_matches()?;
    Ok(())
}
