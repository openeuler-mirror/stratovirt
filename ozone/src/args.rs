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

use util::arg_parser::{Arg, ArgParser};

const VERSION: Option<&'static str> = option_env!("CARGO_PFG_VERSION");

/// Create arguments parser from cmdline.
pub fn create_args_parser<'a>() -> ArgParser<'a> {
    ArgParser::new("Ozone")
        .version(VERSION.unwrap_or("unknown"))
        .author("Huawei Technologies Co., Ltd")
        .about("A light security sandbox.\nUse \'--\' to set exec_file arguments")
        .arg(
            Arg::with_name("name")
                .long("name")
                .value_name("process_name")
                .help("set the name of the ozone.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("exec_file")
                .long("exec-file")
                .value_name("binary_file_path")
                .help("set the executable binary file of the ozone.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .long("uid")
                .value_name("user id")
                .help("set the user id of the ozone.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gid")
                .long("gid")
                .value_name("group id")
                .help("set the group id of the ozone.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("source_files")
                .long("source")
                .value_name("source_file")
                .help("set the source file of the ozone, such as vmlinux and rootfs")
                .required(false)
                .takes_values(true),
        )
        .arg(
            Arg::with_name("network namespace")
                .long("netns")
                .value_name("network namespace path")
                .help("set the network namespace of the ozone.")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("clean_resource")
                .long("clean-resource")
                .help("clean ozone mount path.")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("capability")
                .long("capability")
                .value_name("set capabilities")
                .help("set the capabilities of the ozone.")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cgroup")
                .long("cgroup")
                .help("set cgroup arguments, use -cgroup <controler1>=<value1> ...")
                .required(false)
                .takes_values(true),
        )
        .arg(
            Arg::with_name("numa")
                .long("numa")
                .value_name("set numa node")
                .help("set the numa node of the ozone.")
                .required(false)
                .takes_value(true),
        )
}
