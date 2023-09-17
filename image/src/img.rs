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

use std::{
    fs::File,
    os::unix::prelude::{FileExt, OpenOptionsExt},
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Result};

pub(crate) fn image_create(_args: Vec<String>) -> Result<()> {
    todo!()
}

pub(crate) fn image_check(_args: Vec<String>) -> Result<()> {
    todo!()
}

pub(crate) fn image_snapshot(_args: Vec<String>) -> Result<()> {
    todo!()
}

pub fn print_help() {
    print!(
        r#"Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
Usage: stratovirt-img [standard options] command [command options]
Stratovirt disk image utility

'-h', '--help'       display this help and exit
'-v', '--version'    output version information and exit

Command syntax:
create [-f fmt] [-o options] filename [size]
check [-r [leaks | all]] [-no_print_error] [-f fmt] filename
snapshot [-l | -a snapshot | -c snapshot | -d snapshot] filename

Command parameters:
'filename' is a disk image filename
'fmt' is the disk image format
'size' is the disk image size in bytes
'options' is a comma separated list of format specific options in a
name=value format.

Parameters to check subcommand:
 '-no_print_error' don't print error detail.
 '-r' tries to repair any inconsistencies that are found during the check.
 '-r leaks' repairs only cluster leaks, whereas '-r all' fixes all
     kinds of errors.

Parameters to snapshot subcommand:
'snapshot' is the name of the snapshot to create, apply or delete
 '-a' applies a snapshot (revert disk to saved state)
 '-c' creates a snapshot
 '-d' deletes a snapshot
 '-l' lists all snapshots in the given image
"#,
    );
}
