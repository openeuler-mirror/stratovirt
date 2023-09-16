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

use crate::cmdline::ArgsParse;
use block_backend::{
    qcow2::{header::QcowHeader, InternalSnapshotOps, Qcow2Driver, SyncAioInfo},
    raw::RawDriver,
    BlockDriverOps, BlockProperty, CheckResult, CreateOptions, FIX_ERRORS, FIX_LEAKS, NO_FIX,
    SECTOR_SIZE,
};
use machine_manager::config::{memory_unit_conversion, DiskFormat};
use util::{
    aio::{Aio, AioEngine},
    file::{lock_file, open_file, unlock_file},
};

pub(crate) fn image_create(args: Vec<String>) -> Result<()> {
    let mut create_options = CreateOptions::default();
    let mut arg_parser = ArgsParse::create(vec!["h", "help"], vec!["f"], vec!["o"]);
    arg_parser.parse(args.clone())?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    let mut disk_fmt = DiskFormat::Raw;
    if let Some(fmt) = arg_parser.opt_str("f") {
        disk_fmt = DiskFormat::from_str(&fmt)?;
    };

    let extra_options = arg_parser.opt_strs("o");
    for option in extra_options {
        if option.starts_with("cluster_size=") {
            let vec: Vec<String> = option.split('=').map(|str| str.to_string()).collect();
            if vec.len() == 2 && vec[0] == *"cluster_size" {
                let str = vec[1].clone();
                create_options.cluster_size = Some(memory_unit_conversion(&str, 1)?);
                continue;
            }
        }
        if option.starts_with("refcount_bits=") {
            let vec: Vec<String> = option.split('=').map(|str| str.to_string()).collect();
            if vec.len() == 2 && vec[0] == *"refcount_bits" {
                let value = vec[1].clone();
                create_options.refcount_bits = Some(value.parse::<u64>()?);
                continue;
            }
        }

        bail!("Invalid parameter '{}'", option);
    }

    let len = arg_parser.free.len();
    match len {
        0 => bail!("Image creation requires path and size parameters"),
        1 => bail!("Image creation requires size parameters"),
        2 => {
            create_options.path = arg_parser.free[0].clone();
            let img_size_str = arg_parser.free[1].clone();
            create_options.img_size = memory_unit_conversion(&img_size_str, 1)?;
        }
        _ => {
            let param = arg_parser.free[2].clone();
            bail!("Unexpected argument: {}", param);
        }
    }

    let path = create_options.path.clone();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CREAT | libc::O_TRUNC)
        .open(path.clone())?;

    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off)?;
    let image_info = match disk_fmt {
        DiskFormat::Raw => {
            create_options.conf.format = DiskFormat::Raw;
            let mut raw_driver = RawDriver::new(file, aio, create_options.conf.clone());
            raw_driver.create_image(&create_options)?
        }
        DiskFormat::Qcow2 => {
            create_options.conf.format = DiskFormat::Qcow2;
            let mut qcow2_driver = Qcow2Driver::new(file, aio, create_options.conf.clone())?;
            qcow2_driver.create_image(&create_options)?
        }
    };
    println!("Stratovirt-img: {}", image_info);

    Ok(())
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
