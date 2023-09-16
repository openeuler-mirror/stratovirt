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

enum SnapshotOperation {
    Create,
    Delete,
    Apply,
    List,
}

pub struct ImageFile {
    file: File,
    path: String,
}

impl ImageFile {
    fn create(path: &str, read_only: bool) -> Result<Self> {
        let file = open_file(path, read_only, false)?;

        // Add write lock for image file.
        lock_file(&file, path, read_only).with_context(|| {
            format!(
                "Could not open '{0}': Failed to get \"write\" lock\n\
                Is another process using the image {0}",
                path
            )
        })?;

        Ok(Self {
            file,
            path: path.to_string(),
        })
    }

    /// If the image format is not specified by user, active detection is required
    /// For qcow2: will check its version in header.
    /// If the image does not belong to any supported format, it defaults to raw.
    fn detect_img_format(&self) -> Result<DiskFormat> {
        let mut buf = vec![0_u8; SECTOR_SIZE as usize];
        self.file.read_at(&mut buf, 0)?;

        let mut disk_format = DiskFormat::Raw;
        if let Ok(header) = QcowHeader::from_vec(&buf) {
            if header.version == 3 {
                disk_format = DiskFormat::Qcow2;
            }
        }

        Ok(disk_format)
    }

    fn check_img_format(
        &self,
        input_fmt: Option<DiskFormat>,
        detect_fmt: DiskFormat,
    ) -> Result<DiskFormat> {
        let real_fmt = match input_fmt {
            Some(fmt) if fmt == DiskFormat::Raw => DiskFormat::Raw,
            Some(fmt) => {
                if fmt != detect_fmt {
                    bail!(
                        "Could not open '{}': Image is not in {} fmt",
                        self.path,
                        fmt.to_string()
                    );
                }
                fmt
            }
            _ => detect_fmt,
        };

        Ok(real_fmt)
    }
}

impl Drop for ImageFile {
    fn drop(&mut self) {
        if let Err(e) = unlock_file(&self.file, &self.path) {
            println!("{:?}", e);
        }
    }
}

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

pub(crate) fn image_check(args: Vec<String>) -> Result<()> {
    let mut arg_parser =
        ArgsParse::create(vec!["no_print_error", "h", "help"], vec!["f", "r"], vec![]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    let mut quite = false;
    let mut disk_fmt: Option<DiskFormat> = None;
    let mut fix = NO_FIX;

    if arg_parser.opt_present("no_print_error") {
        quite = true;
    }
    if let Some(fmt) = arg_parser.opt_str("f") {
        disk_fmt = Some(DiskFormat::from_str(&fmt)?);
    }

    if let Some(kind) = arg_parser.opt_str("r") {
        if kind == "leaks".to_string() {
            fix |= FIX_LEAKS;
        } else if kind == "all".to_string() {
            fix |= FIX_LEAKS;
            fix |= FIX_ERRORS;
        } else {
            bail!(
                "Unknown option value for -r {:?}(expects 'leaks' or 'all')",
                kind
            );
        }
    }

    // Parse image path.
    let len = arg_parser.free.len();
    let path = match len {
        0 => bail!("Image check requires path"),
        1 => arg_parser.free[0].clone(),
        _ => {
            let param = arg_parser.free[1].clone();
            bail!("Unexpected argument: {}", param);
        }
    };

    let read_only = fix == NO_FIX;
    let image_file = ImageFile::create(&path, read_only)?;
    let detect_fmt = image_file.detect_img_format()?;
    let real_fmt = image_file.check_img_format(disk_fmt, detect_fmt)?;

    let mut check_res = CheckResult::default();
    let file = image_file.file.try_clone()?;
    match real_fmt {
        DiskFormat::Raw => {
            bail!("stratovirt-img: This image format does not support checks");
        }
        DiskFormat::Qcow2 => {
            let mut conf = BlockProperty::default();
            conf.format = DiskFormat::Qcow2;
            let mut qcow2_driver = create_qcow2_driver_for_check(file, conf)?;
            let ret = qcow2_driver.check_image(&mut check_res, quite, fix);
            let check_message = check_res.collect_check_message();
            print!("{}", check_message);
            ret
        }
    }
}

pub(crate) fn image_snapshot(args: Vec<String>) -> Result<()> {
    let mut arg_parser =
        ArgsParse::create(vec!["l", "h", "help"], vec!["f", "c", "d", "a"], vec![]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    let mut snapshot_name: String = String::from("");
    let mut snapshot_operation: Option<SnapshotOperation> = None;
    let mut disk_fmt: Option<DiskFormat> = None;
    let err_msg = "Cannot mix '-l', '-a', '-c', '-d'".to_string();

    if let Some(fmt) = arg_parser.opt_str("f") {
        disk_fmt = Some(DiskFormat::from_str(&fmt)?);
    }

    if arg_parser.opt_present("l") {
        snapshot_operation = Some(SnapshotOperation::List);
    }

    if let Some(name) = arg_parser.opt_str("c") {
        if snapshot_operation.is_some() {
            bail!("{}", err_msg);
        }
        snapshot_operation = Some(SnapshotOperation::Create);
        snapshot_name = name;
    }

    if let Some(name) = arg_parser.opt_str("d") {
        if snapshot_operation.is_some() {
            bail!("{}", err_msg);
        }
        snapshot_operation = Some(SnapshotOperation::Delete);
        snapshot_name = name;
    }

    if let Some(name) = arg_parser.opt_str("a") {
        if snapshot_operation.is_some() {
            bail!("{}", err_msg);
        }
        snapshot_operation = Some(SnapshotOperation::Apply);
        snapshot_name = name;
    }

    // Parse image path.
    let len = arg_parser.free.len();
    let path = match len {
        0 => bail!("Image snapshot requires path"),
        1 => arg_parser.free[0].clone(),
        _ => {
            let param = arg_parser.free[1].clone();
            bail!("Unexpected argument: {}", param);
        }
    };

    // Detect the image fmt.
    let image_file = ImageFile::create(&path, false)?;
    let detect_fmt = image_file.detect_img_format()?;
    let real_fmt = image_file.check_img_format(disk_fmt, detect_fmt)?;
    if real_fmt != DiskFormat::Qcow2 {
        bail!(
            "Could not create snapshot '{}'(Operation not supported)",
            snapshot_name
        );
    }

    // Create qcow2 driver.
    let mut qcow2_conf = BlockProperty::default();
    qcow2_conf.format = DiskFormat::Qcow2;
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off).unwrap();
    let mut qcow2_driver = Qcow2Driver::new(image_file.file.try_clone()?, aio, qcow2_conf.clone())?;
    qcow2_driver.load_metadata(qcow2_conf)?;

    match snapshot_operation {
        Some(SnapshotOperation::Create) => {
            qcow2_driver.create_snapshot(snapshot_name, 0)?;
        }
        Some(SnapshotOperation::List) => {
            let info = qcow2_driver.list_snapshots();
            println!("{}", info);
        }
        Some(SnapshotOperation::Delete) => {
            qcow2_driver.delete_snapshot(snapshot_name)?;
        }
        Some(SnapshotOperation::Apply) => {
            qcow2_driver.apply_snapshot(snapshot_name)?;
        }
        None => return Ok(()),
    };

    Ok(())
}

pub(crate) fn create_qcow2_driver_for_check(
    file: File,
    conf: BlockProperty,
) -> Result<Qcow2Driver<()>> {
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off).unwrap();
    let mut qcow2_driver = Qcow2Driver::new(file, aio, conf.clone())
        .with_context(|| "Failed to create qcow2 driver")?;

    qcow2_driver
        .load_header()
        .with_context(|| "Failed to load header")?;
    qcow2_driver
        .table
        .init_table_info(&qcow2_driver.header, &conf)
        .with_context(|| "Failed to create qcow2 table")?;
    qcow2_driver
        .refcount
        .init_refcount_info(&qcow2_driver.header, &conf);
    qcow2_driver
        .load_refcount_table()
        .with_context(|| "Failed to load refcount table")?;
    qcow2_driver
        .snapshot
        .set_cluster_size(qcow2_driver.header.cluster_size());
    Ok(qcow2_driver)
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
