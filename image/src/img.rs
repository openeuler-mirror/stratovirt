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

use anyhow::{anyhow, bail, Context, Result};

use crate::{cmdline::ArgsParse, BINARY_NAME};
use block_backend::{
    qcow2::{header::QcowHeader, InternalSnapshotOps, Qcow2Driver, SyncAioInfo},
    raw::RawDriver,
    BlockAllocStatus, BlockDriverOps, BlockProperty, CheckResult, CreateOptions, ImageInfo,
    FIX_ERRORS, FIX_LEAKS, NO_FIX, SECTOR_SIZE,
};
use machine_manager::config::{memory_unit_conversion, DiskFormat};
use util::{
    aio::{buffer_is_zero, Aio, AioEngine, Iovec, WriteZeroesState},
    file::{lock_file, open_file, unlock_file},
};

enum SnapshotOperation {
    Create,
    Delete,
    Apply,
    List,
    Rename,
}

pub struct ImageFile {
    file: Arc<File>,
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
            file: Arc::new(file),
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
            Some(DiskFormat::Raw) => DiskFormat::Raw,
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

fn image_do_create(create_options: &CreateOptions, print_info: bool) -> Result<()> {
    let path = create_options.path.clone();
    let file = Arc::new(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CREAT | libc::O_TRUNC)
            .mode(0o660)
            .open(path)?,
    );

    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None)?;

    let mut driver: Box<dyn BlockDriverOps<()>> = match create_options.conf.format {
        DiskFormat::Raw => Box::new(RawDriver::new(file, aio, create_options.conf.clone())),
        DiskFormat::Qcow2 => Box::new(Qcow2Driver::new(file, aio, create_options.conf.clone())?),
    };
    let image_info = driver.as_mut().create_image(create_options)?;

    if print_info {
        println!("Stratovirt-img: {}", image_info);
    }

    Ok(())
}

pub(crate) fn image_create(args: Vec<String>) -> Result<()> {
    let mut create_options = CreateOptions::default();
    let mut arg_parser = ArgsParse::create(vec!["h", "help"], vec!["f"], vec!["o"]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    let fmt = arg_parser.opt_str("f").unwrap_or_else(|| "raw".to_string());
    create_options.conf.format = DiskFormat::from_str(&fmt)?;

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

    image_do_create(&create_options, true)?;

    Ok(())
}

pub(crate) fn image_info(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        bail!("Not enough arguments");
    }
    let mut arg_parser = ArgsParse::create(vec!["h", "help"], vec![], vec![]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    // Parse the image path.
    let len = arg_parser.free.len();
    let img_path = match len {
        0 => bail!("Image path is needed"),
        1 => arg_parser.free[0].clone(),
        _ => {
            let param = arg_parser.free[1].clone();
            bail!("Unexpected argument: {}", param);
        }
    };

    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None)?;
    let image_file = ImageFile::create(&img_path, false)?;
    let detect_fmt = image_file.detect_img_format()?;
    let conf = BlockProperty {
        format: detect_fmt,
        ..Default::default()
    };
    let mut driver: Box<dyn BlockDriverOps<()>> = match detect_fmt {
        DiskFormat::Raw => Box::new(RawDriver::new(image_file.file.clone(), aio, conf)),
        DiskFormat::Qcow2 => {
            let mut qocw2_driver = Qcow2Driver::new(image_file.file.clone(), aio, conf.clone())?;
            qocw2_driver.load_metadata(conf)?;
            Box::new(qocw2_driver)
        }
    };

    let mut image_info = ImageInfo {
        path: img_path,
        ..Default::default()
    };
    driver.query_image(&mut image_info)?;
    print!("{}", image_info);
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
        if kind == *"leaks" {
            fix |= FIX_LEAKS;
        } else if kind == *"all" {
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
    let file = image_file.file.clone();
    match real_fmt {
        DiskFormat::Raw => {
            bail!("stratovirt-img: This image format does not support checks");
        }
        DiskFormat::Qcow2 => {
            let conf = BlockProperty {
                format: DiskFormat::Qcow2,
                ..Default::default()
            };
            let mut qcow2_driver = create_qcow2_driver_for_check(file, conf)?;
            let ret = qcow2_driver.check_image(&mut check_res, quite, fix);
            let check_message = check_res.collect_check_message();
            print!("{}", check_message);
            ret
        }
    }
}

pub(crate) fn image_resize(mut args: Vec<String>) -> Result<()> {
    if args.len() < 2 {
        bail!("Not enough arguments");
    }
    let size_str = args.pop().unwrap();
    let mut arg_parser = ArgsParse::create(vec!["h", "help"], vec!["f"], vec![]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    // Parse the image path.
    let len = arg_parser.free.len();
    let img_path = match len {
        0 => bail!("Expecting image file name and size"),
        1 => arg_parser.free[0].clone(),
        _ => bail!("Unexpected argument: {}", arg_parser.free[1]),
    };

    // If the disk format is specified by user, it will be used firstly,
    // or it will be detected.
    let mut disk_fmt = None;
    if let Some(fmt) = arg_parser.opt_str("f") {
        disk_fmt = Some(DiskFormat::from_str(&fmt)?);
    };

    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None)?;
    let image_file = ImageFile::create(&img_path, false)?;
    let detect_fmt = image_file.detect_img_format()?;
    let real_fmt = image_file.check_img_format(disk_fmt, detect_fmt)?;
    let conf = BlockProperty {
        format: real_fmt,
        ..Default::default()
    };
    let mut driver: Box<dyn BlockDriverOps<()>> = match real_fmt {
        DiskFormat::Raw => Box::new(RawDriver::new(image_file.file.clone(), aio, conf)),
        DiskFormat::Qcow2 => {
            let mut qocw2_driver = Qcow2Driver::new(image_file.file.clone(), aio, conf.clone())?;
            qocw2_driver.load_metadata(conf)?;
            Box::new(qocw2_driver)
        }
    };

    let old_size = driver.disk_size()?;
    // Only expansion is supported currently.
    let new_size = if size_str.starts_with('+') {
        let size = memory_unit_conversion(&size_str, 1)?;
        old_size
            .checked_add(size)
            .ok_or_else(|| anyhow!("Disk size is too large for chosen offset"))?
    } else if size_str.starts_with('-') {
        bail!("The shrink operation is not supported");
    } else {
        let new_size = memory_unit_conversion(&size_str, 1)?;
        if new_size < old_size {
            bail!("The shrink operation is not supported");
        }
        new_size
    };

    driver.resize(new_size)?;
    println!("Image resized.");

    Ok(())
}

// Default 4k(8 sectors) for sparse detection.
const DEFAULT_SPARSE_SIZE: u8 = 8;
// Default 2M buffer size for convert.
const DEFAULT_BUF_SIZE: usize = 1 << 21;

#[derive(Debug, PartialEq, Eq)]
enum ConvertDataStatus {
    Zero = 0,
    Data,
}

impl ConvertDataStatus {
    fn from_bool(is_zero: bool) -> Self {
        if is_zero {
            ConvertDataStatus::Zero
        } else {
            ConvertDataStatus::Data
        }
    }
}

// Describe a continuous address segment which has the same allocation status when converting.
#[derive(PartialEq, Eq)]
struct ConvertSeg {
    start: u64,
    len: u64,
    status: ConvertDataStatus,
}

impl ConvertSeg {
    fn new(start: u64, len: u64, is_zero: bool) -> Self {
        Self {
            start,
            len,
            status: ConvertDataStatus::from_bool(is_zero),
        }
    }
}

fn convert_do_read(
    driver: &mut dyn BlockDriverOps<()>,
    buf: &mut [u8],
    len: u64,
    offset: u64,
) -> Result<()> {
    let iov = vec![Iovec {
        iov_base: buf.as_ptr() as u64,
        iov_len: len,
    }];
    driver.read_vectored(iov, offset as usize, ())
}

fn convert_do_seg_write(
    driver: &mut dyn BlockDriverOps<()>,
    buf: &mut [u8],
    data_seg: &ConvertSeg,
) -> Result<()> {
    match data_seg.status {
        ConvertDataStatus::Data => {
            let iov = vec![Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: data_seg.len,
            }];
            driver.write_vectored(iov, data_seg.start as usize, ())
        }
        ConvertDataStatus::Zero => {
            // The output image is a newly created sparse file, which defaults to all holes.
            // Sequential writing does not require writing zeroes again. Do nothing.
            Ok(())
        }
    }
}

fn convert_do_write(
    driver: &mut dyn BlockDriverOps<()>,
    buf: &mut [u8],
    buf_len: u64,
    offset: u64,
    sparse_size: u64,
) -> Result<()> {
    let mut convert_seg = ConvertSeg::new(offset, 0, true);
    let mut first_check = true;

    let mut pos = 0_u64;
    while pos < buf_len {
        let detect_size = std::cmp::min(sparse_size, buf_len - pos);
        let detect_buf = &buf[pos as usize..(pos + detect_size) as usize];

        // SAFETY: Buffer is a local `Vec` variable in `image_convert`, its base and len are both valid values.
        let local_zero = unsafe { buffer_is_zero(detect_buf.as_ptr() as u64, detect_size) };

        if first_check {
            convert_seg.status = ConvertDataStatus::from_bool(local_zero);
            first_check = false;
        }

        if ConvertDataStatus::from_bool(local_zero) != convert_seg.status {
            convert_do_seg_write(
                driver,
                &mut buf[(convert_seg.start - offset) as usize..pos as usize],
                &convert_seg,
            )?;

            convert_seg.status = ConvertDataStatus::from_bool(local_zero);
            convert_seg.start = offset + pos;
            convert_seg.len = detect_size;

            pos += detect_size;
            continue;
        }

        convert_seg.len += detect_size;
        pos += detect_size;
    }

    if !first_check {
        convert_do_seg_write(
            driver,
            &mut buf[(convert_seg.start - offset) as usize..pos as usize],
            &convert_seg,
        )?;
    }
    Ok(())
}

fn image_create_blockdriver(
    file: Arc<File>,
    format: DiskFormat,
) -> Result<Box<dyn BlockDriverOps<()>>> {
    let conf = BlockProperty {
        format,
        ..Default::default()
    };
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();

    match format {
        DiskFormat::Qcow2 => {
            let mut qcow2_driver = Qcow2Driver::new(file, aio, conf.clone())?;
            qcow2_driver.load_metadata(conf)?;
            Ok(Box::new(qcow2_driver))
        }
        DiskFormat::Raw => Ok(Box::new(RawDriver::new(file, aio, conf))),
    }
}

pub(crate) fn image_convert(args: Vec<String>) -> Result<()> {
    let mut arg_parser = ArgsParse::create(vec!["h", "help"], vec!["f", "O", "S"], vec![]);
    arg_parser.parse(args)?;

    if arg_parser.opt_present("h") || arg_parser.opt_present("help") {
        print_help();
        return Ok(());
    }

    // Parse the image path. Command line should have 2 args at the end(input filename and output filename).
    if arg_parser.free.len() != 2 {
        bail!("Invalid input/output filenames.");
    }
    let input_path = arg_parser.free[0].clone();
    let output_path = arg_parser.free[1].clone();

    // Check output image filename: to avoid accidentally deleting existing files,
    // it is prohibited to use the name of an existing file as the output image name.
    if std::path::Path::new(&output_path).exists() {
        bail!(
            "The file {} already exists, please use a different name.",
            output_path
        );
    }

    // Parse the input image format. If not set, it will detect the corresponding image file to determine the image format.
    let input_fmt_str = arg_parser.opt_str("f").unwrap_or_default();
    let input_image_file = ImageFile::create(&input_path, true)?;
    let detect_input_fmt = input_image_file.detect_img_format()?;
    if !input_fmt_str.is_empty() {
        let input_fmt = DiskFormat::from_str(&input_fmt_str)?;
        if detect_input_fmt != input_fmt {
            bail!("'{}' is not a {} file.", input_path, input_fmt_str);
        }
    }

    // Parse the output image format. Default is "raw".
    let output_fmt_str = arg_parser.opt_str("O").unwrap_or_else(|| "raw".to_string());
    let output_fmt = DiskFormat::from_str(&output_fmt_str)?;

    // Parse the min sparse.
    let min_sparse_str = arg_parser
        .opt_str("S")
        .unwrap_or_else(|| DEFAULT_SPARSE_SIZE.to_string());
    let min_sparse = min_sparse_str.parse::<u64>()? * SECTOR_SIZE;

    // Create input image driver.
    let mut input_driver_box =
        image_create_blockdriver(input_image_file.file.clone(), detect_input_fmt)?;
    let input_driver = input_driver_box.as_mut();
    let size = input_driver.disk_size()?;

    // Create new output file.
    let mut create_options = CreateOptions {
        path: output_path.clone(),
        img_size: size,
        ..Default::default()
    };
    create_options.conf.format = output_fmt;
    image_do_create(&create_options, false)?;

    // Create output image driver.
    let output_image_file = ImageFile::create(&output_path, false)?;
    let mut output_driver_box =
        image_create_blockdriver(output_image_file.file.clone(), output_fmt)?;
    let output_driver = output_driver_box.as_mut();

    // Convert from src image to dst image.
    let mut offset = 0;
    let mut buf = vec![0_u8; DEFAULT_BUF_SIZE];
    while offset < size {
        // Get address segments with the same allocation status.
        let (status, len) = input_driver.get_address_alloc_status(offset as u64, size - offset)?;
        match status {
            // `DATA` means that these data should be read from the src image and be written to the dst image.
            BlockAllocStatus::DATA => {
                let mut need_convert = len;
                let mut cur_offset = offset;
                while need_convert > 0 {
                    let data_len = std::cmp::min(DEFAULT_BUF_SIZE as u64, need_convert);
                    convert_do_read(input_driver, &mut buf, data_len, cur_offset)?;
                    convert_do_write(output_driver, &mut buf, data_len, cur_offset, min_sparse)?;
                    cur_offset += data_len;
                    need_convert -= data_len;
                }
            }
            // `ZERO` means that these data can be treated as holes.
            BlockAllocStatus::ZERO => {
                // The output image is a newly created sparse file, which defaults to all holes.
                // Sequential writing does not require writing zeroes again. Do nothing.
            }
        };

        offset += len;
    }

    Ok(())
}

pub(crate) fn image_snapshot(args: Vec<String>) -> Result<()> {
    let mut arg_parser = ArgsParse::create(
        vec!["l", "h", "help", "r"],
        vec!["f", "c", "d", "a"],
        vec![],
    );
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

    let len = arg_parser.free.len();

    // Rename snapshot name.
    let mut old_snapshot_name = String::from("");
    let mut new_snapshot_name = String::from("");
    if arg_parser.opt_present("r") {
        if len != 3 {
            bail!("Invalid args number.");
        }
        snapshot_operation = Some(SnapshotOperation::Rename);
        old_snapshot_name = arg_parser.free[0].clone();
        new_snapshot_name = arg_parser.free[1].clone();
    }

    // Parse image path.
    let path = match len {
        0 => bail!("Image snapshot requires path"),
        1 => arg_parser.free[0].clone(),
        3 => arg_parser.free[2].clone(),
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
    let qcow2_conf = BlockProperty {
        format: DiskFormat::Qcow2,
        discard: true,
        write_zeroes: WriteZeroesState::Unmap,
        ..Default::default()
    };

    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
    let mut qcow2_driver = Qcow2Driver::new(image_file.file.clone(), aio, qcow2_conf.clone())?;
    qcow2_driver.load_metadata(qcow2_conf)?;

    match snapshot_operation {
        Some(SnapshotOperation::Create) => {
            qcow2_driver.create_snapshot(snapshot_name, 0)?;
        }
        Some(SnapshotOperation::List) => {
            let info = qcow2_driver.list_snapshots();
            println!("Snapshot list:");
            print!("{}", info);
        }
        Some(SnapshotOperation::Delete) => {
            qcow2_driver.delete_snapshot(snapshot_name)?;
        }
        Some(SnapshotOperation::Apply) => {
            qcow2_driver.apply_snapshot(snapshot_name)?;
        }
        Some(SnapshotOperation::Rename) => {
            qcow2_driver.rename_snapshot(old_snapshot_name, new_snapshot_name)?;
        }
        None => return Ok(()),
    };

    Ok(())
}

pub(crate) fn create_qcow2_driver_for_check(
    file: Arc<File>,
    conf: BlockProperty,
) -> Result<Qcow2Driver<()>> {
    let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
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

pub(crate) fn print_version() {
    println!(
        "{} version {}\
        Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.",
        BINARY_NAME,
        util::VERSION,
    )
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
info filename
check [-r [leaks | all]] [-no_print_error] [-f fmt] filename
resize [-f fmt] filename [+]size
snapshot [-l | -a snapshot | -c snapshot | -d snapshot | -r old_snapshot_name new_snapshot_name] filename
convert [-f input_fmt | -O output_fmt | -S sparse_size ] input_filename output_filename

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
 '-r' change the name of a snapshot

Parameters to convert subcommand:
 '-f fmt' is input image format.
 '-O output_fmt' is output image format.
 '-S sparse_size' is the consecutive number of bytes that must contain only zeroes to create a sparse image during conversion. Unit: sector(512 bytes). Default is 8.
 'input_filename' is the name of the input file using *input_fmt* image format.
 'output_filename' is the name of the output file using *output_fmt* image format.
"#,
    );
}

#[cfg(test)]
mod test {
    use std::{
        fs::remove_file,
        io::{Seek, SeekFrom},
    };

    use super::*;
    use block_backend::qcow2::{
        refcount::Qcow2DiscardType, HostRange, ENTRY_SIZE, L2_TABLE_OFFSET_MASK,
        QCOW2_OFFSET_COPIED,
    };
    use util::aio::Iovec;

    const K: u64 = 1024;
    const M: u64 = 1024 * 1024;
    const G: u64 = 1024 * 1024 * 1024;

    #[allow(dead_code)]
    pub struct TestQcow2Image {
        pub header: QcowHeader,
        pub cluster_bits: u64,
        pub path: String,
        pub file: Arc<File>,
    }

    impl TestQcow2Image {
        pub fn create(cluster_bits: u64, refcount_bits: u64, path: &str, img_size: &str) -> Self {
            let cluster_size = 1 << cluster_bits;
            // Create image.
            let create_str = format!(
                "-f qcow2 -o cluster_size={} -o refcount_bits={} {} {}",
                cluster_size, refcount_bits, path, img_size,
            );
            let create_args: Vec<String> =
                create_str.split(' ').map(|str| str.to_string()).collect();
            assert!(image_create(create_args).is_ok());

            // Read header.
            let file = open_file(path, false, false).unwrap();
            let mut buf = vec![0; QcowHeader::len()];
            assert!(file.read_at(&mut buf, 0).is_ok());
            let header = QcowHeader::from_vec(&buf).unwrap();
            assert_eq!(u64::from(header.cluster_bits), cluster_bits);

            Self {
                header,
                cluster_bits,
                path: path.to_string(),
                file: Arc::new(file),
            }
        }

        fn create_driver(&self) -> Qcow2Driver<()> {
            let conf = BlockProperty {
                format: DiskFormat::Qcow2,
                ..Default::default()
            };
            let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
            let mut qcow2_driver = Qcow2Driver::new(self.file.clone(), aio, conf.clone()).unwrap();
            qcow2_driver.load_metadata(conf).unwrap();
            qcow2_driver
        }

        fn create_driver_for_check(&self) -> Qcow2Driver<()> {
            let file = self.file.clone();
            let conf = BlockProperty {
                format: DiskFormat::Qcow2,
                ..Default::default()
            };

            create_qcow2_driver_for_check(file, conf).unwrap()
        }

        fn read_data(&self, guest_offset: u64, buf: &Vec<u8>) -> Result<()> {
            let mut qocw2_driver = self.create_driver();
            qocw2_driver.read_vectored(
                vec![Iovec {
                    iov_base: buf.as_ptr() as u64,
                    iov_len: buf.len() as u64,
                }],
                guest_offset as usize,
                (),
            )
        }

        fn write_data(&self, guest_offset: u64, buf: &Vec<u8>) -> Result<()> {
            let mut qocw2_driver = self.create_driver();
            qocw2_driver.write_vectored(
                vec![Iovec {
                    iov_base: buf.as_ptr() as u64,
                    iov_len: buf.len() as u64,
                }],
                guest_offset as usize,
                (),
            )
        }

        fn check_image(&self, quite: bool, fix: u64) -> bool {
            let mut res = CheckResult::default();
            let mut qcow2_driver = self.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());

            res.err_num == 0
                && res.leaks == 0
                && res.leaks_fixed == 0
                && res.corruptions == 0
                && res.corruptions_fixed == 0
        }

        fn file_len(&mut self) -> u64 {
            let file_len = self.file.as_ref().seek(SeekFrom::End(0)).unwrap();
            file_len
        }

        fn clear_reftable(&mut self) {
            self.header.refcount_table_clusters = 0;
            self.header.refcount_table_offset = 0;

            let mut buf = self.header.to_vec();
            assert!(self.file.write_at(&mut buf, 0).is_ok());
        }
    }

    impl Drop for TestQcow2Image {
        fn drop(&mut self) {
            assert!(remove_file(self.path.clone()).is_ok());
        }
    }

    struct TestRawImage {
        path: String,
    }

    impl TestRawImage {
        fn create(path: String, img_size: String) -> Self {
            let create_str = format!("-f raw {} {}", path, img_size);
            let create_args: Vec<String> =
                create_str.split(' ').map(|str| str.to_string()).collect();
            assert!(image_create(create_args).is_ok());

            Self { path }
        }

        fn create_driver(&mut self) -> RawDriver<()> {
            let conf = BlockProperty::default();

            let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();

            let file = open_file(&self.path, false, false).unwrap();

            RawDriver::new(Arc::new(file), aio, conf)
        }
    }

    impl Drop for TestRawImage {
        fn drop(&mut self) {
            assert!(remove_file(self.path.clone()).is_ok());
        }
    }

    fn vec_is_fill_with(vec: &Vec<u8>, num: u8) -> bool {
        for elem in vec {
            if elem != &num {
                return false;
            }
        }
        true
    }

    fn image_write(
        driver: &mut dyn BlockDriverOps<()>,
        offset: usize,
        buf: &Vec<u8>,
    ) -> Result<()> {
        driver.write_vectored(
            vec![Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            }],
            offset,
            (),
        )
    }

    fn image_read(driver: &mut dyn BlockDriverOps<()>, offset: usize, buf: &Vec<u8>) -> Result<()> {
        driver.read_vectored(
            vec![Iovec {
                iov_base: buf.as_ptr() as u64,
                iov_len: buf.len() as u64,
            }],
            offset,
            (),
        )
    }

    /// Test the function of creating image.
    /// TestStep:
    ///   1. Create image with different args.
    /// Expect:
    ///   1. If the format of args is invalid, creation failed.
    #[test]
    fn test_args_parse_of_imgae_create() {
        let path = "/tmp/test_args_parse_of_imgae_create.qcow2";
        let test_case = vec![
            (
                "-f qcow2 -o cluster_size=65536 -o refcount_bits=16 img_path +1G",
                true,
            ),
            (
                "-f qcow2 -o cluster_size=65536 refcount_bits=16 img_path +1G",
                false,
            ),
            ("-h", true),
            ("-f raw img_path +1G", true),
            ("-f raw img_path", false),
            ("-f raw -o refcount_bits=16 img_path +1G", false),
            ("-f raw -o cluster_size=65536 img_path +1G", false),
            ("-f invalid_fmt img_path", false),
            ("img_path +1G", true),
            ("img_path 1G", true),
            ("-f qcow2 -o cluster_size=256 img_path +1G", false),
            ("-f qcow2 img_path +1G", true),
            ("-f qcow2 img_path +0G", false),
            ("-f qcow2 -b backing_file img_path +1G", false),
            ("-f qcow2 img_path", false),
            ("-f qcow2 +1G", false),
            ("-f qcow2 img_path +1G extra_params", false),
            ("-f qcow2 -o cluster_size=65536 img_path +1G", true),
            ("-f qcow2 -o refcount_bits=16 img_path +1G", true),
            ("-f qcow2 -o refcount_bits=128 img_path +1G", false),
            ("-f qcow2 -o refcount_bits=63 img_path +1G", false),
            ("-f qcow2 -o cluster_size img_path +1G", false),
            ("-f qcow2 -o cluster_size=65536 img_path", false),
            ("-f qcow2 -o invalid_param img_path", false),
            ("-f qcow2 -f raw img_path +1G", true),
        ];

        for case in test_case {
            let create_str = case.0.replace("img_path", path);
            println!("Create options: {}", create_str);
            let create_args: Vec<String> =
                create_str.split(' ').map(|str| str.to_string()).collect();

            if case.1 {
                assert!(image_create(create_args).is_ok());
            } else {
                assert!(image_create(create_args).is_err());
            }
        }

        assert!(remove_file(path).is_ok());
    }

    /// Test the function of query image.
    /// TestStep:
    ///   2. Query image info with different type.
    /// Expect:
    ///   1. Ihe invalid args will result in failure.
    #[test]
    fn test_args_parse_of_image_info() {
        let path = "/tmp/test_args_parse_of_image_info.qcow2";
        let test_case = vec![
            ("img_path", true),
            ("-f qcow2", false),
            ("invalid_args", false),
            ("img_path +1G", false),
            ("-h", true),
            ("--help", true),
        ];

        for case in test_case {
            let cmd_str = case.0.replace("img_path", path);
            let args: Vec<String> = cmd_str.split(' ').map(|str| str.to_string()).collect();

            // Query image info with type of qcow2.
            assert!(image_create(vec![
                "-f".to_string(),
                "qcow2".to_string(),
                path.to_string(),
                "+10M".to_string()
            ])
            .is_ok());
            assert_eq!(image_info(args.clone()).is_ok(), case.1);

            // Query image info with type of raw.
            assert!(image_create(vec![
                "-f".to_string(),
                "raw".to_string(),
                path.to_string(),
                "+10M".to_string()
            ])
            .is_ok());
            assert_eq!(image_info(args).is_ok(), case.1);
        }

        assert!(remove_file(path).is_ok());
    }

    /// Test the function of creating image.
    /// TestStep:
    ///   1. Create image with different cluster bits, image size and refcount bits.
    /// Expect:
    ///   1. The header of new image meets expectations.
    ///   2. No errors were found during the image check.
    #[test]
    fn test_create_qcow2_img() {
        let path = "/tmp/test_create_qcow2_img.qcow2";
        // (cluster bits, image size in str, image size in number)
        let test_case = [
            (9, "+1G", G),
            (9, "+128G", 128 * G),
            (10, "+20M", 20 * M),
            (16, "+50M", 50 * M),
            (16, "1024M", G),
            (16, "+128G", 128 * G),
        ];
        // Only refcount bit=16 is supported currently.
        let refcount_bits = 16;

        for case in test_case {
            let cluster_bits = case.0;
            let cluster_size = 1 << cluster_bits;
            let image_size = case.2;
            let mut test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, case.1);

            // Check header.
            let file_len = test_image.file_len();
            let l1_size = test_image.header.l1_size;
            let reftable_clusters = test_image.header.refcount_table_clusters;
            let reftable_size = u64::from(reftable_clusters) * cluster_size / ENTRY_SIZE;
            let refblock_size = cluster_size / (refcount_bits / 8);

            assert_ne!(l1_size, 0);
            assert_ne!(reftable_clusters, 0);
            assert!(u64::from(l1_size) * cluster_size * cluster_size / ENTRY_SIZE >= image_size);
            assert!(reftable_size * refblock_size * cluster_size >= file_len);
            assert_eq!(u64::from(test_image.header.cluster_bits), cluster_bits);
            assert_eq!(test_image.header.size, image_size);

            // Check refcount.
            assert!(test_image.check_image(false, 0));
        }
    }

    /// Test the function of detect image format.
    /// TestStep:
    ///   1. Create image with different disk format.
    ///   2. Detect the format of disk.
    ///   3. Apply image check, and specify the format of raw.
    /// Expect:
    ///   1. The detected disk format is correct.
    ///   2. Image check returned error, as raw format is not supported to check.
    #[test]
    fn test_detect_image_format() {
        let path = "/tmp/test_detect_image_format.qcow2";
        let test_case = [
            ("-f raw path +1G", DiskFormat::Raw),
            ("-f qcow2 path +1G", DiskFormat::Qcow2),
        ];
        let check_str = format!("-f raw {}", path);
        let check_args: Vec<String> = check_str.split(' ').map(|str| str.to_string()).collect();

        for case in test_case {
            let create_str = case.0.replace("path", path);
            println!("stratovirt-img {}", create_str);
            let create_args: Vec<String> =
                create_str.split(' ').map(|str| str.to_string()).collect();
            assert!(image_create(create_args).is_ok());

            let image_file = ImageFile::create(path, false).unwrap();
            assert_eq!(image_file.detect_img_format().unwrap(), case.1);

            assert!(image_check(check_args.clone()).is_err());
        }

        assert!(remove_file(path).is_ok());
    }

    /// Test the function of check image.
    /// TestStep:
    ///   1. Check image with different args.
    /// Expect:
    ///   1. If the args is invalid, check operation failed.
    #[test]
    fn test_args_parse_of_image_check() {
        let path = "/tmp/test_args_parse_of_image_check";
        let create_str = "-f disk_fmt img_path +1G".replace("img_path", path);
        let test_case = [
            ("qcow2", "-f qcow2 img_path", true),
            ("qcow2", "-f qcow2", false),
            ("qcow2", "-r leaks -f qcow2 img_path", true),
            ("qcow2", "-r all -f qcow2 img_path", true),
            ("qcow2", "-r invalid_param -f qcow2 img_path", false),
            ("qcow2", "-r -f qcow2 img_path", false),
            ("qcow2", "-f raw img_path", false),
            ("qcow2", "img_path", true),
            ("qcow2", "-f qcow2 img_path extra_params", false),
            ("qcow2", "-f raw -f qcow2 img_path", true),
            ("qcow2", "-f qcow2 -f raw img_path", false),
            ("raw", "-f qcow2 img_path", false),
        ];

        for case in test_case {
            let create_string = create_str.replace("disk_fmt", case.0);
            let create_args: Vec<String> = create_string
                .split(' ')
                .map(|str| str.to_string())
                .collect();
            println!("Create args: {}", create_string);
            assert!(image_create(create_args.clone()).is_ok());

            let check_str = case.1.replace("img_path", path);
            let check_args: Vec<String> = check_str.split(' ').map(|str| str.to_string()).collect();
            println!("Check args: {}", check_str);

            if case.2 {
                assert!(image_check(check_args).is_ok());
            } else {
                assert!(image_check(check_args).is_err());
            }

            assert!(remove_file(path).is_ok());
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create image with different image size.
    ///   2. Alloc a a new cluster, and create a snapshot, so the real refcount of this cluster is 2.
    ///   3. Decrease the refcount of this cluster in refcount block
    /// Expect:
    ///   1. The corruptions cluster can be found and fixed during image check.
    #[test]
    fn test_check_refcount_corruptions() {
        let path = "/tmp/test_check_refcount_corruptions.qcow2";
        // (cluster bits, image size in str, image size in number)
        let test_case = [
            (16, "+50M", 50 * M),
            (16, "1024M", G),
            (16, "+128G", 128 * G),
        ];
        // Only refcount bit=16 is supported currently.
        let refcount_bits = 16;

        for case in test_case {
            let cluster_bits = case.0;
            let cluster_size = 1 << cluster_bits;
            let test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, case.1);
            let mut qcow2_driver = test_image.create_driver();

            // 1. Alloc a cluster.
            // 2. Create a snapshot on the image, so the refcount of this cluster is 2.
            // 3. Decrease the refcount of this cluster.
            let buf = vec![1_u8; cluster_size as usize];
            assert!(qcow2_driver
                .write_vectored(
                    vec![Iovec {
                        iov_base: buf.as_ptr() as u64,
                        iov_len: buf.len() as u64,
                    }],
                    0,
                    (),
                )
                .is_ok());
            // Get hostoffset of 0
            let mut offset = 0;
            match qcow2_driver.host_offset_for_read(0, cluster_size).unwrap() {
                HostRange::DataNotInit(_) => assert!(false),
                HostRange::DataAddress(addr, bytes) => {
                    assert!(bytes >= cluster_size);
                    offset = addr;
                }
            };
            assert_ne!(offset, 0);
            assert!(qcow2_driver
                .create_snapshot("test_refcount".to_string(), 0)
                .is_ok());
            qcow2_driver
                .refcount
                .update_refcount(offset, 1, -1, true, &Qcow2DiscardType::Never)
                .unwrap();
            drop(qcow2_driver);

            // Check refcount.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver
                .check_image(&mut res, false, FIX_ERRORS)
                .is_ok());
            assert_eq!(res.corruptions_fixed, 1);
            assert_eq!(res.corruptions, 0);
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create image with different image size.
    ///   2. Alloc a a new cluster, the real reference of this cluster is 1.
    ///   3. Update the reference of this cluster to 10.
    /// Expect:
    ///   1. The leaks cluster can be found and fixed by image check.
    #[test]
    fn test_check_refcount_leaks() {
        let path = "/tmp/test_check_refcount_leaks.qcow2";
        // (cluster bits, image size in str, image size in number, number clusters)
        let test_case = [
            (16, "+50M", 50 * M, 1),
            (16, "1024M", G, 1),
            (16, "1024M", G, 11),
            (16, "+128G", 128 * G, 1),
            (16, "+128G", 128 * G, 37),
        ];
        // Only refcount bit=16 is supported currently.
        let refcount_bits = 16;

        for case in test_case {
            let cluster_bits = case.0;
            let test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, case.1);
            let mut qcow2_driver = test_image.create_driver();

            // Alloc cluster, and update the refcount to 10.
            let nb_clusters = case.3 as u64;
            let offset = qcow2_driver.alloc_cluster(nb_clusters, true).unwrap();
            qcow2_driver
                .refcount
                .update_refcount(offset, nb_clusters, 9, true, &Qcow2DiscardType::Never)
                .unwrap();
            drop(qcow2_driver);

            // Check refcount.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, false, FIX_LEAKS).is_ok());
            assert_eq!(res.leaks, 0);
            assert_eq!(res.leaks_fixed, nb_clusters as i32);
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create a new image.
    ///   2. Alloc a new cluster, the real reference of this cluster is 1,
    ///      the l1 entry of this cluster identification with oflag of copied.
    ///   3. Clean the oflag of copied in l1 entry of this cluster, and apply image check.
    /// Expect:
    ///   1. The wrong of oflag in l1 entry can be found and fixed.
    #[test]
    fn test_check_remove_oflag_copied_in_l1_entry() {
        let path = "/tmp/test_check_remove_oflag_copied_in_l1_entry.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let image_size = 1 << 30;
        let image_size_str = "+1G";

        let test_case = vec![
            // (fix, guest_offset, corruptions, corruptions_fixed)
            (0, 0, 1, 0),
            (FIX_LEAKS, 0, 0, 1),
            (FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, cluster_size * 10, 0, 1),
            (FIX_LEAKS, cluster_size * 10, 0, 1),
            (FIX_ERRORS, cluster_size * 10, 0, 1),
            (
                FIX_LEAKS | FIX_ERRORS,
                cluster_size + cluster_size / 2,
                0,
                1,
            ),
            (FIX_LEAKS, image_size - cluster_size, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, image_size - cluster_size, 0, 1),
        ];

        // Test different guest offset
        for case in test_case {
            let quite = false;
            let fix = case.0;
            let guest_offset = case.1;
            let expect_corruptions = case.2;
            let expect_corruptions_fixed = case.3;
            let test_image =
                TestQcow2Image::create(cluster_bits, refcount_bits, path, image_size_str);
            // Write data to guest offset.
            let buf = vec![1_u8; cluster_size as usize];
            assert!(test_image.write_data(guest_offset, &buf).is_ok());

            // Modify the oflag of l1 entry of cluster 0.
            let mut qcow2_driver = test_image.create_driver();
            let l1_idx = qcow2_driver.table.get_l1_table_index(guest_offset);
            qcow2_driver.table.l1_table[l1_idx as usize] &= !QCOW2_OFFSET_COPIED;
            assert!(qcow2_driver.table.save_l1_table().is_ok());
            drop(qcow2_driver);

            // Check and fix error copied flag in l1 table.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            assert_eq!(res.corruptions, expect_corruptions);
            assert_eq!(res.corruptions_fixed, expect_corruptions_fixed);
            let message = res.collect_check_message();
            println!("{}", message);
            drop(qcow2_driver);

            // The oflag error in l1 table has been fixed.
            if expect_corruptions_fixed != 0 {
                let qcow2_driver = test_image.create_driver();
                assert_ne!(
                    qcow2_driver.table.l1_table[l1_idx as usize] & QCOW2_OFFSET_COPIED,
                    0
                );
                drop(qcow2_driver);
            }
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create a new image.
    ///   2. Alloc a a new cluster, the real reference of this cluster is 1,
    ///      the l2 entry of this cluster identification with oflag of copied.
    ///   3. Clean the oflag of copied in l2 entry of this cluster, and apply image check.
    /// Expect:
    ///   2. The wrong of oflag in l2 entry can be found and fixed.
    #[test]
    fn test_check_remove_oflag_copied_in_l2_entry() {
        let path = "/tmp/test_check_remove_oflag_copied_in_l2_entry.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let image_size = 1 << 30;
        let image_size_str = "+1G";

        let test_case = vec![
            // (fix, guest_offset, corruptions, corruptions_fixed)
            (0, 0, 1, 0),
            (FIX_LEAKS, 0, 0, 1),
            (FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, cluster_size * 10, 0, 1),
            (FIX_LEAKS, cluster_size * 10, 0, 1),
            (FIX_ERRORS, cluster_size * 10, 0, 1),
            (
                FIX_LEAKS | FIX_ERRORS,
                cluster_size + cluster_size / 2,
                0,
                1,
            ),
            (FIX_LEAKS, image_size - cluster_size, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, image_size - cluster_size, 0, 1),
        ];

        // Test different guest offset
        for case in test_case {
            let quite = false;
            let fix = case.0;
            let guest_offset = case.1;
            let expect_corruptions = case.2;
            let expect_corruptions_fixed = case.3;
            let test_image =
                TestQcow2Image::create(cluster_bits, refcount_bits, path, image_size_str);
            // Write data to guest offset.
            let buf = vec![1_u8; cluster_size as usize];
            assert!(test_image.write_data(guest_offset, &buf).is_ok());

            // Modify the oflag of l2 entry.
            let mut qcow2_driver = test_image.create_driver();
            let l2_idx = qcow2_driver.table.get_l2_table_index(guest_offset) as usize;
            let cache_entry = qcow2_driver.get_table_cluster(guest_offset).unwrap();
            let mut l2_entry = cache_entry.borrow_mut().get_entry_map(l2_idx).unwrap();
            l2_entry &= !QCOW2_OFFSET_COPIED;
            assert!(cache_entry
                .borrow_mut()
                .set_entry_map(l2_idx, l2_entry)
                .is_ok());
            qcow2_driver
                .table
                .l2_table_cache
                .add_dirty_table(cache_entry);
            drop(qcow2_driver);

            // Check and fix copied flag in l2 table.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            assert_eq!(res.corruptions, expect_corruptions);
            assert_eq!(res.corruptions_fixed, expect_corruptions_fixed);
            let message = res.collect_check_message();
            println!("{}", message);
            drop(qcow2_driver);

            // The oflag error in l2 table has been fixed.
            if expect_corruptions_fixed != 0 {
                let mut qcow2_driver = test_image.create_driver();
                let cache_entry = qcow2_driver.get_table_cluster(guest_offset).unwrap();
                let l2_entry = cache_entry.borrow_mut().get_entry_map(l2_idx).unwrap();
                assert_ne!(l2_entry & QCOW2_OFFSET_COPIED, 0);
                drop(qcow2_driver);
            }
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create a new image.
    ///   2. Alloc a a new cluster, and create a new snapshot. So the oflag of copied in l1 entry will be cleared,
    ///      which means writing to this cluster will result in copy on write.
    ///   3. Set the oflag of copied in l1 entry of this cluster, and apply image check.
    /// Expect:
    ///   1. The wrong of oflag in l1 entry can be found and fixed.
    #[test]
    fn test_check_add_oflag_copied_in_l1_entry() {
        let path = "/tmp/test_check_add_oflag_copied_in_l1_entry.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let image_size = 1 << 30;
        let image_size_str = "+1G";
        let test_case = vec![
            // (fix, guest_offset, corruptions, corruptions_fixed)
            (0, 0, 1, 0),
            (FIX_LEAKS, 0, 0, 1),
            (FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, cluster_size * 10, 0, 1),
            (FIX_LEAKS, cluster_size * 10, 0, 1),
            (FIX_ERRORS, cluster_size * 10, 0, 1),
            (
                FIX_LEAKS | FIX_ERRORS,
                cluster_size + cluster_size / 2,
                0,
                1,
            ),
            (FIX_LEAKS, image_size - cluster_size, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, image_size - cluster_size, 0, 1),
        ];

        // Test different guest offset
        for case in test_case {
            let quite = false;
            let fix = case.0;
            let guest_offset = case.1;
            let expect_corruptions = case.2;
            let expect_corruptions_fixed = case.3;

            // Write data to guest offset.
            let test_image =
                TestQcow2Image::create(cluster_bits, refcount_bits, path, image_size_str);
            let buf = vec![1_u8; cluster_size as usize];
            assert!(test_image.write_data(guest_offset, &buf).is_ok());

            // Create a new snapshot, ensure that the refcount of data cluster is 2.
            assert!(image_snapshot(vec![
                "-c".to_string(),
                "test_snapshot0".to_string(),
                path.to_string()
            ])
            .is_ok());

            // Add the oflag copied for l1 entry.
            let mut qcow2_driver = test_image.create_driver();
            let l1_idx = qcow2_driver.table.get_l1_table_index(guest_offset);
            qcow2_driver.table.l1_table[l1_idx as usize] |= QCOW2_OFFSET_COPIED;
            assert!(qcow2_driver.table.save_l1_table().is_ok());
            drop(qcow2_driver);

            // Check and fix error copied flag in l1 table.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            assert_eq!(res.corruptions, expect_corruptions);
            assert_eq!(res.corruptions_fixed, expect_corruptions_fixed);
            let message = res.collect_check_message();
            println!("{}", message);
            drop(qcow2_driver);

            // The oflag error in l1 table has been fixed.
            if expect_corruptions_fixed != 0 {
                let qcow2_driver = test_image.create_driver();
                assert_eq!(
                    qcow2_driver.table.l1_table[l1_idx as usize] & QCOW2_OFFSET_COPIED,
                    0
                );
                drop(qcow2_driver);
            }
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create a new image.
    ///   2. Alloc a a new cluster, and create a new snapshot. So the oflag of l2 entry will be cleared,
    ///      which means writing to this cluster will result in copy on write.
    ///   3. Set the oflag of copied in l2 entry of this cluster, and apply image check.
    /// Expect:
    ///   2. The wrong of oflag in l2 entry can be found and fixed.
    #[test]
    fn test_check_add_oflag_copied_in_l2_entry() {
        let path = "/tmp/test_check_add_oflag_copied_in_l2_entry.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let image_size = 1 << 30;
        let image_size_str = "+1G";
        let test_case = vec![
            // (fix, guest_offset, corruptions, corruptions_fixed)
            (0, 0, 1, 0),
            (FIX_LEAKS, 0, 0, 1),
            (FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, 0, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, cluster_size * 10, 0, 1),
            (FIX_LEAKS, cluster_size * 10, 0, 1),
            (FIX_ERRORS, cluster_size * 10, 0, 1),
            (
                FIX_LEAKS | FIX_ERRORS,
                cluster_size + cluster_size / 2,
                0,
                1,
            ),
            (FIX_LEAKS, image_size - cluster_size, 0, 1),
            (FIX_LEAKS | FIX_ERRORS, image_size - cluster_size, 0, 1),
        ];

        // Test different guest offset
        for case in test_case {
            let fix = case.0;
            let quite = false;
            let guest_offset = case.1;
            let expect_corruptions = case.2;
            let expect_corruptions_fixed = case.3;

            // Write data to guest offset.
            let test_image =
                TestQcow2Image::create(cluster_bits, refcount_bits, path, image_size_str);
            let buf = vec![1_u8; cluster_size as usize];
            assert!(test_image.write_data(guest_offset, &buf).is_ok());

            // Create a new snapshot, ensure that the refcount of data cluster is 2.
            assert!(image_snapshot(vec![
                "-c".to_string(),
                "test_snapshot0".to_string(),
                path.to_string()
            ])
            .is_ok());

            // Add the oflag copide for l2 entry.
            let mut qcow2_driver = test_image.create_driver();
            let l2_idx = qcow2_driver.table.get_l2_table_index(guest_offset) as usize;
            let cache_entry = qcow2_driver.get_table_cluster(guest_offset).unwrap();
            let mut l2_entry = cache_entry.borrow_mut().get_entry_map(l2_idx).unwrap();
            l2_entry |= QCOW2_OFFSET_COPIED;
            assert!(cache_entry
                .borrow_mut()
                .set_entry_map(l2_idx, l2_entry)
                .is_ok());
            qcow2_driver
                .table
                .l2_table_cache
                .add_dirty_table(cache_entry);
            drop(qcow2_driver);

            // Check and fix error copied flag in l1 table.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            assert_eq!(res.corruptions, expect_corruptions);
            assert_eq!(res.corruptions_fixed, expect_corruptions_fixed);
            let message = res.collect_check_message();
            println!("{}", message);
            drop(qcow2_driver);

            // The oflag error in l2 table has been fixed.
            if expect_corruptions_fixed != 0 {
                let mut qcow2_driver = test_image.create_driver();
                let cache_entry = qcow2_driver.get_table_cluster(guest_offset).unwrap();
                let l2_entry = cache_entry.borrow_mut().get_entry_map(l2_idx).unwrap();
                assert_eq!(l2_entry & QCOW2_OFFSET_COPIED, 0);
                drop(qcow2_driver);
            }
        }
    }

    /// Test the function of image check.
    ///
    /// TestStep:
    ///   1. Create a new image with different cluster bits and image size.
    ///   2. Set the refcount table offset and refcount table clusters to 0 in header,
    ///      so it is unable to find data of refcount table by header.
    ///   3. Apply image check.
    /// Expect:
    ///   1. The refcount table and refcount block of this image can be rebuild.
    #[test]
    fn test_rebuild_refcount() {
        let path = "/tmp/test_rebuild_refcount.qcow2";
        // (cluster bits, image size in str, image size in number)
        let test_case = [
            (9, "+1G", G),
            (10, "+20M", 20 * M),
            (16, "+50M", 50 * M),
            (16, "1024M", G),
            (16, "+128G", 128 * G),
        ];
        // Only refcount bit=16 is supported currently.
        let refcount_bits = 16;

        for case in test_case {
            let cluster_bits = case.0;
            let mut test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, case.1);
            test_image.clear_reftable();

            // Try to rebuild refcount table.
            let fix = FIX_ERRORS | FIX_LEAKS;
            let quite = false;

            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            assert_eq!(res.corruptions, 0);
            assert!(res.corruptions_fixed != 0);
            drop(qcow2_driver);
        }
    }

    /// Test the function of image check.
    /// 1. If the l2 offset is not align to cluster size, it will be set to zero during checking.
    /// 2. The value of reserved area of l2 entry is expected to 0(Seen L2_STD_RESERVED_MASK). If not ,
    /// and error message will be recorded, but the repair action will not be tooken, as this error has no other impact.
    ///
    /// TestStep:
    ///   1. Create a new image.
    ///   2. Alloc a new cluster, change the offset in l2 entry of this cluster.
    ///   3. Apply image check.
    /// Expect:
    ///   1. The refcount table and refcount block of this image can be rebuild.
    #[test]
    fn test_check_fix_l2_entry() {
        let path = "/tmp/test_check_fix_l2_entry.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let image_size_str = "+1G";
        let fix = FIX_LEAKS | FIX_ERRORS;
        let quite = false;

        let guest_offset = 0;
        let test_case: Vec<(u64, bool)> = vec![
            (1 << 1, false),
            (1 << 8, false),
            (1 << 9, true),
            (1 << (cluster_bits - 1), true),
            (1 << 57, false),
        ];

        for case in test_case {
            // Write data to guest offset.
            let offset = case.0;
            let need_fixed = case.1;
            println!("offset: {}, need_fixed: {}", offset, need_fixed);
            let test_image =
                TestQcow2Image::create(cluster_bits, refcount_bits, path, image_size_str);
            let buf = vec![1_u8; cluster_size as usize];
            assert!(test_image.write_data(guest_offset, &buf).is_ok());

            // Modify the l2 offset, make it not align to cluster size.
            let mut qcow2_driver = test_image.create_driver();
            let l2_idx = qcow2_driver.table.get_l2_table_index(guest_offset) as usize;
            let cache_entry = qcow2_driver.get_table_cluster(guest_offset).unwrap();
            let mut l2_entry = cache_entry.borrow_mut().get_entry_map(l2_idx).unwrap();
            let l2_offset = l2_entry & L2_TABLE_OFFSET_MASK;
            let l2_entry_flag = l2_entry & !L2_TABLE_OFFSET_MASK;
            l2_entry = (l2_offset + offset) | l2_entry_flag;
            assert!(cache_entry
                .borrow_mut()
                .set_entry_map(l2_idx, l2_entry)
                .is_ok());
            qcow2_driver
                .table
                .l2_table_cache
                .add_dirty_table(cache_entry);
            drop(qcow2_driver);

            // Check and fix error copied flag in l1 table.
            let mut res = CheckResult::default();
            let mut qcow2_driver = test_image.create_driver_for_check();
            assert!(qcow2_driver.check_image(&mut res, quite, fix).is_ok());
            if need_fixed {
                assert_eq!(res.corruptions, 0);
                assert_eq!(res.corruptions_fixed, 1);
            } else {
                assert_eq!(res.corruptions, 1);
                assert_eq!(res.corruptions_fixed, 0);
            }
            drop(qcow2_driver);
        }
    }

    /// Test the function of snapshot operation.
    /// TestStep:
    ///   1. Operate snapshot with different args.
    /// Expect:
    ///   1. If the args is invalid, operation failed.
    #[test]
    fn test_args_parse_of_image_snapshot() {
        let path = "/tmp/test_args_parse_of_image_snapshot";
        let create_str = "-f disk_fmt img_path +1G".replace("img_path", path);
        let test_case = [
            ("qcow2", "-c snapshot0 img_path", true),
            ("qcow2", "-f qcow2 -l img_path", true),
            ("qcow2", "-r old_snapshot_name img_path", false),
            ("qcow2", "-d snapshot0 img_path", false),
            ("qcow2", "-a snapshot0 img_path", false),
            ("qcow2", "-c snapshot0 -l img_path", false),
            (
                "raw",
                "-r old_snapshot_name new_snapshot_name img_path",
                false,
            ),
            ("raw", "-f qcow2 -l img_path", false),
            ("raw", "-l img_path", false),
        ];

        for case in test_case {
            let create_string = create_str.replace("disk_fmt", case.0);
            let create_args: Vec<String> = create_string
                .split(' ')
                .map(|str| str.to_string())
                .collect();
            println!("Create args: {}", create_string);
            assert!(image_create(create_args).is_ok());

            let snapshot_str = case.1.replace("img_path", path);
            let snapshot_args: Vec<String> =
                snapshot_str.split(' ').map(|str| str.to_string()).collect();
            let ret = image_snapshot(snapshot_args);
            if case.2 {
                assert!(ret.is_ok());
            } else {
                assert!(ret.is_err());
            }

            assert!(remove_file(path).is_ok());
        }
    }

    /// Test the function of apply snapshot.
    ///
    /// TestStep:
    ///   1. Create a new image. alloc a new cluster and write 1.
    ///   2. Create snapshot named snapshot0, write 2 to the cluster.
    ///   3. Create snapshot named snapshot1, write 3 to the cluster.
    ///   4. Apply snapshot named snapshot0, and read the data by qcow2 driver.
    /// Expect:
    ///   1. No errors were found during the image check.
    ///   2. The data read after snapshot apply is 2.
    #[test]
    fn test_check_snapshot_apply_basic() {
        let path = "/tmp/test_check_snapshot_apply_basic.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;
        let test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, "+1G");
        let quite = false;
        let fix = FIX_ERRORS | FIX_LEAKS;

        assert!(test_image.check_image(quite, fix));
        let buf = vec![1_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());
        assert!(test_image.check_image(quite, fix));

        // Create a snapshot named test_snapshot0
        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot0".to_string(),
            path.to_string()
        ])
        .is_ok());

        assert!(test_image.check_image(quite, fix));
        let buf = vec![2_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());
        assert!(test_image.check_image(quite, fix));

        // Create as snapshot named test_snapshot1.
        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot1".to_string(),
            path.to_string()
        ])
        .is_ok());

        assert!(test_image.check_image(quite, fix));
        let buf = vec![3_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());
        assert!(test_image.check_image(quite, fix));

        // Apply snapshot named test_snapshot0.
        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot0".to_string(),
            path.to_string()
        ])
        .is_ok());

        assert!(test_image.check_image(quite, fix));
        let buf = vec![0_u8; cluster_size as usize];
        assert!(test_image.read_data(0, &buf).is_ok());
        for elem in buf {
            assert_eq!(elem, 1);
        }
        let buf = vec![4_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());
        assert!(test_image.check_image(quite, fix));

        // Apply snapshot named test_snapshot1
        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot1".to_string(),
            path.to_string()
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let buf = vec![0_u8; cluster_size as usize];
        assert!(test_image.read_data(0, &buf).is_ok());
        for elem in buf {
            assert_eq!(elem, 2);
        }
    }

    /// Test the function of snapshot rename.
    ///
    /// TestStep:
    ///   1. Create a new image. alloc a new cluster and write 1.
    ///   2. Create snapshot named test_snapshot0, write 2 to the cluster.
    ///   3. Create snapshot named test_snapshot1, write 3 to the cluster.
    ///   4. Rename test_snapshot0 to test_snapshot0-new.
    ///   5. Apply snapshot named test_snapshot0.
    ///   6. Apply snapshot named test_snapshot0-new.
    /// Expect:
    ///   1. step 5 is failure and step 1/2/3/4/6 is success.
    ///   2. The data read after snapshot apply is 2.
    #[test]
    fn test_snapshot_rename_basic() {
        let path = "/tmp/test_snapshot_rename_basic.qcow2";
        let cluster_bits = 16;
        let cluster_size = 1 << cluster_bits;
        let refcount_bits = 16;

        // Create a new image. alloc a new cluster and write 1.
        let test_image = TestQcow2Image::create(cluster_bits, refcount_bits, path, "+1G");
        let buf = vec![1_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());

        // Create snapshot named test_snapshot0, write 2 to the cluster.
        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot0".to_string(),
            path.to_string()
        ])
        .is_ok());
        let buf = vec![2_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());

        // Create snapshot named test_snapshot1, write 3 to the cluster.
        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot1".to_string(),
            path.to_string()
        ])
        .is_ok());
        let buf = vec![3_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());

        // Rename test_snapshot0 to test_snapshot1.
        assert!(image_snapshot(vec![
            "-r".to_string(),
            "test_snapshot0".to_string(),
            "test_snapshot1".to_string(),
            path.to_string()
        ])
        .is_err());

        // Rename test_snapshot0 to test_snapshot0-new.
        assert!(image_snapshot(vec![
            "-r".to_string(),
            "test_snapshot0".to_string(),
            "test_snapshot0-new".to_string(),
            path.to_string()
        ])
        .is_ok());

        // Apply snapshot named test_snapshot0.
        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot0".to_string(),
            path.to_string()
        ])
        .is_err());

        // Apply snapshot named test_snapshot-new.
        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot0-new".to_string(),
            path.to_string()
        ])
        .is_ok());

        // The data read after snapshot apply is 2.
        let buf = vec![0_u8; cluster_size as usize];
        assert!(test_image.read_data(0, &buf).is_ok());
        for elem in buf {
            assert_eq!(elem, 1);
        }

        // Rename non-existed snapshot name.
        assert!(image_snapshot(vec![
            "-r".to_string(),
            "test_snapshot11111".to_string(),
            "test_snapshot11111-new".to_string(),
            path.to_string()
        ])
        .is_err());

        let buf = vec![4_u8; cluster_size as usize];
        assert!(test_image.write_data(0, &buf).is_ok());

        // Rename test_snapshot1 to test_snapshot123.
        assert!(image_snapshot(vec![
            "-r".to_string(),
            "test_snapshot1".to_string(),
            "test_snapshot123".to_string(),
            path.to_string()
        ])
        .is_ok());

        // Apply snapshot named test_snapshot123
        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot123".to_string(),
            path.to_string()
        ])
        .is_ok());
        let buf = vec![0_u8; cluster_size as usize];
        assert!(test_image.read_data(0, &buf).is_ok());
        for elem in buf {
            assert_eq!(elem, 2);
        }
    }

    /// Test the function of resize image.
    ///
    /// TestStep:
    ///   1. Resize the image with different args.
    /// Expect:
    ///   1. If the format of args is invalid, the operation return error.
    #[test]
    fn test_arg_parse_of_image_resize() {
        let path = "/tmp/test_arg_parse_of_image_resize.img";
        let test_case = vec![
            ("qcow2", "-f qcow2 img_path +1M", true),
            ("qcow2", "-f raw img_path +1M", true),
            ("qcow2", "img_path +0M", true),
            ("qcow2", "img_path +1M", true),
            ("qcow2", "img_path 10M", true),
            ("qcow2", "img_path 11M", true),
            ("qcow2", "img_path 9M", false),
            ("qcow2", "img_path 1M", false),
            ("qcow2", "img_path ++1M", false),
            ("qcow2", "img_path +511", false),
            ("qcow2", "img_path -1M", false),
            ("qcow2", "img_path +1M extra_args", false),
            ("qcow2", "+1M", false),
            ("qcow2", "", false),
            ("raw", "img_path +1M", true),
            ("raw", "img_path 18446744073709551615", false),
            ("raw", "img_path +511", false),
            ("raw", "-f raw img_path +1M", true),
            ("raw", "-f qcow2 img_path +1M", false),
        ];

        for (img_type, cmd, res) in test_case {
            assert!(image_create(vec![
                "-f".to_string(),
                img_type.to_string(),
                path.to_string(),
                "+10M".to_string()
            ])
            .is_ok());

            // Apply resize operation.
            let cmd = cmd.replace("img_path", path);
            let args: Vec<String> = cmd.split(' ').map(|str| str.to_string()).collect();
            assert_eq!(image_resize(args).is_ok(), res);

            assert!(remove_file(path).is_ok());
        }
    }

    /// Test the function of resize for raw image.
    ///
    /// TestStep:
    /// 1. Create a raw image with size of 10M.
    /// 2. Write data 1 in the range of [0, 10M]， with expect 1.
    /// 3. Resize the image with +10M.
    /// 4. Write data 2 in the range of [10M, 20M], with expect 1.
    /// 5. Read the data from the image, with expect 2.
    ///
    /// Expect:
    /// 1. Data successfully written to disk.
    /// 2. The data read from disk meets expectation.
    #[test]
    fn test_resize_raw() {
        // Step 1: Create a raw image with size of 10M.
        let path = "/tmp/test_resize_raw.raw";
        let mut test_image = TestRawImage::create(path.to_string(), "10M".to_string());

        // Step 2: Write data 1 in the range of [0, 10M].
        let mut offset: usize = 0;
        let buf = vec![1; 10240];
        let mut driver = test_image.create_driver();
        while offset < 10 * M as usize {
            assert!(image_write(&mut driver, offset, &buf).is_ok());
            offset += 10240;
        }
        drop(driver);

        // Step 3: Resize the image with 10M.
        assert!(image_resize(vec![
            "-f".to_string(),
            "raw".to_string(),
            path.to_string(),
            "+10M".to_string(),
        ])
        .is_ok());

        // Step 4: Write data 2 in the range of [10M, 20M]
        let buf = vec![2; 10240];
        let mut driver = test_image.create_driver();
        while offset < (10 + 10) * M as usize {
            assert!(image_write(&mut driver, offset, &buf).is_ok());
            offset += 10240;
        }

        // Step 5: Read the data from the image, the data read from disk meets expectation.
        let mut offset = 0;
        let buf = vec![0; 10240];
        while offset < 10 * M as usize {
            assert!(image_read(&mut driver, offset, &buf).is_ok());
            assert!(vec_is_fill_with(&buf, 1));
            offset += 10240;
        }

        while offset < (10 + 10) * M as usize {
            assert!(image_read(&mut driver, offset, &buf).is_ok());
            assert!(vec_is_fill_with(&buf, 2));
            offset += 10240;
        }
    }

    /// Test the function of resize for qcow2 image.
    ///
    /// TestStep:
    /// 1. Create a qcow2 image with size of 10M.
    /// 2. Write data 1 in the range of [0, 10M]， with expect 1.
    /// 3. Resize the image with +10M.
    /// 4. Write data 2 in the range of [10M, 20M], with expect 1.
    /// 5. Read the data from the image, with expect 2.
    ///
    /// Expect:
    /// 1. Data successfully written to disk.
    /// 2. The data read from disk meets expectation.
    #[test]
    fn test_resize_qcow2() {
        let path = "/tmp/test_resize_qcow2.qcow2";
        // Step 1: Create a qcow2 image with size of 10M.
        let test_image = TestQcow2Image::create(16, 16, path, "+10M");

        // Step 2: Write data of 1 to the disk in the range of [0, 10M]
        let mut offset = 0;
        let buf = vec![1; 10240];
        let mut qcow2_driver = test_image.create_driver();
        while offset < 10 * M {
            assert!(image_write(&mut qcow2_driver, offset as usize, &buf).is_ok());
            offset += 10240;
        }
        // If the offset exceed the virtual size, it is expect to be failed.
        assert!(image_write(&mut qcow2_driver, offset as usize, &buf).is_err());
        drop(qcow2_driver);

        // Step 3: Resize the image with 10M.
        assert!(image_resize(vec![
            "-f".to_string(),
            "qcow2".to_string(),
            path.to_string(),
            "+10M".to_string(),
        ])
        .is_ok());

        // Step4: Write data 2 in the range of [10M, 20M]
        let buf = vec![2; 10240];
        let mut qcow2_driver = test_image.create_driver();
        while offset < (10 + 10) * M {
            assert!(image_write(&mut qcow2_driver, offset as usize, &buf).is_ok());
            offset += 10240;
        }
        assert!(image_write(&mut qcow2_driver, offset as usize, &buf).is_err());

        // Step 5: Read the data from the image.
        let mut offset = 0;
        let buf = vec![0; 10240];
        while offset < 10 * M {
            assert!(image_read(&mut qcow2_driver, offset as usize, &buf).is_ok());
            assert!(vec_is_fill_with(&buf, 1));
            offset += 10240;
        }

        while offset < (10 + 10) * M {
            assert!(image_read(&mut qcow2_driver, offset as usize, &buf).is_ok());
            assert!(vec_is_fill_with(&buf, 2));
            offset += 10240;
        }
        assert!(image_read(&mut qcow2_driver, offset as usize, &buf).is_err());
    }

    /// Test resize image with snapshot operation.
    ///
    /// TestStep:
    /// 1. Create a qcow2 image with size of 1G.
    /// 2. Perform the operations of snapshot and image resize.
    #[test]
    fn test_image_resize_with_snapshot() {
        let path = "/tmp/test_image_resize_with_snapshot.qcow2";
        let test_image = TestQcow2Image::create(16, 16, path, "1G");
        let mut driver = test_image.create_driver();
        let buf = vec![1; 1024 * 1024];
        assert!(image_write(&mut driver, 0, &buf).is_ok());
        assert_eq!(driver.header.size, G);
        drop(driver);
        let quite = false;
        let fix = FIX_ERRORS | FIX_LEAKS;

        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot_1G".to_string(),
            path.to_string()
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![2; 1024 * 1024];
        assert!(image_write(&mut driver, 0, &buf).is_ok());
        assert_eq!(driver.header.size, G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));

        assert!(image_resize(vec![
            "-f".to_string(),
            "qcow2".to_string(),
            path.to_string(),
            "+20G".to_string(),
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![3; 1024 * 1024];
        assert!(image_write(&mut driver, 20 * G as usize, &buf).is_ok());

        assert!(image_read(&mut driver, 0, &buf).is_ok());
        assert!(vec_is_fill_with(&buf, 2));
        assert_eq!(driver.header.size, 21 * G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));

        assert!(image_snapshot(vec![
            "-c".to_string(),
            "test_snapshot_21G".to_string(),
            path.to_string()
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![4; 1024 * 1024];
        assert!(image_write(&mut driver, 20 * G as usize, &buf).is_ok());
        assert_eq!(driver.header.size, 21 * G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));

        assert!(image_resize(vec![
            "-f".to_string(),
            "qcow2".to_string(),
            path.to_string(),
            "+10G".to_string(),
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![5; 1024 * 1024];
        assert!(image_write(&mut driver, 30 * G as usize, &buf).is_ok());

        assert!(image_read(&mut driver, 20 * G as usize, &buf).is_ok());
        assert!(vec_is_fill_with(&buf, 4));
        assert_eq!(driver.header.size, 31 * G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));

        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot_1G".to_string(),
            path.to_string()
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![0; 1024 * 1024];
        assert!(image_read(&mut driver, 0, &buf).is_ok());
        assert!(vec_is_fill_with(&buf, 1));
        assert_eq!(driver.header.size, G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));

        assert!(image_snapshot(vec![
            "-a".to_string(),
            "test_snapshot_21G".to_string(),
            path.to_string()
        ])
        .is_ok());
        assert!(test_image.check_image(quite, fix));
        let mut driver = test_image.create_driver();
        let buf = vec![0; 1024 * 1024];
        assert!(image_read(&mut driver, 20 * G as usize, &buf).is_ok());
        assert!(vec_is_fill_with(&buf, 3));
        assert_eq!(driver.header.size, 21 * G);
        drop(driver);
        assert!(test_image.check_image(quite, fix));
    }

    /// Test image convert from qcow2 to raw.
    ///
    /// TestStep:
    /// 1. Create a qcow2 image with size of 10G.
    /// 2. Write data to this image in different position.
    /// 3. Convert this qcow2 to raw.
    /// 4. Read data in the same position.
    #[test]
    fn test_image_convert_from_qcow2_to_raw() {
        let src_path = "/tmp/test_image_convert_src.qcow2";
        let dst_path = "/tmp/test_image_convert_dst.raw";
        let _ = remove_file(src_path);
        let _ = remove_file(dst_path);

        let test_image = TestQcow2Image::create(16, 16, src_path, "10G");
        let mut src_driver = test_image.create_driver();

        // Write 1M data(number 1) in offset 0.
        let buf1 = vec![1_u8; 1 * M as usize];
        assert!(image_write(&mut src_driver, 0, &buf1).is_ok());
        // Write 1M data(number 2) in offset 5G.
        let buf2 = vec![2_u8; 1 * M as usize];
        assert!(image_write(&mut src_driver, 5 * G as usize, &buf2).is_ok());
        // Write 1M data(number 3) in last 1M.
        let buf3 = vec![3_u8; 1 * M as usize];
        assert!(image_write(&mut src_driver, 10 * G as usize - 1 * M as usize, &buf3).is_ok());
        // Write 1M data(number 0) in random offset (eg: 300M offset).
        let buf4 = vec![0_u8; 1 * M as usize];
        assert!(image_write(&mut src_driver, 300 * M as usize, &buf4).is_ok());

        drop(src_driver);

        assert!(image_convert(vec![
            "-f".to_string(),
            "qcow2".to_string(),
            "-O".to_string(),
            "raw".to_string(),
            src_path.to_string(),
            dst_path.to_string()
        ])
        .is_ok());

        // Open the converted raw image.
        let conf = BlockProperty::default();
        let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
        let file = open_file(dst_path, true, false).unwrap();
        let mut dst_driver = RawDriver::new(Arc::new(file), aio, conf);

        // Read 1M data in offset 0.
        let buf = vec![0; 1 * M as usize];
        assert!(image_read(&mut dst_driver, 0, &buf).is_ok());
        assert_eq!(buf, buf1);
        // Read 1M data in offset 5G.
        assert!(image_read(&mut dst_driver, 5 * G as usize, &buf).is_ok());
        assert_eq!(buf, buf2);
        // Read 1M data in last 1M.
        assert!(image_read(&mut dst_driver, 10 * G as usize - 1 * M as usize, &buf).is_ok());
        assert_eq!(buf, buf3);

        let mut img_info = ImageInfo::default();
        assert!(dst_driver.query_image(&mut img_info).is_ok());
        assert_eq!(img_info.virtual_size, 10 * G);
        // 1M data(number 0) in offset 300M will not consume space.
        assert_eq!(img_info.actual_size, 3 * M);

        // Clean.
        assert!(remove_file(dst_path).is_ok());
    }

    /// Test image convert parameters parsing.
    ///
    /// TestStep:
    /// 1. Create a qcow2 image with size of 1G.
    /// 2. Write two continuous `4k 0 buffer + 4k 1 buffer` to this image.
    /// 3. Test default parameters.
    /// 4. Test existed destination file.
    /// 5. Test min sparse.
    #[test]
    fn test_image_convert_parameters_parsing() {
        let src_path = "/tmp/test_image_convert_paring_src.qcow2";
        let dst_path = "/tmp/test_image_convert_paring_dst.raw";
        let _ = remove_file(src_path);
        let _ = remove_file(dst_path);

        let test_image = TestQcow2Image::create(16, 16, src_path, "1G");
        let mut src_driver = test_image.create_driver();

        // Write 4k data(number 0) in offset 16k.
        assert!(image_write(
            &mut src_driver,
            16 * K as usize,
            &vec![0_u8; 4 * K as usize]
        )
        .is_ok());
        // Write 4k data(number 1) in offset 20k.
        assert!(image_write(
            &mut src_driver,
            20 * K as usize,
            &vec![1_u8; 4 * K as usize]
        )
        .is_ok());
        // Write 4k data(number 0) in offset 24k.
        assert!(image_write(
            &mut src_driver,
            24 * K as usize,
            &vec![0_u8; 4 * K as usize]
        )
        .is_ok());
        // Write 4k data(number 1) in offset 28k.
        assert!(image_write(
            &mut src_driver,
            28 * K as usize,
            &vec![1_u8; 4 * K as usize]
        )
        .is_ok());

        drop(src_driver);

        // test1: The default value of the parameters.
        // `stratovirt-img convert src_path dst_path`
        // Eq: `stratovirt-img convert -f qcow2 -O raw -S 8 src_path dst_path`
        assert!(image_convert(vec![src_path.to_string(), dst_path.to_string()]).is_ok());
        // Check output format.
        let output_image_file = ImageFile::create(&dst_path, true).unwrap();
        let detect_output_fmt = output_image_file.detect_img_format().unwrap();
        assert_eq!(detect_output_fmt, DiskFormat::Raw);
        drop(output_image_file);
        // Check sparse size by querying output file size.
        let conf = BlockProperty::default();
        let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
        let file = open_file(dst_path, true, false).unwrap();
        let mut img_info = ImageInfo::default();
        let mut dst_driver = RawDriver::new(Arc::new(file), aio, conf);
        assert!(dst_driver.query_image(&mut img_info).is_ok());
        // Raw file has allocated filled first part (sized 4k(host page size), see function `alloc_first_block`) for
        // detecting the alignment length.
        assert_eq!(img_info.actual_size, 4 * K + 8 * K); // 4K allocated filled first part + 8K data.
        drop(dst_driver);
        assert!(remove_file(dst_path).is_ok());

        // test2: The destination file already exists.
        let existed_raw = TestRawImage::create(dst_path.to_string(), "1G".to_string());
        assert!(image_convert(vec![
            "-f".to_string(),
            "qcow2".to_string(),
            "-O".to_string(),
            "raw".to_string(),
            src_path.to_string(),
            dst_path.to_string()
        ])
        .is_err());
        drop(existed_raw);

        // test3: Sparse test.
        // stratovirt-img convert -f qcow2 -O raw -S 16 src_path dst_path
        assert!(image_convert(vec![
            "-S".to_string(),
            "16".to_string(), // 16 sectors.(8K)
            src_path.to_string(),
            dst_path.to_string()
        ])
        .is_ok());
        // Query the image size.
        let conf = BlockProperty::default();
        let aio = Aio::new(Arc::new(SyncAioInfo::complete_func), AioEngine::Off, None).unwrap();
        let file = open_file(dst_path, true, false).unwrap();
        let mut img_info = ImageInfo::default();
        let mut dst_driver = RawDriver::new(Arc::new(file), aio, conf);
        assert!(dst_driver.query_image(&mut img_info).is_ok());
        // min_sparse is 16k. So, these continuous `4K 0 buffer + 4K 1 buffer` will be considered as all data buffer sized 8k.
        // Will not create holes here.
        assert_eq!(img_info.actual_size, 4 * K + 16 * K);
        drop(dst_driver);
        assert!(remove_file(dst_path).is_ok());
    }
}
