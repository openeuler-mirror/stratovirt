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

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use log::info;

use crate::error::BootLoaderError;
use address_space::{AddressSpace, GuestAddress};
use devices::legacy::{error::LegacyError as FwcfgErrorKind, FwCfgEntryType, FwCfgOps};
use util::byte_code::ByteCode;

const AARCH64_KERNEL_OFFSET: u64 = 0x8_0000;

/// Boot loader config used for aarch64.
#[derive(Default, Debug)]
pub struct AArch64BootLoaderConfig {
    /// Path of kernel image.
    pub kernel: Option<PathBuf>,
    /// Path of initrd image.
    pub initrd: Option<PathBuf>,
    /// Start address of guest memory.
    pub mem_start: u64,
}

/// The start address for `kernel image`, `initrd image` and `dtb` in guest memory.
pub struct AArch64BootLoader {
    /// PC register on aarch64 platform.
    pub boot_pc: u64,
    /// Start address for `initrd image` in guest memory.
    pub initrd_start: u64,
    /// Initrd file size, 0 means no initrd file.
    pub initrd_size: u64,
    /// Start address for `dtb` in guest memory.
    pub dtb_start: u64,
}

fn load_kernel(
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    kernel_start: u64,
    kernel_path: &Path,
    sys_mem: &Arc<AddressSpace>,
) -> Result<u64> {
    let mut kernel_image =
        File::open(kernel_path).with_context(|| BootLoaderError::BootLoaderOpenKernel)?;
    let kernel_size = kernel_image.metadata().unwrap().len();
    let kernel_end = kernel_start + kernel_size;

    if let Some(fw_cfg) = fwcfg {
        let mut kernel_data = Vec::new();
        kernel_image.read_to_end(&mut kernel_data)?;
        let mut lock_dev = fw_cfg.lock().unwrap();
        lock_dev
            .add_data_entry(
                FwCfgEntryType::KernelSize,
                (kernel_size as u32).as_bytes().to_vec(),
            )
            .with_context(|| FwcfgErrorKind::AddEntryErr("KernelSize".to_string()))?;
        lock_dev
            .add_data_entry(FwCfgEntryType::KernelData, kernel_data)
            .with_context(|| FwcfgErrorKind::AddEntryErr("KernelData".to_string()))?;
    } else {
        if sys_mem
            .memory_end_address()
            .raw_value()
            .checked_sub(kernel_end)
            .is_none()
        {
            return Err(anyhow!(BootLoaderError::KernelOverflow(
                kernel_start,
                kernel_size
            )));
        }
        sys_mem
            .write(&mut kernel_image, GuestAddress(kernel_start), kernel_size)
            .with_context(|| "Fail to write kernel to guest memory")?;
    }
    Ok(kernel_end)
}

fn load_initrd(
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
    initrd_path: &Path,
    sys_mem: &Arc<AddressSpace>,
    kernel_end: u64,
) -> Result<(u64, u64)> {
    let mut initrd_image =
        File::open(initrd_path).with_context(|| BootLoaderError::BootLoaderOpenInitrd)?;
    let initrd_size = initrd_image.metadata().unwrap().len();

    let initrd_start = sys_mem
        .memory_end_address()
        .raw_value()
        .checked_sub(initrd_size)
        .filter(|addr| addr >= &kernel_end)
        .with_context(|| BootLoaderError::InitrdOverflow(kernel_end, initrd_size))?;

    if let Some(fw_cfg) = fwcfg {
        let mut initrd_data = Vec::new();
        initrd_image.read_to_end(&mut initrd_data)?;
        let mut lock_dev = fw_cfg.lock().unwrap();
        lock_dev
            .add_data_entry(
                FwCfgEntryType::InitrdAddr,
                (initrd_start as u32).as_bytes().to_vec(),
            )
            .with_context(|| FwcfgErrorKind::AddEntryErr("InitrdAddr".to_string()))?;
        lock_dev
            .add_data_entry(
                FwCfgEntryType::InitrdSize,
                (initrd_size as u32).as_bytes().to_vec(),
            )
            .with_context(|| FwcfgErrorKind::AddEntryErr("InitrdSize".to_string()))?;
        lock_dev
            .add_data_entry(FwCfgEntryType::InitrdData, initrd_data)
            .with_context(|| FwcfgErrorKind::AddEntryErr("InitrdData".to_string()))?;
    } else {
        sys_mem
            .write(&mut initrd_image, GuestAddress(initrd_start), initrd_size)
            .with_context(|| "Fail to write initrd to guest memory")?;
    }

    Ok((initrd_start, initrd_size))
}

/// Load PE(vmlinux.bin) linux kernel and other boot source to Guest Memory.
///
/// # Steps
///
/// 1. Prepare for linux kernel boot env, return guest memory layout.
/// 2. According guest memory layout, load linux kernel to guest memory.
/// 3. According guest memory layout, load initrd image to guest memory.
///
/// # Arguments
///
/// * `config` - boot source config, contains kernel, initrd.
/// * `sys_mem` - guest memory.
///
/// # Errors
///
/// Load kernel, initrd to guest memory failed. Boot source is broken or
/// guest memory is abnormal.
pub fn load_linux(
    config: &AArch64BootLoaderConfig,
    sys_mem: &Arc<AddressSpace>,
    fwcfg: Option<&Arc<Mutex<dyn FwCfgOps>>>,
) -> Result<AArch64BootLoader> {
    // The memory layout is as follow:
    // 1. dtb address: memory start
    // 2. kernel address: memory start + AARCH64_KERNEL_OFFSET
    // 3. initrd address: memory end - inird_size
    let dtb_addr = config.mem_start;
    if sys_mem
        .memory_end_address()
        .raw_value()
        .checked_sub(u64::from(util::device_tree::FDT_MAX_SIZE))
        .filter(|addr| addr >= &config.mem_start)
        .is_none()
    {
        return Err(anyhow!(BootLoaderError::DTBOverflow(
            sys_mem.memory_end_address().raw_value()
        )));
    }

    let kernel_start = config.mem_start + AARCH64_KERNEL_OFFSET;
    let boot_pc = if fwcfg.is_some() { 0 } else { kernel_start };

    if config.kernel.is_none() {
        return Ok(AArch64BootLoader {
            boot_pc,
            initrd_start: 0,
            initrd_size: 0,
            dtb_start: dtb_addr,
        });
    }

    let kernel_end = load_kernel(
        fwcfg,
        kernel_start,
        config.kernel.as_ref().unwrap(),
        sys_mem,
    )
    .with_context(|| "Fail to load kernel")?;

    let mut initrd_start = 0_u64;
    let mut initrd_size = 0_u64;
    if config.initrd.is_some() {
        let initrd_tuple = load_initrd(fwcfg, config.initrd.as_ref().unwrap(), sys_mem, kernel_end)
            .with_context(|| "Fail to load initrd")?;
        initrd_start = initrd_tuple.0;
        initrd_size = initrd_tuple.1;
    } else {
        info!("No initrd image file.");
    }

    Ok(AArch64BootLoader {
        boot_pc,
        initrd_start,
        initrd_size,
        dtb_start: dtb_addr,
    })
}
