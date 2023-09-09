// Copyright (c) 2022 Huawei Technologies Co.,Ltd. All rights reserved.
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

use anyhow::{anyhow, bail, Context, Result};

use super::{error::ConfigError, pci_args_check, DiskFormat};
use crate::config::{
    check_arg_too_long, CmdParser, ConfigCheck, VmConfig, DEFAULT_VIRTQUEUE_SIZE, MAX_VIRTIO_QUEUE,
};
use util::aio::AioEngine;

/// According to Virtio Spec.
/// Max_channel should be 0.
/// Max_target should be less than or equal to 255.
pub const VIRTIO_SCSI_MAX_TARGET: u16 = 255;
/// Max_lun should be less than or equal to 16383 (2^14 - 1).
pub const VIRTIO_SCSI_MAX_LUN: u16 = 16383;

/// Only support peripheral device addressing format(8 bits for lun) in stratovirt now.
/// So, max lun id supported is 255 (2^8 - 1).
const SUPPORT_SCSI_MAX_LUN: u16 = 255;

// Seg_max = queue_size - 2. So, size of each virtqueue for virtio-scsi should be larger than 2.
const MIN_QUEUE_SIZE_SCSI: u16 = 2;
// Max size of each virtqueue for virtio-scsi.
const MAX_QUEUE_SIZE_SCSI: u16 = 1024;

#[derive(Debug, Clone)]
pub struct ScsiCntlrConfig {
    /// Virtio-scsi-pci device id.
    pub id: String,
    /// Thread name of io handler.
    pub iothread: Option<String>,
    /// Number of scsi cmd queues.
    pub queues: u32,
    /// Boot path of this scsi controller. It's prefix of scsi device's boot path.
    pub boot_prefix: Option<String>,
    /// Virtqueue size for all queues.
    pub queue_size: u16,
}

impl Default for ScsiCntlrConfig {
    fn default() -> Self {
        ScsiCntlrConfig {
            id: "".to_string(),
            iothread: None,
            // At least 1 cmd queue.
            queues: 1,
            boot_prefix: None,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        }
    }
}

impl ConfigCheck for ScsiCntlrConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "virtio-scsi-pci device id")?;

        if self.iothread.is_some() {
            check_arg_too_long(self.iothread.as_ref().unwrap(), "iothread name")?;
        }

        if self.queues < 1 || self.queues > MAX_VIRTIO_QUEUE as u32 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "queues number of scsi controller".to_string(),
                1,
                true,
                MAX_VIRTIO_QUEUE as u64,
                true,
            )));
        }

        if self.queue_size <= MIN_QUEUE_SIZE_SCSI || self.queue_size > MAX_QUEUE_SIZE_SCSI {
            return Err(anyhow!(ConfigError::IllegalValue(
                "virtqueue size of scsi controller".to_string(),
                MIN_QUEUE_SIZE_SCSI as u64,
                false,
                MAX_QUEUE_SIZE_SCSI as u64,
                true
            )));
        }

        if self.queue_size & (self.queue_size - 1) != 0 {
            bail!("Virtqueue size should be power of 2!");
        }

        Ok(())
    }
}

pub fn parse_scsi_controller(
    drive_config: &str,
    queues_auto: Option<u16>,
) -> Result<ScsiCntlrConfig> {
    let mut cmd_parser = CmdParser::new("virtio-scsi-pci");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("iothread")
        .push("num-queues")
        .push("queue-size");

    cmd_parser.parse(drive_config)?;

    pci_args_check(&cmd_parser)?;

    let mut cntlr_cfg = ScsiCntlrConfig::default();

    if let Some(iothread) = cmd_parser.get_value::<String>("iothread")? {
        cntlr_cfg.iothread = Some(iothread);
    }

    cntlr_cfg.id = cmd_parser.get_value::<String>("id")?.with_context(|| {
        ConfigError::FieldIsMissing("id".to_string(), "virtio scsi pci".to_string())
    })?;

    if let Some(queues) = cmd_parser.get_value::<u32>("num-queues")? {
        cntlr_cfg.queues = queues;
    } else if let Some(queues) = queues_auto {
        cntlr_cfg.queues = queues as u32;
    }

    if let Some(size) = cmd_parser.get_value::<u16>("queue-size")? {
        cntlr_cfg.queue_size = size;
    }

    cntlr_cfg.check()?;
    Ok(cntlr_cfg)
}

#[derive(Clone, Debug)]
pub struct ScsiDevConfig {
    /// Scsi Device id.
    pub id: String,
    /// The image file path.
    pub path_on_host: String,
    /// Serial number of the scsi device.
    pub serial: Option<String>,
    /// Scsi controller which the scsi device attaches to.
    pub cntlr: String,
    /// Scsi device can not do write operation.
    pub read_only: bool,
    /// If true, use direct access io.
    pub direct: bool,
    /// Async IO type.
    pub aio_type: AioEngine,
    /// Boot order.
    pub boot_index: Option<u8>,
    /// Scsi four level hierarchical address(host, channel, target, lun).
    pub channel: u8,
    pub target: u8,
    pub lun: u16,
    pub format: DiskFormat,
    pub l2_cache_size: Option<u64>,
    pub refcount_cache_size: Option<u64>,
}

impl Default for ScsiDevConfig {
    fn default() -> Self {
        ScsiDevConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            serial: None,
            cntlr: "".to_string(),
            read_only: false,
            direct: true,
            aio_type: AioEngine::Native,
            boot_index: None,
            channel: 0,
            target: 0,
            lun: 0,
            format: DiskFormat::Raw,
            l2_cache_size: None,
            refcount_cache_size: None,
        }
    }
}

pub fn parse_scsi_device(vm_config: &mut VmConfig, drive_config: &str) -> Result<ScsiDevConfig> {
    let mut cmd_parser = CmdParser::new("scsi-device");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("scsi-id")
        .push("lun")
        .push("serial")
        .push("bootindex")
        .push("drive");

    cmd_parser.parse(drive_config)?;

    let mut scsi_dev_cfg = ScsiDevConfig::default();

    let scsi_drive = cmd_parser.get_value::<String>("drive")?.with_context(|| {
        ConfigError::FieldIsMissing("drive".to_string(), "scsi device".to_string())
    })?;

    if let Some(boot_index) = cmd_parser.get_value::<u8>("bootindex")? {
        scsi_dev_cfg.boot_index = Some(boot_index);
    }

    if let Some(serial) = cmd_parser.get_value::<String>("serial")? {
        scsi_dev_cfg.serial = Some(serial);
    }

    scsi_dev_cfg.id = cmd_parser.get_value::<String>("id")?.with_context(|| {
        ConfigError::FieldIsMissing("id".to_string(), "scsi device".to_string())
    })?;

    if let Some(bus) = cmd_parser.get_value::<String>("bus")? {
        // Format "$parent_cntlr_name.0" is required by scsi bus.
        let strs = bus.split('.').collect::<Vec<&str>>();
        if strs.len() != 2 || strs[1] != "0" {
            bail!("Invalid scsi bus {}", bus);
        }
        scsi_dev_cfg.cntlr = strs[0].to_string();
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "bus".to_string(),
            "scsi device".to_string()
        )));
    }

    if let Some(target) = cmd_parser.get_value::<u8>("scsi-id")? {
        if target > VIRTIO_SCSI_MAX_TARGET as u8 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "scsi-id of scsi device".to_string(),
                0,
                true,
                VIRTIO_SCSI_MAX_TARGET as u64,
                true,
            )));
        }
        scsi_dev_cfg.target = target;
    }

    if let Some(lun) = cmd_parser.get_value::<u16>("lun")? {
        // Do not support Flat space addressing format(14 bits for lun) in stratovirt now.
        // We now support peripheral device addressing format(8 bits for lun).
        // So, MAX_LUN should be less than 255(2^8 - 1) temporarily.
        if lun > SUPPORT_SCSI_MAX_LUN {
            return Err(anyhow!(ConfigError::IllegalValue(
                "lun of scsi device".to_string(),
                0,
                true,
                SUPPORT_SCSI_MAX_LUN as u64,
                true,
            )));
        }
        scsi_dev_cfg.lun = lun;
    }

    let drive_arg = &vm_config
        .drives
        .remove(&scsi_drive)
        .with_context(|| "No drive configured matched for scsi device")?;
    scsi_dev_cfg.path_on_host = drive_arg.path_on_host.clone();
    scsi_dev_cfg.read_only = drive_arg.read_only;
    scsi_dev_cfg.direct = drive_arg.direct;
    scsi_dev_cfg.aio_type = drive_arg.aio;
    scsi_dev_cfg.format = drive_arg.format;
    scsi_dev_cfg.l2_cache_size = drive_arg.l2_cache_size;
    scsi_dev_cfg.refcount_cache_size = drive_arg.refcount_cache_size;

    Ok(scsi_dev_cfg)
}
