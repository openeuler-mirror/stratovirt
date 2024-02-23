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

use super::{error::ConfigError, pci_args_check};
use crate::config::{
    check_arg_too_long, CmdParser, ConfigCheck, DEFAULT_VIRTQUEUE_SIZE, MAX_VIRTIO_QUEUE,
};

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
