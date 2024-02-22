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

use super::error::ConfigError;
use crate::config::{
    check_arg_nonexist, check_arg_too_long, CmdParser, ConfigCheck, ScsiDevConfig, VmConfig,
};
use util::aio::AioEngine;

/// XHCI controller configuration.
#[derive(Debug)]
pub struct XhciConfig {
    pub id: Option<String>,
    // number of usb2.0 ports
    pub p2: Option<u8>,
    // number of usb3.0 ports
    pub p3: Option<u8>,
    pub iothread: Option<String>,
}

impl XhciConfig {
    fn new() -> Self {
        XhciConfig {
            id: None,
            p2: None,
            p3: None,
            iothread: None,
        }
    }

    fn check_ports(&self) -> Result<()> {
        if self.p2.is_some() && self.p2.unwrap() == 0 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "usb port2 number".to_string(),
                0,
                true,
                u8::MAX as u64,
                false,
            )));
        }
        if self.p3.is_some() && self.p3.unwrap() == 0 {
            return Err(anyhow!(ConfigError::IllegalValue(
                "usb port3 number".to_string(),
                0,
                true,
                u8::MAX as u64,
                false
            )));
        }
        Ok(())
    }
}

impl ConfigCheck for XhciConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "xhci controller")?;
        if let Some(iothread) = self.iothread.as_ref() {
            check_arg_too_long(iothread, "iothread name")?;
        }
        self.check_ports()
    }
}

pub fn parse_xhci(conf: &str) -> Result<XhciConfig> {
    let mut cmd_parser = CmdParser::new("nec-usb-xhci");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("p2")
        .push("p3")
        .push("iothread");
    cmd_parser.parse(conf)?;
    let mut dev = XhciConfig::new();
    dev.id = cmd_parser.get_value::<String>("id")?;
    dev.p2 = cmd_parser.get_value::<u8>("p2")?;
    dev.p3 = cmd_parser.get_value::<u8>("p3")?;
    dev.iothread = cmd_parser.get_value::<String>("iothread")?;

    dev.check()?;
    Ok(dev)
}

pub fn check_id(id: Option<String>, device: &str) -> Result<()> {
    check_arg_nonexist(id.clone(), "id", device)?;
    check_arg_too_long(&id.unwrap(), "id")?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct UsbStorageConfig {
    /// USB Storage device id.
    pub id: Option<String>,
    /// The scsi backend config.
    pub scsi_cfg: ScsiDevConfig,
    /// The backend scsi device type(Disk or CD-ROM).
    pub media: String,
}

impl UsbStorageConfig {
    fn new() -> Self {
        Self {
            id: None,
            scsi_cfg: ScsiDevConfig::default(),
            media: "".to_string(),
        }
    }
}

impl Default for UsbStorageConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigCheck for UsbStorageConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "usb-storage")?;

        if self.scsi_cfg.aio_type != AioEngine::Off || self.scsi_cfg.direct {
            bail!("USB-storage: \"aio=off,direct=false\" must be configured.");
        }

        Ok(())
    }
}

pub fn parse_usb_storage(vm_config: &mut VmConfig, drive_config: &str) -> Result<UsbStorageConfig> {
    let mut cmd_parser = CmdParser::new("usb-storage");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("port")
        .push("drive");

    cmd_parser.parse(drive_config)?;

    let mut dev = UsbStorageConfig::new();
    dev.id = cmd_parser.get_value::<String>("id")?;

    let storage_drive = cmd_parser.get_value::<String>("drive")?.with_context(|| {
        ConfigError::FieldIsMissing("drive".to_string(), "usb storage device".to_string())
    })?;

    let drive_arg = &vm_config
        .drives
        .remove(&storage_drive)
        .with_context(|| "No drive configured matched for usb storage device.")?;
    dev.scsi_cfg.path_on_host = drive_arg.path_on_host.clone();
    dev.scsi_cfg.read_only = drive_arg.read_only;
    dev.scsi_cfg.aio_type = drive_arg.aio;
    dev.scsi_cfg.direct = drive_arg.direct;
    dev.scsi_cfg.format = drive_arg.format;
    dev.scsi_cfg.l2_cache_size = drive_arg.l2_cache_size;
    dev.scsi_cfg.refcount_cache_size = drive_arg.refcount_cache_size;
    dev.media = drive_arg.media.clone();

    dev.check()?;
    Ok(dev)
}
