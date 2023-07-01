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

use super::{error::ConfigError, get_cameradev_by_id, UnsignedInteger};
use crate::config::{
    check_arg_nonexist, check_arg_too_long, CamBackendType, CameraDevConfig, CmdParser,
    ConfigCheck, ScsiDevConfig, VmConfig,
};
use util::aio::AioEngine;

const USBHOST_ADDR_MAX: u8 = 127;

/// XHCI controller configuration.
#[derive(Debug)]
pub struct XhciConfig {
    pub id: Option<String>,
    // number of usb2.0 ports
    pub p2: Option<u8>,
    // number of usb3.0 ports
    pub p3: Option<u8>,
}

impl XhciConfig {
    fn new() -> Self {
        XhciConfig {
            id: None,
            p2: None,
            p3: None,
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
        .push("p3");
    cmd_parser.parse(conf)?;
    let mut dev = XhciConfig::new();
    dev.id = cmd_parser.get_value::<String>("id")?;

    if let Some(p2) = cmd_parser.get_value::<u8>("p2")? {
        dev.p2 = Some(p2);
    }

    if let Some(p3) = cmd_parser.get_value::<u8>("p3")? {
        dev.p3 = Some(p3);
    }

    dev.check()?;
    Ok(dev)
}

#[derive(Debug)]
pub struct UsbKeyboardConfig {
    pub id: Option<String>,
}

impl UsbKeyboardConfig {
    fn new() -> Self {
        UsbKeyboardConfig { id: None }
    }
}

impl ConfigCheck for UsbKeyboardConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "usb-keyboard")
    }
}

pub fn parse_usb_keyboard(conf: &str) -> Result<UsbKeyboardConfig> {
    let mut cmd_parser = CmdParser::new("usb-kbd");
    cmd_parser.push("").push("id").push("bus").push("port");
    cmd_parser.parse(conf)?;
    let mut dev = UsbKeyboardConfig::new();
    dev.id = cmd_parser.get_value::<String>("id")?;

    dev.check()?;
    Ok(dev)
}

#[derive(Debug)]
pub struct UsbTabletConfig {
    pub id: Option<String>,
}

impl UsbTabletConfig {
    fn new() -> Self {
        UsbTabletConfig { id: None }
    }
}

impl ConfigCheck for UsbTabletConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "usb-tablet")
    }
}

pub fn parse_usb_tablet(conf: &str) -> Result<UsbTabletConfig> {
    let mut cmd_parser = CmdParser::new("usb-tablet");
    cmd_parser.push("").push("id").push("bus").push("port");
    cmd_parser.parse(conf)?;
    let mut dev = UsbTabletConfig::new();
    dev.id = cmd_parser.get_value::<String>("id")?;

    dev.check()?;
    Ok(dev)
}

pub fn parse_usb_camera(vm_config: &mut VmConfig, conf: &str) -> Result<UsbCameraConfig> {
    let mut cmd_parser = CmdParser::new("usb-camera");
    cmd_parser
        .push("")
        .push("id")
        .push("cameradev")
        .push("iothread");
    cmd_parser.parse(conf)?;

    let mut dev = UsbCameraConfig::new();
    let drive = cmd_parser
        .get_value::<String>("cameradev")
        .with_context(|| "`cameradev` is missing for usb-camera")?;
    let cameradev = get_cameradev_by_id(vm_config, drive.clone().unwrap()).with_context(|| {
        format!(
            "no cameradev found with id {:?} for usb-camera",
            drive.unwrap()
        )
    })?;

    dev.id = cmd_parser.get_value::<String>("id")?;
    dev.backend = cameradev.backend;
    dev.path = cameradev.path.clone();
    dev.drive = cameradev;
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
pub struct UsbCameraConfig {
    pub id: Option<String>,
    pub backend: CamBackendType,
    pub path: Option<String>,
    pub iothread: Option<String>,
    pub drive: CameraDevConfig,
}

impl UsbCameraConfig {
    pub fn new() -> Self {
        UsbCameraConfig {
            id: None,
            backend: CamBackendType::Demo,
            path: None,
            iothread: None,
            drive: CameraDevConfig::new(),
        }
    }
}

impl Default for UsbCameraConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigCheck for UsbCameraConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "usb-camera")?;
        if self.iothread.is_some() {
            check_arg_too_long(self.iothread.as_ref().unwrap(), "iothread name")?;
        }
        Ok(())
    }
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
    dev.media = drive_arg.media.clone();

    dev.check()?;
    Ok(dev)
}

#[derive(Clone, Debug, Default)]
pub struct UsbHostConfig {
    /// USB Host device id.
    pub id: Option<String>,
    /// The bus number of the USB Host device.
    pub hostbus: u8,
    /// The addr number of the USB Host device.
    pub hostaddr: u8,
    /// The physical port number of the USB host device.
    pub hostport: Option<String>,
    /// The vendor id of the USB Host device.
    pub vendorid: u16,
    /// The product id of the USB Host device.
    pub productid: u16,
    pub iso_urb_frames: u32,
    pub iso_urb_count: u32,
}

impl UsbHostConfig {
    fn check_range(&self) -> Result<()> {
        if self.hostaddr > USBHOST_ADDR_MAX {
            bail!("USB Host hostaddr out of range");
        }
        Ok(())
    }
}

impl ConfigCheck for UsbHostConfig {
    fn check(&self) -> Result<()> {
        check_id(self.id.clone(), "usb-host")?;
        self.check_range()
    }
}

pub fn parse_usb_host(cfg_args: &str) -> Result<UsbHostConfig> {
    let mut cmd_parser = CmdParser::new("usb-host");
    cmd_parser
        .push("")
        .push("id")
        .push("hostbus")
        .push("hostaddr")
        .push("hostport")
        .push("vendorid")
        .push("productid")
        .push("isobsize")
        .push("isobufs");

    cmd_parser.parse(cfg_args)?;

    let dev = UsbHostConfig {
        id: cmd_parser.get_value::<String>("id")?,
        hostbus: cmd_parser.get_value::<u8>("hostbus")?.unwrap_or(0),
        hostaddr: cmd_parser.get_value::<u8>("hostaddr")?.unwrap_or(0),
        hostport: cmd_parser.get_value::<String>("hostport")?,
        vendorid: cmd_parser
            .get_value::<UnsignedInteger>("vendorid")?
            .unwrap_or(UnsignedInteger(0))
            .0 as u16,
        productid: cmd_parser
            .get_value::<UnsignedInteger>("productid")?
            .unwrap_or(UnsignedInteger(0))
            .0 as u16,
        iso_urb_frames: cmd_parser.get_value::<u32>("isobsize")?.unwrap_or(32),
        iso_urb_count: cmd_parser.get_value::<u32>("isobufs")?.unwrap_or(4),
    };

    dev.check()?;
    Ok(dev)
}
