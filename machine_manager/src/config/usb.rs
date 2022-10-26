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

use super::error::ConfigError;
use anyhow::{anyhow, bail, Result};

use crate::config::{CmdParser, ConfigCheck, MAX_STRING_LENGTH};

/// XHCI contoller configuration.
#[derive(Debug)]
pub struct XhciConfig {
    pub id: String,
}

impl XhciConfig {
    fn new() -> Self {
        XhciConfig { id: String::new() }
    }
}

impl ConfigCheck for XhciConfig {
    fn check(&self) -> Result<()> {
        check_id(&self.id)
    }
}

pub fn parse_xhci(conf: &str) -> Result<XhciConfig> {
    let mut cmd_parser = CmdParser::new("nec-usb-xhci");
    cmd_parser.push("").push("id").push("bus").push("addr");
    cmd_parser.parse(conf)?;
    let mut dev = XhciConfig::new();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        dev.id = id;
    } else {
        bail!("id is none for usb xhci");
    }

    dev.check()?;
    Ok(dev)
}

#[derive(Debug)]
pub struct UsbKeyboardConfig {
    pub id: String,
}

impl UsbKeyboardConfig {
    fn new() -> Self {
        UsbKeyboardConfig { id: String::new() }
    }
}

impl ConfigCheck for UsbKeyboardConfig {
    fn check(&self) -> Result<()> {
        check_id(&self.id)
    }
}

pub fn parse_usb_keyboard(conf: &str) -> Result<UsbKeyboardConfig> {
    let mut cmd_parser = CmdParser::new("usb-kbd");
    cmd_parser.push("").push("id");
    cmd_parser.parse(conf)?;
    let mut dev = UsbKeyboardConfig::new();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        dev.id = id;
    } else {
        bail!("id is none for usb keyboard");
    }
    dev.check()?;
    Ok(dev)
}

#[derive(Debug)]
pub struct UsbTabletConfig {
    pub id: String,
}

impl UsbTabletConfig {
    fn new() -> Self {
        UsbTabletConfig { id: String::new() }
    }
}

impl ConfigCheck for UsbTabletConfig {
    fn check(&self) -> Result<()> {
        check_id(&self.id)
    }
}

pub fn parse_usb_tablet(conf: &str) -> Result<UsbTabletConfig> {
    let mut cmd_parser = CmdParser::new("usb-tablet");
    cmd_parser.push("").push("id");
    cmd_parser.parse(conf)?;
    let mut dev = UsbTabletConfig::new();
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        dev.id = id;
    } else {
        bail!("id is none for usb tablet");
    }
    dev.check()?;
    Ok(dev)
}

fn check_id(id: &str) -> Result<()> {
    if id.len() > MAX_STRING_LENGTH {
        return Err(anyhow!(ConfigError::StringLengthTooLong(
            "id".to_string(),
            MAX_STRING_LENGTH
        )));
    }
    Ok(())
}
