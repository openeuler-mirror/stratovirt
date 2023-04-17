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

use std::sync::Arc;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use crate::config::{CmdParser, ExBool, VmConfig};

/// Event fd related to power button in gtk.
pub struct UiContext {
    /// Name of virtual machine.
    pub vm_name: String,
    /// Gracefully Shutdown.
    pub power_button: Option<Arc<EventFd>>,
    /// Forced Shutdown.
    pub shutdown_req: Option<Arc<EventFd>>,
}

/// GTK related configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Create the GTK thread.
    pub gtk: bool,
    /// Fix window size.
    pub fix_size: bool,
    /// Keep the window fill the desktop.
    pub full_screen: bool,
}

impl VmConfig {
    pub fn add_display(&mut self, vm_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("display");
        cmd_parser.push("").push("full-screen").push("fix-size");
        cmd_parser.parse(vm_config)?;
        let mut display_config = DisplayConfig::default();
        if let Some(str) = cmd_parser.get_value::<String>("")? {
            match str.as_str() {
                "gtk" => display_config.gtk = true,
                _ => bail!("Unsupport device: {}", str),
            }
        }
        if let Some(default) = cmd_parser.get_value::<ExBool>("fix-size")? {
            display_config.fix_size = default.into();
        }
        if let Some(default) = cmd_parser.get_value::<ExBool>("full-screen")? {
            display_config.full_screen = default.into();
        }

        self.display = Some(display_config);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_gtk() {
        let mut vm_config = VmConfig::default();
        let config_line = "";
        assert!(vm_config.add_display(config_line).is_err());

        let config_line = "gtk";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);
        assert_eq!(display_config.fix_size, false);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=on";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, true);
        assert_eq!(display_config.fix_size, false);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=off";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);
        assert_eq!(display_config.fix_size, false);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,fix-size=on";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);
        assert_eq!(display_config.fix_size, true);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,fix-size=off";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);
        assert_eq!(display_config.fix_size, false);
    }
}
