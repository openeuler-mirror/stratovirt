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

#[cfg(feature = "gtk")]
use std::sync::Arc;

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
#[cfg(feature = "gtk")]
use vmm_sys_util::eventfd::EventFd;

use crate::config::{CmdParser, ExBool, VmConfig};

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
static DEFAULT_UI_PATH: &str = "/tmp/";

/// Event fd related to power button in gtk.
#[cfg(feature = "gtk")]
pub struct UiContext {
    /// Name of virtual machine.
    pub vm_name: String,
    /// Gracefully Shutdown.
    pub power_button: Option<Arc<EventFd>>,
    /// Forced Shutdown.
    pub shutdown_req: Option<Arc<EventFd>>,
    /// Pause Virtual Machine.
    pub pause_req: Option<Arc<EventFd>>,
    /// Resume Virtual Machine.
    pub resume_req: Option<Arc<EventFd>>,
}

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OhuiConfig {
    /// Use OHUI.
    pub ohui: bool,
    /// Create the OHUI thread.
    pub iothread: Option<String>,
    /// Confirm related files' path.
    pub path: String,
}

/// GTK and OHUI related configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisplayConfig {
    /// Create the GTK thread.
    pub gtk: bool,
    /// App name if configured.
    pub app_name: Option<String>,
    /// Keep the window fill the desktop.
    pub full_screen: bool,
    /// Used for OHUI
    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    pub ohui_config: OhuiConfig,
}

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
impl DisplayConfig {
    pub fn get_ui_path(&self) -> String {
        self.ohui_config.path.clone()
    }
}

impl VmConfig {
    pub fn add_display(&mut self, vm_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("display");
        cmd_parser.push("").push("full-screen").push("app-name");
        #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
        cmd_parser.push("iothread").push("socks-path");
        cmd_parser.parse(vm_config)?;
        let mut display_config = DisplayConfig::default();
        if let Some(str) = cmd_parser.get_value::<String>("")? {
            match str.as_str() {
                "gtk" => display_config.gtk = true,
                #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
                "ohui" => display_config.ohui_config.ohui = true,
                _ => bail!("Unsupported device: {}", str),
            }
        }
        if let Some(name) = cmd_parser.get_value::<String>("app-name")? {
            display_config.app_name = Some(name);
        }
        if let Some(default) = cmd_parser.get_value::<ExBool>("full-screen")? {
            display_config.full_screen = default.into();
        }

        #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
        if display_config.ohui_config.ohui {
            if let Some(iothread) = cmd_parser.get_value::<String>("iothread")? {
                display_config.ohui_config.iothread = Some(iothread);
            }

            if let Some(path) = cmd_parser.get_value::<String>("socks-path")? {
                let path = std::fs::canonicalize(path.clone()).with_context(|| {
                    format!("Failed to get real directory path: {:?}", path.clone())
                })?;
                if !path.exists() {
                    bail!(
                        "The defined directory {:?} path doesn't exist",
                        path.as_os_str()
                    );
                }
                if !path.is_dir() {
                    bail!(
                        "The defined socks-path {:?} is not directory",
                        path.as_os_str()
                    );
                }
                display_config.ohui_config.path = path.to_str().unwrap().to_string();
            } else {
                display_config.ohui_config.path = DEFAULT_UI_PATH.to_string();
            }
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

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=on";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, true);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=off";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,app-name=desktopappengine";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.gtk, true);
        assert_eq!(display_config.full_screen, false);
        assert_eq!(
            display_config.app_name,
            Some("desktopappengine".to_string())
        );
    }
}
