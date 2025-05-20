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

use anyhow::Result;
#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
use anyhow::{bail, Context};
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};
#[cfg(feature = "gtk")]
use vmm_sys_util::eventfd::EventFd;

use crate::config::{parse_bool, str_slip_to_clap, VmConfig};

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
fn get_dir_path(p: &str) -> Result<String> {
    if cfg!(debug_assertions) {
        return Ok(p.to_string());
    }

    let path = std::fs::canonicalize(p)
        .with_context(|| format!("Failed to get real directory path: {:?}", p))?;
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

    Ok(path.to_str().unwrap().to_string())
}

/// GTK and OHUI related configuration.
#[derive(Parser, Debug, Clone, Default, Serialize, Deserialize)]
#[command(no_binary_name(true))]

pub struct DisplayConfig {
    #[arg(long, alias = "classtype", value_parser = ["gtk", "ohui"])]
    pub display_type: String,
    /// App name if configured.
    #[arg(long)]
    pub app_name: Option<String>,
    /// Keep the window fill the desktop.
    #[arg(long, default_value = "off", action = ArgAction::Append, value_parser = parse_bool)]
    pub full_screen: bool,
    /// Create the OHUI thread.
    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    #[arg(long)]
    pub iothread: Option<String>,
    /// Confirm socket path. Default socket path is "/tmp".
    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    #[arg(long, alias = "socks-path", default_value = "/tmp/", value_parser = get_dir_path)]
    pub sock_path: String,
    /// Define the directory path for OHUI framebuffer and cursor.
    #[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
    #[arg(long, alias = "ui-path", default_value_if("display_type", "ohui", "/dev/shm/hwf/"), default_value = "/tmp/", value_parser = get_dir_path)]
    pub ui_path: String,
}

#[cfg(all(target_env = "ohos", feature = "ohui_srv"))]
impl DisplayConfig {
    pub fn get_sock_path(&self) -> String {
        self.sock_path.clone()
    }

    pub fn get_ui_path(&self) -> String {
        self.ui_path.clone()
    }
}

impl VmConfig {
    pub fn add_display(&mut self, vm_config: &str) -> Result<()> {
        let display_config =
            DisplayConfig::try_parse_from(str_slip_to_clap(vm_config, true, false))?;
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
        assert_eq!(display_config.display_type, "gtk");
        assert!(!display_config.full_screen);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=on";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.display_type, "gtk");
        assert!(display_config.full_screen);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,full-screen=off";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.display_type, "gtk");
        assert!(!display_config.full_screen);

        let mut vm_config = VmConfig::default();
        let config_line = "gtk,app-name=desktopappengine";
        assert!(vm_config.add_display(config_line).is_ok());
        let display_config = vm_config.display.unwrap();
        assert_eq!(display_config.display_type, "gtk");
        assert!(!display_config.full_screen);
        assert_eq!(
            display_config.app_name,
            Some("desktopappengine".to_string())
        );
    }
}
