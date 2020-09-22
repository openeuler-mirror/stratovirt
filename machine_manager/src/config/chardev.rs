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

extern crate serde;
extern crate serde_json;

use serde::{Deserialize, Serialize};

use super::errors::{ErrorKind, Result};
use crate::config::{CmdParams, ConfigCheck, ParamOperation, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_GUEST_CID: u64 = 4_294_967_295;
const MIN_GUEST_CID: u64 = 3;

/// Config structure for virtio-console.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsoleConfig {
    pub console_id: String,
    pub socket_path: String,
}

impl ConsoleConfig {
    /// Create `ConsoleConfig` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Option<Vec<Self>> {
        serde_json::from_value(value.clone()).ok()
    }
}

impl ConfigCheck for ConsoleConfig {
    fn check(&self) -> Result<()> {
        if self.console_id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "console id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.socket_path.len() > MAX_PATH_LENGTH {
            return Err(
                ErrorKind::StringLengthTooLong("socket path".to_string(), MAX_PATH_LENGTH).into(),
            );
        }

        Ok(())
    }
}

impl VmConfig {
    /// Add new virtio-console device to `VmConfig`.
    fn add_console(&mut self, console: ConsoleConfig) {
        if let Some(mut consoles) = self.consoles.clone() {
            consoles.push(console);
            self.consoles = Some(consoles);
        } else {
            let mut consoles: Vec<ConsoleConfig> = Vec::new();
            consoles.push(console);
            self.consoles = Some(consoles);
        }
    }

    /// Update '-console ...' network config to `VmConfig`.
    pub fn update_console(&mut self, console_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(console_config);
        let mut console = ConsoleConfig::default();
        if let Some(console_id) = cmd_params.get("id") {
            console.console_id = console_id.value;
        }
        if let Some(console_path) = cmd_params.get("path") {
            console.socket_path = console_path.value;
        }
        self.add_console(console);
    }

    /// Get virtio-console's config from `device` and `chardev` config.
    pub fn get_virtio_console(&self) -> Vec<ConsoleConfig> {
        let mut console_cfg: Vec<ConsoleConfig> = Vec::new();
        if let Some(console_devs) = self.consoles.as_ref() {
            for console_dev in console_devs {
                console_cfg.push(console_dev.clone())
            }
        }
        console_cfg
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SerialConfig {
    pub stdio: bool,
}

impl SerialConfig {
    /// Create `SerialConfig` from `Value` structure.
    ///
    /// # Arguments
    ///
    /// * `Value` - structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }
}

impl VmConfig {
    pub fn update_serial(&mut self, serial_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(serial_config);

        if let Some(serial_type) = cmd_params.get("") {
            if serial_type.to_string() == "stdio" {
                self.serial = Some(SerialConfig { stdio: true });
            } else {
                self.serial = Some(SerialConfig { stdio: false });
            }
        }
    }
}

/// Config structure for virtio-vsock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VsockConfig {
    pub vsock_id: String,
    pub guest_cid: u64,
    pub vhost_fd: Option<i32>,
}

impl VsockConfig {
    /// Create `VsockConfig` from `Value` structure.
    /// `Value` structure can be gotten by `json_file`.
    pub fn from_value(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }
}

impl ConfigCheck for VsockConfig {
    fn check(&self) -> Result<()> {
        if self.vsock_id.len() > MAX_STRING_LENGTH {
            return Err(
                ErrorKind::StringLengthTooLong("vsock id".to_string(), MAX_STRING_LENGTH).into(),
            );
        }

        if self.guest_cid < MIN_GUEST_CID || self.guest_cid >= MAX_GUEST_CID {
            return Err(ErrorKind::GuestCidError.into());
        }

        Ok(())
    }
}

impl VmConfig {
    pub fn update_vsock(&mut self, vsock_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(vsock_config);

        if let Some(device_type) = cmd_params.get("") {
            if device_type.value.contains("vsock") {
                let vhost_fd = cmd_params.get_value_i32("vhostfd");
                self.vsock = Some(VsockConfig {
                    vsock_id: cmd_params.get_value_str("id").unwrap(),
                    guest_cid: cmd_params.get_value_u64("guest-cid").unwrap(),
                    vhost_fd,
                });
            }
        }
    }
}
