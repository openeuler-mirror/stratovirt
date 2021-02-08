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
use crate::config::{CmdParser, ConfigCheck, VmConfig};

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
    pub fn from_value(value: &serde_json::Value) -> Result<Vec<Self>> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
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
    fn add_console(&mut self, console: ConsoleConfig) -> Result<()> {
        if let Some(mut consoles) = self.consoles.clone() {
            for c in &consoles {
                if c.console_id == console.console_id {
                    return Err(ErrorKind::IdRepeat(
                        c.console_id.to_string(),
                        "virtio-console".to_string(),
                    )
                    .into());
                }
            }

            consoles.push(console);
            self.consoles = Some(consoles);
        } else {
            let mut consoles: Vec<ConsoleConfig> = Vec::new();
            consoles.push(console);
            self.consoles = Some(consoles);
        }

        Ok(())
    }

    /// Update '-console ...' network config to `VmConfig`.
    pub fn update_console(&mut self, console_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("chardev");
        cmd_parser.push("id").push("path");

        cmd_parser.parse(console_config)?;

        let mut console = ConsoleConfig::default();
        if let Some(console_id) = cmd_parser.get_value::<String>("id")? {
            console.console_id = console_id;
        } else {
            return Err(ErrorKind::FieldIsMissing("id", "chardev").into());
        };
        if let Some(console_path) = cmd_parser.get_value::<String>("path")? {
            console.socket_path = console_path;
        } else {
            return Err(ErrorKind::FieldIsMissing("path", "chardev").into());
        };

        self.add_console(console)
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
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
    }
}

impl VmConfig {
    pub fn update_serial(&mut self, serial_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("serial");
        cmd_parser.push("");

        cmd_parser.parse(serial_config)?;

        let mut stdio = false;
        if let Some(serial_type) = cmd_parser.get_value::<String>("")? {
            match serial_type.as_str() {
                "stdio" => stdio = true,
                _ => return Err(ErrorKind::InvalidParam(serial_type).into()),
            }
        };
        self.serial = Some(SerialConfig { stdio });

        Ok(())
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
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let ret = serde_json::from_value(value.clone())?;
        Ok(ret)
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
            return Err(ErrorKind::IllegalValue(
                "Vsock guest-cid".to_string(),
                MIN_GUEST_CID,
                true,
                MAX_GUEST_CID,
                false,
            )
            .into());
        }

        Ok(())
    }
}

impl VmConfig {
    pub fn update_vsock(&mut self, vsock_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("device");
        cmd_parser
            .push("")
            .push("id")
            .push("guest-cid")
            .push("vhostfd");

        cmd_parser.parse(vsock_config)?;

        if let Some(device_type) = cmd_parser.get_value::<String>("")? {
            if device_type == "vsock" {
                if self.vsock.is_some() {
                    bail!("Device vsock can only be set one for one StratoVirt VM.");
                }

                let vsock_id = if let Some(vsock_id) = cmd_parser.get_value::<String>("id")? {
                    vsock_id
                } else {
                    return Err(ErrorKind::FieldIsMissing("id", "vsock").into());
                };

                let guest_cid = if let Some(cid) = cmd_parser.get_value::<u64>("guest-cid")? {
                    cid
                } else {
                    return Err(ErrorKind::FieldIsMissing("guest-cid", "vsock").into());
                };

                let vhost_fd = cmd_parser.get_value::<i32>("vhostfd")?;
                self.vsock = Some(VsockConfig {
                    vsock_id,
                    guest_cid,
                    vhost_fd,
                });
            } else {
                return Err(ErrorKind::UnknownDeviceType(device_type).into());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_console_config_json_parser() {
        let json = r#"
        [{
            "console_id": "test_console",
            "socket_path": "/path/to/socket"
        }]
        "#;
        let value = serde_json::from_str(json).unwrap();
        let configs = ConsoleConfig::from_value(&value);
        assert!(configs.is_ok());
        let console_configs = configs.unwrap();
        assert_eq!(console_configs.len(), 1);
        assert_eq!(console_configs[0].console_id, "test_console");
        assert_eq!(console_configs[0].socket_path, "/path/to/socket");
        let json = r#"
        [{
            "console_id": "test_console",
            "console_type": "unix_socket"
        }]
        "#;
        let value = serde_json::from_str(json).unwrap();
        let configs = ConsoleConfig::from_value(&value);
        assert!(configs.is_err());
    }

    #[test]
    fn test_console_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .update_console("id=test_console,path=/path/to/socket")
            .is_ok());
        let console_configs = vm_config.get_virtio_console();
        assert_eq!(console_configs.len(), 1);
        assert_eq!(console_configs[0].console_id, "test_console");
        assert_eq!(console_configs[0].socket_path, "/path/to/socket");
        assert!(console_configs[0].check().is_ok());
    }
    #[test]
    fn test_serial_config_parser() {
        let mut vm_config = VmConfig::default();
        let json = r#"
        {
            "stdio": false
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let config = SerialConfig::from_value(&value);
        assert!(config.is_ok());
        assert!(!config.as_ref().unwrap().stdio);
        vm_config.serial = config.ok();
        assert!(vm_config.update_serial("stdio").is_ok());
        assert!(vm_config.serial.as_ref().unwrap().stdio);
    }
    #[test]
    fn test_vsock_config_json_parser() {
        let json = r#"
        {
            "vsock_id": "test_vsock",
            "guest_cid": 3,
            "vhost_fd": 4
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let config = VsockConfig::from_value(&value);
        assert!(config.is_ok());
        let vsock_config = config.unwrap();
        assert_eq!(vsock_config.vsock_id, "test_vsock");
        assert_eq!(vsock_config.guest_cid, 3);
        assert_eq!(vsock_config.vhost_fd, Some(4));
        let json = r#"
        {
            "vsock_id": "test_vsock",
            "guest_cid": "3"
        }
        "#;
        let value = serde_json::from_str(json).unwrap();
        let config = VsockConfig::from_value(&value);
        assert!(config.is_err());
    }
    #[test]
    fn test_vsock_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .update_vsock("vsock,id=test_vsock,guest-cid=3")
            .is_ok());
        if let Some(vsock_config) = vm_config.vsock {
            assert_eq!(vsock_config.vsock_id, "test_vsock");
            assert_eq!(vsock_config.guest_cid, 3);
            assert_eq!(vsock_config.vhost_fd, None);
            assert!(vsock_config.check().is_ok())
        } else {
            assert!(false)
        }
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .update_vsock("vsock,id=test_vsock,guest-cid=3,vhostfd=4")
            .is_ok());
        if let Some(vsock_config) = vm_config.vsock {
            assert_eq!(vsock_config.vsock_id, "test_vsock");
            assert_eq!(vsock_config.guest_cid, 3);
            assert_eq!(vsock_config.vhost_fd, Some(4));
            assert!(vsock_config.check().is_ok())
        } else {
            assert!(false)
        }
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .update_vsock("vsock,id=test_vsock,guest-cid=1")
            .is_ok());
        if let Some(vsock_config) = vm_config.vsock {
            assert_eq!(vsock_config.vsock_id, "test_vsock");
            assert_eq!(vsock_config.guest_cid, 1);
            assert_eq!(vsock_config.vhost_fd, None);
            assert!(vsock_config.check().is_err())
        } else {
            assert!(false)
        }
    }
}
