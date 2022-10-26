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

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, get_pci_bdf, pci_args_check, PciBdf};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig, MAX_PATH_LENGTH, MAX_STRING_LENGTH};
use crate::qmp::qmp_schema;

const MAX_GUEST_CID: u64 = 4_294_967_295;
const MIN_GUEST_CID: u64 = 3;

/// Charecter device options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChardevType {
    Stdio,
    Pty,
    Socket {
        path: String,
        server: bool,
        nowait: bool,
    },
    File(String),
}

/// Config structure for virtio-console.
#[derive(Debug, Clone)]
pub struct VirtioConsole {
    pub id: String,
    pub chardev: ChardevConfig,
}

/// Config structure for character device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChardevConfig {
    pub id: String,
    pub backend: ChardevType,
}

impl ConfigCheck for ChardevConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "chardev id".to_string(),
                MAX_STRING_LENGTH,
            )));
        }

        let len = match &self.backend {
            ChardevType::Socket { path, .. } => path.len(),
            ChardevType::File(path) => path.len(),
            _ => 0,
        };
        if len > MAX_PATH_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "socket path".to_string(),
                MAX_PATH_LENGTH
            )));
        }

        Ok(())
    }
}

fn check_chardev_args(cmd_parser: CmdParser) -> Result<()> {
    if let Some(chardev_type) = cmd_parser.get_value::<String>("")? {
        let chardev_str = chardev_type.as_str();
        let server = cmd_parser.get_value::<String>("server")?;
        let nowait = cmd_parser.get_value::<String>("nowait")?;
        match chardev_str {
            "stdio" | "pty" | "file" => {
                if server.is_some() {
                    bail!(
                        "Chardev of {}-type does not support \'server\' argument",
                        chardev_str
                    );
                }
                if nowait.is_some() {
                    bail!(
                        "Chardev of {}-type does not support \'nowait\' argument",
                        chardev_str
                    );
                }
            }
            "socket" => {
                if let Some(server) = server {
                    if server.ne("") {
                        bail!("No parameter needed for server");
                    }
                }
                if let Some(nowait) = nowait {
                    if nowait.ne("") {
                        bail!("No parameter needed for nowait");
                    }
                }
            }
            _ => (),
        }
    }
    Ok(())
}

pub fn parse_chardev(cmd_parser: CmdParser) -> Result<ChardevConfig> {
    let chardev_id = if let Some(chardev_id) = cmd_parser.get_value::<String>("id")? {
        chardev_id
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing("id", "chardev")));
    };
    let backend = cmd_parser.get_value::<String>("")?;
    let path = cmd_parser.get_value::<String>("path")?;
    let server = if let Some(server) = cmd_parser.get_value::<String>("server")? {
        if server.ne("") {
            bail!("No parameter needed for server");
        }
        true
    } else {
        false
    };
    let nowait = if let Some(nowait) = cmd_parser.get_value::<String>("nowait")? {
        if nowait.ne("") {
            bail!("No parameter needed for nowait");
        }
        true
    } else {
        false
    };
    check_chardev_args(cmd_parser)?;
    let chardev_type = if let Some(backend) = backend {
        match backend.as_str() {
            "stdio" => ChardevType::Stdio,
            "pty" => ChardevType::Pty,
            "socket" => {
                if let Some(path) = path {
                    ChardevType::Socket {
                        path,
                        server,
                        nowait,
                    }
                } else {
                    return Err(anyhow!(ConfigError::FieldIsMissing(
                        "path",
                        "socket-type chardev"
                    )));
                }
            }
            "file" => {
                if let Some(path) = path {
                    ChardevType::File(path)
                } else {
                    return Err(anyhow!(ConfigError::FieldIsMissing(
                        "path",
                        "file-type chardev"
                    )));
                }
            }
            _ => {
                return Err(anyhow!(ConfigError::InvalidParam(
                    backend,
                    "chardev".to_string()
                )))
            }
        }
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing("backend", "chardev")));
    };

    Ok(ChardevConfig {
        id: chardev_id,
        backend: chardev_type,
    })
}

/// Get chardev config from qmp arguments.
///
/// # Arguments
///
/// * `args` - The qmp arguments.
pub fn get_chardev_config(args: qmp_schema::CharDevAddArgument) -> Result<ChardevConfig> {
    let backend = args.backend;
    if backend.backend_type.as_str() != "socket" {
        return Err(anyhow!(ConfigError::InvalidParam(
            "backend".to_string(),
            backend.backend_type
        )));
    }

    let data = backend.backend_data;
    if data.server {
        error!("Not support chardev socket as server now.");
        return Err(anyhow!(ConfigError::InvalidParam(
            "backend".to_string(),
            "server".to_string()
        )));
    }

    let addr = data.addr;
    if addr.addr_type.as_str() != "unix" {
        error!("Just support \"unix\" addr type option now.");
        return Err(anyhow!(ConfigError::InvalidParam(
            "backend".to_string(),
            "addr".to_string()
        )));
    }

    Ok(ChardevConfig {
        id: args.id,
        backend: ChardevType::Socket {
            path: addr.addr_data.path,
            server: data.server,
            nowait: false,
        },
    })
}

/// Get chardev socket path from ChardevConfig struct.
///
/// # Arguments
///
/// * `char_dev` - ChardevConfig struct reference.
/// * `vm_config` - mutable VmConfig struct reference.
pub fn get_chardev_socket_path(chardev: &str, vm_config: &mut VmConfig) -> Result<String> {
    if let Some(char_dev) = vm_config.chardev.remove(chardev) {
        match char_dev.backend.clone() {
            ChardevType::Socket {
                path,
                server,
                nowait,
            } => {
                if server || nowait {
                    bail!(
                        "Argument \'server\' or \'nowait\' is not need for chardev \'{}\'",
                        path
                    );
                }
                Ok(path)
            }
            _ => {
                bail!("Chardev {:?} backend should be socket type.", &char_dev.id);
            }
        }
    } else {
        bail!("Chardev: {:?} not found for character device", &chardev);
    }
}

pub fn parse_virtconsole(vm_config: &mut VmConfig, config_args: &str) -> Result<VirtioConsole> {
    let mut cmd_parser = CmdParser::new("virtconsole");
    cmd_parser.push("").push("id").push("chardev");
    cmd_parser.parse(config_args)?;

    let chardev_name = if let Some(chardev) = cmd_parser.get_value::<String>("chardev")? {
        chardev
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "chardev",
            "virtconsole"
        )));
    };

    let id = if let Some(chardev_id) = cmd_parser.get_value::<String>("id")? {
        chardev_id
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing("id", "virtconsole")));
    };

    if let Some(char_dev) = vm_config.chardev.remove(&chardev_name) {
        return Ok(VirtioConsole {
            id,
            chardev: char_dev,
        });
    }
    bail!("Chardev {:?} not found or is in use", &chardev_name);
}

impl VmConfig {
    /// Add chardev config to `VmConfig`.
    pub fn add_chardev(&mut self, chardev_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("chardev");
        cmd_parser
            .push("")
            .push("id")
            .push("path")
            .push("server")
            .push("nowait");

        cmd_parser.parse(chardev_config)?;

        let chardev = parse_chardev(cmd_parser)?;
        chardev.check()?;
        let chardev_id = chardev.id.clone();
        if self.chardev.get(&chardev_id).is_none() {
            self.chardev.insert(chardev_id, chardev);
        } else {
            bail!("Chardev {:?} has been added", &chardev_id);
        }
        Ok(())
    }

    /// Add chardev config to vm config.
    ///
    /// # Arguments
    ///
    /// * `conf` - The chardev config to be added to the vm.
    pub fn add_chardev_with_config(&mut self, conf: ChardevConfig) -> Result<()> {
        if let Err(e) = conf.check() {
            bail!("Chardev config checking failed, {}", e.to_string());
        }

        let chardev_id = conf.id.clone();
        if self.chardev.get(&chardev_id).is_none() {
            self.chardev.insert(chardev_id, conf);
        } else {
            bail!("Chardev {:?} has been added", chardev_id);
        }
        Ok(())
    }

    /// Delete chardev config from vm config.
    ///
    /// # Arguments
    ///
    /// * `id` - The chardev id which is used to delete chardev config.
    pub fn del_chardev_by_id(&mut self, id: &str) -> Result<()> {
        if self.chardev.get(id).is_some() {
            self.chardev.remove(id);
        } else {
            bail!("Chardev {} not found", id);
        }
        Ok(())
    }
}

/// Config structure for serial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerialConfig {
    pub chardev: ChardevConfig,
}

impl VmConfig {
    pub fn add_serial(&mut self, serial_config: &str) -> Result<()> {
        let parse_vec: Vec<&str> = serial_config.split(':').collect();
        let chardev_id = match parse_vec[0] {
            "chardev" => {
                if parse_vec.len() == 2 {
                    parse_vec[1]
                } else {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        serial_config.to_string(),
                        "serial".to_string(),
                    )));
                }
            }
            _ => {
                let chardev_config = serial_config.to_string() + ",id=serial_chardev";
                self.add_chardev(&chardev_config)
                    .with_context(|| "Failed to add chardev")?;
                "serial_chardev"
            }
        };
        if let Some(char_dev) = self.chardev.remove(chardev_id) {
            self.serial = Some(SerialConfig { chardev: char_dev });
            return Ok(());
        }
        bail!("Chardev {:?} not found or is in use", chardev_id);
    }
}

/// Config structure for virtio-vsock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VsockConfig {
    pub id: String,
    pub guest_cid: u64,
    pub vhost_fd: Option<i32>,
}

impl ConfigCheck for VsockConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "vsock id".to_string(),
                MAX_STRING_LENGTH
            )));
        }

        if self.guest_cid < MIN_GUEST_CID || self.guest_cid >= MAX_GUEST_CID {
            return Err(anyhow!(ConfigError::IllegalValue(
                "Vsock guest-cid".to_string(),
                MIN_GUEST_CID,
                true,
                MAX_GUEST_CID,
                false,
            )));
        }

        Ok(())
    }
}

pub fn parse_vsock(vsock_config: &str) -> Result<VsockConfig> {
    let mut cmd_parser = CmdParser::new("vhost-vsock");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("guest-cid")
        .push("vhostfd");
    cmd_parser.parse(vsock_config)?;
    pci_args_check(&cmd_parser)?;
    let id = if let Some(vsock_id) = cmd_parser.get_value::<String>("id")? {
        vsock_id
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing("id", "vsock")));
    };

    let guest_cid = if let Some(cid) = cmd_parser.get_value::<u64>("guest-cid")? {
        cid
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing("guest-cid", "vsock")));
    };

    let vhost_fd = cmd_parser.get_value::<i32>("vhostfd")?;
    let vsock = VsockConfig {
        id,
        guest_cid,
        vhost_fd,
    };
    Ok(vsock)
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct VirtioSerialInfo {
    pub id: String,
    pub pci_bdf: Option<PciBdf>,
    pub multifunction: bool,
}

impl ConfigCheck for VirtioSerialInfo {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "virtio-serial id".to_string(),
                MAX_STRING_LENGTH,
            )));
        }

        Ok(())
    }
}

pub fn parse_virtio_serial(vm_config: &mut VmConfig, serial_config: &str) -> Result<()> {
    let mut cmd_parser = CmdParser::new("virtio-serial");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction");
    cmd_parser.parse(serial_config)?;
    pci_args_check(&cmd_parser)?;

    if vm_config.virtio_serial.is_none() {
        let id = if let Some(id) = cmd_parser.get_value::<String>("id")? {
            id
        } else {
            "".to_string()
        };
        let multifunction = if let Some(switch) = cmd_parser.get_value::<ExBool>("multifunction")? {
            switch.into()
        } else {
            false
        };
        let virtio_serial = if serial_config.contains("-pci") {
            let pci_bdf = get_pci_bdf(serial_config)?;
            VirtioSerialInfo {
                id,
                pci_bdf: Some(pci_bdf),
                multifunction,
            }
        } else {
            VirtioSerialInfo {
                id,
                pci_bdf: None,
                multifunction,
            }
        };
        virtio_serial.check()?;
        vm_config.virtio_serial = Some(virtio_serial);
    } else {
        bail!("Only one virtio serial device is supported");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_virtio_serial;

    #[test]
    fn test_mmio_console_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(parse_virtio_serial(&mut vm_config, "virtio-serial-device").is_ok());
        assert!(vm_config
            .add_chardev("socket,id=test_console,path=/path/to/socket,server,nowait")
            .is_ok());
        let virt_console = parse_virtconsole(
            &mut vm_config,
            "virtconsole,chardev=test_console,id=console1",
        );
        assert!(virt_console.is_ok());
        let console_cfg = virt_console.unwrap();
        assert_eq!(console_cfg.id, "console1");
        assert_eq!(
            console_cfg.chardev.backend,
            ChardevType::Socket {
                path: "/path/to/socket".to_string(),
                server: true,
                nowait: true,
            }
        );

        let mut vm_config = VmConfig::default();
        assert!(
            parse_virtio_serial(&mut vm_config, "virtio-serial-device,bus=pcie.0,addr=0x1")
                .is_err()
        );
        assert!(vm_config
            .add_chardev("sock,id=test_console,path=/path/to/socket")
            .is_err());

        let mut vm_config = VmConfig::default();
        assert!(parse_virtio_serial(&mut vm_config, "virtio-serial-device").is_ok());
        assert!(vm_config
            .add_chardev("socket,id=test_console,path=/path/to/socket,server,nowait")
            .is_ok());
        let virt_console = parse_virtconsole(
            &mut vm_config,
            "virtconsole,chardev=test_console1,id=console1",
        );
        // test_console1 does not exist.
        assert!(virt_console.is_err());
    }

    #[test]
    fn test_pci_console_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(
            parse_virtio_serial(&mut vm_config, "virtio-serial-pci,bus=pcie.0,addr=0x1.0x2")
                .is_ok()
        );
        assert!(vm_config
            .add_chardev("socket,id=test_console,path=/path/to/socket,server,nowait")
            .is_ok());
        let virt_console = parse_virtconsole(
            &mut vm_config,
            "virtconsole,chardev=test_console,id=console1",
        );
        assert!(virt_console.is_ok());
        let console_cfg = virt_console.unwrap();

        assert_eq!(console_cfg.id, "console1");
        let serial_info = vm_config.virtio_serial.clone().unwrap();
        assert!(serial_info.pci_bdf.is_some());
        let bdf = serial_info.pci_bdf.unwrap();
        assert_eq!(bdf.bus, "pcie.0");
        assert_eq!(bdf.addr, (1, 2));
        assert_eq!(
            console_cfg.chardev.backend,
            ChardevType::Socket {
                path: "/path/to/socket".to_string(),
                server: true,
                nowait: true,
            }
        );

        let mut vm_config = VmConfig::default();
        assert!(parse_virtio_serial(
            &mut vm_config,
            "virtio-serial-pci,bus=pcie.0,addr=0x1.0x2,multifunction=on"
        )
        .is_ok());
    }

    #[test]
    fn test_vsock_config_cmdline_parser() {
        let vsock_cfg_op = parse_vsock("vhost-vsock-device,id=test_vsock,guest-cid=3");
        assert!(vsock_cfg_op.is_ok());

        let vsock_config = vsock_cfg_op.unwrap();
        assert_eq!(vsock_config.id, "test_vsock");
        assert_eq!(vsock_config.guest_cid, 3);
        assert_eq!(vsock_config.vhost_fd, None);
        assert!(vsock_config.check().is_ok());

        let vsock_cfg_op = parse_vsock("vhost-vsock-device,id=test_vsock,guest-cid=3,vhostfd=4");
        assert!(vsock_cfg_op.is_ok());

        let vsock_config = vsock_cfg_op.unwrap();
        assert_eq!(vsock_config.id, "test_vsock");
        assert_eq!(vsock_config.guest_cid, 3);
        assert_eq!(vsock_config.vhost_fd, Some(4));
        assert!(vsock_config.check().is_ok());
    }

    #[test]
    fn test_chardev_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_chardev("socket,id=test_id,path=/path/to/socket")
            .is_ok());
        assert!(vm_config
            .add_chardev("socket,id=test_id,path=/path/to/socket")
            .is_err());
        if let Some(char_dev) = vm_config.chardev.remove("test_id") {
            assert_eq!(
                char_dev.backend,
                ChardevType::Socket {
                    path: "/path/to/socket".to_string(),
                    server: false,
                    nowait: false,
                }
            );
        } else {
            assert!(false);
        }
    }
}
