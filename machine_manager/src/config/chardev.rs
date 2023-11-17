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

use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context, Result};
use log::error;
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, get_pci_bdf, pci_args_check, PciBdf};
use crate::config::{
    check_arg_too_long, CmdParser, ConfigCheck, ExBool, VmConfig, MAX_PATH_LENGTH,
};
use crate::qmp::qmp_schema;

const MAX_GUEST_CID: u64 = 4_294_967_295;
const MIN_GUEST_CID: u64 = 3;

/// Default value of max ports for virtio-serial.
const DEFAULT_SERIAL_PORTS_NUMBER: u32 = 31;

/// Character device options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChardevType {
    Stdio,
    Pty,
    UnixSocket {
        path: String,
        server: bool,
        nowait: bool,
    },
    TcpSocket {
        host: String,
        port: u16,
        server: bool,
        nowait: bool,
    },
    File(String),
}

/// Config structure for virtio-serial-port.
#[derive(Debug, Clone)]
pub struct VirtioSerialPort {
    pub id: String,
    pub chardev: ChardevConfig,
    pub nr: u32,
    pub is_console: bool,
}

impl ConfigCheck for VirtioSerialPort {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "chardev id")
    }
}

/// Config structure for character device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChardevConfig {
    pub id: String,
    pub backend: ChardevType,
}

impl ConfigCheck for ChardevConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "chardev id")?;
        match &self.backend {
            ChardevType::UnixSocket { path, .. } => {
                if path.len() > MAX_PATH_LENGTH {
                    return Err(anyhow!(ConfigError::StringLengthTooLong(
                        "unix-socket path".to_string(),
                        MAX_PATH_LENGTH
                    )));
                }
                Ok(())
            }
            ChardevType::TcpSocket { host, port, .. } => {
                if *port == 0u16 {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        "port".to_string(),
                        "tcp-socket".to_string()
                    )));
                }
                let ip_address = IpAddr::from_str(host);
                if ip_address.is_err() {
                    return Err(anyhow!(ConfigError::InvalidParam(
                        "host".to_string(),
                        "tcp-socket".to_string()
                    )));
                }
                Ok(())
            }
            ChardevType::File(path) => {
                if path.len() > MAX_PATH_LENGTH {
                    return Err(anyhow!(ConfigError::StringLengthTooLong(
                        "file path".to_string(),
                        MAX_PATH_LENGTH
                    )));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn check_chardev_fields(
    dev_type: &str,
    cmd_parser: &CmdParser,
    supported_fields: &[&str],
) -> Result<()> {
    for (field, value) in &cmd_parser.params {
        let supported_field = supported_fields.contains(&field.as_str());
        if !supported_field && value.is_some() {
            bail!(
                "Chardev of type {} does not support \'{}\' argument",
                dev_type,
                field
            );
        }
    }
    Ok(())
}

fn parse_stdio_chardev(chardev_id: String, cmd_parser: CmdParser) -> Result<ChardevConfig> {
    let supported_fields = ["", "id"];
    check_chardev_fields("stdio", &cmd_parser, &supported_fields)?;
    Ok(ChardevConfig {
        id: chardev_id,
        backend: ChardevType::Stdio,
    })
}

fn parse_pty_chardev(chardev_id: String, cmd_parser: CmdParser) -> Result<ChardevConfig> {
    let supported_fields = ["", "id"];
    check_chardev_fields("pty", &cmd_parser, &supported_fields)?;
    Ok(ChardevConfig {
        id: chardev_id,
        backend: ChardevType::Pty,
    })
}

fn parse_file_chardev(chardev_id: String, cmd_parser: CmdParser) -> Result<ChardevConfig> {
    let supported_fields = ["", "id", "path"];
    check_chardev_fields("file", &cmd_parser, &supported_fields)?;

    let path = cmd_parser
        .get_value::<String>("path")?
        .with_context(|| ConfigError::FieldIsMissing("path".to_string(), "chardev".to_string()))?;

    let default_value = path.clone();
    let file_path = std::fs::canonicalize(path).map_or(default_value, |canonical_path| {
        String::from(canonical_path.to_str().unwrap())
    });

    Ok(ChardevConfig {
        id: chardev_id,
        backend: ChardevType::File(file_path),
    })
}

fn parse_socket_chardev(chardev_id: String, cmd_parser: CmdParser) -> Result<ChardevConfig> {
    let mut server_enabled = false;
    let server = cmd_parser.get_value::<String>("server")?;
    if let Some(server) = server {
        if server.ne("") {
            bail!("No parameter needed for server");
        }
        server_enabled = true;
    }

    let mut nowait_enabled = false;
    let nowait = cmd_parser.get_value::<String>("nowait")?;
    if let Some(nowait) = nowait {
        if nowait.ne("") {
            bail!("No parameter needed for nowait");
        }
        nowait_enabled = true;
    }

    let path = cmd_parser.get_value::<String>("path")?;
    if let Some(path) = path {
        let supported_fields = ["", "id", "path", "server", "nowait"];
        check_chardev_fields("unix-socket", &cmd_parser, &supported_fields)?;

        let default_value = path.clone();
        let socket_path = std::fs::canonicalize(path).map_or(default_value, |canonical_path| {
            String::from(canonical_path.to_str().unwrap())
        });

        return Ok(ChardevConfig {
            id: chardev_id,
            backend: ChardevType::UnixSocket {
                path: socket_path,
                server: server_enabled,
                nowait: nowait_enabled,
            },
        });
    }

    let port = cmd_parser.get_value::<u16>("port")?;
    if let Some(port) = port {
        let supported_fields = ["", "id", "host", "port", "server", "nowait"];
        check_chardev_fields("tcp-socket", &cmd_parser, &supported_fields)?;

        let host = cmd_parser.get_value::<String>("host")?;
        return Ok(ChardevConfig {
            id: chardev_id,
            backend: ChardevType::TcpSocket {
                host: host.unwrap_or_else(|| String::from("0.0.0.0")),
                port,
                server: server_enabled,
                nowait: nowait_enabled,
            },
        });
    }

    Err(anyhow!(ConfigError::InvalidParam(
        "backend".to_string(),
        "chardev".to_string()
    )))
}

pub fn parse_chardev(chardev_config: &str) -> Result<ChardevConfig> {
    let mut cmd_parser = CmdParser::new("chardev");
    for field in ["", "id", "path", "host", "port", "server", "nowait"] {
        cmd_parser.push(field);
    }

    cmd_parser.parse(chardev_config)?;

    let chardev_id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| ConfigError::FieldIsMissing("id".to_string(), "chardev".to_string()))?;

    let backend = cmd_parser
        .get_value::<String>("")?
        .with_context(|| ConfigError::InvalidParam("backend".to_string(), "chardev".to_string()))?;

    match backend.as_str() {
        "stdio" => parse_stdio_chardev(chardev_id, cmd_parser),
        "pty" => parse_pty_chardev(chardev_id, cmd_parser),
        "file" => parse_file_chardev(chardev_id, cmd_parser),
        "socket" => parse_socket_chardev(chardev_id, cmd_parser),
        _ => Err(anyhow!(ConfigError::InvalidParam(
            backend,
            "chardev".to_string()
        ))),
    }
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
        backend: ChardevType::UnixSocket {
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
            ChardevType::UnixSocket {
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
                bail!(
                    "Chardev {:?} backend should be unix-socket type.",
                    &char_dev.id
                );
            }
        }
    } else {
        bail!("Chardev: {:?} not found for character device", &chardev);
    }
}

pub fn parse_virtserialport(
    vm_config: &mut VmConfig,
    config_args: &str,
    is_console: bool,
    free_nr: u32,
    free_port0: bool,
) -> Result<VirtioSerialPort> {
    let mut cmd_parser = CmdParser::new("virtserialport");
    cmd_parser.push("").push("id").push("chardev").push("nr");
    cmd_parser.parse(config_args)?;

    let chardev_name = cmd_parser
        .get_value::<String>("chardev")?
        .with_context(|| {
            ConfigError::FieldIsMissing("chardev".to_string(), "virtserialport".to_string())
        })?;
    let id = cmd_parser.get_value::<String>("id")?.with_context(|| {
        ConfigError::FieldIsMissing("id".to_string(), "virtserialport".to_string())
    })?;

    let nr = cmd_parser
        .get_value::<u32>("nr")?
        .unwrap_or(if is_console && free_port0 { 0 } else { free_nr });

    if nr == 0 && !is_console {
        bail!("Port number 0 on virtio-serial devices reserved for virtconsole device.");
    }

    if let Some(chardev) = vm_config.chardev.remove(&chardev_name) {
        let port_cfg = VirtioSerialPort {
            id,
            chardev,
            nr,
            is_console,
        };
        port_cfg.check()?;
        return Ok(port_cfg);
    }
    bail!("Chardev {:?} not found or is in use", &chardev_name);
}

impl VmConfig {
    /// Add chardev config to `VmConfig`.
    pub fn add_chardev(&mut self, chardev_config: &str) -> Result<()> {
        let chardev = parse_chardev(chardev_config)?;
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
        check_arg_too_long(&self.id, "vsock id")?;

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
    let id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| ConfigError::FieldIsMissing("id".to_string(), "vsock".to_string()))?;

    let guest_cid = cmd_parser.get_value::<u64>("guest-cid")?.with_context(|| {
        ConfigError::FieldIsMissing("guest-cid".to_string(), "vsock".to_string())
    })?;

    let vhost_fd = cmd_parser.get_value::<i32>("vhostfd")?;
    let vsock = VsockConfig {
        id,
        guest_cid,
        vhost_fd,
    };
    Ok(vsock)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirtioSerialInfo {
    pub id: String,
    pub pci_bdf: Option<PciBdf>,
    pub multifunction: bool,
    pub max_ports: u32,
}

impl ConfigCheck for VirtioSerialInfo {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "virtio-serial id")?;

        if self.max_ports < 1 || self.max_ports > DEFAULT_SERIAL_PORTS_NUMBER {
            return Err(anyhow!(ConfigError::IllegalValue(
                "Virtio-serial max_ports".to_string(),
                1,
                true,
                DEFAULT_SERIAL_PORTS_NUMBER as u64,
                true
            )));
        }

        Ok(())
    }
}

pub fn parse_virtio_serial(
    vm_config: &mut VmConfig,
    serial_config: &str,
) -> Result<VirtioSerialInfo> {
    let mut cmd_parser = CmdParser::new("virtio-serial");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("max_ports");
    cmd_parser.parse(serial_config)?;
    pci_args_check(&cmd_parser)?;

    if vm_config.virtio_serial.is_some() {
        bail!("Only one virtio serial device is supported");
    }

    let id = cmd_parser.get_value::<String>("id")?.unwrap_or_default();
    let multifunction = cmd_parser
        .get_value::<ExBool>("multifunction")?
        .map_or(false, |switch| switch.into());
    let max_ports = cmd_parser
        .get_value::<u32>("max_ports")?
        .unwrap_or(DEFAULT_SERIAL_PORTS_NUMBER);
    let virtio_serial = if serial_config.contains("-pci") {
        let pci_bdf = get_pci_bdf(serial_config)?;
        VirtioSerialInfo {
            id,
            pci_bdf: Some(pci_bdf),
            multifunction,
            max_ports,
        }
    } else {
        VirtioSerialInfo {
            id,
            pci_bdf: None,
            multifunction,
            // Micro_vm does not support multi-ports in virtio-serial-device.
            max_ports: 1,
        }
    };
    virtio_serial.check()?;
    vm_config.virtio_serial = Some(virtio_serial.clone());

    Ok(virtio_serial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_virtio_serial;

    fn test_mmio_console_config_cmdline_parser(chardev_cfg: &str, expected_chardev: ChardevType) {
        let mut vm_config = VmConfig::default();
        assert!(parse_virtio_serial(&mut vm_config, "virtio-serial-device").is_ok());
        assert!(vm_config.add_chardev(chardev_cfg).is_ok());

        let virt_console = parse_virtserialport(
            &mut vm_config,
            "virtconsole,chardev=test_console,id=console1,nr=1",
            true,
            0,
            true,
        );
        assert!(virt_console.is_ok());

        let console_cfg = virt_console.unwrap();
        assert_eq!(console_cfg.id, "console1");
        assert_eq!(console_cfg.chardev.backend, expected_chardev);

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
        let virt_console = parse_virtserialport(
            &mut vm_config,
            "virtconsole,chardev=test_console1,id=console1,nr=1",
            true,
            0,
            true,
        );
        // test_console1 does not exist.
        assert!(virt_console.is_err());
    }

    #[test]
    fn test_mmio_console_config_cmdline_parser_1() {
        let chardev_cfg = "socket,id=test_console,path=/path/to/socket,server,nowait";
        let expected_chardev = ChardevType::UnixSocket {
            path: "/path/to/socket".to_string(),
            server: true,
            nowait: true,
        };
        test_mmio_console_config_cmdline_parser(chardev_cfg, expected_chardev)
    }

    #[test]
    fn test_mmio_console_config_cmdline_parser_2() {
        let chardev_cfg = "socket,id=test_console,host=127.0.0.1,port=9090,server,nowait";
        let expected_chardev = ChardevType::TcpSocket {
            host: "127.0.0.1".to_string(),
            port: 9090,
            server: true,
            nowait: true,
        };
        test_mmio_console_config_cmdline_parser(chardev_cfg, expected_chardev)
    }

    fn test_pci_console_config_cmdline_parser(chardev_cfg: &str, expected_chardev: ChardevType) {
        let mut vm_config = VmConfig::default();
        let virtio_arg = "virtio-serial-pci,bus=pcie.0,addr=0x1.0x2";
        assert!(parse_virtio_serial(&mut vm_config, virtio_arg).is_ok());
        assert!(vm_config.add_chardev(chardev_cfg).is_ok());

        let virt_console = parse_virtserialport(
            &mut vm_config,
            "virtconsole,chardev=test_console,id=console1,nr=1",
            true,
            0,
            true,
        );
        assert!(virt_console.is_ok());
        let console_cfg = virt_console.unwrap();

        assert_eq!(console_cfg.id, "console1");
        let serial_info = vm_config.virtio_serial.clone().unwrap();
        assert!(serial_info.pci_bdf.is_some());
        let bdf = serial_info.pci_bdf.unwrap();
        assert_eq!(bdf.bus, "pcie.0");
        assert_eq!(bdf.addr, (1, 2));
        assert_eq!(console_cfg.chardev.backend, expected_chardev);

        let mut vm_config = VmConfig::default();
        assert!(parse_virtio_serial(
            &mut vm_config,
            "virtio-serial-pci,bus=pcie.0,addr=0x1.0x2,multifunction=on"
        )
        .is_ok());
    }

    #[test]
    fn test_pci_console_config_cmdline_parser_1() {
        let chardev_cfg = "socket,id=test_console,path=/path/to/socket,server,nowait";
        let expected_chardev = ChardevType::UnixSocket {
            path: "/path/to/socket".to_string(),
            server: true,
            nowait: true,
        };
        test_pci_console_config_cmdline_parser(chardev_cfg, expected_chardev)
    }

    #[test]
    fn test_pci_console_config_cmdline_parser_2() {
        let chardev_cfg = "socket,id=test_console,host=127.0.0.1,port=9090,server,nowait";
        let expected_chardev = ChardevType::TcpSocket {
            host: "127.0.0.1".to_string(),
            port: 9090,
            server: true,
            nowait: true,
        };
        test_pci_console_config_cmdline_parser(chardev_cfg, expected_chardev)
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
        let check_argument = |arg: String, expect: ChardevType| {
            let mut vm_config = VmConfig::default();
            assert!(vm_config.add_chardev(&arg).is_ok());
            assert!(vm_config.add_chardev(&arg).is_err());

            let device_id = "test_id";
            if let Some(char_dev) = vm_config.chardev.remove(device_id) {
                assert_eq!(char_dev.backend, expect);
            } else {
                assert!(false);
            }
        };

        check_argument("stdio,id=test_id".to_string(), ChardevType::Stdio);
        check_argument("pty,id=test_id".to_string(), ChardevType::Pty);
        check_argument(
            "file,id=test_id,path=/some/file".to_string(),
            ChardevType::File("/some/file".to_string()),
        );

        let extra_params = [
            ("", false, false),
            (",server", true, false),
            (",nowait", false, true),
            (",server,nowait", true, true),
            (",nowait,server", true, true),
        ];
        for (param, server_state, nowait_state) in extra_params {
            check_argument(
                format!("{}{}", "socket,id=test_id,path=/path/to/socket", param),
                ChardevType::UnixSocket {
                    path: "/path/to/socket".to_string(),
                    server: server_state,
                    nowait: nowait_state,
                },
            );
            check_argument(
                format!("{}{}", "socket,id=test_id,port=9090", param),
                ChardevType::TcpSocket {
                    host: "0.0.0.0".to_string(),
                    port: 9090,
                    server: server_state,
                    nowait: nowait_state,
                },
            );
            check_argument(
                format!(
                    "{}{}",
                    "socket,id=test_id,host=172.56.16.12,port=7070", param
                ),
                ChardevType::TcpSocket {
                    host: "172.56.16.12".to_string(),
                    port: 7070,
                    server: server_state,
                    nowait: nowait_state,
                },
            );
        }
    }
}
