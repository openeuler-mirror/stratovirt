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
use clap::{ArgAction, Parser, Subcommand};
use log::error;
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, get_pci_bdf, pci_args_check, str_slip_to_clap, PciBdf};
use crate::config::{
    check_arg_too_long, valid_id, valid_path, valid_socket_path, CmdParser, ConfigCheck, ExBool,
    VmConfig,
};
use crate::qmp::qmp_schema;

const MAX_GUEST_CID: u64 = 4_294_967_295;
const MIN_GUEST_CID: u64 = 3;

/// Default value of max ports for virtio-serial.
const DEFAULT_SERIAL_PORTS_NUMBER: u32 = 31;

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
#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct ChardevConfig {
    #[command(subcommand)]
    pub classtype: ChardevType,
}

impl ChardevConfig {
    pub fn id(&self) -> String {
        match &self.classtype {
            ChardevType::Stdio { id } => id,
            ChardevType::Pty { id } => id,
            ChardevType::Socket { id, .. } => id,
            ChardevType::File { id, .. } => id,
        }
        .clone()
    }
}

impl ConfigCheck for ChardevConfig {
    fn check(&self) -> Result<()> {
        if let ChardevType::Socket { .. } = self.classtype {
            self.classtype.socket_type()?;
        }

        Ok(())
    }
}

/// Character device options.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChardevType {
    Stdio {
        #[arg(long, value_parser = valid_id)]
        id: String,
    },
    Pty {
        #[arg(long, value_parser = valid_id)]
        id: String,
    },
    // Unix Socket: use `path`.
    // Tcp Socket: use `host` and `port`.
    #[clap(group = clap::ArgGroup::new("unix-socket").args(&["host", "port"]).requires("port").multiple(true).conflicts_with("tcp-socket"))]
    #[clap(group = clap::ArgGroup::new("tcp-socket").arg("path").conflicts_with("unix-socket"))]
    Socket {
        #[arg(long, value_parser = valid_id)]
        id: String,
        #[arg(long, value_parser = valid_socket_path)]
        path: Option<String>,
        #[arg(long, value_parser = valid_host, default_value = "0.0.0.0")]
        host: String,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        #[arg(long, action = ArgAction::SetTrue)]
        server: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        nowait: bool,
    },
    File {
        #[arg(long, value_parser = valid_id)]
        id: String,
        #[arg(long, value_parser = valid_path)]
        path: String,
    },
}

impl ChardevType {
    pub fn socket_type(&self) -> Result<SocketType> {
        if let ChardevType::Socket {
            path, host, port, ..
        } = self
        {
            if path.is_some() && port.is_none() {
                return Ok(SocketType::Unix {
                    path: path.clone().unwrap(),
                });
            } else if port.is_some() && path.is_none() {
                return Ok(SocketType::Tcp {
                    host: host.clone(),
                    port: (*port).unwrap(),
                });
            }
        }
        bail!("Not socket type or invalid socket type");
    }
}

pub enum SocketType {
    Unix { path: String },
    Tcp { host: String, port: u16 },
}

fn valid_host(host: &str) -> Result<String> {
    let ip_address = IpAddr::from_str(host);
    if ip_address.is_err() {
        return Err(anyhow!(ConfigError::InvalidParam(
            "host".to_string(),
            "tcp-socket".to_string()
        )));
    }
    Ok(host.to_string())
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
        classtype: ChardevType::Socket {
            id: args.id,
            path: Some(addr.addr_data.path),
            host: "0.0.0.0".to_string(),
            port: None,
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
pub fn get_chardev_socket_path(chardev: ChardevConfig) -> Result<String> {
    let id = chardev.id();
    if let ChardevType::Socket {
        path,
        server,
        nowait,
        ..
    } = chardev.classtype
    {
        path.clone()
            .with_context(|| format!("Chardev {:?} backend should be unix-socket type.", id))?;
        if server || nowait {
            bail!(
                "Argument \'server\' or \'nowait\' is not need for chardev \'{}\'",
                path.unwrap()
            );
        }
        return Ok(path.unwrap());
    }
    bail!("Chardev {:?} backend should be unix-socket type.", id);
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
        let chardev = ChardevConfig::try_parse_from(str_slip_to_clap(chardev_config, true, true))?;
        chardev.check()?;
        self.add_chardev_with_config(chardev)?;
        Ok(())
    }

    /// Add chardev config to vm config.
    ///
    /// # Arguments
    ///
    /// * `conf` - The chardev config to be added to the vm.
    pub fn add_chardev_with_config(&mut self, conf: ChardevConfig) -> Result<()> {
        let chardev_id = conf.id();
        if self.chardev.get(&chardev_id).is_some() {
            bail!("Chardev {:?} has been added", chardev_id);
        }
        self.chardev.insert(chardev_id, conf);
        Ok(())
    }

    /// Delete chardev config from vm config.
    ///
    /// # Arguments
    ///
    /// * `id` - The chardev id which is used to delete chardev config.
    pub fn del_chardev_by_id(&mut self, id: &str) -> Result<()> {
        self.chardev
            .remove(id)
            .with_context(|| format!("Chardev {} not found", id))?;
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
        assert_eq!(console_cfg.chardev.classtype, expected_chardev);

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
        let expected_chardev = ChardevType::Socket {
            id: "test_console".to_string(),
            path: Some("/path/to/socket".to_string()),
            host: "0.0.0.0".to_string(),
            port: None,
            server: true,
            nowait: true,
        };
        test_mmio_console_config_cmdline_parser(chardev_cfg, expected_chardev)
    }

    #[test]
    fn test_mmio_console_config_cmdline_parser_2() {
        let chardev_cfg = "socket,id=test_console,host=127.0.0.1,port=9090,server,nowait";
        let expected_chardev = ChardevType::Socket {
            id: "test_console".to_string(),
            path: None,
            host: "127.0.0.1".to_string(),
            port: Some(9090),
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
        assert_eq!(console_cfg.chardev.classtype, expected_chardev);

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
        let expected_chardev = ChardevType::Socket {
            id: "test_console".to_string(),
            path: Some("/path/to/socket".to_string()),
            host: "0.0.0.0".to_string(),
            port: None,
            server: true,
            nowait: true,
        };
        test_pci_console_config_cmdline_parser(chardev_cfg, expected_chardev)
    }

    #[test]
    fn test_pci_console_config_cmdline_parser_2() {
        let chardev_cfg = "socket,id=test_console,host=127.0.0.1,port=9090,server,nowait";
        let expected_chardev = ChardevType::Socket {
            id: "test_console".to_string(),
            path: None,
            host: "127.0.0.1".to_string(),
            port: Some(9090),
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
                assert_eq!(char_dev.classtype, expect);
            } else {
                assert!(false);
            }
        };

        check_argument(
            "stdio,id=test_id".to_string(),
            ChardevType::Stdio {
                id: "test_id".to_string(),
            },
        );
        check_argument(
            "pty,id=test_id".to_string(),
            ChardevType::Pty {
                id: "test_id".to_string(),
            },
        );
        check_argument(
            "file,id=test_id,path=/some/file".to_string(),
            ChardevType::File {
                id: "test_id".to_string(),
                path: "/some/file".to_string(),
            },
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
                ChardevType::Socket {
                    id: "test_id".to_string(),
                    path: Some("/path/to/socket".to_string()),
                    host: "0.0.0.0".to_string(),
                    port: None,
                    server: server_state,
                    nowait: nowait_state,
                },
            );
            check_argument(
                format!("{}{}", "socket,id=test_id,port=9090", param),
                ChardevType::Socket {
                    id: "test_id".to_string(),
                    path: None,
                    host: "0.0.0.0".to_string(),
                    port: Some(9090),
                    server: server_state,
                    nowait: nowait_state,
                },
            );
            check_argument(
                format!(
                    "{}{}",
                    "socket,id=test_id,host=172.56.16.12,port=7070", param
                ),
                ChardevType::Socket {
                    id: "test_id".to_string(),
                    path: None,
                    host: "172.56.16.12".to_string(),
                    port: Some(7070),
                    server: server_state,
                    nowait: nowait_state,
                },
            );
        }
    }
}
