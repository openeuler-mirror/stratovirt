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

use super::{error::ConfigError, str_slip_to_clap};
use super::{get_pci_df, parse_bool};
use crate::config::{valid_id, valid_path, valid_socket_path, ConfigCheck, VmConfig};
use crate::qmp::qmp_schema;

/// Default value of max ports for virtio-serial.
const DEFAULT_SERIAL_PORTS_NUMBER: u32 = 31;

/// Config structure for virtio-serial-port.
#[derive(Parser, Debug, Clone)]
#[command(no_binary_name(true))]
pub struct VirtioSerialPortCfg {
    #[arg(long, value_parser = ["virtconsole", "virtserialport"])]
    pub classtype: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub chardev: String,
    #[arg(long)]
    pub nr: Option<u32>,
}

impl ConfigCheck for VirtioSerialPortCfg {
    fn check(&self) -> Result<()> {
        if self.classtype != "virtconsole" && self.nr.unwrap() == 0 {
            bail!("Port number 0 on virtio-serial devices reserved for virtconsole device.");
        }

        Ok(())
    }
}

impl VirtioSerialPortCfg {
    /// If nr is not set in command line. Configure incremental maximum value for virtconsole.
    /// Configure incremental maximum value(except 0) for virtserialport.
    pub fn auto_nr(&mut self, free_port0: bool, free_nr: u32, max_nr_ports: u32) -> Result<()> {
        let free_console_nr = if free_port0 { 0 } else { free_nr };
        let auto_nr = match self.classtype.as_str() {
            "virtconsole" => free_console_nr,
            "virtserialport" => free_nr,
            _ => bail!("Invalid classtype."),
        };
        let nr = self.nr.unwrap_or(auto_nr);
        if nr >= max_nr_ports {
            bail!(
                "virtio serial port nr {} should be less than virtio serial's max_nr_ports {}",
                nr,
                max_nr_ports
            );
        }

        self.nr = Some(nr);
        Ok(())
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

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct VirtioSerialInfo {
    #[arg(long, value_parser = ["virtio-serial-pci", "virtio-serial-device"])]
    pub classtype: String,
    #[arg(long, default_value = "", value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long, default_value = "31", value_parser = clap::value_parser!(u32).range(1..=DEFAULT_SERIAL_PORTS_NUMBER as i64))]
    pub max_ports: u32,
}

impl VirtioSerialInfo {
    pub fn auto_max_ports(&mut self) {
        if self.classtype == "virtio-serial-device" {
            // Micro_vm does not support multi-ports in virtio-serial-device.
            self.max_ports = 1;
        }
    }
}

impl ConfigCheck for VirtioSerialInfo {
    fn check(&self) -> Result<()> {
        match self.classtype.as_str() {
            "virtio-serial-pci" => {}
            "virtio-serial-device" => {
                if self.bus.is_some() || self.addr.is_some() || self.multifunction.is_some() {
                    bail!("virtio mmio device should not set bus/addr/multifunction");
                }
            }
            _ => {
                bail!("Invalid classtype.");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mmio_console_config_cmdline_parser(chardev_cfg: &str, expected_chardev: ChardevType) {
        let mut vm_config = VmConfig::default();
        let serial_cmd = "virtio-serial-device";
        let mut serial_cfg =
            VirtioSerialInfo::try_parse_from(str_slip_to_clap(serial_cmd, true, false)).unwrap();
        serial_cfg.auto_max_ports();
        assert!(serial_cfg.check().is_ok());
        vm_config.virtio_serial = Some(serial_cfg.clone());
        assert!(vm_config.add_chardev(chardev_cfg).is_ok());

        let port_cmd = "virtconsole,chardev=test_console,id=console1,nr=0";
        let mut port_cfg =
            VirtioSerialPortCfg::try_parse_from(str_slip_to_clap(port_cmd, true, false)).unwrap();
        assert!(port_cfg.auto_nr(true, 0, serial_cfg.max_ports).is_ok());
        let chardev = vm_config.chardev.remove(&port_cfg.chardev).unwrap();
        assert_eq!(port_cfg.id, "console1");
        assert_eq!(port_cfg.nr.unwrap(), 0);
        assert_eq!(chardev.classtype, expected_chardev);

        // Error: VirtioSerialPortCfg.nr >= VirtioSerialInfo.max_nr_ports.
        let port_cmd = "virtconsole,chardev=test_console,id=console1,nr=1";
        let mut port_cfg =
            VirtioSerialPortCfg::try_parse_from(str_slip_to_clap(port_cmd, true, false)).unwrap();
        assert!(port_cfg.auto_nr(true, 0, serial_cfg.max_ports).is_err());

        let mut vm_config = VmConfig::default();
        let serial_cmd = "virtio-serial-device,bus=pcie.0,addr=0x1";
        let serial_cfg =
            VirtioSerialInfo::try_parse_from(str_slip_to_clap(serial_cmd, true, false)).unwrap();
        assert!(serial_cfg.check().is_err());
        assert!(vm_config
            .add_chardev("sock,id=test_console,path=/path/to/socket")
            .is_err());
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
        let serial_cmd = "virtio-serial-pci,bus=pcie.0,addr=0x1.0x2,multifunction=on";
        let mut serial_cfg =
            VirtioSerialInfo::try_parse_from(str_slip_to_clap(serial_cmd, true, false)).unwrap();
        serial_cfg.auto_max_ports();
        assert!(serial_cfg.check().is_ok());
        vm_config.virtio_serial = Some(serial_cfg.clone());
        assert!(vm_config.add_chardev(chardev_cfg).is_ok());

        let console_cmd = "virtconsole,chardev=test_console,id=console1,nr=1";
        let mut console_cfg =
            VirtioSerialPortCfg::try_parse_from(str_slip_to_clap(console_cmd, true, false))
                .unwrap();
        assert!(console_cfg.auto_nr(true, 0, serial_cfg.max_ports).is_ok());
        let chardev = vm_config.chardev.remove(&console_cfg.chardev).unwrap();
        assert_eq!(console_cfg.id, "console1");
        let serial_info = vm_config.virtio_serial.clone().unwrap();
        assert_eq!(serial_info.bus.unwrap(), "pcie.0");
        assert_eq!(serial_info.addr.unwrap(), (1, 2));
        assert_eq!(chardev.classtype, expected_chardev);
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
