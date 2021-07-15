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

use super::{
    errors::{ErrorKind, Result},
    get_pci_bdf, pci_args_check, PciBdf,
};
use crate::config::{CmdParser, ConfigCheck, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_GUEST_CID: u64 = 4_294_967_295;
const MIN_GUEST_CID: u64 = 3;

#[derive(Debug, Clone, Default)]
pub struct ConsoleConfig {
    pub id: String,
    pub socket_path: String,
}

#[derive(Debug, Clone, Default)]
pub struct VirtioConsole {
    pub id: String,
    pub console_cfg: ConsoleConfig,
}

#[derive(Debug, Clone, Default)]
pub struct CharDevice {
    pub id: String,
    pub backend: String,
}

impl ConfigCheck for ConsoleConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
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

pub fn parse_chardev(cmd_parser: CmdParser) -> Result<ConsoleConfig> {
    let mut chardev = ConsoleConfig::default();
    if let Some(chardev_id) = cmd_parser.get_value::<String>("id")? {
        chardev.id = chardev_id;
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "chardev").into());
    };

    if let Some(chardev_type) = cmd_parser.get_value::<String>("")? {
        if chardev_type == *"socket" {
            if let Some(chardev_path) = cmd_parser.get_value::<String>("path")? {
                chardev.socket_path = chardev_path;
            } else {
                return Err(ErrorKind::FieldIsMissing("path", "chardev").into());
            };
            if let Some(server) = cmd_parser.get_value::<String>("server")? {
                if server.ne("") {
                    bail!("No parament needed for server");
                }
            } else {
                bail!("Argument \'nowait\' is needed for socket chardev.");
            }
            if let Some(nowait) = cmd_parser.get_value::<String>("nowait")? {
                if nowait.ne("") {
                    bail!("No parament needed for nowait");
                }
            } else {
                bail!("Argument \'nowait\' is needed for socket chardev.");
            }
        } else {
            bail!("Unsupported chardev type: {:?}", &chardev_type);
        }
    } else {
        return Err(ErrorKind::FieldIsMissing("backend", "chardev").into());
    };

    Ok(chardev)
}

pub fn parse_virtconsole(vm_config: &VmConfig, config_args: &str) -> Result<VirtioConsole> {
    let mut cmd_parser = CmdParser::new("virtconsole");
    cmd_parser.push("").push("id").push("chardev");
    cmd_parser.parse(config_args)?;

    let chardev_name = if let Some(chardev) = cmd_parser.get_value::<String>("chardev")? {
        chardev
    } else {
        return Err(ErrorKind::FieldIsMissing("chardev", "virtconsole").into());
    };

    let id = if let Some(chardev_id) = cmd_parser.get_value::<String>("id")? {
        chardev_id
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "virtconsole").into());
    };

    if let Some(char_dev) = vm_config.chardev.get(&chardev_name) {
        Ok(VirtioConsole {
            id,
            console_cfg: char_dev.clone(),
        })
    } else {
        bail!("Chardev {:?} not found", &chardev_name);
    }
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
            bail!("Chardev {:?} has been added");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SerialConfig {
    pub stdio: bool,
}

impl VmConfig {
    pub fn add_serial(&mut self, serial_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("serial");
        cmd_parser.push("");

        cmd_parser.parse(serial_config)?;

        let mut stdio = false;
        if let Some(serial_type) = cmd_parser.get_value::<String>("")? {
            match serial_type.as_str() {
                "stdio" => stdio = true,
                _ => return Err(ErrorKind::InvalidParam(serial_type, "serial".to_string()).into()),
            }
        };
        self.serial = Some(SerialConfig { stdio });

        Ok(())
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

pub fn parse_vsock(vsock_config: &str) -> Result<VsockConfig> {
    let mut cmd_parser = CmdParser::new("vhost-vsock");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("guest-cid")
        .push("vhostfd");
    cmd_parser.parse(vsock_config)?;
    pci_args_check(&cmd_parser)?;
    let id = if let Some(vsock_id) = cmd_parser.get_value::<String>("id")? {
        vsock_id
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "vsock").into());
    };

    let guest_cid = if let Some(cid) = cmd_parser.get_value::<u64>("guest-cid")? {
        cid
    } else {
        return Err(ErrorKind::FieldIsMissing("guest-cid", "vsock").into());
    };
    let device_type = cmd_parser.get_value::<String>("")?;
    // Safe, because "parse_vsock" function only be called when certain
    // devices type are added.
    let dev_type = device_type.unwrap();
    if dev_type == *"vhost-vsock-device" {
        if cmd_parser.get_value::<String>("bus")?.is_some() {
            bail!("virtio mmio device does not support bus property");
        }
        if cmd_parser.get_value::<String>("addr")?.is_some() {
            bail!("virtio mmio device does not support addr property");
        }
    }
    let vhost_fd = cmd_parser.get_value::<i32>("vhostfd")?;
    let vsock = VsockConfig {
        id,
        guest_cid,
        vhost_fd,
    };
    Ok(vsock)
}

#[derive(Clone, Default, Debug)]
pub struct VirtioSerialInfo {
    pub id: String,
    pub pci_bdf: Option<PciBdf>,
}

impl ConfigCheck for VirtioSerialInfo {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "virtio-serial id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        Ok(())
    }
}

pub fn parse_virtio_serial(vm_config: &mut VmConfig, serial_config: &str) -> Result<()> {
    let mut cmd_parser = CmdParser::new("virtio-serial");
    cmd_parser.push("").push("id").push("bus").push("addr");
    cmd_parser.parse(serial_config)?;
    pci_args_check(&cmd_parser)?;

    if vm_config.virtio_serial.is_none() {
        let id = if let Some(id) = cmd_parser.get_value::<String>("id")? {
            id
        } else {
            "".to_string()
        };
        let virtio_serial = if serial_config.contains("-pci") {
            let pci_bdf = get_pci_bdf(serial_config)?;
            VirtioSerialInfo {
                id,
                pci_bdf: Some(pci_bdf),
            }
        } else {
            VirtioSerialInfo { id, pci_bdf: None }
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
        assert_eq!(console_cfg.console_cfg.socket_path, "/path/to/socket");

        let mut vm_config = VmConfig::default();
        assert!(
            parse_virtio_serial(&mut vm_config, "virtio-serial-device,bus=pcie.0,addr=0x1")
                .is_err()
        );
        assert!(vm_config
            .add_chardev("pty,id=test_console,path=/path/to/socket")
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
        let serial_info = vm_config.virtio_serial.unwrap();
        assert!(serial_info.pci_bdf.is_some());
        let bdf = serial_info.pci_bdf.unwrap();
        assert_eq!(bdf.bus, "pcie.0");
        assert_eq!(bdf.addr, (1, 2));
        assert_eq!(console_cfg.console_cfg.socket_path, "/path/to/socket");
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
}
