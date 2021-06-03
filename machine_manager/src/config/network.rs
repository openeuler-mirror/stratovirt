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
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAC_ADDRESS_LENGTH: usize = 17;

/// Config struct for network
/// Contains network device config, such as `host_dev_name`, `mac`...
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    pub iface_id: String,
    pub host_dev_name: String,
    pub mac: Option<String>,
    pub tap_fd: Option<i32>,
    pub vhost_type: Option<String>,
    pub vhost_fd: Option<i32>,
    pub iothread: Option<String>,
}

impl NetworkInterfaceConfig {
    pub fn set_mac(&mut self, mac_addr: String) {
        self.mac = Some(mac_addr);
    }
}

impl Default for NetworkInterfaceConfig {
    fn default() -> Self {
        NetworkInterfaceConfig {
            iface_id: "".to_string(),
            host_dev_name: "".to_string(),
            mac: None,
            tap_fd: None,
            vhost_type: None,
            vhost_fd: None,
            iothread: None,
        }
    }
}

impl ConfigCheck for NetworkInterfaceConfig {
    fn check(&self) -> Result<()> {
        if self.iface_id.len() > MAX_STRING_LENGTH {
            return Err(
                ErrorKind::StringLengthTooLong("iface id".to_string(), MAX_STRING_LENGTH).into(),
            );
        }

        if self.host_dev_name.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                self.host_dev_name.clone(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.mac.is_some() && !check_mac_address(self.mac.as_ref().unwrap()) {
            return Err(ErrorKind::MacFormatError.into());
        }

        if let Some(vhost_type) = self.vhost_type.as_ref() {
            if vhost_type != "vhost-kernel" {
                return Err(ErrorKind::UnknownVhostType.into());
            }
        }

        if self.iothread.is_some() && self.iothread.as_ref().unwrap().len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "iothread name".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        Ok(())
    }
}

impl VmConfig {
    /// Add new network device to `VmConfig`
    fn add_netdev(&mut self, net: NetworkInterfaceConfig) -> Result<()> {
        if self.nets.is_some() {
            for n in self.nets.as_ref().unwrap() {
                if n.iface_id == net.iface_id {
                    return Err(
                        ErrorKind::IdRepeat("netdev".to_string(), n.iface_id.to_string()).into(),
                    );
                }
            }
            self.nets.as_mut().unwrap().push(net);
        } else {
            self.nets = Some(vec![net]);
        }

        Ok(())
    }

    /// Add '-netdev ...' network config to `VmConfig`
    /// Some attr in `NetworkInterfaceConfig` would be found in `DeviceConfig`
    pub fn add_net(&mut self, net_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("netdev");
        cmd_parser
            .push("id")
            .push("netdev")
            .push("mac")
            .push("fds")
            .push("vhost")
            .push("vhostfds")
            .push("iothread");

        cmd_parser.parse(net_config)?;

        let mut net = NetworkInterfaceConfig::default();
        if let Some(net_id) = cmd_parser.get_value::<String>("id")? {
            net.iface_id = net_id;
        } else {
            return Err(ErrorKind::FieldIsMissing("id", "netdev").into());
        }
        if let Some(net_hostname) = cmd_parser.get_value::<String>("netdev")? {
            net.host_dev_name = net_hostname;
        } else {
            return Err(ErrorKind::FieldIsMissing("netdev", "netdev").into());
        }
        if let Some(vhost) = cmd_parser.get_value::<ExBool>("vhost")? {
            if vhost.into() {
                net.vhost_type = Some(String::from("vhost-kernel"));
            }
        }
        net.mac = cmd_parser.get_value::<String>("mac")?;
        net.tap_fd = cmd_parser.get_value::<i32>("fds")?;
        net.vhost_fd = cmd_parser.get_value::<i32>("vhostfds")?;
        net.iothread = cmd_parser.get_value::<String>("iothread")?;

        self.add_netdev(net)
    }
}

fn check_mac_address(mac: &str) -> bool {
    if mac.len() != MAC_ADDRESS_LENGTH {
        return false;
    }

    let mac_vec: Vec<&str> = mac.split(':').collect();
    if mac_vec.len() != 6 {
        return false;
    }

    let bit_list = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B',
        'C', 'D', 'E', 'F',
    ];
    for mac_bit in mac_vec {
        if mac_bit.len() != 2 {
            return false;
        }
        let mut mac_bit_char = mac_bit.chars();
        if !bit_list.contains(&mac_bit_char.next().unwrap())
            || !bit_list.contains(&mac_bit_char.next().unwrap())
        {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_net("id=eth0,netdev=tap0").is_ok());
        let configs = vm_config.nets.clone();
        assert!(configs.is_some());
        let network_configs = configs.unwrap();
        assert_eq!(network_configs[0].iface_id, "eth0");
        assert_eq!(network_configs[0].host_dev_name, "tap0");
        assert!(network_configs[0].mac.is_none());
        assert!(network_configs[0].tap_fd.is_none());
        assert!(network_configs[0].vhost_type.is_none());
        assert!(network_configs[0].vhost_fd.is_none());
        assert!(vm_config
            .add_net("id=eth1,netdev=tap1,mac=12:34:56:78:9A:BC,vhost=on,vhostfds=4")
            .is_ok());
        let configs = vm_config.nets.clone();
        assert!(configs.is_some());
        let network_configs = configs.unwrap();
        assert_eq!(network_configs[1].iface_id, "eth1");
        assert_eq!(network_configs[1].host_dev_name, "tap1");
        assert_eq!(
            network_configs[1].mac,
            Some(String::from("12:34:56:78:9A:BC"))
        );
        assert!(network_configs[1].tap_fd.is_none());
        assert_eq!(
            network_configs[1].vhost_type,
            Some(String::from("vhost-kernel"))
        );
        assert_eq!(network_configs[1].vhost_fd, Some(4));
    }
}
