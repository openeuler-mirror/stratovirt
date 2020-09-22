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
}

impl NetworkInterfaceConfig {
    /// Create `NetworkInterfacesConfig` from `Value` structure
    /// `Value` structure can be gotten by `json_file`
    pub fn from_value(value: &serde_json::Value) -> Option<Vec<Self>> {
        serde_json::from_value(value.clone()).ok()
    }

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

        Ok(())
    }
}

impl VmConfig {
    /// Add new network device to `VmConfig`
    fn add_netdev(&mut self, net: NetworkInterfaceConfig) {
        if let Some(mut nets) = self.nets.clone() {
            nets.push(net);
            self.nets = Some(nets);
        } else {
            let mut nets: Vec<NetworkInterfaceConfig> = Vec::new();
            nets.push(net);
            self.nets = Some(nets);
        }
    }

    /// Update '-netdev ...' network config to `VmConfig`
    /// Some attr in `NetworkInterfaceConfig` would be found in `DeviceConfig`
    pub fn update_net(&mut self, net_config: String) {
        let cmd_params: CmdParams = CmdParams::from_str(net_config);
        let mut net = NetworkInterfaceConfig::default();

        if let Some(net_id) = cmd_params.get("id") {
            net.iface_id = net_id.value;
        }
        if let Some(net_hostname) = cmd_params.get("netdev") {
            net.host_dev_name = net_hostname.value;
        }
        if let Some(net_mac) = cmd_params.get("mac") {
            net.mac = Some(net_mac.value);
        }
        if let Some(tap_fd) = cmd_params.get("fds") {
            net.tap_fd = Some(tap_fd.value_to_u32() as i32);
        }
        if let Some(vhost) = cmd_params.get("vhost") {
            if vhost.to_bool() {
                net.vhost_type = Some("vhost-kernel".to_string());
            }
        }
        if let Some(vhostfd) = cmd_params.get("vhostfds") {
            net.vhost_fd = Some(vhostfd.value_to_u32() as i32);
        }

        self.add_netdev(net);
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
