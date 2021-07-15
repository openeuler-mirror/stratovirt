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
    pci_args_check,
};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig};

const MAX_STRING_LENGTH: usize = 255;
const MAC_ADDRESS_LENGTH: usize = 17;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDevcfg {
    pub id: String,
    pub tap_fd: Option<i32>,
    pub vhost_type: Option<String>,
    pub vhost_fd: Option<i32>,
    pub ifname: String,
}

impl Default for NetDevcfg {
    fn default() -> Self {
        NetDevcfg {
            id: "".to_string(),
            tap_fd: None,
            vhost_type: None,
            vhost_fd: None,
            ifname: "".to_string(),
        }
    }
}

/// Config struct for network
/// Contains network device config, such as `host_dev_name`, `mac`...
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaceConfig {
    pub id: String,
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
            id: "".to_string(),
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
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong("id".to_string(), MAX_STRING_LENGTH).into());
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

pub fn parse_netdev(cmd_parser: CmdParser) -> Result<NetDevcfg> {
    let mut net = NetDevcfg::default();
    let netdev_type = if let Some(netdev_type) = cmd_parser.get_value::<String>("")? {
        netdev_type
    } else {
        "".to_string()
    };
    if netdev_type.ne("tap") {
        bail!("Unsupported netdev type: {:?}", &netdev_type);
    }
    if let Some(net_id) = cmd_parser.get_value::<String>("id")? {
        net.id = net_id;
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "netdev").into());
    }
    if let Some(ifname) = cmd_parser.get_value::<String>("ifname")? {
        net.ifname = ifname;
    }

    if let Some(vhost) = cmd_parser.get_value::<ExBool>("vhost")? {
        if vhost.into() {
            net.vhost_type = Some(String::from("vhost-kernel"));
        }
    }
    net.tap_fd = cmd_parser.get_value::<i32>("fd")?;
    net.vhost_fd = cmd_parser.get_value::<i32>("vhostfd")?;
    if net.vhost_fd.is_some() && net.vhost_type.is_none() {
        bail!("Argument \'vhostfd\' is not needed for virtio-net device");
    }
    if net.tap_fd.is_none() && net.ifname.eq("") {
        bail!("Tap device is missing, use \'ifname\' or \'fd\' to configure a tap device");
    }

    Ok(net)
}

pub fn parse_net(vm_config: &mut VmConfig, net_config: &str) -> Result<NetworkInterfaceConfig> {
    let mut cmd_parser = CmdParser::new("virtio-net");
    cmd_parser
        .push("")
        .push("id")
        .push("netdev")
        .push("bus")
        .push("addr")
        .push("mac")
        .push("iothread");

    cmd_parser.parse(net_config)?;
    pci_args_check(&cmd_parser)?;
    let mut netdevinterfacecfg = NetworkInterfaceConfig::default();

    let netdev = if let Some(devname) = cmd_parser.get_value::<String>("netdev")? {
        devname
    } else {
        return Err(ErrorKind::FieldIsMissing("netdev", "net").into());
    };
    let netid = if let Some(id) = cmd_parser.get_value::<String>("id")? {
        id
    } else {
        "".to_string()
    };
    netdevinterfacecfg.iothread = cmd_parser.get_value::<String>("iothread")?;
    netdevinterfacecfg.mac = cmd_parser.get_value::<String>("mac")?;

    if let Some(netcfg) = &vm_config.netdevs.remove(&netdev) {
        netdevinterfacecfg.id = netid;
        netdevinterfacecfg.host_dev_name = netcfg.ifname.clone();
        netdevinterfacecfg.tap_fd = netcfg.tap_fd;
        netdevinterfacecfg.vhost_fd = netcfg.vhost_fd;
        netdevinterfacecfg.vhost_type = netcfg.vhost_type.clone();
    } else {
        bail!("Netdev: {:?} not found for net device", &netdev);
    }

    netdevinterfacecfg.check()?;
    Ok(netdevinterfacecfg)
}

impl VmConfig {
    pub fn add_netdev(&mut self, netdev_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("netdev");
        cmd_parser
            .push("")
            .push("id")
            .push("fd")
            .push("vhost")
            .push("ifname")
            .push("vhostfd");

        cmd_parser.parse(netdev_config)?;
        let drive_cfg = parse_netdev(cmd_parser)?;
        let netdev_id = drive_cfg.id.clone();
        if self.netdevs.get(&netdev_id).is_none() {
            self.netdevs.insert(netdev_id, drive_cfg);
        } else {
            bail!("Netdev {:?} has been added");
        }

        Ok(())
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
    use crate::config::get_pci_bdf;

    use super::*;

    #[test]
    fn test_network_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_netdev("tap,id=eth0,ifname=tap0").is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net0,netdev=eth0,iothread=iothread0",
        );
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "net0");
        assert_eq!(network_configs.host_dev_name, "tap0");
        assert_eq!(network_configs.iothread, Some("iothread0".to_string()));
        assert!(network_configs.mac.is_none());
        assert!(network_configs.tap_fd.is_none());
        assert!(network_configs.vhost_type.is_none());
        assert!(network_configs.vhost_fd.is_none());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net1,netdev=eth1,mac=12:34:56:78:9A:BC",
        );
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "net1");
        assert_eq!(network_configs.host_dev_name, "tap1");
        assert_eq!(network_configs.mac, Some(String::from("12:34:56:78:9A:BC")));
        assert!(network_configs.tap_fd.is_none());
        assert_eq!(
            network_configs.vhost_type,
            Some(String::from("vhost-kernel"))
        );
        assert_eq!(network_configs.vhost_fd, Some(4));

        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_netdev("tap,id=eth1,fd=35").is_ok());
        let net_cfg_res = parse_net(&mut vm_config, "virtio-net-device,id=net1,netdev=eth1");
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "net1");
        assert_eq!(network_configs.host_dev_name, "");
        assert_eq!(network_configs.tap_fd, Some(35));

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net1,netdev=eth2,mac=12:34:56:78:9A:BC",
        );
        assert!(net_cfg_res.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_netdev("tap,id=eth1,fd=35").is_ok());
        let net_cfg_res = parse_net(&mut vm_config, "virtio-net-device,id=net1,netdev=eth3");
        assert!(net_cfg_res.is_err());
    }

    #[test]
    fn test_pci_network_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();

        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let net_cfg =
            "virtio-net-pci,id=net1,netdev=eth1,bus=pcie.0,addr=0x1.0x2,mac=12:34:56:78:9A:BC";
        let net_cfg_res = parse_net(&mut vm_config, net_cfg);
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "net1");
        assert_eq!(network_configs.host_dev_name, "tap1");
        assert_eq!(network_configs.mac, Some(String::from("12:34:56:78:9A:BC")));
        assert!(network_configs.tap_fd.is_none());
        assert_eq!(
            network_configs.vhost_type,
            Some(String::from("vhost-kernel"))
        );
        assert_eq!(network_configs.vhost_fd, Some(4));
        let pci_bdf = get_pci_bdf(net_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));

        let net_cfg_res = parse_net(&mut vm_config, net_cfg);
        assert!(net_cfg_res.is_err());
    }
}
