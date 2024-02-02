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

use std::os::unix::io::RawFd;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{error::ConfigError, pci_args_check};
use crate::config::get_chardev_socket_path;
use crate::config::{
    check_arg_too_long, CmdParser, ConfigCheck, ExBool, VmConfig, DEFAULT_VIRTQUEUE_SIZE,
    MAX_PATH_LENGTH, MAX_VIRTIO_QUEUE,
};
use crate::qmp::{qmp_channel::QmpChannel, qmp_schema};

const MAC_ADDRESS_LENGTH: usize = 17;

/// Max virtqueue size of each virtqueue.
pub const MAX_QUEUE_SIZE_NET: u16 = 4096;
/// Max num of virtqueues.
const MAX_QUEUE_PAIRS: usize = MAX_VIRTIO_QUEUE / 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDevcfg {
    pub id: String,
    pub tap_fds: Option<Vec<i32>>,
    pub vhost_type: Option<String>,
    pub vhost_fds: Option<Vec<i32>>,
    pub ifname: String,
    pub queues: u16,
    pub chardev: Option<String>,
}

impl Default for NetDevcfg {
    fn default() -> Self {
        NetDevcfg {
            id: "".to_string(),
            tap_fds: None,
            vhost_type: None,
            vhost_fds: None,
            ifname: "".to_string(),
            queues: 2,
            chardev: None,
        }
    }
}

impl ConfigCheck for NetDevcfg {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "id")?;
        check_arg_too_long(&self.ifname, "ifname")?;

        if let Some(vhost_type) = self.vhost_type.as_ref() {
            if vhost_type != "vhost-kernel" && vhost_type != "vhost-user" {
                return Err(anyhow!(ConfigError::UnknownVhostType));
            }
        }

        if !is_netdev_queues_valid(self.queues) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "number queues of net device".to_string(),
                1,
                true,
                MAX_VIRTIO_QUEUE as u64 / 2,
                true,
            )));
        }

        Ok(())
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
    pub tap_fds: Option<Vec<i32>>,
    pub vhost_type: Option<String>,
    pub vhost_fds: Option<Vec<i32>>,
    pub iothread: Option<String>,
    pub queues: u16,
    pub mq: bool,
    pub socket_path: Option<String>,
    /// All queues of a net device have the same queue size now.
    pub queue_size: u16,
}

impl Default for NetworkInterfaceConfig {
    fn default() -> Self {
        NetworkInterfaceConfig {
            id: "".to_string(),
            host_dev_name: "".to_string(),
            mac: None,
            tap_fds: None,
            vhost_type: None,
            vhost_fds: None,
            iothread: None,
            queues: 2,
            mq: false,
            socket_path: None,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
        }
    }
}

impl ConfigCheck for NetworkInterfaceConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "id")?;
        check_arg_too_long(&self.host_dev_name, "host dev name")?;

        if self.mac.is_some() && !check_mac_address(self.mac.as_ref().unwrap()) {
            return Err(anyhow!(ConfigError::MacFormatError));
        }

        if self.iothread.is_some() {
            check_arg_too_long(self.iothread.as_ref().unwrap(), "iothread name")?;
        }

        if self.socket_path.is_some() && self.socket_path.as_ref().unwrap().len() > MAX_PATH_LENGTH
        {
            return Err(anyhow!(ConfigError::StringLengthTooLong(
                "socket path".to_string(),
                MAX_PATH_LENGTH
            )));
        }

        if self.queue_size < DEFAULT_VIRTQUEUE_SIZE || self.queue_size > MAX_QUEUE_SIZE_NET {
            return Err(anyhow!(ConfigError::IllegalValue(
                "queue size of net device".to_string(),
                DEFAULT_VIRTQUEUE_SIZE as u64,
                true,
                MAX_QUEUE_SIZE_NET as u64,
                true
            )));
        }

        if self.queue_size & (self.queue_size - 1) != 0 {
            bail!("queue size of net device should be power of 2!");
        }

        Ok(())
    }
}

fn parse_fds(cmd_parser: &CmdParser, name: &str) -> Result<Option<Vec<i32>>> {
    if let Some(fds) = cmd_parser.get_value::<String>(name)? {
        let mut raw_fds = Vec::new();
        for fd in fds.split(':').collect::<Vec<&str>>().iter() {
            raw_fds.push(
                (*fd)
                    .parse::<i32>()
                    .with_context(|| "Failed to parse fds")?,
            );
        }
        Ok(Some(raw_fds))
    } else {
        Ok(None)
    }
}

fn parse_netdev(cmd_parser: CmdParser) -> Result<NetDevcfg> {
    let mut net = NetDevcfg::default();
    let netdev_type = cmd_parser.get_value::<String>("")?.unwrap_or_default();
    if netdev_type.ne("tap") && netdev_type.ne("vhost-user") {
        bail!("Unsupported netdev type: {:?}", &netdev_type);
    }
    net.id = cmd_parser
        .get_value::<String>("id")?
        .with_context(|| ConfigError::FieldIsMissing("id".to_string(), "netdev".to_string()))?;
    if let Some(ifname) = cmd_parser.get_value::<String>("ifname")? {
        net.ifname = ifname;
    }
    if let Some(queue_pairs) = cmd_parser.get_value::<u16>("queues")? {
        let queues = queue_pairs.checked_mul(2);
        if queues.is_none() || !is_netdev_queues_valid(queues.unwrap()) {
            return Err(anyhow!(ConfigError::IllegalValue(
                "number queues of net device".to_string(),
                1,
                true,
                MAX_VIRTIO_QUEUE as u64 / 2,
                true,
            )));
        }

        net.queues = queues.unwrap();
    }

    if let Some(tap_fd) = parse_fds(&cmd_parser, "fd")? {
        net.tap_fds = Some(tap_fd);
    } else if let Some(tap_fds) = parse_fds(&cmd_parser, "fds")? {
        net.tap_fds = Some(tap_fds);
    }
    if let Some(fds) = &net.tap_fds {
        let fds_num =
            fds.len()
                .checked_mul(2)
                .with_context(|| format!("Invalid fds number {}", fds.len()))? as u16;
        if fds_num > net.queues {
            net.queues = fds_num;
        }
    }

    if let Some(vhost) = cmd_parser.get_value::<ExBool>("vhost")? {
        if vhost.into() {
            net.vhost_type = Some(String::from("vhost-kernel"));
        }
    } else if netdev_type.eq("vhost-user") {
        net.vhost_type = Some(String::from("vhost-user"));
    }
    if let Some(chardev) = cmd_parser.get_value::<String>("chardev")? {
        net.chardev = Some(chardev);
    }
    if let Some(vhost_fd) = parse_fds(&cmd_parser, "vhostfd")? {
        net.vhost_fds = Some(vhost_fd);
    } else if let Some(vhost_fds) = parse_fds(&cmd_parser, "vhostfds")? {
        net.vhost_fds = Some(vhost_fds);
    }
    if let Some(fds) = &net.vhost_fds {
        let fds_num = fds
            .len()
            .checked_mul(2)
            .with_context(|| format!("Invalid vhostfds number {}", fds.len()))?
            as u16;
        if fds_num > net.queues {
            net.queues = fds_num;
        }
    }

    if net.vhost_fds.is_some() && net.vhost_type.is_none() {
        bail!("Argument \'vhostfd\' is not needed for virtio-net device");
    }
    if net.tap_fds.is_none() && net.ifname.eq("") && netdev_type.ne("vhost-user") {
        bail!("Tap device is missing, use \'ifname\' or \'fd\' to configure a tap device");
    }

    net.check()?;

    Ok(net)
}

pub fn parse_net(vm_config: &mut VmConfig, net_config: &str) -> Result<NetworkInterfaceConfig> {
    let mut cmd_parser = CmdParser::new("virtio-net");
    cmd_parser
        .push("")
        .push("id")
        .push("netdev")
        .push("mq")
        .push("vectors")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("mac")
        .push("iothread")
        .push("queue-size");

    cmd_parser.parse(net_config)?;
    pci_args_check(&cmd_parser)?;
    let mut netdevinterfacecfg = NetworkInterfaceConfig::default();

    let netdev = cmd_parser
        .get_value::<String>("netdev")?
        .with_context(|| ConfigError::FieldIsMissing("netdev".to_string(), "net".to_string()))?;
    let netid = cmd_parser.get_value::<String>("id")?.unwrap_or_default();

    if let Some(mq) = cmd_parser.get_value::<ExBool>("mq")? {
        netdevinterfacecfg.mq = mq.inner;
    }
    netdevinterfacecfg.iothread = cmd_parser.get_value::<String>("iothread")?;
    netdevinterfacecfg.mac = cmd_parser.get_value::<String>("mac")?;
    if let Some(queue_size) = cmd_parser.get_value::<u16>("queue-size")? {
        netdevinterfacecfg.queue_size = queue_size;
    }

    let netcfg = &vm_config
        .netdevs
        .remove(&netdev)
        .with_context(|| format!("Netdev: {:?} not found for net device", &netdev))?;
    netdevinterfacecfg.id = netid;
    netdevinterfacecfg.host_dev_name = netcfg.ifname.clone();
    netdevinterfacecfg.tap_fds = netcfg.tap_fds.clone();
    netdevinterfacecfg.vhost_fds = netcfg.vhost_fds.clone();
    netdevinterfacecfg.vhost_type = netcfg.vhost_type.clone();
    netdevinterfacecfg.queues = netcfg.queues;
    if let Some(chardev) = &netcfg.chardev {
        netdevinterfacecfg.socket_path = Some(get_chardev_socket_path(chardev, vm_config)?);
    }

    netdevinterfacecfg.check()?;
    Ok(netdevinterfacecfg)
}

fn get_netdev_fd(fd_name: &str) -> Result<RawFd> {
    if let Some(fd) = QmpChannel::get_fd(fd_name) {
        Ok(fd)
    } else {
        // try to convert string to RawFd
        let fd_num = fd_name
            .parse::<i32>()
            .with_context(|| format!("Failed to parse fd: {}", fd_name))?;
        Ok(fd_num)
    }
}

fn get_netdev_fds(fds_name: &str) -> Result<Vec<RawFd>> {
    let fds_vec: Vec<&str> = fds_name.split(':').collect();
    let mut fds = Vec::new();
    for fd_name in fds_vec {
        fds.push(get_netdev_fd(fd_name)?);
    }
    if fds.len() > MAX_QUEUE_PAIRS {
        bail!(
            "The num of fd {} is bigger than max queue num {}",
            fds.len(),
            MAX_QUEUE_PAIRS
        );
    }
    Ok(fds)
}

pub fn get_netdev_config(args: Box<qmp_schema::NetDevAddArgument>) -> Result<NetDevcfg> {
    let queues = args
        .queues
        .unwrap_or(1)
        .checked_mul(2)
        .with_context(|| "Invalid 'queues' value")?;
    if !is_netdev_queues_valid(queues) {
        bail!(
            "The 'queues' {} is bigger than max queue num {}",
            queues / 2,
            MAX_QUEUE_PAIRS
        );
    }
    let mut config = NetDevcfg {
        id: args.id,
        tap_fds: None,
        vhost_type: None,
        vhost_fds: None,
        ifname: String::new(),
        queues,
        chardev: args.chardev,
    };

    if let Some(tap_fd) = args.fd {
        if args.if_name.is_some()
            || args.script.is_some()
            || args.downscript.is_some()
            || args.queues.is_some()
            || args.fds.is_some()
            || args.vhostfds.is_some()
        {
            bail!("fd is conflict with ifname/script/downscript/queues/fds/vhostfds");
        }
        let fd = get_netdev_fd(&tap_fd)?;
        config.tap_fds = Some(vec![fd]);

        if let Some(vhostfd) = args.vhostfd {
            let fd = get_netdev_fd(&vhostfd)?;
            config.vhost_fds = Some(vec![fd]);
        }
    } else if let Some(tap_fds) = args.fds {
        if args.if_name.is_some()
            || args.script.is_some()
            || args.downscript.is_some()
            || args.queues.is_some()
            || args.vhostfd.is_some()
        {
            bail!("fds are conflict with ifname/script/downscript/queues/vhostfd");
        }
        config.tap_fds = Some(get_netdev_fds(&tap_fds)?);
        config.queues = 2 * config.tap_fds.as_ref().unwrap().len() as u16;

        if let Some(vhostfds) = args.vhostfds {
            config.vhost_fds = Some(get_netdev_fds(&vhostfds)?);
            if config.tap_fds.as_ref().unwrap().len() != config.vhost_fds.as_ref().unwrap().len() {
                bail!("The num of vhostfds must equal to fds");
            }
        }
    } else if let Some(if_name) = args.if_name {
        config.ifname = if_name;
    }

    // Get net device type.
    let netdev_type = args.net_type.unwrap_or_default();
    let vhost = args.vhost.unwrap_or_default();
    if vhost {
        if netdev_type.ne("vhost-user") {
            config.vhost_type = Some(String::from("vhost-kernel"));
        } else {
            bail!("vhost-user netdev does not support 'vhost' option");
        }
    } else if netdev_type.eq("vhost-user") {
        config.vhost_type = Some(netdev_type.clone());
    }

    if config.vhost_fds.is_some() && config.vhost_type.is_none() {
        bail!("Argument 'vhostfd' or 'vhostfds' are not needed for virtio-net device");
    }
    if config.tap_fds.is_none() && config.ifname.eq("") && netdev_type.ne("vhost-user") {
        bail!("Tap device is missing, use 'ifname' or 'fd' to configure a tap device");
    }

    Ok(config)
}

impl VmConfig {
    pub fn add_netdev(&mut self, netdev_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("netdev");
        cmd_parser
            .push("")
            .push("id")
            .push("fd")
            .push("fds")
            .push("vhost")
            .push("ifname")
            .push("vhostfd")
            .push("vhostfds")
            .push("queues")
            .push("chardev");

        cmd_parser.parse(netdev_config)?;
        let drive_cfg = parse_netdev(cmd_parser)?;
        self.add_netdev_with_config(drive_cfg)
    }

    pub fn add_netdev_with_config(&mut self, conf: NetDevcfg) -> Result<()> {
        let netdev_id = conf.id.clone();
        if self.netdevs.get(&netdev_id).is_none() {
            self.netdevs.insert(netdev_id, conf);
        } else {
            bail!("Netdev {:?} has been added", netdev_id);
        }
        Ok(())
    }

    pub fn del_netdev_by_id(&mut self, id: &str) -> Result<()> {
        if self.netdevs.get(id).is_some() {
            self.netdevs.remove(id);
        } else {
            bail!("Netdev {} not found", id);
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

fn is_netdev_queues_valid(queues: u16) -> bool {
    queues >= 1 && queues <= MAX_VIRTIO_QUEUE as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{get_pci_bdf, MAX_STRING_LENGTH};

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
        assert!(network_configs.tap_fds.is_none());
        assert!(network_configs.vhost_type.is_none());
        assert!(network_configs.vhost_fds.is_none());

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
        assert!(network_configs.tap_fds.is_none());
        assert_eq!(
            network_configs.vhost_type,
            Some(String::from("vhost-kernel"))
        );
        assert_eq!(network_configs.vhost_fds, Some(vec![4]));

        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_netdev("tap,id=eth1,fd=35").is_ok());
        let net_cfg_res = parse_net(&mut vm_config, "virtio-net-device,id=net1,netdev=eth1");
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "net1");
        assert_eq!(network_configs.host_dev_name, "");
        assert_eq!(network_configs.tap_fds, Some(vec![35]));

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

        // multi queue testcases
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth0,ifname=tap0,queues=4")
            .is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net0,netdev=eth0,iothread=iothread0,mq=on,vectors=6",
        );
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.queues, 8);
        assert_eq!(network_configs.mq, true);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth0,fds=34:35:36:37:38")
            .is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net0,netdev=eth0,iothread=iothread0,mq=off,vectors=12",
        );
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.queues, 10);
        assert_eq!(network_configs.tap_fds, Some(vec![34, 35, 36, 37, 38]));
        assert_eq!(network_configs.mq, false);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth0,fds=34:35:36:37:38,vhost=on,vhostfds=39:40:41:42:43")
            .is_ok());
        let net_cfg_res = parse_net(
            &mut vm_config,
            "virtio-net-device,id=net0,netdev=eth0,iothread=iothread0,mq=off,vectors=12",
        );
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.queues, 10);
        assert_eq!(network_configs.vhost_fds, Some(vec![39, 40, 41, 42, 43]));
        assert_eq!(network_configs.mq, false);
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
        assert!(network_configs.tap_fds.is_none());
        assert_eq!(
            network_configs.vhost_type,
            Some(String::from("vhost-kernel"))
        );
        assert_eq!(network_configs.vhost_fds.unwrap()[0], 4);
        let pci_bdf = get_pci_bdf(net_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));

        let net_cfg_res = parse_net(&mut vm_config, net_cfg);
        assert!(net_cfg_res.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let net_cfg =
            "virtio-net-pci,id=net1,netdev=eth1,bus=pcie.0,addr=0x1.0x2,mac=12:34:56:78:9A:BC,multifunction=on";
        assert!(parse_net(&mut vm_config, net_cfg).is_ok());

        // For vhost-user net
        assert!(vm_config.add_netdev("vhost-user,id=netdevid").is_ok());
        let net_cfg =
            "virtio-net-pci,id=netid,netdev=netdevid,bus=pcie.0,addr=0x2.0x0,mac=12:34:56:78:9A:BC";
        let net_cfg_res = parse_net(&mut vm_config, net_cfg);
        assert!(net_cfg_res.is_ok());
        let network_configs = net_cfg_res.unwrap();
        assert_eq!(network_configs.id, "netid");
        assert_eq!(network_configs.vhost_type, Some("vhost-user".to_string()));
        assert_eq!(network_configs.mac, Some("12:34:56:78:9A:BC".to_string()));

        assert!(vm_config
            .add_netdev("vhost-user,id=netdevid2,chardev=chardevid2")
            .is_ok());
        let net_cfg =
            "virtio-net-pci,id=netid2,netdev=netdevid2,bus=pcie.0,addr=0x2.0x0,mac=12:34:56:78:9A:BC";
        let net_cfg_res = parse_net(&mut vm_config, net_cfg);
        assert!(net_cfg_res.is_err());
    }

    #[test]
    fn test_netdev_config_check() {
        let mut netdev_conf = NetDevcfg::default();
        for _ in 0..MAX_STRING_LENGTH {
            netdev_conf.id += "A";
        }
        assert!(netdev_conf.check().is_ok());

        // Overflow
        netdev_conf.id += "A";
        assert!(netdev_conf.check().is_err());

        let mut netdev_conf = NetDevcfg::default();
        for _ in 0..MAX_STRING_LENGTH {
            netdev_conf.ifname += "A";
        }
        assert!(netdev_conf.check().is_ok());

        // Overflow
        netdev_conf.ifname += "A";
        assert!(netdev_conf.check().is_err());

        let mut netdev_conf = NetDevcfg::default();
        netdev_conf.vhost_type = None;
        assert!(netdev_conf.check().is_ok());
        netdev_conf.vhost_type = Some(String::from("vhost-kernel"));
        assert!(netdev_conf.check().is_ok());
        netdev_conf.vhost_type = Some(String::from("vhost-"));
        assert!(netdev_conf.check().is_err());
    }

    #[test]
    fn test_add_netdev_with_different_queues() {
        let mut vm_config = VmConfig::default();

        let set_queues = |q: u16| {
            format!(
                "vhost-user,id=netdevid{num},chardev=chardevid,queues={num}",
                num = q.to_string()
            )
        };

        assert!(vm_config.add_netdev(&set_queues(0)).is_err());
        assert!(vm_config.add_netdev(&set_queues(1)).is_ok());
        assert!(vm_config
            .add_netdev(&set_queues(MAX_VIRTIO_QUEUE as u16 / 2))
            .is_ok());
        assert!(vm_config
            .add_netdev(&set_queues(MAX_VIRTIO_QUEUE as u16 / 2 + 1))
            .is_err());
    }

    #[test]
    fn test_add_netdev_with_config() {
        let mut vm_config = VmConfig::default();

        let netdev_list = ["netdev-0", "netdev-1", "netdev-2"];
        for id in netdev_list.iter() {
            let mut net_conf = NetDevcfg::default();
            net_conf.id = String::from(*id);
            assert!(vm_config.add_netdev_with_config(net_conf).is_ok());

            let netdev = vm_config.netdevs.get(*id).unwrap();
            assert_eq!(*id, netdev.id);
        }

        let mut net_conf = NetDevcfg::default();
        net_conf.id = String::from("netdev-0");
        assert!(vm_config.add_netdev_with_config(net_conf).is_err());
    }

    #[test]
    fn test_del_netdev_by_id() {
        let mut vm_config = VmConfig::default();

        assert!(vm_config.del_netdev_by_id("netdev-0").is_err());

        let netdev_list = ["netdev-0", "netdev-1", "netdev-2"];
        for id in netdev_list.iter() {
            let mut net_conf = NetDevcfg::default();
            net_conf.id = String::from(*id);
            assert!(vm_config.add_netdev_with_config(net_conf).is_ok());

            let netdev = vm_config.netdevs.get(*id).unwrap();
            assert_eq!(*id, netdev.id);
        }

        for id in netdev_list.iter() {
            let mut net_conf = NetDevcfg::default();
            net_conf.id = String::from(*id);
            assert!(vm_config.netdevs.get(*id).is_some());
            assert!(vm_config.del_netdev_by_id(*id).is_ok());
            assert!(vm_config.netdevs.get(*id).is_none());
        }
    }

    fn check_err_msg(netdev: Box<qmp_schema::NetDevAddArgument>, err_msg: &str) {
        if let Err(err) = get_netdev_config(netdev) {
            assert_eq!(err.to_string(), err_msg);
        } else {
            assert!(false);
        }
    }

    #[test]
    fn test_get_netdev_config() {
        QmpChannel::object_init();
        // Normal test with common elem.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            id: "netdev".to_string(),
            if_name: Some("tap0".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        let net_cfg = get_netdev_config(netdev).unwrap();
        assert_eq!(net_cfg.id, "netdev");
        assert_eq!(net_cfg.ifname, "tap0");

        // Set fd_name and fd_value to qmp channel.
        for i in 0..5 {
            let fd_name = "fd-net0".to_string() + &i.to_string();
            QmpChannel::set_fd(fd_name, 11 + i);
            let vhostfd_name = "vhostfd-net0".to_string() + &i.to_string();
            QmpChannel::set_fd(vhostfd_name, 21 + i);
        }

        // Normal test with 'fd' value or name.
        for value in ["11", "fd-net00"] {
            let netdev = Box::new(qmp_schema::NetDevAddArgument {
                fd: Some(value.to_string()),
                ..qmp_schema::NetDevAddArgument::default()
            });
            let net_cfg = get_netdev_config(netdev).unwrap();
            assert_eq!(net_cfg.tap_fds.unwrap()[0], 11);
        }

        // Normal test with 'fds' value or name.
        for value in ["11:12:13:14", "fd-net00:fd-net01:fd-net02:fd-net03"] {
            let netdev = Box::new(qmp_schema::NetDevAddArgument {
                fds: Some(value.to_string()),
                ..qmp_schema::NetDevAddArgument::default()
            });
            let net_cfg = get_netdev_config(netdev).unwrap();
            assert_eq!(net_cfg.tap_fds.unwrap(), [11, 12, 13, 14]);
        }

        // Normal test with 'vhostfd'.
        for (fd, vhostfd) in [("11", "21"), ("fd-net00", "vhostfd-net00")] {
            let netdev = Box::new(qmp_schema::NetDevAddArgument {
                fd: Some(fd.to_string()),
                vhostfd: Some(vhostfd.to_string()),
                vhost: Some(true),
                ..qmp_schema::NetDevAddArgument::default()
            });
            let net_cfg = get_netdev_config(netdev).unwrap();
            assert_eq!(net_cfg.tap_fds.unwrap()[0], 11);
            assert_eq!(net_cfg.vhost_fds.unwrap()[0], 21);
            assert_eq!(net_cfg.vhost_type.unwrap(), "vhost-kernel");
        }

        // Normal test with 'vhostfds'.
        for (fds, vhostfds) in [
            ("11:12:13:14", "21:22:23:24"),
            (
                "fd-net00:fd-net01:fd-net02:fd-net03",
                "vhostfd-net00:vhostfd-net01:vhostfd-net02:vhostfd-net03",
            ),
        ] {
            let netdev = Box::new(qmp_schema::NetDevAddArgument {
                fds: Some(fds.to_string()),
                vhostfds: Some(vhostfds.to_string()),
                vhost: Some(true),
                ..qmp_schema::NetDevAddArgument::default()
            });
            let net_cfg = get_netdev_config(netdev).unwrap();
            assert_eq!(net_cfg.tap_fds.unwrap(), [11, 12, 13, 14]);
            assert_eq!(net_cfg.vhost_fds.unwrap(), [21, 22, 23, 24]);
            assert_eq!(net_cfg.vhost_type.unwrap(), "vhost-kernel");
        }

        let err_msgs = [
            "Invalid 'queues' value",
            "fd is conflict with ifname/script/downscript/queues/fds/vhostfds",
            "fds are conflict with ifname/script/downscript/queues/vhostfd",
            "The num of vhostfds must equal to fds",
            "vhost-user netdev does not support 'vhost' option",
            "Argument 'vhostfd' or 'vhostfds' are not needed for virtio-net device",
            "Tap device is missing, use 'ifname' or 'fd' to configure a tap device",
        ];

        // Abnornal test with invalid 'queues': u16::MAX.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            queues: Some(u16::MAX),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[0]);

        // Abnornal test with invalid 'queues': MAX_QUEUE_PAIRS + 1.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            queues: Some(MAX_QUEUE_PAIRS as u16 + 1),
            ..qmp_schema::NetDevAddArgument::default()
        });
        let err_msg = format!(
            "The 'queues' {} is bigger than max queue num {}",
            MAX_QUEUE_PAIRS + 1,
            MAX_QUEUE_PAIRS
        );
        check_err_msg(netdev, &err_msg);

        // Abnornal test with 'fd' and 'vhostfds'.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fd: Some("11".to_string()),
            vhostfds: Some("21:22:23:24".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[1]);

        // Abnornal test with 'fds' and 'vhostfd'.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fds: Some("11:12:13:14".to_string()),
            vhostfd: Some("21".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[2]);

        // Abnornal test with different num of 'fds' and 'vhostfds'.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fds: Some("11:12:13:14".to_string()),
            vhostfds: Some("21:22:23".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[3]);

        // Abnornal test with 'net_type=vhost-user'.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fd: Some("11".to_string()),
            vhostfd: Some("21".to_string()),
            vhost: Some(true),
            net_type: Some("vhost-user".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[4]);

        // Abnornal test with 'fds/vhostfds' and no 'vhost'.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fds: Some("11:12:13:14".to_string()),
            vhostfds: Some("21:22:23:24".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[5]);

        // Abnornal test with all default value.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, &err_msgs[6]);

        // Abnornal test with invalid fd value.
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fd: Some("invalid_fd".to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        check_err_msg(netdev, "Failed to parse fd: invalid_fd");

        // Abnornal test with fd num bigger than MAX_QUEUE_PAIRS.
        let mut fds = "0".to_string();
        for i in 1..MAX_QUEUE_PAIRS + 1 {
            fds += &(":".to_string() + &i.to_string());
        }
        let netdev = Box::new(qmp_schema::NetDevAddArgument {
            fds: Some(fds.to_string()),
            ..qmp_schema::NetDevAddArgument::default()
        });
        let err_msg = format!(
            "The num of fd {} is bigger than max queue num {}",
            MAX_QUEUE_PAIRS + 1,
            MAX_QUEUE_PAIRS
        );
        check_err_msg(netdev, &err_msg);
    }
}
