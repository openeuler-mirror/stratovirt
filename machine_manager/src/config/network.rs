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
use clap::{ArgAction, Parser};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::{get_pci_df, parse_bool, str_slip_to_clap, valid_id, valid_virtqueue_size};
use crate::config::{ConfigCheck, VmConfig, DEFAULT_VIRTQUEUE_SIZE, MAX_VIRTIO_QUEUE};
use crate::qmp::{qmp_channel::QmpChannel, qmp_schema};

const MAC_ADDRESS_LENGTH: usize = 17;

/// Max virtqueue size of each virtqueue.
const MAX_QUEUE_SIZE_NET: u64 = 4096;
/// Max num of virtqueues.
const MAX_QUEUE_PAIRS: usize = MAX_VIRTIO_QUEUE / 2;

#[derive(Parser, Debug, Clone, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct NetDevcfg {
    #[arg(long, alias="classtype", value_parser = ["tap", "vhost-user"])]
    pub netdev_type: String,
    #[arg(long, value_parser = valid_id)]
    pub id: String,
    #[arg(long, aliases = ["fds", "fd"], use_value_delimiter = true, value_delimiter = ':')]
    pub tap_fds: Option<Vec<i32>>,
    #[arg(long, alias = "vhost", default_value = "off", value_parser = parse_bool, action = ArgAction::Append)]
    pub vhost_kernel: bool,
    #[arg(long, aliases = ["vhostfds", "vhostfd"], use_value_delimiter = true, value_delimiter = ':')]
    pub vhost_fds: Option<Vec<i32>>,
    #[arg(long, default_value = "", value_parser = valid_id)]
    pub ifname: String,
    #[arg(long, default_value = "1", value_parser = parse_queues)]
    pub queues: u16,
    #[arg(long)]
    pub chardev: Option<String>,
}

impl NetDevcfg {
    pub fn vhost_type(&self) -> Option<String> {
        if self.vhost_kernel {
            return Some("vhost-kernel".to_string());
        }
        if self.netdev_type == "vhost-user" {
            return Some("vhost-user".to_string());
        }
        // Default: virtio net.
        None
    }

    fn auto_queues(&mut self) -> Result<()> {
        if let Some(fds) = &self.tap_fds {
            let fds_num = fds
                .len()
                .checked_mul(2)
                .with_context(|| format!("Invalid fds number {}", fds.len()))?
                as u16;
            if fds_num > self.queues {
                self.queues = fds_num;
            }
        }
        if let Some(fds) = &self.vhost_fds {
            let fds_num = fds
                .len()
                .checked_mul(2)
                .with_context(|| format!("Invalid vhostfds number {}", fds.len()))?
                as u16;
            if fds_num > self.queues {
                self.queues = fds_num;
            }
        }
        Ok(())
    }
}

fn parse_queues(q: &str) -> Result<u16> {
    let queues = q
        .parse::<u16>()?
        .checked_mul(2)
        .with_context(|| "Invalid 'queues' value")?;
    is_netdev_queues_valid(queues)?;
    Ok(queues)
}

impl Default for NetDevcfg {
    fn default() -> Self {
        NetDevcfg {
            netdev_type: "".to_string(),
            id: "".to_string(),
            tap_fds: None,
            vhost_kernel: false,
            vhost_fds: None,
            ifname: "".to_string(),
            queues: 2,
            chardev: None,
        }
    }
}

impl ConfigCheck for NetDevcfg {
    fn check(&self) -> Result<()> {
        if self.vhost_kernel && self.netdev_type == "vhost-user" {
            bail!("vhost-user netdev does not support 'vhost' option");
        }

        if self.vhost_fds.is_some() && self.vhost_type().is_none() {
            bail!("Argument 'vhostfd' or 'vhostfds' are not needed for virtio-net device");
        }
        if self.tap_fds.is_none() && self.ifname.eq("") && self.netdev_type.ne("vhost-user") {
            bail!("Tap device is missing, use \'ifname\' or \'fd\' to configure a tap device");
        }

        is_netdev_queues_valid(self.queues)?;

        Ok(())
    }
}

/// Config struct for network
/// Contains network device config, such as `host_dev_name`, `mac`...
#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
#[serde(deny_unknown_fields)]
#[command(no_binary_name(true))]
pub struct NetworkInterfaceConfig {
    #[arg(long, value_parser = ["virtio-net-pci", "virtio-net-device"])]
    pub classtype: String,
    #[arg(long, default_value = "", value_parser = valid_id)]
    pub id: String,
    #[arg(long)]
    pub netdev: String,
    #[arg(long)]
    pub bus: Option<String>,
    #[arg(long, value_parser = get_pci_df)]
    pub addr: Option<(u8, u8)>,
    #[arg(long, value_parser = parse_bool, action = ArgAction::Append)]
    pub multifunction: Option<bool>,
    #[arg(long, value_parser = valid_mac)]
    pub mac: Option<String>,
    #[arg(long)]
    pub iothread: Option<String>,
    #[arg(long)]
    pub rx_iothread: Option<String>,
    #[arg(long)]
    pub tx_iothread: Option<String>,
    #[arg(long, default_value="off", value_parser = parse_bool, action = ArgAction::Append)]
    pub mq: bool,
    // All queues of a net device have the same queue size now.
    #[arg(long, default_value = "256", alias = "queue-size", value_parser = valid_network_queue_size)]
    pub queue_size: u16,
    // MSI-X vectors the this network device has. This member isn't used now in stratovirt.
    #[arg(long, default_value = "0")]
    pub vectors: u16,
}

impl Default for NetworkInterfaceConfig {
    fn default() -> Self {
        NetworkInterfaceConfig {
            classtype: "".to_string(),
            id: "".to_string(),
            netdev: "".to_string(),
            bus: None,
            addr: None,
            multifunction: None,
            mac: None,
            iothread: None,
            rx_iothread: None,
            tx_iothread: None,
            mq: false,
            queue_size: DEFAULT_VIRTQUEUE_SIZE,
            vectors: 0,
        }
    }
}

impl NetworkInterfaceConfig {
    pub fn auto_iothread(&mut self) {
        // If rx_iothread or tx_iothread is not configured, the default iothread will be used.
        if self.rx_iothread.is_none() {
            self.rx_iothread = self.iothread.clone();
        }
        if self.tx_iothread.is_none() {
            self.tx_iothread = self.iothread.clone();
        }
    }
}

fn valid_network_queue_size(s: &str) -> Result<u16> {
    let size: u64 = s.parse()?;
    valid_virtqueue_size(size, u64::from(DEFAULT_VIRTQUEUE_SIZE), MAX_QUEUE_SIZE_NET)?;

    Ok(size as u16)
}

impl ConfigCheck for NetworkInterfaceConfig {
    fn check(&self) -> Result<()> {
        if self.mac.is_some() && !check_mac_address(self.mac.as_ref().unwrap()) {
            return Err(anyhow!(ConfigError::MacFormatError));
        }

        valid_network_queue_size(&self.queue_size.to_string())?;

        Ok(())
    }
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
    is_netdev_queues_valid(queues)?;
    let mut config = NetDevcfg {
        netdev_type: args.net_type.unwrap_or_default(),
        id: args.id,
        tap_fds: None,
        vhost_kernel: args.vhost.unwrap_or_default(),
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

    config.check()?;

    Ok(config)
}

impl VmConfig {
    pub fn add_netdev(&mut self, netdev_config: &str) -> Result<()> {
        let mut netdev_cfg =
            NetDevcfg::try_parse_from(str_slip_to_clap(netdev_config, true, false))?;
        netdev_cfg.auto_queues()?;
        netdev_cfg.check()?;
        self.add_netdev_with_config(netdev_cfg)
    }

    pub fn add_netdev_with_config(&mut self, conf: NetDevcfg) -> Result<()> {
        let netdev_id = conf.id.clone();
        if self.netdevs.get(&netdev_id).is_some() {
            bail!("Netdev {:?} has been added", netdev_id);
        }
        self.netdevs.insert(netdev_id, conf);
        Ok(())
    }

    pub fn del_netdev_by_id(&mut self, id: &str) -> Result<()> {
        self.netdevs
            .remove(id)
            .with_context(|| format!("Netdev {} not found", id))?;

        Ok(())
    }
}

fn valid_mac(mac: &str) -> Result<String> {
    if !check_mac_address(mac) {
        return Err(anyhow!(ConfigError::MacFormatError));
    }
    Ok(mac.to_string())
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

fn is_netdev_queues_valid(queues: u16) -> Result<()> {
    if !(queues >= 2 && queues <= MAX_VIRTIO_QUEUE as u16) {
        return Err(anyhow!(ConfigError::IllegalValue(
            "number queues of net device".to_string(),
            1,
            true,
            MAX_QUEUE_PAIRS as u64,
            true,
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netdev_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();

        // Test1: Right.
        assert!(vm_config.add_netdev("tap,id=eth0,ifname=tap0").is_ok());
        assert!(vm_config.add_netdev("tap,id=eth0,ifname=tap0").is_err());
        let netdev_cfg = vm_config.netdevs.get("eth0").unwrap();
        assert_eq!(netdev_cfg.id, "eth0");
        assert_eq!(netdev_cfg.ifname, "tap0");
        assert!(netdev_cfg.tap_fds.is_none());
        assert_eq!(netdev_cfg.vhost_kernel, false);
        assert!(netdev_cfg.vhost_fds.is_none());
        assert_eq!(netdev_cfg.queues, 2);
        assert!(netdev_cfg.vhost_type().is_none());

        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let netdev_cfg = vm_config.netdevs.get("eth1").unwrap();
        assert_eq!(netdev_cfg.ifname, "tap1");
        assert_eq!(netdev_cfg.vhost_type().unwrap(), "vhost-kernel");
        assert_eq!(netdev_cfg.vhost_fds, Some(vec![4]));

        assert!(vm_config.add_netdev("tap,id=eth2,fd=35").is_ok());
        let netdev_cfg = vm_config.netdevs.get("eth2").unwrap();
        assert_eq!(netdev_cfg.tap_fds, Some(vec![35]));

        assert!(vm_config
            .add_netdev("tap,id=eth3,ifname=tap0,queues=4")
            .is_ok());
        let netdev_cfg = vm_config.netdevs.get("eth3").unwrap();
        assert_eq!(netdev_cfg.queues, 8);

        assert!(vm_config
            .add_netdev("tap,id=eth4,fds=34:35:36:37:38")
            .is_ok());
        let netdev_cfg = vm_config.netdevs.get("eth4").unwrap();
        assert_eq!(netdev_cfg.queues, 10);
        assert_eq!(netdev_cfg.tap_fds, Some(vec![34, 35, 36, 37, 38]));

        assert!(vm_config
            .add_netdev("tap,id=eth5,fds=34:35:36:37:38,vhost=on,vhostfds=39:40:41:42:43")
            .is_ok());
        let netdev_cfg = vm_config.netdevs.get("eth5").unwrap();
        assert_eq!(netdev_cfg.queues, 10);
        assert_eq!(netdev_cfg.vhost_fds, Some(vec![39, 40, 41, 42, 43]));

        // Test2: Missing values
        assert!(vm_config
            .add_netdev("tap,fds=34:35:36:37:38,vhost=on")
            .is_err());

        // Test3: Illegal values.
        assert!(vm_config
            .add_netdev("tap,id=eth10,fds=34:35:36:37:38,vhost=on,vhostfds=39,40,41,42,43")
            .is_err());
        assert!(vm_config.add_netdev("tap,id=eth10,queues=0").is_err());
        assert!(vm_config.add_netdev("tap,id=eth10,queues=17").is_err());
    }

    #[test]
    fn test_networkinterface_config_cmdline_parser() {
        // Test1: Right.
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_netdev("tap,id=eth1,ifname=tap1,vhost=on,vhostfd=4")
            .is_ok());
        let net_cmd =
            "virtio-net-pci,id=net1,netdev=eth1,bus=pcie.0,addr=0x1.0x2,mac=12:34:56:78:9A:BC,mq=on,vectors=6,queue-size=2048,multifunction=on";
        let net_cfg =
            NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false)).unwrap();
        assert_eq!(net_cfg.id, "net1");
        assert_eq!(net_cfg.netdev, "eth1");
        assert_eq!(net_cfg.bus.unwrap(), "pcie.0");
        assert_eq!(net_cfg.addr.unwrap(), (1, 2));
        assert_eq!(net_cfg.mac.unwrap(), "12:34:56:78:9A:BC");
        assert_eq!(net_cfg.vectors, 6);
        assert_eq!(net_cfg.mq, true);
        assert_eq!(net_cfg.queue_size, 2048);
        assert_eq!(net_cfg.multifunction, Some(true));
        let netdev_cfg = vm_config.netdevs.get(&net_cfg.netdev).unwrap();
        assert_eq!(netdev_cfg.vhost_type().unwrap(), "vhost-kernel");

        // Test2: Default values.
        let mut vm_config = VmConfig::default();
        assert!(vm_config.add_netdev("vhost-user,id=netdevid").is_ok());
        let net_cmd =
            "virtio-net-pci,id=netid,netdev=netdevid,bus=pcie.0,addr=0x2.0x0,mac=12:34:56:78:9A:BC";
        let net_cfg =
            NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false)).unwrap();
        assert_eq!(net_cfg.queue_size, 256);
        assert_eq!(net_cfg.mq, false);
        assert_eq!(net_cfg.vectors, 0);
        let netdev_cfg = vm_config.netdevs.get(&net_cfg.netdev).unwrap();
        assert_eq!(netdev_cfg.vhost_type().unwrap(), "vhost-user");

        // Test3: Missing Parameters.
        let net_cmd = "virtio-net-pci,id=netid";
        let result = NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false));
        assert!(result.is_err());

        // Test4: Illegal Parameters.
        let net_cmd = "virtio-net-pci,id=netid,netdev=netdevid,mac=1:1:1";
        let result = NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false));
        assert!(result.is_err());
        let net_cmd = "virtio-net-pci,id=netid,netdev=netdevid,queue-size=128";
        let result = NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false));
        assert!(result.is_err());
        let net_cmd = "virtio-net-pci,id=netid,netdev=netdevid,queue-size=10240";
        let result = NetworkInterfaceConfig::try_parse_from(str_slip_to_clap(net_cmd, true, false));
        assert!(result.is_err());
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
            assert_eq!(net_cfg.vhost_type().unwrap(), "vhost-kernel");
            assert_eq!(net_cfg.tap_fds.unwrap()[0], 11);
            assert_eq!(net_cfg.vhost_fds.unwrap()[0], 21);
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
            assert_eq!(net_cfg.vhost_type().unwrap(), "vhost-kernel");
            assert_eq!(net_cfg.tap_fds.unwrap(), vec![11, 12, 13, 14]);
            assert_eq!(net_cfg.vhost_fds.unwrap(), vec![21, 22, 23, 24]);
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
            "number queues of net device must >= 1 and <= {}.",
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
        // number queues of net device
        let err_msg = format!(
            "The num of fd {} is bigger than max queue num {}",
            MAX_QUEUE_PAIRS + 1,
            MAX_QUEUE_PAIRS
        );
        check_err_msg(netdev, &err_msg);
    }
}
