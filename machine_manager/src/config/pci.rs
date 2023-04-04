// Copyright (c) 2020 Huawei Technologies Co.,Ltd. All rights reserved.
//
// Stratovirt is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan
// PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//         http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
// KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::{CmdParser, ConfigCheck};
use crate::config::{check_arg_too_long, ExBool};
use util::num_ops::str_to_usize;

/// Basic information of pci devices such as bus number,
/// slot number and function number.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PciBdf {
    /// Bus number
    pub bus: String,
    /// Slot number and func number
    pub addr: (u8, u8),
}

impl PciBdf {
    pub fn new(bus: String, addr: (u8, u8)) -> Self {
        PciBdf { bus, addr }
    }
}

impl Default for PciBdf {
    fn default() -> PciBdf {
        PciBdf {
            bus: "pcie.0".to_string(),
            addr: (0, 0),
        }
    }
}

/// Basic information of RootPort like port number.
#[derive(Debug, Clone)]
pub struct RootPortConfig {
    pub port: u8,
    pub id: String,
    pub multifunction: bool,
}

impl ConfigCheck for RootPortConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.id, "root_port id")
    }
}

impl Default for RootPortConfig {
    fn default() -> Self {
        RootPortConfig {
            port: 0,
            id: "".to_string(),
            multifunction: false,
        }
    }
}

pub fn get_pci_df(addr: &str) -> Result<(u8, u8)> {
    let addr_vec: Vec<&str> = addr.split('.').collect();
    if addr_vec.len() > 2 {
        bail!(
            "The number of args for addr is supported to be no more than two, find :{}",
            addr_vec.len()
        );
    }

    let slot = addr_vec.first().unwrap();
    let slot =
        str_to_usize(slot.to_string()).with_context(|| format!("Invalid slot num: {}", slot))?;
    if slot > 31 {
        bail!("Invalid slot num: {}", slot);
    }

    let func = if addr_vec.get(1).is_some() {
        let function = addr_vec.get(1).unwrap();
        str_to_usize(function.to_string())
            .with_context(|| format!("Invalid function num: {}", function))?
    } else {
        0
    };
    if func > 7 {
        bail!("Invalid function num: {}", func);
    }

    Ok((slot as u8, func as u8))
}

pub fn get_pci_bdf(pci_cfg: &str) -> Result<PciBdf> {
    let mut cmd_parser = CmdParser::new("bdf");
    cmd_parser.push("").push("bus").push("addr");
    cmd_parser.get_parameters(pci_cfg)?;

    let mut pci_bdf = PciBdf::default();
    if let Some(bus) = cmd_parser.get_value::<String>("bus")? {
        pci_bdf.bus = bus;
    } else {
        bail!("Bus not specified for pci device");
    }
    if let Some(addr) = cmd_parser.get_value::<String>("addr")? {
        pci_bdf.addr = get_pci_df(&addr).with_context(|| "Failed to get addr")?;
    } else {
        bail!("No addr found for pci device");
    }
    Ok(pci_bdf)
}

pub fn get_multi_function(pci_cfg: &str) -> Result<bool> {
    let mut cmd_parser = CmdParser::new("multifunction");
    cmd_parser.push("").push("multifunction");
    cmd_parser.get_parameters(pci_cfg)?;

    if let Some(multi_func) = cmd_parser
        .get_value::<ExBool>("multifunction")
        .with_context(|| "Failed to get multifunction parameter, please set on or off (default).")?
    {
        return Ok(multi_func.inner);
    }

    Ok(false)
}

pub fn parse_root_port(rootport_cfg: &str) -> Result<RootPortConfig> {
    let mut cmd_parser = CmdParser::new("pcie-root-port");
    cmd_parser
        .push("")
        .push("bus")
        .push("addr")
        .push("port")
        .push("chassis")
        .push("multifunction")
        .push("id");
    cmd_parser.parse(rootport_cfg)?;

    let mut root_port = RootPortConfig::default();
    let port = cmd_parser.get_value::<String>("port")?;
    if port.is_none() {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "port".to_string(),
            "rootport".to_string()
        )));
    }
    // Safety: as port is validated non-none at the previous line, it's safe to unwrap() it
    root_port.port = str_to_usize(port.unwrap())? as u8;

    let _ = cmd_parser.get_value::<u8>("chassis")?;

    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        root_port.id = id;
    } else {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "id".to_string(),
            "rootport".to_string()
        )));
    }
    root_port.multifunction =
        if let Some(multi_func) = cmd_parser.get_value::<ExBool>("multifunction")? {
            multi_func.into()
        } else {
            false
        };
    root_port.check()?;

    Ok(root_port)
}

pub fn pci_args_check(cmd_parser: &CmdParser) -> Result<()> {
    let device_type = cmd_parser.get_value::<String>("")?;
    let dev_type = device_type.unwrap();
    // Safe, because this function only be called when certain
    // devices type are added.
    if dev_type.ends_with("-device") {
        if cmd_parser.get_value::<String>("bus")?.is_some() {
            bail!("virtio mmio device does not support bus arguments");
        }
        if cmd_parser.get_value::<String>("addr")?.is_some() {
            bail!("virtio mmio device does not support addr arguments");
        }
        if cmd_parser.get_value::<ExBool>("multifunction")?.is_some() {
            bail!("virtio mmio device does not support multifunction arguments");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pci_df() {
        let addr = "0x7";
        let df = get_pci_df(addr);
        assert!(df.is_ok());
        assert_eq!(df.unwrap(), (7, 0));

        let addr = "0x10.0x4";
        let df = get_pci_df(addr);
        assert!(df.is_ok());
        assert_eq!(df.unwrap(), (16, 4));

        let addr = "8.2";
        let df = get_pci_df(addr);
        assert!(df.is_ok());
        assert_eq!(df.unwrap(), (8, 2));

        let addr = ".0x5";
        let df = get_pci_df(addr);
        assert!(df.is_err());

        let addr = "0x111";
        let df = get_pci_df(addr);
        assert!(df.is_err());
    }

    #[test]
    fn test_get_pci_bdf_01() {
        let pci_bdf = get_pci_bdf("virtio-blk-device,bus=pcie.0,addr=0x1.0x2");
        assert!(pci_bdf.is_ok());
        let bdf = pci_bdf.unwrap();
        assert_eq!(bdf.bus, "pcie.0".to_string());
        assert_eq!(bdf.addr, (1, 2));

        let pci_bdf = get_pci_bdf("virtio-balloon-device,bus=pcie.0,addr=0x1");
        assert!(pci_bdf.is_ok());
        let bdf = pci_bdf.unwrap();
        assert_eq!(bdf.bus, "pcie.0".to_string());
        assert_eq!(bdf.addr, (1, 0));
    }

    #[test]
    fn test_get_pci_bdf_02() {
        let pci_bdf = get_pci_bdf("virtio-balloon-device,bus=pcie.0,addr=0x1.0x2.0x3");
        assert!(pci_bdf.is_err());
        // Error, because too many args in option "addr".

        let pci_bdf = get_pci_bdf("virtio-balloon-device,bus=pcie.0,addr=abcd.dcba");
        assert!(pci_bdf.is_err());

        let pci_bdf = get_pci_bdf("virtio-balloon-device,bus=pcie.0");
        assert!(pci_bdf.is_err());

        let pci_bdf = get_pci_bdf("virtio-balloon-device,addr=0x1.0x2");
        assert!(pci_bdf.is_err());
    }

    #[test]
    fn test_get_multi_function() {
        assert_eq!(
            get_multi_function("virtio-balloon-device,bus=pcie.0,addr=0x1.0x2").unwrap(),
            false
        );
        assert_eq!(
            get_multi_function("virtio-balloon-device,bus=pcie.0,addr=0x1.0x2,multifunction=on")
                .unwrap(),
            true
        );
        assert_eq!(
            get_multi_function("virtio-balloon-device,bus=pcie.0,addr=0x1.0x2,multifunction=off")
                .unwrap(),
            false
        );
        assert!(get_multi_function(
            "virtio-balloon-device,bus=pcie.0,addr=0x1.0x2,multifunction=close"
        )
        .is_err());
    }
}
