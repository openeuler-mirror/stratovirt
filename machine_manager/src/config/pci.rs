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

extern crate serde;
extern crate serde_json;

use super::errors::{Result, ResultExt};
use super::CmdParser;

/// Basic information of pci devices such as bus number,
/// slot number and function number.
#[derive(Debug, Clone)]
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
}

impl Default for RootPortConfig {
    fn default() -> Self {
        RootPortConfig {
            port: 0,
            id: "".to_string(),
        }
    }
}

pub fn get_pci_bdf(cmd_parser: CmdParser) -> Result<PciBdf> {
    let mut pci_bdf = PciBdf::default();
    if let Some(bus) = cmd_parser.get_value::<String>("bus")? {
        pci_bdf.bus = bus;
    } else {
        bail!("Bus not specified for pci device");
    }
    if let Some(addr) = cmd_parser.get_value::<String>("addr")? {
        let addr_vec: Vec<&str> = addr.split('.').collect();
        if addr_vec.len() > 2 {
            bail!(
                "The number of args for addr is supported to be no more than two, find :{}",
                addr_vec.len()
            );
        }
        let slot = addr_vec.get(0).unwrap();
        let without_prefix = slot.trim_start_matches("0x");
        let slot = u8::from_str_radix(without_prefix, 16)
            .chain_err(|| format!("Invalid slot num: {}", slot))?;
        if slot > 31 {
            bail!("Invalid slot num: {}", slot);
        }
        let func = if addr_vec.get(1).is_some() {
            let function = addr_vec.get(1).unwrap();
            let without_prefix = function.trim_start_matches("0x");
            u8::from_str_radix(without_prefix, 16)
                .chain_err(|| format!("Invalid function num: {}", function))?
        } else {
            0
        };
        if func > 7 {
            bail!("Invalid function num: {}", func);
        }
        pci_bdf.addr = (slot, func);
    } else {
        bail!("No addr found for pci device");
    }
    Ok(pci_bdf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pci_bdf_01() {
        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("bus=pcie.0,addr=0x1.0x2").is_ok());
        let bdf = get_pci_bdf(cmd_parser).unwrap();
        assert_eq!(bdf.bus, "pcie.0".to_string());
        assert_eq!(bdf.addr, (1, 2));
    }

    #[test]
    fn test_get_pci_bdf_02() {
        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("bus=pcie.0,addr=0x1").is_ok());
        let bdf = get_pci_bdf(cmd_parser).unwrap();
        assert_eq!(bdf.bus, "pcie.0".to_string());
        assert_eq!(bdf.addr, (1, 0));
    }
    #[test]
    fn test_get_pci_bdf_03() {
        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("bus=pcie.0,addr=0x1.0x2.0x3").is_ok());
        // Error, because too many args in option "addr".
        assert!(get_pci_bdf(cmd_parser).is_err());

        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("bus=pcie.0,addr=abcd.dcba").is_ok());
        assert!(get_pci_bdf(cmd_parser).is_err());

        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("bus=pcie.0").is_ok());
        assert!(get_pci_bdf(cmd_parser).is_err());

        let mut cmd_parser = CmdParser::new("pci");

        cmd_parser.push("").push("bus").push("addr");
        assert!(cmd_parser.parse("addr=0x1.0x2").is_ok());
        assert!(get_pci_bdf(cmd_parser).is_err());
    }
}
