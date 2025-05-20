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

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::get_value_of_parameter;
use util::num_ops::str_to_num;

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

pub fn get_pci_df(addr: &str) -> Result<(u8, u8)> {
    let addr_vec: Vec<&str> = addr.split('.').collect();
    if addr_vec.len() > 2 {
        bail!(
            "The number of args for addr is supported to be no more than two, find :{}",
            addr_vec.len()
        );
    }

    let slot = addr_vec.first().unwrap();
    let slot = str_to_num::<u8>(slot).with_context(|| format!("Invalid slot num: {}", slot))?;
    if slot > 31 {
        bail!("Invalid slot num: {}", slot);
    }

    let func = if addr_vec.get(1).is_some() {
        let function = addr_vec.get(1).unwrap();
        str_to_num::<u8>(function).with_context(|| format!("Invalid function num: {}", function))?
    } else {
        0
    };
    if func > 7 {
        bail!("Invalid function num: {}", func);
    }

    Ok((slot, func))
}

pub fn get_pci_bdf(pci_cfg: &str) -> Result<PciBdf> {
    let bus = get_value_of_parameter("bus", pci_cfg)?;
    let addr_str = get_value_of_parameter("addr", pci_cfg)?;
    if addr_str.is_empty() {
        bail!("Invalid addr.");
    }
    let addr = get_pci_df(&addr_str).with_context(|| "Failed to get addr")?;
    let pci_bdf = PciBdf::new(bus, addr);

    Ok(pci_bdf)
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
}
