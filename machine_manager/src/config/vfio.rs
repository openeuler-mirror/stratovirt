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

use anyhow::{anyhow, Result};

use super::error::ConfigError;
use crate::config::{check_arg_too_long, CmdParser, ConfigCheck};

#[derive(Default, Debug)]
pub struct VfioConfig {
    pub sysfsdev: String,
    pub host: String,
    pub id: String,
}

impl ConfigCheck for VfioConfig {
    fn check(&self) -> Result<()> {
        check_arg_too_long(&self.host, "host")?;
        check_arg_too_long(&self.id, "id")?;

        Ok(())
    }
}

pub fn parse_vfio(vfio_config: &str) -> Result<VfioConfig> {
    let mut cmd_parser = CmdParser::new("vfio-pci");
    cmd_parser
        .push("")
        .push("host")
        .push("sysfsdev")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction");
    cmd_parser.parse(vfio_config)?;

    let mut vfio: VfioConfig = VfioConfig::default();
    if let Some(host) = cmd_parser.get_value::<String>("host")? {
        vfio.host = host;
    }

    if let Some(sysfsdev) = cmd_parser.get_value::<String>("sysfsdev")? {
        vfio.sysfsdev = sysfsdev;
    }

    if vfio.host.is_empty() && vfio.sysfsdev.is_empty() {
        return Err(anyhow!(ConfigError::FieldIsMissing(
            "host nor sysfsdev".to_string(),
            "vfio".to_string()
        )));
    }

    if !vfio.host.is_empty() && !vfio.sysfsdev.is_empty() {
        return Err(anyhow!(ConfigError::InvalidParam(
            "host and sysfsdev".to_string(),
            "vfio".to_string()
        )));
    }

    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        vfio.id = id;
    }
    vfio.check()?;

    Ok(vfio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::get_pci_bdf;

    #[test]
    fn test_check_vfio_config() {
        let mut vfio_config =
            parse_vfio("vfio-pci,host=0000:1a:00.3,id=net,bus=pcie.0,addr=0x1.0x2").unwrap();
        assert!(vfio_config.check().is_ok());

        vfio_config.host = "IYqUdAMXggoUMU28eBJCxQGUirYYSyW1cfGJI3ZpZAzMFCKnVPA5e7gnurLtXjCm\
        YoG5pfqRDbN7M2dpSd8fzSbufAJaor8UY9xbH7BybZ7WDEFmkxgCQp6PWgaBSmLOCe1tEMs4RQ938ZLnh8ej\
        Q81VovbrU7ecafacCn9AJQoidN3Seab3QOEd4SJbtd4hAPeYvsXLVa6xOZxtVjqjRxk9b36feF0C5JrucVcs\
        QsusZZtVfUFUZxOoV8JltVsBmdasnic"
            .to_string();
        assert!(vfio_config.check().is_err());

        vfio_config.id = "LPwM1h4QUTCjL4fX2gFdCdPrF9S0kGHf0onpU6E4fyI6Jmzg0DCM9sffvEVjaVu1ilp\
        2OrgCWzvNBflYvUUihPj3ePPYs3erSHmSOmQZbnGEFsiBSTJHfPAsRtWJoipeIh9cgIR1tnU3OjwPPli4gmb6\
        E6GgSyMd0oQtUGFyNf5pRHlYqlx3s7PMPVUtRJP0bBnNd5eDwWAotInu33h6UI0zfKgckAxeVdEROKAExx5xWK\
        V3AgPhvvPzFx3chYymy"
            .to_string();
        assert!(vfio_config.check().is_err());
    }

    #[test]
    fn test_vfio_config_cmdline_parser() {
        let vfio_cfg = parse_vfio("vfio-pci,host=0000:1a:00.3,id=net");
        assert!(vfio_cfg.is_ok());
        let vfio_config = vfio_cfg.unwrap();
        assert_eq!(vfio_config.host, "0000:1a:00.3");
        assert_eq!(vfio_config.id, "net");
    }

    #[test]
    fn test_pci_vfio_config_cmdline_parser() {
        let vfio_cfg1 = "vfio-pci,host=0000:1a:00.3,id=net,bus=pcie.0,addr=0x1.0x2";
        let config1 = parse_vfio(vfio_cfg1);
        assert!(config1.is_ok());
        let vfio_cfg2 = "vfio-pci,host=0000:1a:00.3,bus=pcie.0,addr=0x1.0x2";
        let config2 = parse_vfio(vfio_cfg2);
        assert!(config2.is_ok());
        let vfio_cfg3 = "vfio-pci,id=net,bus=pcie.0,addr=0x1.0x2";
        let config3 = parse_vfio(vfio_cfg3);
        assert!(config3.is_err());

        let pci_bdf = get_pci_bdf(vfio_cfg1);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));

        let vfio_cfg1 =
            "vfio-pci,host=0000:1a:00.3,id=net,bus=pcie.0,addr=0x1.0x2,multifunction=on";
        assert!(parse_vfio(vfio_cfg1).is_ok());
    }
}
