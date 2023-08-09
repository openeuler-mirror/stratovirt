// Copyright (c) 2023 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{CmdParser, VmConfig};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType0Config {
    pub vender: Option<String>,
    pub version: Option<String>,
    pub date: Option<String>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType1Config {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub serial: Option<String>,
    pub sku: Option<String>,
    pub family: Option<String>,
    pub uuid: Option<Uuid>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType2Config {
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub serial: Option<String>,
    pub asset: Option<String>,
    pub location: Option<String>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType3Config {
    pub manufacturer: Option<String>,
    pub version: Option<String>,
    pub serial: Option<String>,
    pub sku: Option<String>,
    pub asset: Option<String>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType4Config {
    pub manufacturer: Option<String>,
    pub version: Option<String>,
    pub serial: Option<String>,
    pub asset: Option<String>,
    pub sock_pfx: Option<String>,
    pub part: Option<String>,
    pub max_speed: Option<u64>,
    pub current_speed: Option<u64>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosType17Config {
    pub manufacturer: Option<String>,
    pub serial: Option<String>,
    pub asset: Option<String>,
    pub loc_pfx: Option<String>,
    pub part: Option<String>,
    pub speed: u16,
    pub bank: Option<String>,
    pub added: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct SmbiosConfig {
    pub type0: SmbiosType0Config,
    pub type1: SmbiosType1Config,
    pub type2: SmbiosType2Config,
    pub type3: SmbiosType3Config,
    pub type4: SmbiosType4Config,
    pub type17: SmbiosType17Config,
}

/// Check if the uuid is valid.
fn check_valid_uuid(uuid: &str) -> bool {
    if uuid.len() != 36 {
        return false;
    }

    // Char located at 8, 13, 18, 23 should be `-`
    let indexes = &[8, 13, 18, 23];
    for i in indexes {
        if uuid.chars().nth(*i).unwrap() != '-' {
            return false;
        }
    }

    for ch in uuid.chars() {
        if ch != '-' && (!ch.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

/// Convert an ASCII string to a 128-bit buffer.
/// format: 33DB4D5E-1FF7-401C-9657-7441C03DD766
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Uuid {
    pub name: Vec<u8>,
}

impl FromStr for Uuid {
    type Err = ();

    fn from_str(str: &str) -> std::result::Result<Self, Self::Err> {
        let name = str.to_string();

        if !check_valid_uuid(&name) {
            return Err(());
        }

        let mut uuid_bytes = Vec::new();
        // If the UUID is "aabbccdd-eeff-gghh-iijj-kkllmmnnoopp", then the encoded order is:
        // dd cc bb aa ff ee hh gg ii jj kk ll mm nn oo pp
        let index = &[6, 4, 2, 0, 11, 9, 16, 14, 19, 21, 24, 26, 28, 30, 32, 34];

        for i in index {
            let mut chars = name.chars();
            uuid_bytes.push(
                (chars.nth(*i).unwrap().to_digit(16).unwrap() as u8) << 4
                    | chars.next().unwrap().to_digit(16).unwrap() as u8,
            );
        }
        Ok(Uuid { name: uuid_bytes })
    }
}

impl VmConfig {
    /// # Arguments
    ///
    /// * `type0` - The type0 cmdline string.
    fn add_smbios_type0(&mut self, type0: &str) -> Result<()> {
        if self.smbios.type0.added {
            bail!("smbios type0 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("vendor")
            .push("version")
            .push("date");
        cmd_parser.parse(type0)?;

        self.smbios.type0.vender = cmd_parser.get_value::<String>("vendor")?;
        self.smbios.type0.version = cmd_parser.get_value::<String>("version")?;
        self.smbios.type0.date = cmd_parser.get_value::<String>("date")?;
        self.smbios.type0.added = true;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type1` - The type1 cmdline string.
    fn add_smbios_type1(&mut self, type1: &str) -> Result<()> {
        if self.smbios.type1.added {
            bail!("smbios type1 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("manufacturer")
            .push("product")
            .push("version")
            .push("serial")
            .push("sku")
            .push("uuid")
            .push("family");
        cmd_parser.parse(type1)?;

        self.smbios.type1.manufacturer = cmd_parser.get_value::<String>("manufacturer")?;
        self.smbios.type1.product = cmd_parser.get_value::<String>("product")?;
        self.smbios.type1.version = cmd_parser.get_value::<String>("version")?;
        self.smbios.type1.serial = cmd_parser.get_value::<String>("serial")?;
        self.smbios.type1.sku = cmd_parser.get_value::<String>("sku")?;
        self.smbios.type1.family = cmd_parser.get_value::<String>("family")?;
        self.smbios.type1.uuid = cmd_parser.get_value::<Uuid>("uuid")?;
        self.smbios.type1.added = true;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type2` - The type2 cmdline string.
    fn add_smbios_type2(&mut self, type2: &str) -> Result<()> {
        if self.smbios.type2.added {
            bail!("smbios type2 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("manufacturer")
            .push("product")
            .push("version")
            .push("serial")
            .push("asset")
            .push("location");
        cmd_parser.parse(type2)?;

        self.smbios.type2.manufacturer = cmd_parser.get_value::<String>("manufacturer")?;
        self.smbios.type2.product = cmd_parser.get_value::<String>("product")?;
        self.smbios.type2.version = cmd_parser.get_value::<String>("version")?;
        self.smbios.type2.serial = cmd_parser.get_value::<String>("serial")?;
        self.smbios.type2.asset = cmd_parser.get_value::<String>("asset")?;
        self.smbios.type2.location = cmd_parser.get_value::<String>("location")?;
        self.smbios.type2.added = true;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type3` - The type3 cmdline string.
    fn add_smbios_type3(&mut self, type3: &str) -> Result<()> {
        if self.smbios.type3.added {
            bail!("smbios type3 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("manufacturer")
            .push("version")
            .push("serial")
            .push("sku")
            .push("asset");
        cmd_parser.parse(type3)?;

        self.smbios.type3.manufacturer = cmd_parser.get_value::<String>("manufacturer")?;
        self.smbios.type3.version = cmd_parser.get_value::<String>("version")?;
        self.smbios.type3.serial = cmd_parser.get_value::<String>("serial")?;
        self.smbios.type3.sku = cmd_parser.get_value::<String>("sku")?;
        self.smbios.type3.asset = cmd_parser.get_value::<String>("asset")?;
        self.smbios.type3.added = true;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type4` - The type4 cmdline string.
    fn add_smbios_type4(&mut self, type4: &str) -> Result<()> {
        if self.smbios.type4.added {
            bail!("smbios type4 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("manufacturer")
            .push("version")
            .push("serial")
            .push("sock_pfx")
            .push("max-speed")
            .push("current-speed")
            .push("part")
            .push("asset");
        cmd_parser.parse(type4)?;

        self.smbios.type4.manufacturer = cmd_parser.get_value::<String>("manufacturer")?;
        self.smbios.type4.version = cmd_parser.get_value::<String>("version")?;
        self.smbios.type4.serial = cmd_parser.get_value::<String>("serial")?;
        self.smbios.type4.asset = cmd_parser.get_value::<String>("asset")?;
        self.smbios.type4.part = cmd_parser.get_value::<String>("part")?;
        self.smbios.type4.sock_pfx = cmd_parser.get_value::<String>("sock_pfx")?;
        self.smbios.type4.max_speed = cmd_parser.get_value::<u64>("max-speed")?;
        self.smbios.type4.current_speed = cmd_parser.get_value::<u64>("current-speed")?;
        self.smbios.type4.added = true;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type17` - The type17 cmdline string.
    fn add_smbios_type17(&mut self, type17: &str) -> Result<()> {
        if self.smbios.type17.added {
            bail!("smbios type17 has been added");
        }

        let mut cmd_parser = CmdParser::new("smbios");
        cmd_parser
            .push("")
            .push("type")
            .push("loc_pfx")
            .push("bank")
            .push("manufacturer")
            .push("serial")
            .push("speed")
            .push("part")
            .push("asset");
        cmd_parser.parse(type17)?;

        self.smbios.type17.manufacturer = cmd_parser.get_value::<String>("manufacturer")?;
        self.smbios.type17.loc_pfx = cmd_parser.get_value::<String>("loc_pfx")?;
        self.smbios.type17.serial = cmd_parser.get_value::<String>("serial")?;
        self.smbios.type17.asset = cmd_parser.get_value::<String>("asset")?;
        self.smbios.type17.part = cmd_parser.get_value::<String>("part")?;
        self.smbios.type17.speed = if let Some(speed) = cmd_parser.get_value::<u16>("speed")? {
            speed
        } else {
            0
        };
        self.smbios.type17.bank = cmd_parser.get_value::<String>("bank")?;
        self.smbios.type17.added = true;

        Ok(())
    }

    /// Add argument `smbios_args` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `smbios_args` - The args of object.
    pub fn add_smbios(&mut self, smbios_args: &str) -> Result<()> {
        let mut cmd_params = CmdParser::new("smbios");
        cmd_params.push("").push("type");

        cmd_params.get_parameters(smbios_args)?;
        let smbios_type = cmd_params
            .get_value::<String>("type")?
            .with_context(|| "smbios type not specified")?;
        match smbios_type.as_str() {
            "0" => {
                self.add_smbios_type0(smbios_args)?;
            }
            "1" => {
                self.add_smbios_type1(smbios_args)?;
            }
            "2" => {
                self.add_smbios_type2(smbios_args)?;
            }
            "3" => {
                self.add_smbios_type3(smbios_args)?;
            }
            "4" => {
                self.add_smbios_type4(smbios_args)?;
            }
            "17" => {
                self.add_smbios_type17(smbios_args)?;
            }
            _ => {
                bail!("Unknow smbios type: {:?}", &smbios_type);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_smbios_uuid() {
        let uuid = Uuid::from_str("33DB4D5E-1FF7-401C-9657-7441C03DD766").unwrap();

        assert_eq!(
            uuid.name.to_vec(),
            &[
                0x5E, 0x4D, 0xDB, 0x33, 0xF7, 0x1F, 0x1C, 0x40, 0x96, 0x57, 0x74, 0x41, 0xC0, 0x3D,
                0xD7, 0x66
            ]
        );
    }
}
