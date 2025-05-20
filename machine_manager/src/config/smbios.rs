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

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use super::{get_value_of_parameter, str_slip_to_clap};
use crate::config::VmConfig;

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType0Config {
    #[arg(long, alias = "type", value_parser = ["0"])]
    pub smbios_type: String,
    #[arg(long)]
    pub vendor: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub date: Option<String>,
    // Note: we don't set `ArgAction::Append` for `added`, so it cannot be specified
    // from the command line, as command line will parse errors.
    #[arg(long, default_value = "true")]
    pub added: bool,
}

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType1Config {
    #[arg(long, alias = "type", value_parser = ["1"])]
    pub smbios_type: String,
    #[arg(long)]
    pub manufacturer: Option<String>,
    #[arg(long)]
    pub product: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub serial: Option<String>,
    #[arg(long)]
    pub sku: Option<String>,
    #[arg(long)]
    pub family: Option<String>,
    #[arg(long, value_parser = get_uuid)]
    pub uuid: Option<Uuid>,
    #[arg(long, default_value = "true")]
    pub added: bool,
}

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType2Config {
    #[arg(long, alias = "type", value_parser = ["2"])]
    pub smbios_type: String,
    #[arg(long)]
    pub manufacturer: Option<String>,
    #[arg(long)]
    pub product: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub serial: Option<String>,
    #[arg(long)]
    pub asset: Option<String>,
    #[arg(long)]
    pub location: Option<String>,
    #[arg(long, default_value = "true")]
    pub added: bool,
}

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType3Config {
    #[arg(long, alias = "type", value_parser = ["3"])]
    pub smbios_type: String,
    #[arg(long)]
    pub manufacturer: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub serial: Option<String>,
    #[arg(long)]
    pub sku: Option<String>,
    #[arg(long)]
    pub asset: Option<String>,
    #[arg(long, default_value = "true")]
    pub added: bool,
}

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType4Config {
    #[arg(long, alias = "type", value_parser = ["4"])]
    pub smbios_type: String,
    #[arg(long)]
    pub manufacturer: Option<String>,
    #[arg(long)]
    pub version: Option<String>,
    #[arg(long)]
    pub serial: Option<String>,
    #[arg(long)]
    pub asset: Option<String>,
    #[arg(long, alias = "sock_pfx")]
    pub sock_pfx: Option<String>,
    #[arg(long)]
    pub part: Option<String>,
    #[arg(long)]
    pub max_speed: Option<u64>,
    #[arg(long)]
    pub current_speed: Option<u64>,
    #[arg(long, default_value = "true")]
    pub added: bool,
}

#[derive(Parser, Clone, Default, Debug, Serialize, Deserialize)]
#[command(no_binary_name(true))]
pub struct SmbiosType17Config {
    #[arg(long, alias = "type", value_parser = ["17"])]
    pub smbios_type: String,
    #[arg(long)]
    pub manufacturer: Option<String>,
    #[arg(long)]
    pub serial: Option<String>,
    #[arg(long)]
    pub asset: Option<String>,
    #[arg(long, alias = "loc_pfx")]
    pub loc_pfx: Option<String>,
    #[arg(long)]
    pub part: Option<String>,
    #[arg(long, default_value = "0")]
    pub speed: u16,
    #[arg(long)]
    pub bank: Option<String>,
    #[arg(long, default_value = "true")]
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
    type Err = anyhow::Error;

    fn from_str(str: &str) -> std::result::Result<Self, Self::Err> {
        let name = str.to_string();

        if !check_valid_uuid(&name) {
            return Err(anyhow!("Invalid uuid {}", name));
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

fn get_uuid(s: &str) -> Result<Uuid> {
    let uuid = Uuid::from_str(s)?;
    Ok(uuid)
}

impl VmConfig {
    /// # Arguments
    ///
    /// * `type0` - The type0 cmdline string.
    fn add_smbios_type0(&mut self, type0: &str) -> Result<()> {
        if self.smbios.type0.added {
            bail!("smbios type0 has been added");
        }

        let type0_cfg = SmbiosType0Config::try_parse_from(str_slip_to_clap(type0, false, false))?;
        self.smbios.type0 = type0_cfg;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type1` - The type1 cmdline string.
    fn add_smbios_type1(&mut self, type1: &str) -> Result<()> {
        if self.smbios.type1.added {
            bail!("smbios type1 has been added");
        }

        let type1_cfg = SmbiosType1Config::try_parse_from(str_slip_to_clap(type1, false, false))?;
        self.smbios.type1 = type1_cfg;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type2` - The type2 cmdline string.
    fn add_smbios_type2(&mut self, type2: &str) -> Result<()> {
        if self.smbios.type2.added {
            bail!("smbios type2 has been added");
        }
        let type2_cfg = SmbiosType2Config::try_parse_from(str_slip_to_clap(type2, false, false))?;
        self.smbios.type2 = type2_cfg;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type3` - The type3 cmdline string.
    fn add_smbios_type3(&mut self, type3: &str) -> Result<()> {
        if self.smbios.type3.added {
            bail!("smbios type3 has been added");
        }

        let type3_cfg = SmbiosType3Config::try_parse_from(str_slip_to_clap(type3, false, false))?;
        self.smbios.type3 = type3_cfg;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type4` - The type4 cmdline string.
    fn add_smbios_type4(&mut self, type4: &str) -> Result<()> {
        if self.smbios.type4.added {
            bail!("smbios type4 has been added");
        }

        let type4_cfg = SmbiosType4Config::try_parse_from(str_slip_to_clap(type4, false, false))?;
        self.smbios.type4 = type4_cfg;

        Ok(())
    }

    /// # Arguments
    ///
    /// * `type17` - The type17 cmdline string.
    fn add_smbios_type17(&mut self, type17: &str) -> Result<()> {
        if self.smbios.type17.added {
            bail!("smbios type17 has been added");
        }

        let type17_cfg =
            SmbiosType17Config::try_parse_from(str_slip_to_clap(type17, false, false))?;
        self.smbios.type17 = type17_cfg;

        Ok(())
    }

    /// Add argument `smbios_args` to `VmConfig`.
    ///
    /// # Arguments
    ///
    /// * `smbios_args` - The args of object.
    pub fn add_smbios(&mut self, smbios_args: &str) -> Result<()> {
        let smbios_type = get_value_of_parameter("type", smbios_args)?;
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
                bail!("Unknown smbios type: {:?}", &smbios_type);
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

    #[test]
    fn test_add_smbios() {
        let mut vm_config = VmConfig::default();

        let smbios0 = "type=0,vendor=fake,version=fake,date=fake";
        let smbios1 = "type=1,manufacturer=fake,version=fake,product=fake,serial=fake,uuid=33DB4D5E-1FF7-401C-9657-7441C03DD766,sku=fake,family=fake";
        let smbios2 = "type=2,manufacturer=fake,product=fake,version=fake,serial=fake,asset=fake,location=fake";
        let smbios3 = "type=3,manufacturer=fake,version=fake,serial=fake,asset=fake,sku=fake";
        let smbios4 = "type=4,sock_pfx=fake,manufacturer=fake,version=fake,serial=fake,asset=fake,part=fake,max-speed=1,current-speed=1";
        let smbios17 = "type=17,loc_pfx=fake,bank=fake,manufacturer=fake,serial=fake,asset=fake,part=fake,speed=1";

        assert!(vm_config.add_smbios(smbios0).is_ok());
        assert!(vm_config.add_smbios(smbios1).is_ok());
        assert!(vm_config.add_smbios(smbios2).is_ok());
        assert!(vm_config.add_smbios(smbios3).is_ok());
        assert!(vm_config.add_smbios(smbios4).is_ok());
        assert!(vm_config.add_smbios(smbios17).is_ok());
        assert!(vm_config.add_smbios(smbios0).is_err());
    }
}
