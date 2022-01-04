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

use std::fs::metadata;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    errors::{ErrorKind, Result},
    pci_args_check,
};
use crate::config::{CmdParser, ConfigCheck, ExBool, VmConfig, MAX_PATH_LENGTH, MAX_STRING_LENGTH};

const MAX_SERIAL_NUM: usize = 20;
const MAX_IOPS: u64 = 1_000_000;
const MAX_UNIT_ID: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlkDevConfig {
    pub id: String,
    pub path_on_host: String,
    pub read_only: bool,
    pub direct: bool,
    pub serial_num: Option<String>,
    pub iothread: Option<String>,
    pub iops: Option<u64>,
}

impl Default for BlkDevConfig {
    fn default() -> Self {
        BlkDevConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            serial_num: None,
            iothread: None,
            iops: None,
        }
    }
}

/// Config struct for `drive`.
/// Contains block device's attr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriveConfig {
    pub id: String,
    pub path_on_host: String,
    pub read_only: bool,
    pub direct: bool,
    pub iops: Option<u64>,
}

impl Default for DriveConfig {
    fn default() -> Self {
        DriveConfig {
            id: "".to_string(),
            path_on_host: "".to_string(),
            read_only: false,
            direct: true,
            iops: None,
        }
    }
}

impl DriveConfig {
    /// Check whether the drive file path on the host is valid.
    pub fn check_path(&self) -> Result<()> {
        let blk = Path::new(&self.path_on_host);
        match metadata(blk) {
            Ok(meta) => {
                if ((meta.st_mode() & libc::S_IFREG) != libc::S_IFREG)
                    && ((meta.st_mode() & libc::S_IFBLK) != libc::S_IFBLK)
                {
                    return Err(ErrorKind::UnRegularFile("Drive File".to_string()).into());
                }
            }
            Err(e) => {
                error!("Failed to check the drive metadata: {}", e);
                return Err(ErrorKind::UnRegularFile("Drive File".to_string()).into());
            }
        }
        if let Some(file_name) = blk.file_name() {
            if file_name.len() > MAX_STRING_LENGTH {
                return Err(ErrorKind::StringLengthTooLong(
                    "File name".to_string(),
                    MAX_STRING_LENGTH,
                )
                .into());
            }
        } else {
            error!("Failed to check the drive file name");
            return Err(ErrorKind::UnRegularFile("Drive File".to_string()).into());
        }
        Ok(())
    }
}

impl ConfigCheck for DriveConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(
                ErrorKind::StringLengthTooLong("Drive id".to_string(), MAX_STRING_LENGTH).into(),
            );
        }
        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "Drive device path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }
        if self.iops.is_some() && self.iops.unwrap() > MAX_IOPS {
            return Err(ErrorKind::IllegalValue(
                "iops of block device".to_string(),
                0,
                true,
                MAX_IOPS,
                true,
            )
            .into());
        }
        Ok(())
    }
}

impl ConfigCheck for BlkDevConfig {
    fn check(&self) -> Result<()> {
        if self.id.len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device id".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if self.serial_num.is_some() && self.serial_num.as_ref().unwrap().len() > MAX_SERIAL_NUM {
            return Err(ErrorKind::StringLengthTooLong(
                "drive serial number".to_string(),
                MAX_SERIAL_NUM,
            )
            .into());
        }

        if self.iothread.is_some() && self.iothread.as_ref().unwrap().len() > MAX_STRING_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "iothread name".to_string(),
                MAX_STRING_LENGTH,
            )
            .into());
        }

        if self.iops.is_some() && self.iops.unwrap() > MAX_IOPS {
            return Err(ErrorKind::IllegalValue(
                "iops of block device".to_string(),
                0,
                true,
                MAX_IOPS,
                true,
            )
            .into());
        }

        Ok(())
    }
}

pub fn parse_drive(cmd_parser: CmdParser) -> Result<DriveConfig> {
    let mut drive = DriveConfig::default();

    if let Some(format) = cmd_parser.get_value::<String>("format")? {
        if format.ne("raw") {
            bail!("Only \'raw\' type of block is supported");
        }
    }

    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        drive.id = id;
    } else {
        return Err(ErrorKind::FieldIsMissing("id", "blk").into());
    }

    if let Some(file) = cmd_parser.get_value::<String>("file")? {
        drive.path_on_host = file;
    } else {
        return Err(ErrorKind::FieldIsMissing("file", "blk").into());
    }

    if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
        drive.read_only = read_only.into();
    }
    if let Some(direct) = cmd_parser.get_value::<ExBool>("direct")? {
        drive.direct = direct.into();
    }
    drive.iops = cmd_parser.get_value::<u64>("throttling.iops-total")?;
    Ok(drive)
}

pub fn parse_blk(vm_config: &mut VmConfig, drive_config: &str) -> Result<BlkDevConfig> {
    let mut cmd_parser = CmdParser::new("virtio-blk");
    cmd_parser
        .push("")
        .push("id")
        .push("bus")
        .push("addr")
        .push("multifunction")
        .push("drive")
        .push("bootindex")
        .push("serial")
        .push("iothread");

    cmd_parser.parse(drive_config)?;

    pci_args_check(&cmd_parser)?;

    if let Err(ref e) = cmd_parser.get_value::<u8>("bootindex") {
        bail!("Failed to parse \'bootindex\': {:?}", &e);
    }

    let mut blkdevcfg = BlkDevConfig::default();
    let blkdrive = if let Some(drive) = cmd_parser.get_value::<String>("drive")? {
        drive
    } else {
        return Err(ErrorKind::FieldIsMissing("drive", "blk").into());
    };

    if let Some(iothread) = cmd_parser.get_value::<String>("iothread")? {
        blkdevcfg.iothread = Some(iothread);
    }

    if let Some(serial) = cmd_parser.get_value::<String>("serial")? {
        blkdevcfg.serial_num = Some(serial);
    }

    if let Some(drive_arg) = &vm_config.drives.remove(&blkdrive) {
        blkdevcfg.id = drive_arg.id.clone();
        blkdevcfg.path_on_host = drive_arg.path_on_host.clone();
        blkdevcfg.read_only = drive_arg.read_only;
        blkdevcfg.direct = drive_arg.direct;
        blkdevcfg.iops = drive_arg.iops;
    } else {
        bail!("No drive configured matched for blk device");
    }
    blkdevcfg.check()?;
    Ok(blkdevcfg)
}

/// Config struct for `pflash`.
/// Contains pflash device's attr.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PFlashConfig {
    pub path_on_host: String,
    pub read_only: bool,
    pub unit: usize,
}

impl Default for PFlashConfig {
    fn default() -> Self {
        PFlashConfig {
            path_on_host: String::new(),
            read_only: false,
            unit: 0_usize,
        }
    }
}

impl ConfigCheck for PFlashConfig {
    fn check(&self) -> Result<()> {
        if self.path_on_host.len() > MAX_PATH_LENGTH {
            return Err(ErrorKind::StringLengthTooLong(
                "drive device path".to_string(),
                MAX_PATH_LENGTH,
            )
            .into());
        }

        if self.unit >= MAX_UNIT_ID {
            return Err(ErrorKind::UnitIdError(self.unit, MAX_UNIT_ID).into());
        }
        Ok(())
    }
}

impl VmConfig {
    /// Add '-drive ...' drive config to `VmConfig`.
    pub fn add_drive(&mut self, drive_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser.push("if");

        cmd_parser.get_parameters(drive_config)?;
        let drive_type = if let Some(_type) = cmd_parser.get_value::<String>("if")? {
            _type
        } else {
            "none".to_string()
        };
        match drive_type.as_str() {
            "none" => {
                self.add_block_drive(&drive_config)?;
            }
            "pflash" => {
                self.add_pflash(&drive_config)?;
            }
            _ => {
                bail!("Unknow 'if' argument: {:?}", drive_type.as_str());
            }
        }

        Ok(())
    }

    fn add_block_drive(&mut self, block_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("drive");
        cmd_parser
            .push("file")
            .push("id")
            .push("readonly")
            .push("direct")
            .push("format")
            .push("if")
            .push("throttling.iops-total")
            .push("serial");

        cmd_parser.parse(block_config)?;
        let drive_cfg = parse_drive(cmd_parser)?;
        self.add_drive_with_config(drive_cfg)
    }

    /// Add drive config to vm config.
    ///
    /// # Arguments
    ///
    /// * `drive_conf` - The drive config to be added to the vm.
    pub fn add_drive_with_config(&mut self, drive_conf: DriveConfig) -> Result<()> {
        let drive_id = drive_conf.id.clone();
        if self.drives.get(&drive_id).is_none() {
            self.drives.insert(drive_id, drive_conf);
        } else {
            bail!("Drive {} has been added", drive_id);
        }
        Ok(())
    }

    /// Delete drive config in vm config by id.
    ///
    /// # Arguments
    ///
    /// * `drive_id` - Drive id.
    pub fn del_drive_by_id(&mut self, drive_id: &str) -> Result<()> {
        if self.drives.get(drive_id).is_some() {
            self.drives.remove(drive_id);
        } else {
            bail!("Drive {} not found", drive_id);
        }
        Ok(())
    }

    /// Add new flash device to `VmConfig`.
    fn add_flashdev(&mut self, pflash: PFlashConfig) -> Result<()> {
        if self.pflashs.is_some() {
            for pf in self.pflashs.as_ref().unwrap() {
                if pf.unit == pflash.unit {
                    return Err(
                        ErrorKind::IdRepeat("pflash".to_string(), pf.unit.to_string()).into(),
                    );
                }
            }
            self.pflashs.as_mut().unwrap().push(pflash);
        } else {
            self.pflashs = Some(vec![pflash]);
        }
        Ok(())
    }

    /// Add '-pflash ...' pflash config to `VmConfig`.
    pub fn add_pflash(&mut self, pflash_config: &str) -> Result<()> {
        let mut cmd_parser = CmdParser::new("pflash");
        cmd_parser
            .push("if")
            .push("file")
            .push("format")
            .push("readonly")
            .push("unit");

        cmd_parser.parse(pflash_config)?;

        let mut pflash = PFlashConfig::default();

        if let Some(format) = cmd_parser.get_value::<String>("format")? {
            if format.ne("raw") {
                bail!("Only \'raw\' type of pflash is supported");
            }
        }
        if let Some(drive_path) = cmd_parser.get_value::<String>("file")? {
            pflash.path_on_host = drive_path;
        } else {
            return Err(ErrorKind::FieldIsMissing("file", "pflash").into());
        }

        if let Some(read_only) = cmd_parser.get_value::<ExBool>("readonly")? {
            pflash.read_only = read_only.into();
        }

        if let Some(unit_id) = cmd_parser.get_value::<u64>("unit")? {
            pflash.unit = unit_id as usize;
        } else {
            return Err(ErrorKind::FieldIsMissing("unit", "pflash").into());
        }

        pflash.check()?;
        self.add_flashdev(pflash)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::get_pci_bdf;

    use super::*;

    #[test]
    fn test_drive_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive(
                "id=rootfs,file=/path/to/rootfs,readonly=off,direct=on,throttling.iops-total=200"
            )
            .is_ok());
        let blk_cfg_res = parse_blk(
            &mut vm_config,
            "virtio-blk-device,drive=rootfs,iothread=iothread1,serial=111111",
        );
        assert!(blk_cfg_res.is_ok());
        let blk_device_config = blk_cfg_res.unwrap();
        assert_eq!(blk_device_config.id, "rootfs");
        assert_eq!(blk_device_config.path_on_host, "/path/to/rootfs");
        assert_eq!(blk_device_config.direct, true);
        assert_eq!(blk_device_config.read_only, false);
        assert_eq!(blk_device_config.serial_num, Some(String::from("111111")));

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,readonly=off,direct=on")
            .is_ok());
        let blk_cfg_res = parse_blk(
            &mut vm_config,
            "virtio-blk-device,drive=rootfs1,iothread=iothread1,iops=200,serial=111111",
        );
        assert!(blk_cfg_res.is_err()); // Can not find drive named "rootfs1".
    }

    #[test]
    fn test_pci_block_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,readonly=off,direct=on")
            .is_ok());
        let blk_cfg = "virtio-blk-pci,id=blk1,bus=pcie.0,addr=0x1.0x2,drive=rootfs,serial=111111";
        let blk_cfg_res = parse_blk(&mut vm_config, blk_cfg);
        assert!(blk_cfg_res.is_ok());
        let drive_configs = blk_cfg_res.unwrap();
        assert_eq!(drive_configs.id, "rootfs");
        assert_eq!(drive_configs.path_on_host, "/path/to/rootfs");
        assert_eq!(drive_configs.direct, true);
        assert_eq!(drive_configs.read_only, false);
        assert_eq!(drive_configs.serial_num, Some(String::from("111111")));

        let pci_bdf = get_pci_bdf(blk_cfg);
        assert!(pci_bdf.is_ok());
        let pci = pci_bdf.unwrap();
        assert_eq!(pci.bus, "pcie.0".to_string());
        assert_eq!(pci.addr, (1, 2));

        //  drive "rootfs" has been removed.
        let blk_cfg_res = parse_blk(&mut vm_config, blk_cfg);
        assert!(blk_cfg_res.is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("id=rootfs,file=/path/to/rootfs,serial=111111,readonly=off,direct=on")
            .is_ok());
        let blk_cfg =
            "virtio-blk-pci,id=blk1,bus=pcie.0,addr=0x1.0x2,drive=rootfs,multifunction=on";
        assert!(parse_blk(&mut vm_config, blk_cfg).is_ok());
    }

    #[test]
    fn test_pflash_config_cmdline_parser() {
        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0")
            .is_ok());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 1);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit, 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.read_only, true);

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,file=flash0.fd,unit=0,if=pflash")
            .is_ok());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("readonly=on,if=pflash,file=flash0.fd,unit=0")
            .is_ok());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=2")
            .is_err());

        let mut vm_config = VmConfig::default();
        assert!(vm_config
            .add_drive("if=pflash,readonly=on,file=flash0.fd,unit=0")
            .is_ok());
        assert!(vm_config
            .add_drive("if=pflash,file=flash1.fd,unit=1")
            .is_ok());
        assert!(vm_config.pflashs.is_some());
        let pflash = vm_config.pflashs.unwrap();
        assert!(pflash.len() == 2);
        let pflash_cfg = &pflash[0];
        assert_eq!(pflash_cfg.unit, 0);
        assert_eq!(pflash_cfg.path_on_host, "flash0.fd".to_string());
        assert_eq!(pflash_cfg.read_only, true);
        let pflash_cfg = &pflash[1];
        assert_eq!(pflash_cfg.unit, 1);
        assert_eq!(pflash_cfg.path_on_host, "flash1.fd".to_string());
        assert_eq!(pflash_cfg.read_only, false);
    }

    #[test]
    fn test_drive_config_check() {
        let mut drive_conf = DriveConfig::default();
        for _ in 0..MAX_STRING_LENGTH {
            drive_conf.id += "A";
        }
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.id += "A";
        assert!(drive_conf.check().is_err());

        let mut drive_conf = DriveConfig::default();
        for _ in 0..MAX_PATH_LENGTH {
            drive_conf.path_on_host += "A";
        }
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.path_on_host += "A";
        assert!(drive_conf.check().is_err());

        let mut drive_conf = DriveConfig::default();
        drive_conf.iops = Some(MAX_IOPS);
        assert!(drive_conf.check().is_ok());

        let mut drive_conf = DriveConfig::default();
        drive_conf.iops = None;
        assert!(drive_conf.check().is_ok());

        // Overflow
        drive_conf.iops = Some(MAX_IOPS + 1);
        assert!(drive_conf.check().is_err());
    }

    #[test]
    fn test_add_drive_with_config() {
        let mut vm_config = VmConfig::default();

        let drive_list = ["drive-0", "drive-1", "drive-2"];
        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.add_drive_with_config(drive_conf).is_ok());

            let drive = vm_config.drives.get(*id).unwrap();
            assert_eq!(*id, drive.id);
        }

        let mut drive_conf = DriveConfig::default();
        drive_conf.id = String::from("drive-0");
        assert!(vm_config.add_drive_with_config(drive_conf).is_err());
    }

    #[test]
    fn test_del_drive_by_id() {
        let mut vm_config = VmConfig::default();

        assert!(vm_config.del_drive_by_id("drive-0").is_err());

        let drive_list = ["drive-0", "drive-1", "drive-2"];
        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.add_drive_with_config(drive_conf).is_ok());
        }

        for id in drive_list.iter() {
            let mut drive_conf = DriveConfig::default();
            drive_conf.id = String::from(*id);
            assert!(vm_config.drives.get(*id).is_some());
            assert!(vm_config.del_drive_by_id(*id).is_ok());
            assert!(vm_config.drives.get(*id).is_none());
        }
    }
}
