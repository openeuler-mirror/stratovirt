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

use anyhow::{Context, Result};
use regex::Regex;

use super::{CmdParser, VmConfig};
use crate::qmp::qmp_schema;

impl VmConfig {
    /// Add config of hot-plugged devices to `VmConfig`.
    pub fn add_device_config(&mut self, args: &qmp_schema::DeviceAddArgument) -> String {
        let mut device_info = args.driver.clone();

        device_info = format!("{},id={}", device_info, args.id);
        if let Some(addr) = &args.addr {
            device_info = format!("{},addr={}", device_info, addr);
        }
        if let Some(bus) = &args.bus {
            device_info = format!("{},bus={}", device_info, bus);
        }
        if let Some(drive) = &args.drive {
            device_info = format!("{},drive={}", device_info, drive);
        }
        if let Some(mq) = &args.mq {
            device_info = format!("{},mq={}", device_info, mq);
        }
        if let Some(iothread) = &args.iothread {
            device_info = format!("{},iothread={}", device_info, iothread);
        }
        if let Some(multi) = &args.multifunction {
            if *multi {
                device_info = format!("{},multifunction=on", device_info);
            } else {
                device_info = format!("{},multifunction=off", device_info);
            }
        }
        if let Some(queues) = &args.queues {
            device_info = format!("{},num-queues={}", device_info, queues);
        }
        if let Some(size) = &args.queue_size {
            device_info = format!("{},queue-size={}", device_info, size);
        }

        // For net devices only.
        if let Some(mac) = &args.mac {
            device_info = format!("{},mac={}", device_info, mac);
        }
        if let Some(netdev) = &args.netdev {
            device_info = format!("{},netdev={}", device_info, netdev);
        }
        if let Some(mq) = &args.mq {
            device_info = format!("{},mq={}", device_info, mq);
        }

        // For vhost devices only.
        if let Some(chardev) = &args.chardev {
            device_info = format!("{},chardev={}", device_info, chardev);
        }

        // For block devices only.
        if let Some(serial_num) = &args.serial_num {
            device_info = format!("{},serial={}", device_info, serial_num);
        }
        if let Some(boot_index) = &args.boot_index {
            device_info = format!("{},bootindex={}", device_info, boot_index);
        }

        // For vfio devices only.
        if let Some(host) = &args.host {
            device_info = format!("{},addr={}", device_info, host);
        }
        if let Some(sysfsdev) = &args.sysfsdev {
            device_info = format!("{},addr={}", device_info, sysfsdev);
        }

        // For usb camera devices only.
        if let Some(cameradev) = &args.cameradev {
            device_info = format!("{},cameradev={}", device_info, cameradev);
        }

        // For usb host devices only.
        if args.driver == "usb-host" {
            let default_value = "0".to_string();
            let hostbus = args.hostbus.as_ref().unwrap_or(&default_value);
            let hostaddr = args.hostaddr.as_ref().unwrap_or(&default_value);
            let vendorid = args.vendorid.as_ref().unwrap_or(&default_value);
            let productid = args.productid.as_ref().unwrap_or(&default_value);
            device_info = format!(
                "{},hostbus={},hostaddr={},vendorid={},productid={}",
                device_info, hostbus, hostaddr, vendorid, productid
            );
            if let Some(hostport) = &args.hostport {
                device_info = format!("{},hostport={}", device_info, hostport);
            }
            if let Some(isobufs) = &args.isobufs {
                device_info = format!("{},isobufs={}", device_info, isobufs);
            }
            if let Some(isobsize) = &args.isobsize {
                device_info = format!("{},isobsize={}", device_info, isobsize);
            }
        }

        self.devices
            .push((args.driver.clone(), device_info.clone()));

        device_info
    }

    pub fn add_device(&mut self, device_config: &str) -> Result<()> {
        let device_type = parse_device_type(device_config)?;
        self.devices.push((device_type, device_config.to_string()));

        Ok(())
    }

    pub fn del_device_by_id(&mut self, dev_id: String) {
        let rex = format!("id={}(,|$)", dev_id);
        let re = Regex::new(rex.as_str()).unwrap();

        for (index, (_, dev_info)) in self.devices.iter().enumerate() {
            if re.is_match(dev_info.as_str()) {
                self.devices.remove(index);
                return;
            }
        }
    }
}

pub fn parse_device_type(device_config: &str) -> Result<String> {
    let mut cmd_params = CmdParser::new("device");
    cmd_params.push("");
    cmd_params.get_parameters(device_config)?;
    cmd_params
        .get_value::<String>("")?
        .with_context(|| "Missing driver field.")
}

pub fn parse_device_id(device_config: &str) -> Result<String> {
    let mut cmd_parser = CmdParser::new("device");
    cmd_parser.push("id");

    cmd_parser.get_parameters(device_config)?;
    if let Some(id) = cmd_parser.get_value::<String>("id")? {
        Ok(id)
    } else {
        Ok(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_device_id() {
        let test_conf = "virtio-blk-device,drive=rootfs,id=blkid";
        let ret = parse_device_id(test_conf);
        assert!(ret.is_ok());
        let id = ret.unwrap();
        assert_eq!("blkid", id);

        let test_conf = "virtio-blk-device,drive=rootfs";
        let ret = parse_device_id(test_conf);
        assert!(ret.is_ok());
        let id = ret.unwrap();
        assert_eq!("", id);
    }
}
