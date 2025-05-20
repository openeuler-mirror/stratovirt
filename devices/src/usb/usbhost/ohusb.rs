// Copyright (c) 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::ptr;

use anyhow::{bail, Context as anyhowContext, Result};
use libusb1_sys::constants::LIBUSB_OPTION_NO_DEVICE_DISCOVERY;
use log::info;
use rusb::{Context, DeviceHandle, UsbContext};

use super::host_usblib::set_option;
use super::{check_device_valid, UsbHostConfig};
use util::ohos_binding::usb::*;

pub struct OhUsbDev {
    #[allow(dead_code)]
    lib: OhUsb,
    dev_file: File,
}

impl OhUsbDev {
    pub fn new(bus_num: u8, dev_addr: u8) -> Result<Self> {
        // In combination with libusb_wrap_sys_device(), in order to access a device directly without prior device scanning on ohos.
        set_option(LIBUSB_OPTION_NO_DEVICE_DISCOVERY)?;

        let mut ohusb_dev = OhusbDevice {
            busNum: bus_num,
            devAddr: dev_addr,
            fd: -1,
        };

        let lib = OhUsb::new()?;
        match lib.open_device(ptr::addr_of_mut!(ohusb_dev))? {
            0 => {
                if ohusb_dev.fd < 0 {
                    bail!(
                        "Failed to open usb device due to invalid fd {}",
                        ohusb_dev.fd
                    );
                }
            }
            _ => bail!("Failed to open usb device"),
        }
        info!("OH USB: open_device: returned fd is {}", ohusb_dev.fd);

        Ok(Self {
            lib,
            // SAFETY: fd is passed from OH USB framework and we have checked the function return value.
            // Now let's save it to rust File struct.
            dev_file: unsafe { File::from_raw_fd(ohusb_dev.fd) },
        })
    }

    pub fn open(&mut self, cfg: UsbHostConfig, ctx: Context) -> Result<DeviceHandle<Context>> {
        // SAFETY: The validation of fd is guaranteed by new function.
        let handle = unsafe {
            ctx.open_device_with_fd(self.dev_file.as_raw_fd())
                .with_context(|| format!("os last error: {:?}", std::io::Error::last_os_error()))?
        };

        if !check_device_valid(&handle.device()) {
            bail!("Invalid USB host config: {:?}", cfg);
        }

        Ok(handle)
    }
}
